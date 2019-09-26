/********************************************
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/sysfs.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/kobject.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/anon_inodes.h>
#include <linux/uaccess.h>
#include <linux/fcntl.h>
#include "sph_log.h"
#include "sph_version.h"
#include "sphpb.h"
#include "sphpb_punit.h"

const uint32_t grade_active_icebo_higer_ring_divisor	= 40;
const uint32_t grade_active_icebo_lower_divisor		= 55;
const uint32_t grade_active_icebo_same_ring_divisor	= 65;
const uint32_t grade_inactive_icebo			= 70;

/*
 * fixed point 1U15 - number is between 0.0 - 1.99
 * assume always positive number hence - gap between values 0x0000 - 0xFFFF
 */
int fx_U1F15_compare(uint16_t a, uint16_t b)
{
	int ret;

	/*
	 * if equal return 0;
	 */
	if (a == b)
		return 0;

	/*
	 * if a > b - return gap between a and b - positive number
	 * if b > a - retirn gap between b and a - negetive number
	 */

	ret = (a > b) ? (int)(a - b) : 0 - (int)(b - a);

	return ret;
}


int sphpb_mng_get_efficient_ice_list(struct sphpb_pb *sphpb,
				     uint32_t ice_mask,
				     uint16_t ice_to_ring_ratio,
				     uint16_t fx_ice_ice_ratio,
				     uint8_t *o_ice_array,
				     ssize_t array_size)
{
	uint32_t icebo_number;
	uint32_t ice_in_icebo;
	struct list_head ice_power_efficiency_list;
	struct sphpb_ice_node *ice_select, *r;
	uint32_t highp_selection_count = 0;
	uint32_t ice_index = 0;


	INIT_LIST_HEAD(&ice_power_efficiency_list);

	memset(o_ice_array, 0xFF, array_size*(sizeof(uint8_t)));

	/*
	 * loop for all enabled ices in sku
	 */

	while (ice_mask) {
		/*
		 * if ice is available for power on
		 */

		if (ice_mask & 0x1) {
			uint32_t score = 0x0;

			/*
			 * set ice and icebo number - based on ice index
			 */
			icebo_number = ice_index / SPHPB_MAX_ICE_PER_ICEBO;
			ice_in_icebo = (ice_index % SPHPB_MAX_ICE_PER_ICEBO);

			/*
			 * check if icebo if powered on
			 */
			if (sphpb->icebo[icebo_number].enabled_ices_mask) {
				/*
				 * check if ice is not enabled, if ice enabled - no
				 * need to score it - default will be 0x0 - and
				 * will not added to list
				 */
				if (!sphpb->icebo[icebo_number].ice[ice_in_icebo].bEnable) {
					int compare_ring_divisor;

					/*
					 * get requested value comparison vs current ring divisor
					 * > 0 - requested ring divisor is higher then current divisor - need more power
					 * = 0 - request is identical to current icebo divisor - keep same power
					 * < 0 - request id lower then current divisor - no need to increase power
					 */
					compare_ring_divisor = fx_U1F15_compare(ice_to_ring_ratio,
										sphpb->icebo[icebo_number].ice[ice_in_icebo].ring_divisor);

					/*
					 * set score based on comparison results
					 */
					if (compare_ring_divisor == 0x0)
						score = grade_active_icebo_same_ring_divisor;
					else if (compare_ring_divisor > 0x0)
						score = grade_active_icebo_higer_ring_divisor;
					else
						score = grade_active_icebo_lower_divisor;
				}
			} else {
				/*
				 * if icebo is not powered on
				 * power balancer driver will score this state
				 * as best match
				 */
				score = grade_inactive_icebo;
				highp_selection_count++;
			}

			/*
			 * if score was set, new node will be added to sorted list
			 */

			if (score) {
				bool bNodeAddedToList = false;

				ice_select = &sphpb->array_sort_nodes[ice_index];

				ice_select->score = score;
				ice_select->ice_index = ice_index;


				/*
				 * add at higher loaction possible
				 */
				list_for_each_entry(r,
						    &ice_power_efficiency_list,
						    node) {
					if (score >= r->score) {
						list_add_tail(&ice_select->node, &r->node);
						bNodeAddedToList = true;
						break;
					}
				}

				/*
				 * if not added, will be added to tail
				 */
				if (!bNodeAddedToList)
					list_add_tail(&ice_select->node, &ice_power_efficiency_list);
			}
		}

		ice_mask = ice_mask >> 1;
		ice_index++;

		if (highp_selection_count == array_size)
			ice_mask = 0x0;

	}

	ice_index = 0;

	/*
	 * copy sorted list to output array
	 */
	list_for_each_entry(ice_select,
			    &ice_power_efficiency_list,
			    node) {
		if (array_size <= ice_index)
			break;

		o_ice_array[ice_index] = ice_select->ice_index;
		ice_index++;
	}

	return 0;
}




/* set icebo active state */
int sphpb_mng_set_icebo_enable(struct sphpb_pb *sphpb,
			       uint32_t ice_index,
			       bool bEnable)
{
	uint32_t icebo_number = (ice_index / SPHPB_MAX_ICE_PER_ICEBO);
	uint32_t ice_in_icebo = (ice_index % SPHPB_MAX_ICE_PER_ICEBO);
	uint32_t new_enable_mask = (1 << ice_in_icebo);
	uint32_t current_active_mask;
	uint16_t max_icebo_ring_divisor = 0;
	uint32_t index = 0;
	int ret = 0;

	if (sphpb->icebo[icebo_number].ice[index].bEnable == bEnable)
		return 0;

	/*
	 * reset ring and ice ratio values
	 */
	sphpb->icebo[icebo_number].ice[index].ring_divisor = 0x0;
	sphpb->icebo[icebo_number].ice[index].ratio = 0x0;


	/*
	 * if busy is set bit of current ice will be added to enabled_ices_mask
	 * else it will unset bit in this mask
	 */
	if (bEnable)
		sphpb->icebo[icebo_number].enabled_ices_mask |= new_enable_mask;
	else
		sphpb->icebo[icebo_number].enabled_ices_mask &= ~new_enable_mask;

	/*
	 * check how man active ices, and modify icebo requested ring ratio.
	 */
	current_active_mask = sphpb->icebo[icebo_number].enabled_ices_mask;

	/*
	 * check active ices in icebo
	 * for every active ice check what is higher frequency ratio request
	 */
	while (current_active_mask) {

		if ((current_active_mask&0x1) &&
		    fx_U1F15_compare(sphpb->icebo[icebo_number].ice[index].ring_divisor, max_icebo_ring_divisor) > 0)
			max_icebo_ring_divisor = sphpb->icebo[icebo_number].ice[index].ring_divisor;

		current_active_mask = current_active_mask >> 1;
	}

	/*
	 * if icebo ring ratio has changed, driver will update icebo ratio
	 * internal data structure. and if required - driver will update new
	 * ring ratio request
	 */
	if (fx_U1F15_compare(sphpb->icebo[icebo_number].ring_divisor, max_icebo_ring_divisor) > 0) {

		int compare_to_global_ring_divisor;

		/*
		 * check if higher then global ratio
		 */
		compare_to_global_ring_divisor = fx_U1F15_compare(sphpb->icebo[icebo_number].ring_divisor, sphpb->icebo_ring_divisor);

		sphpb->icebo[icebo_number].ring_divisor = max_icebo_ring_divisor;

		if (!compare_to_global_ring_divisor) {
			int i;

			sphpb->icebo[icebo_number].ring_divisor = max_icebo_ring_divisor;

			/*
			 * reset max_icebo_ring_divisor - and find a new max value
			 */
			max_icebo_ring_divisor = 0x0;

			/*
			 * find new higher ring ratio requested
			 */
			for (i = 0; i < SPHPB_MAX_ICEBO_COUNT; i++) {
				if (fx_U1F15_compare(max_icebo_ring_divisor, sphpb->icebo[icebo_number].ring_divisor) > 0)
					max_icebo_ring_divisor = sphpb->icebo[icebo_number].ring_divisor;
			}

			/*
			 * modify global structure
			 */
			sphpb->icebo_ring_divisor = max_icebo_ring_divisor;

			/*
			 * request new ratio
			 */

			if (sphpb->icedrv_cb->set_icebo_to_ring_ratio)
				ret = sphpb->icedrv_cb->set_icebo_to_ring_ratio(sphpb->icebo_ring_divisor);

			if (!ret) {
				sph_log_err(POWER_BALANCER_LOG, "Error: failed to set ring divisor value - ice #%d, value 0x%04x\n",
					    ice_index, sphpb->icebo_ring_divisor);
				return ret;
			}

		}

	}

	return 0;
}


/* request from sphpb to set ice to ring and ice ratio */
int sphpb_mng_request_ice_dvfs_values(struct sphpb_pb *sphpb,
				      uint32_t ice_index,
				      uint16_t ring_divisor,
				      uint32_t ice_ratio)
{
	uint32_t icebo_number = (ice_index / SPHPB_MAX_ICE_PER_ICEBO);
	uint32_t ice_in_icebo = (ice_index % SPHPB_MAX_ICE_PER_ICEBO);
	uint32_t ice_busy_mask = (1 << ice_in_icebo);
	int ret = 0;

	if (!(sphpb->icebo[icebo_number].enabled_ices_mask & ice_busy_mask)) {
		sph_log_err(POWER_BALANCER_LOG, "Error: Bad FSM - request ICE ratio while ICE is not set to busy state - ice #%d\n", ice_index);
		return -EINVAL;
	}

	/*
	 * store requested ring ratio in ice data structure
	 */
	sphpb->icebo[icebo_number].ice[ice_in_icebo].ring_divisor = sphpb->icebo_ring_divisor;

	/*
	 * check if requested ratio is higher then current icebo ratio
	 * if so, driver will check if requested ratio is higher then current
	 * global ratio, if that is true - driver will update request.
	 */
	if (fx_U1F15_compare(ring_divisor, sphpb->icebo[icebo_number].ring_divisor) > 0) {
		sphpb->icebo[icebo_number].ring_divisor = ring_divisor;

		if (fx_U1F15_compare(ring_divisor, sphpb->icebo_ring_divisor) > 0) {
			sphpb->icebo_ring_divisor = ring_divisor;

			/* request to update frequency */
			if (sphpb->icedrv_cb->set_icebo_to_ring_ratio)
				ret = sphpb->icedrv_cb->set_icebo_to_ring_ratio(ring_divisor);

			if (!ret) {
				sph_log_err(POWER_BALANCER_LOG, "Error: failed to set ring divisor value - ice #%d, value 0x%04x\n", ice_index, ring_divisor);
				return ret;
			}
		}
	}

	return ret;
}


