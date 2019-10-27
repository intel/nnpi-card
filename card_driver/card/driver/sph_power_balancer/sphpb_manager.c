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


static int update_ring_divisor(struct sphpb_pb *sphpb,
			       uint32_t         ice_index,
			       uint16_t         ring_divisor)
{
	uint32_t icebo_number = (ice_index / SPHPB_MAX_ICE_PER_ICEBO);
	uint32_t ice_in_icebo = (ice_index % SPHPB_MAX_ICE_PER_ICEBO);
	int ret = 0;
	uint32_t icebo, ice;
	bool set_new_val;

	if (ring_divisor == sphpb->icebo[icebo_number].ice[ice_in_icebo].ring_divisor)
		return 0;

	sphpb->icebo[icebo_number].ice[ice_in_icebo].ring_divisor = ring_divisor;
	sphpb->icebo[icebo_number].ring_divisor = 0;
	sphpb->icebo[icebo_number].ring_divisor_idx = -1;
	for (ice = 0; ice < SPHPB_MAX_ICE_PER_ICEBO; ice++)
		if ((sphpb->icebo[icebo_number].enabled_ices_mask & (1 << ice)) != 0 &&
		    fx_U1F15_compare(sphpb->icebo[icebo_number].ice[ice].ring_divisor, sphpb->icebo[icebo_number].ring_divisor) > 0) {
			sphpb->icebo[icebo_number].ring_divisor = sphpb->icebo[icebo_number].ice[ice].ring_divisor;
			sphpb->icebo[icebo_number].ring_divisor_idx = ice;
		}

	set_new_val = (sphpb->max_ring_divisor_ice_num < 0) ||
		      (fx_U1F15_compare(ring_divisor, sphpb->icebo_ring_divisor) > 0);

	if (!set_new_val &&
	    ice_index == sphpb->max_ring_divisor_ice_num) {
		/* global ring divisor need to be recalculated */
		uint16_t new_max = 0;
		int new_idx = -1;

		for (icebo = 0; icebo < SPHPB_MAX_ICEBO_COUNT; icebo++) {
			if (!sphpb->icebo[icebo].enabled_ices_mask)
				continue;

			if (fx_U1F15_compare(sphpb->icebo[icebo].ring_divisor, new_max) > 0) {
				new_max = sphpb->icebo[icebo].ring_divisor;
				new_idx = icebo * SPHPB_MAX_ICE_PER_ICEBO + sphpb->icebo[icebo].ring_divisor_idx;
			}
		}

		if (new_idx >= 0) {
			ice_index = new_idx;
			ring_divisor = new_max;
			set_new_val = true;
		} else {
			sphpb->max_ring_divisor_ice_num = -1;
		}
	}

	if (set_new_val) {
		if (sphpb->icedrv_cb->set_icebo_to_ring_ratio) {
			ret = sphpb->icedrv_cb->set_icebo_to_ring_ratio(ring_divisor);
			if (ret == 0) {
				sphpb->icebo_ring_divisor = ring_divisor;
				sphpb->max_ring_divisor_ice_num = ice_index;
			} else {
				sph_log_err(POWER_BALANCER_LOG, "Error: Failed to set new ring ratio, ret=%d\n", ret);
			}
		}
	}

	return ret;
}

/* set icebo active state */
int sphpb_mng_set_icebo_enable(struct sphpb_pb *sphpb,
			       uint32_t ice_index,
			       bool bEnable)
{
	uint32_t icebo_number = (ice_index / SPHPB_MAX_ICE_PER_ICEBO);
	uint32_t ice_in_icebo = (ice_index % SPHPB_MAX_ICE_PER_ICEBO);
	uint32_t new_enable_mask = (1 << ice_in_icebo);
	uint32_t index = 0;
	int ret;

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

	ret = update_ring_divisor(sphpb, ice_index, 0);

	return ret;
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
	int ret;

	if (!(sphpb->icebo[icebo_number].enabled_ices_mask & ice_busy_mask)) {
		sph_log_err(POWER_BALANCER_LOG, "Error: Bad FSM - request ICE ratio while ICE is not set to busy state - ice #%d\n", ice_index);
		return -EINVAL;
	}

	ret = update_ring_divisor(sphpb, ice_index, ring_divisor);

	return ret;
}
