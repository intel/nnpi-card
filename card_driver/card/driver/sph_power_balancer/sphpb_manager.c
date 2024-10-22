/********************************************
 * Copyright (C) 2019-2021 Intel Corporation
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
#include <linux/sched/clock.h>

#include "sphpb_sw_counters.h"
#include "sph_log.h"
#include "sph_version.h"
#include "sphpb.h"
#include "sphpb_punit.h"
#include "sphpb_bios_mailbox.h"
#include "sphpb_trace.h"

/* power throttling threasholds*/
#define RING_FREQ_SETP 100llu //MHz
#define RING_THRESHOLD (400llu + RING_FREQ_SETP / 2u) //MHz
#define IA_FREQ_SETP 100000llu //KHz
#define IA_THRESHOLD (400000llu + IA_FREQ_SETP / 2u) //KHz
#define ICEBO_FREQ_SETP 25u //MHz
#define ICEBO_THRESHOLD (200u + ICEBO_FREQ_SETP / 2u) //MHz


#define SPHPB_NO_THROTTLE	0x0
#define	SPHPB_THROTTLE_TO_MAX	0x1
#define	SPHPB_THROTTLE_TO_MIN	0xf


const uint32_t grade_active_icebo_higer_ring_divisor	= 40;
const uint32_t grade_active_icebo_lower_divisor		= 55;
const uint32_t grade_active_icebo_same_ring_divisor	= 65;
const uint32_t grade_inactive_icebo			= 70;

/* Values are in MS/s - refer to min ddr frequency request value */
#define DDR_FREQ_HIGH_MIN_VALUE	18000
#define DDR_FREQ_MED_MIN_VALUE	9000
#define	DDR_FREQ_LOW_MIN_VALUE	0

/*
 * fixed point 1U15 - number is between 0.0 - 1.99
 * assume always positive number hence - gap between values 0x0000 - 0xFFFF
 */
int fx_U1F15_compare(uint16_t a, uint16_t b)
{
	/*
	 * if equal return 0;
	 * if a > b - return gap between a and b - positive number
	 * if b > a - retirn gap between b and a - negetive number
	 */

	return (int)(a - b);
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

int set_ddr_freq(struct sphpb_pb *sphpb, int qclk)
{
	int ret;
	uint32_t pre_ddr_value = sphpb->request_ddr_value;

	if (qclk == sphpb->request_ddr_value)
		return 0;

	sphpb->request_ddr_value = qclk;

	if (sphpb->throttle_data.curr_state != SPHPB_NO_THROTTLE)
		return 0;

	ret = set_sagv_freq(qclk, SAGV_POLICY_DYNAMIC);
	if (unlikely(ret != 0)) {
		sph_log_err(POWER_BALANCER_LOG, "Error: Failed to set new ddr bw request (%d), ret=%d\n", qclk, ret);
		return ret;
	}

	if (g_the_sphpb->debug_log)
		sph_log_info(POWER_BALANCER_LOG,
			     "set ddr frequency mode to %s\n",
			     sph_ddr_bw_to_str[qclk]);

	DO_TRACE(trace__power_set(SPH_TRACE_OP_STATUS_STOP,
				  SPH_TRACE_OP_POWER_SET_DRAM_LEVEL,
				  sphpb->icebo_ring_divisor,
				  pre_ddr_value));


	DO_TRACE(trace__power_set(SPH_TRACE_OP_STATUS_START,
				  SPH_TRACE_OP_POWER_SET_DRAM_LEVEL,
				  sphpb->icebo_ring_divisor,
				  sphpb->request_ddr_value));

	return 0;
}

static int update_ddr_request(struct sphpb_pb *sphpb,
			      uint32_t ice_index,
			      uint32_t ice_bw_request)
{
	uint32_t icebo_number = (ice_index / SPHPB_MAX_ICE_PER_ICEBO);
	uint32_t ice_in_icebo = (ice_index % SPHPB_MAX_ICE_PER_ICEBO);
	enum BIOS_SAGV_CONFIG_POLICIES ddr_value_to_set;
	int ret = 0;

	mutex_lock(&sphpb->mutex_lock);

	if (sphpb->debug_log)
		sph_log_info(POWER_BALANCER_LOG,
			     "Old DDR Bandwidth total requested - %uMB/s, New DDR Bandwidth total Requested %uMB/s\n",
			     sphpb->ddr_bw_req,
			     sphpb->ddr_bw_req + ((int32_t)ice_bw_request - (int32_t)sphpb->icebo[icebo_number].ice[ice_in_icebo].ddr_bw_req));


	sphpb->ddr_bw_req += (int32_t)ice_bw_request - (int32_t)sphpb->icebo[icebo_number].ice[ice_in_icebo].ddr_bw_req;

	sphpb->icebo[icebo_number].ice[ice_in_icebo].ddr_bw_req = ice_bw_request;

	if (sphpb->ddr_bw_req == 0)
		ddr_value_to_set = SAGV_POLICY_DYNAMIC;
	else if (sphpb->ddr_bw_req >= DDR_FREQ_HIGH_MIN_VALUE)
		ddr_value_to_set = SAGV_POLICY_FIXED_HIGH;
	else if (sphpb->ddr_bw_req >= DDR_FREQ_MED_MIN_VALUE)
		ddr_value_to_set = SAGV_POLICY_FIXED_MED;
	else
		ddr_value_to_set = SAGV_POLICY_FIXED_LOW;

	ret = set_ddr_freq(sphpb, ddr_value_to_set);

	mutex_unlock(&sphpb->mutex_lock);

	return ret;
}



static int update_ring_divisor(struct sphpb_pb *sphpb,
			       uint32_t         ice_index,
			       uint16_t         ring_divisor)
{
	uint32_t icebo_number = (ice_index / SPHPB_MAX_ICE_PER_ICEBO);
	uint32_t ice_in_icebo = (ice_index % SPHPB_MAX_ICE_PER_ICEBO);
	uint32_t i;
	int ret = 0;
	uint16_t max_ring_ratio_value = SPHPB_MIN_RING_POSSIBLE_VALUE;
	uint16_t current_ring_ratio_value = sphpb->icebo_ring_divisor;
	bool bActiveIce = false;

	sphpb->icebo[icebo_number].ice[ice_in_icebo].ring_divisor = ring_divisor;

	for (i = 0; i < SPHPB_MAX_ICEBO_COUNT; i++) {
		struct sphpb_icebo_info *icebo = &(sphpb->icebo[i]);
		uint32_t tmp_ring_ratio_value = SPHPB_MIN_RING_POSSIBLE_VALUE;

		if (!icebo->enabled_ices_mask) {
			icebo->ring_divisor = SPHPB_MIN_RING_POSSIBLE_VALUE;
			continue;
		}

		bActiveIce = true;

		switch (icebo->enabled_ices_mask) {
		case 0x1:
			tmp_ring_ratio_value = icebo->ice[0].ring_divisor;
			break;
		case 0x2:
			tmp_ring_ratio_value = icebo->ice[1].ring_divisor;
			break;
		case 0x3:
			if (icebo->ice[0].ring_divisor > icebo->ice[1].ring_divisor)
				tmp_ring_ratio_value = icebo->ice[0].ring_divisor;
			else
				tmp_ring_ratio_value = icebo->ice[1].ring_divisor;
			break;
		};

		if (sphpb->max_icebo_ratio)
			icebo->ring_divisor = (uint16_t) mul_u64_u32_div((uint64_t)tmp_ring_ratio_value,
					((uint32_t)sphpb->icebo[i].ratio * sphpb->icebo[i].ratio),
					((uint32_t)sphpb->max_icebo_ratio * sphpb->max_icebo_ratio));
		else
			icebo->ring_divisor = tmp_ring_ratio_value;

		if (icebo->ring_divisor > max_ring_ratio_value) {
			max_ring_ratio_value = icebo->ring_divisor;
			if (sphpb->debug_log)
				sph_log_info(POWER_BALANCER_LOG, "update new ring divisor to val = 0x%x", max_ring_ratio_value);
		}
	}

	if (!bActiveIce)
		max_ring_ratio_value = sphpb->orig_icebo_ring_divisor;

	if (max_ring_ratio_value != sphpb->icebo_ring_divisor) {
		if (sphpb->icedrv_cb->set_icebo_to_ring_ratio) {
			ret = sphpb->icedrv_cb->set_icebo_to_ring_ratio(max_ring_ratio_value);
			if (ret) {
				sph_log_err(POWER_BALANCER_LOG, "Error: Failed to set new ring ratio, ret=%d\n", ret);
				goto end_func;
			}

			sphpb->icebo_ring_divisor = max_ring_ratio_value;
			if (g_the_sphpb->debug_log)
				sph_log_info(POWER_BALANCER_LOG,
					     "set icebo to ring ratio to 0x%x - fixed_point(U1.15)\n", max_ring_ratio_value);

			if (sphpb->throttle_data.curr_state != SPHPB_NO_THROTTLE) {
				DO_TRACE(trace__power_set(SPH_TRACE_OP_STATUS_STOP,
							 SPH_TRACE_OP_POWER_SET_ICEBO2RING,
							 current_ring_ratio_value,
							 SAGV_POLICY_FIXED_LOW));

				DO_TRACE(trace__power_set(SPH_TRACE_OP_STATUS_START,
							 SPH_TRACE_OP_POWER_SET_ICEBO2RING,
							 sphpb->icebo_ring_divisor,
							 SAGV_POLICY_FIXED_LOW));
			} else {
				DO_TRACE(trace__power_set(SPH_TRACE_OP_STATUS_STOP,
							 SPH_TRACE_OP_POWER_SET_ICEBO2RING,
							 current_ring_ratio_value,
							 sphpb->request_ddr_value));

				DO_TRACE(trace__power_set(SPH_TRACE_OP_STATUS_START,
							 SPH_TRACE_OP_POWER_SET_ICEBO2RING,
							 sphpb->icebo_ring_divisor,
							 sphpb->request_ddr_value));
			}
		}
	}

end_func:

	return ret;
}

static int update_icebo_ratio(struct sphpb_pb *sphpb,
			       uint32_t       ice_index,
			       uint8_t        ratio_fx,
			       uint8_t        off)
{
	uint32_t icebo_number = (ice_index / SPHPB_MAX_ICE_PER_ICEBO);
	uint32_t ice_in_icebo = (ice_index % SPHPB_MAX_ICE_PER_ICEBO);
	uint32_t i;
	uint32_t other_ice_in_icebo = ice_in_icebo ^ 0x1;
	uint32_t other_ice_busy_mask = (1 << other_ice_in_icebo);
	uint8_t need_to_update_ice_driver = off ? 0 : 1;
	int ret = 0;

	if (!off)
		sphpb->icebo[icebo_number].ice[ice_in_icebo].requested_ratio = ratio_fx;

	if (ratio_fx == 0) {
		//check the other ice in icebo if exist and set icebo ratio according to it,
		//otherwise, set current max ratio between all cores.
		if ((sphpb->icebo[icebo_number].enabled_ices_mask & other_ice_busy_mask) &&
		     sphpb->icebo[icebo_number].ice[other_ice_in_icebo].requested_ratio)
			sphpb->icebo[icebo_number].ratio = sphpb->icebo[icebo_number].ice[other_ice_in_icebo].requested_ratio;
		else
			sphpb->icebo[icebo_number].ratio = sphpb->max_icebo_ratio;

		if (sphpb->debug_log)
			sph_log_info(POWER_BALANCER_LOG, "ratio_fx = 0, new_ratio 0x%x\n", sphpb->icebo[icebo_number].ratio);
	} else {
		if (abs(ratio_fx - sphpb->icebo[icebo_number].ratio) >= sphpb->ratio_epsilon || off) {
			uint8_t tmp_hold_max = sphpb->max_icebo_ratio;

			/* Update max inside the icebo */
			if (off) {
				if (sphpb->icebo[icebo_number].enabled_ices_mask & other_ice_busy_mask)
					sphpb->icebo[icebo_number].ratio = sphpb->icebo[icebo_number].ice[other_ice_in_icebo].requested_ratio;
			} else {
				uint8_t first_ice_ratio = sphpb->icebo[icebo_number].ice[ice_in_icebo].requested_ratio;
				uint8_t second_ice_ratio = sphpb->icebo[icebo_number].ice[other_ice_in_icebo].requested_ratio;

				sphpb->icebo[icebo_number].ratio = max(first_ice_ratio, second_ice_ratio);
			}

			if (sphpb->debug_log)
				sph_log_info(POWER_BALANCER_LOG, "received ice ratio value = 0x%x, icebo ratio= 0x%x, current max = 0x%x\n",
									ratio_fx, sphpb->icebo[icebo_number].ratio, sphpb->max_icebo_ratio);

			if (off && ratio_fx == sphpb->max_icebo_ratio) {
				mutex_lock(&sphpb->mutex_lock);

				/* Find the maximum ratio */
				for (i = 0; i < SPHPB_MAX_ICEBO_COUNT; i++) {
					if (sphpb->icebo[i].enabled_ices_mask &&
					   (sphpb->icebo[i].ratio > sphpb->max_icebo_ratio))
						sphpb->max_icebo_ratio = sphpb->icebo[i].ratio;
				}

				mutex_unlock(&sphpb->mutex_lock);
			} else if (sphpb->icebo[icebo_number].ratio > sphpb->max_icebo_ratio) {
				sphpb->max_icebo_ratio = sphpb->icebo[icebo_number].ratio;
			}

			if (tmp_hold_max != sphpb->max_icebo_ratio && !sphpb->ia_changed_by_user) {
				/* Update IA cores ratio value according to the new max in the system */
				sphpb->current_cores_ratios.freqRatio.ia0 = sphpb->max_icebo_ratio / 2;
				sphpb->current_cores_ratios.freqRatio.ia1 = sphpb->max_icebo_ratio / 2;
			} else if (sphpb->ia_changed_by_user) {
				if ((sphpb->current_cores_ratios.freqRatio.ia0 >> 2) > sphpb->max_icebo_ratio)
					sphpb->max_icebo_ratio = sphpb->current_cores_ratios.freqRatio.ia0 >> 2;

				if ((sphpb->current_cores_ratios.freqRatio.ia1 >> 2) > sphpb->max_icebo_ratio)
					sphpb->max_icebo_ratio = sphpb->current_cores_ratios.freqRatio.ia1 >> 2;
			}
			if (sphpb->debug_log)
				sph_log_info(POWER_BALANCER_LOG, "lets update core ratio value = 0x%x, new max = 0x%x\n",
						ratio_fx, sphpb->max_icebo_ratio);
		} else {
			sphpb->icebo[icebo_number].ice[ice_in_icebo].requested_ratio = ratio_fx;
			need_to_update_ice_driver = 0;
			if (sphpb->debug_log)
				sph_log_info(POWER_BALANCER_LOG, "just keep ratio in requested value 0x%x, current ratio= 0x%x",
						ratio_fx, sphpb->icebo[icebo_number].ratio);
		}
	}

	if (need_to_update_ice_driver) {
		//update all 64 bit
		sphpb->current_cores_ratios.freqRatio.icebo0 = sphpb->icebo[0].ratio ? sphpb->icebo[0].ratio : sphpb->max_icebo_ratio;
		sphpb->current_cores_ratios.freqRatio.icebo1 = sphpb->icebo[1].ratio ? sphpb->icebo[1].ratio : sphpb->max_icebo_ratio;
		sphpb->current_cores_ratios.freqRatio.icebo2 = sphpb->icebo[2].ratio ? sphpb->icebo[2].ratio : sphpb->max_icebo_ratio;
		sphpb->current_cores_ratios.freqRatio.icebo3 = sphpb->icebo[3].ratio ? sphpb->icebo[3].ratio : sphpb->max_icebo_ratio;
		sphpb->current_cores_ratios.freqRatio.icebo4 = sphpb->icebo[4].ratio ? sphpb->icebo[4].ratio : sphpb->max_icebo_ratio;
		sphpb->current_cores_ratios.freqRatio.icebo5 = sphpb->icebo[5].ratio ? sphpb->icebo[5].ratio : sphpb->max_icebo_ratio;

		if (sphpb->debug_log)
			sph_log_info(POWER_BALANCER_LOG, "lets update IA and cores ratio value: 0x%llX\n", sphpb->current_cores_ratios.val);

		ret = sphpb->icedrv_cb->set_icebo_to_icebo_ratio(sphpb->current_cores_ratios);
		if (ret)
			sph_log_err(POWER_BALANCER_LOG, "failed to set set_icebo_to_icebo_ratio (0x%llx)", sphpb->current_cores_ratios.val);
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
	int ret = 0;

	if (sphpb->icebo[icebo_number].ice[ice_in_icebo].bEnable == bEnable)
		return 0;

	/*
	 * reset ring and ice ratio values
	 */
	sphpb->icebo[icebo_number].ice[ice_in_icebo].bEnable = bEnable;
	sphpb->icebo[icebo_number].ice[ice_in_icebo].ring_divisor = SPHPB_MIN_RING_POSSIBLE_VALUE;
	/*
	 * if busy is set bit of current ice will be added to enabled_ices_mask
	 * else it will unset bit in this mask
	 */
	if (bEnable)
		sphpb->icebo[icebo_number].enabled_ices_mask |= new_enable_mask;
	else {
		sphpb->icebo[icebo_number].enabled_ices_mask &= ~new_enable_mask;

		/*
		 * in case driver request to modify ice state - driver need to
		 * change frequency request to 0x0 bw for current ICE
		 */
		update_ddr_request(sphpb, ice_index, 0x0);

		/* Need to check if max ratio in system affected by this ice off.
		 * If max has changed, then update_ring_divisor will be called inside update_icebo_ratio below.
		 */
		update_icebo_ratio(sphpb, ice_index, sphpb->icebo[icebo_number].ice[ice_in_icebo].requested_ratio, /*off*/ 1);

		update_ring_divisor(sphpb, ice_index, SPHPB_MIN_RING_POSSIBLE_VALUE);
	}

	return ret;
}


/* request from sphpb to set ice to ring and ice ratio */
int sphpb_mng_request_ice_dvfs_values(struct sphpb_pb *sphpb,
				      uint32_t ice_index,
				      uint32_t ddr_bw_req,
				      uint16_t ring_divisor,
				      uint8_t ice_ratio)
{
	uint32_t icebo_number = (ice_index / SPHPB_MAX_ICE_PER_ICEBO);
	uint32_t ice_in_icebo = (ice_index % SPHPB_MAX_ICE_PER_ICEBO);
	uint32_t ice_busy_mask = (1 << ice_in_icebo);
	int ret;

	if (!(sphpb->icebo[icebo_number].enabled_ices_mask & ice_busy_mask)) {
		sph_log_err(POWER_BALANCER_LOG, "Error: Bad FSM - request ICE ratio while ICE is not set to busy state - ice #%d\n", ice_index);
		return -EINVAL;
	}

	/* update icebo core max ratio */
	ret = update_icebo_ratio(sphpb, ice_index, ice_ratio, 0);
	if (ret) {
		sph_log_err(POWER_BALANCER_LOG, "Error: Failed to update ice %d - icebo ratio value %x, Error(0x%x)\n", ice_index, ice_ratio, ret);
		return ret;
	}

	ret = update_ring_divisor(sphpb, ice_index, ring_divisor);
	if (ret) {
		sph_log_err(POWER_BALANCER_LOG, "Error: Failed to update ice %d - ring divisor value %x, Error(0x%x)\n", ice_index, ring_divisor, ret);
		return ret;
	}

	ret = update_ddr_request(sphpb, ice_index, ddr_bw_req);
	if (ret) {
		sph_log_err(POWER_BALANCER_LOG, "Error: Failed to update ice %d - ddr bw request value %x, Error(0x%x)\n", ice_index, ddr_bw_req, ret);
		return ret;
	}



	return ret;
}

static void update_counters(struct sphpb_pb *sphpb, uint64_t delta_t_us)
{
	struct CORE_PERF_LIMIT_REASONS_MSR freq_reason;
	bool any_throttle = false;

	if (sphpb->throttle_data.curr_state != SPHPB_NO_THROTTLE) {
		NNP_SW_COUNTER_ADD(g_sph_sw_pb_counters, SPHCS_SW_COUNTERS_IPC_OVERSHOOT_PROTECTION_TIME, delta_t_us);
		any_throttle = true;
	}

	rdmsrl(SPH_MSR_CORE_PERF_LIMIT_REASONS, freq_reason.value);
	if (freq_reason.BitField.prochot_log != 0) {
		freq_reason.BitField.prochot_log = 0;
		NNP_SW_COUNTER_ADD(g_sph_sw_pb_counters, SPHCS_SW_COUNTERS_IPC_PROCHOT_TIME, delta_t_us);
		any_throttle = true;
	}
	if (freq_reason.BitField.thermal_log != 0) {
		freq_reason.BitField.thermal_log = 0;
		NNP_SW_COUNTER_ADD(g_sph_sw_pb_counters, SPHCS_SW_COUNTERS_IPC_THERMAL_TIME, delta_t_us);
		any_throttle = true;
	}
	if (freq_reason.BitField.residency_state_regulation_log != 0) {
		freq_reason.BitField.residency_state_regulation_log = 0;
		NNP_SW_COUNTER_ADD(g_sph_sw_pb_counters, SPHCS_SW_COUNTERS_IPC_RESIDENCY_STATE_REG_TIME, delta_t_us);
		any_throttle = true;
	}
	if (freq_reason.BitField.ratl_log != 0) {
		freq_reason.BitField.ratl_log = 0;
		NNP_SW_COUNTER_ADD(g_sph_sw_pb_counters, SPHCS_SW_COUNTERS_IPC_RATL_TIME, delta_t_us);
		any_throttle = true;
	}
	if (freq_reason.BitField.pl1_log != 0) {
		freq_reason.BitField.pl1_log = 0;
		NNP_SW_COUNTER_ADD(g_sph_sw_pb_counters, SPHCS_SW_COUNTERS_IPC_PL1_TIME, delta_t_us);
		any_throttle = true;
	}
	if (freq_reason.BitField.pl2_log != 0) {
		freq_reason.BitField.pl2_log = 0;
		NNP_SW_COUNTER_ADD(g_sph_sw_pb_counters, SPHCS_SW_COUNTERS_IPC_PL2_TIME, delta_t_us);
		any_throttle = true;
	}
	if (freq_reason.BitField.vr_therm_alert_log != 0 ||
	    freq_reason.BitField.vr_therm_design_current_log != 0 ||
	    freq_reason.BitField.max_turbo_limit_log != 0 ||
	    freq_reason.BitField.turbo_transition_attenuation_log != 0 ||
	    freq_reason.BitField.other_log != 0) {
		freq_reason.BitField.vr_therm_alert_log = 0;
		freq_reason.BitField.vr_therm_design_current_log = 0;
		freq_reason.BitField.max_turbo_limit_log = 0;
		freq_reason.BitField.turbo_transition_attenuation_log = 0;
		freq_reason.BitField.other_log = 0;
		NNP_SW_COUNTER_ADD(g_sph_sw_pb_counters, SPHCS_SW_COUNTERS_IPC_OTHER_TIME, delta_t_us);
		any_throttle = true;
	}

	if (any_throttle) {
		NNP_SW_COUNTER_ADD(g_sph_sw_pb_counters,
				   SPHCS_SW_COUNTERS_IPC_THROTTLING_TIME, delta_t_us);
		wrmsrl(SPH_MSR_CORE_PERF_LIMIT_REASONS, freq_reason.value);
	}
}

int do_throttle(struct sphpb_pb *sphpb,
		uint32_t avg_power_mW,
		uint32_t power_limit1_mW)
{
	uint64_t ring_clock_ticks, ring_freq, time_us, delta_t_us;
	uint32_t cpu, icebo, ice_freq;
	uint8_t new_state;
	bool all_min = true;
	int ret = 0;

	time_us = nnp_time_us();
	delta_t_us = time_us - sphpb->throttle_data.time_us;
	sphpb->throttle_data.time_us = time_us;

	update_counters(sphpb, delta_t_us);

	/*
	 * RING
	 * check if ring frequency is set at minimum.
	 */
	rdmsrl(MSR_UNC_PERF_UNCORE_CLOCK_TICKS, ring_clock_ticks);
	ring_freq = (ring_clock_ticks - sphpb->throttle_data.ring_clock_ticks) /
		    delta_t_us;
	if (ring_freq > RING_THRESHOLD) //400MHz
		all_min = false;
	sphpb->throttle_data.ring_clock_ticks = ring_clock_ticks;

	/*
	 * IA
	 * check if ia cores frequency are set at minimum
	 */
	for (cpu = 0; cpu < num_possible_cpus(); ++cpu) {
		if (!cpu_online(cpu)) {
			sphpb->throttle_data.cpu_stat[cpu].aperf = 0;
			sphpb->throttle_data.cpu_stat[cpu].mperf = 0;
		} else {
			uint64_t aperf, mperf, cpu_freq;

			aperf = sphpb->throttle_data.cpu_stat[cpu].aperf;
			mperf = sphpb->throttle_data.cpu_stat[cpu].mperf;

			smp_call_function_single(cpu,
						 aperfmperf_snapshot_khz,
						 &sphpb->throttle_data.cpu_stat[cpu],
						 true);
			if (aperf == 0 || mperf == 0)
				continue;

			cpu_freq = (sphpb->throttle_data.cpu_stat[cpu].aperf - aperf) /
					(sphpb->throttle_data.cpu_stat[cpu].mperf - mperf);
			if (cpu_freq > IA_THRESHOLD) //400000KHz = 400MHz
				all_min = false;
		}
	}

	mutex_lock(&sphpb->mutex_lock);

	if (unlikely(sphpb->icedrv_cb == NULL ||
		     sphpb->icedrv_cb->get_icebo_frequency == NULL ||
		     sphpb->icedrv_cb->set_clock_squash == NULL)) {
		if (sphpb->debug_log)
			sph_log_info(POWER_BALANCER_LOG, "Failed - Ice Driver Not Registered\n");

		goto end_func;
	}

	/*
	 * ICES
	 * check if active ICEBOs frequency are set at minimum.
	 */
	if (all_min) {
		for (icebo = 0; icebo < SPHPB_MAX_ICEBO_COUNT; ++icebo) {
			if (sphpb->icebo[icebo].enabled_ices_mask != 0) {
				ret = sphpb->icedrv_cb->get_icebo_frequency(icebo, &ice_freq);
				if (unlikely(ret < 0)) {
					sph_log_err(POWER_BALANCER_LOG, "Unable to get ICEBO (%u) frequency Err(%d)\n", icebo, ret);
					continue;
				}
				if (ice_freq > ICEBO_THRESHOLD) { //200MHz
					all_min = false;
					break;
				}
			}
		}
	}


	/*
	 * Decide on throttle state:
	 * supported states:
	 *  - SPHPB_NO_THROTTLE - indicates  that throttling is not active/required
	 *  - SPHPB_THROTTLE_TO_MAX - indicates the pcode will try to throttle the system to maximum
	 *  - SPHPB_THROTTLE_TO_MIN - indicates the pcode will try to throttle the system to minimum ( first level of throttling)
	 * - 14 steps are between SPHPB_THROTTLE_TO_MIN to SPHPB_THROTTLE_TO_MAX (0xf, 0xe, ... , 0x2, 0x1)
	 */

	if (all_min && (avg_power_mW > mult_frac(power_limit1_mW, 103llu, 100llu))) {
		// throttle more
		if (sphpb->throttle_data.curr_state == SPHPB_NO_THROTTLE)
			new_state = SPHPB_THROTTLE_TO_MIN;
		else if (sphpb->throttle_data.curr_state > SPHPB_THROTTLE_TO_MAX)
			new_state = sphpb->throttle_data.curr_state - 1;
		else
			goto end_func;
	} else if (!all_min || (avg_power_mW <= power_limit1_mW)) {
		// throttle less
		if (sphpb->throttle_data.curr_state == SPHPB_NO_THROTTLE)
			goto end_func;
		else if (sphpb->throttle_data.curr_state < SPHPB_THROTTLE_TO_MIN)
			new_state = sphpb->throttle_data.curr_state + 1;
		else
			new_state = SPHPB_NO_THROTTLE;
	} else
		goto end_func;

	if (sphpb->request_ddr_value != SAGV_POLICY_FIXED_LOW) {
		if (new_state == SPHPB_NO_THROTTLE) {
			ret = set_sagv_freq(sphpb->request_ddr_value, SAGV_POLICY_DYNAMIC);
			if (unlikely(ret < 0)) {
				sph_log_err(POWER_BALANCER_LOG, "Throttling failure: set_sagv_freq dynamic failed with err:%d.\n", ret);
				goto end_func;
			}
		} else if (new_state == SPHPB_THROTTLE_TO_MIN && sphpb->throttle_data.curr_state == SPHPB_NO_THROTTLE) {
			ret = set_sagv_freq(SAGV_POLICY_FIXED_LOW, SAGV_POLICY_DYNAMIC);
			if (unlikely(ret < 0)) {
				sph_log_err(POWER_BALANCER_LOG, "Throttling failure: set_sagv_freq fixed failed with err:%d.\n", ret);
				goto end_func;
			}
		}
	}

	ret = sphpb->icedrv_cb->set_clock_squash(0, new_state, new_state != SPHPB_NO_THROTTLE);
	if (unlikely(ret < 0)) {
		sph_log_err(POWER_BALANCER_LOG, "Throttling failure: set_clock_squash failed with err(%d)\n", ret);
		goto cleanup_ddr_value;
	}


	sphpb->throttle_data.curr_state = new_state;

	mutex_unlock(&sphpb->mutex_lock);

	if (sphpb->throttle_data.curr_state != SPHPB_NO_THROTTLE) {
		if (g_the_sphpb->debug_log)
			sph_log_info(POWER_BALANCER_LOG,
				     "throttling is enabled: state(%u), p(%umW), set ddr mode to %s\n",
				     sphpb->throttle_data.curr_state, avg_power_mW, sph_ddr_bw_to_str[SAGV_POLICY_FIXED_LOW]);

		DO_TRACE(trace__power_set(SPH_TRACE_OP_STATUS_START,
					 SPH_TRACE_OP_POWER_SET_THROTTLE,
					 sphpb->icebo_ring_divisor,
					 SAGV_POLICY_FIXED_LOW));
	} else {
		if (g_the_sphpb->debug_log)
			sph_log_info(POWER_BALANCER_LOG,
				     "throttling is disabled: state(%u), p(%umW), set ddr mode to %s\n",
				     sphpb->throttle_data.curr_state, avg_power_mW, sph_ddr_bw_to_str[sphpb->request_ddr_value]);


		DO_TRACE(trace__power_set(SPH_TRACE_OP_STATUS_STOP,
					 SPH_TRACE_OP_POWER_SET_THROTTLE,
					 sphpb->icebo_ring_divisor,
					 sphpb->request_ddr_value));
	}

	return ret;

cleanup_ddr_value:

	if (sphpb->request_ddr_value != SAGV_POLICY_FIXED_LOW) {
		if (new_state == SPHPB_NO_THROTTLE)
			set_sagv_freq(SAGV_POLICY_FIXED_LOW, SAGV_POLICY_DYNAMIC);
		else if (new_state == SPHPB_THROTTLE_TO_MIN && sphpb->throttle_data.curr_state == SPHPB_NO_THROTTLE)
			set_sagv_freq(sphpb->request_ddr_value, SAGV_POLICY_DYNAMIC);
	}

end_func:
	mutex_unlock(&sphpb->mutex_lock);

	return ret;
}
