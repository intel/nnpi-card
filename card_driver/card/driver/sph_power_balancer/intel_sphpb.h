/********************************************
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

/*
 * @file intel_sphpb.h
 *
 * @brief Header file defining sph power balancer driver api
 *
 * This header file defines interface used in kernel for accessing power balancer engine.
 *
 */

#ifndef _INTEL_SPH_POWER_BALANCER_H_
#define _INTEL_SPH_POWER_BALANCER_H_


struct sphpb_icedrv_callbacks {
	/* ices per icebo */
	uint32_t ices_per_icebo;

	/* callback to set ice 2 ring ratio */
	int (*set_icebo_to_ring_ratio)(uint16_t value);
	/* callback to get ice 2 ring ratio */
	int (*get_icebo_to_ring_ratio)(uint16_t *value);
	/* callback to set icebo ratio value */
	int (*set_icebo_to_icebo_ratio)(uint32_t icebo, uint32_t value);
	/* callback to get icebo ratio value */
	int (*get_icebo_to_icebo_ratio)(uint32_t icebo, uint32_t *value);
	/* callback to get icebo frequency */
	int (*get_icebo_frequency)(uint32_t icebo, uint32_t *freq);
	/* callback to set clock squash value */
	int (*set_clock_squash)(uint32_t icebo_mask, uint8_t t_state_req, bool enable);
};



struct sphpb_callbacks {
	/* request to get a list of recommended ices to use when job starts */
	/*
	 * ring_divisor_fx - 1U15 - fixed point value between 0.0 to 1.99999 ratio between ice to ring
	 * ratio_fx - currently undefined value - TBD
	 *            value between 0.0 - 1.0 define relative ratio from current frequency of ice in system.
	 *            ICE_FREQUENCY = (ratio_fx * MAX_FREQUENCY)
	 */

	int (*get_efficient_ice_list)(uint64_t ice_mask,
				      uint32_t ddr_bw,
				      uint16_t ring_divisor_fx,
				      uint16_t ratio_fx,
				      uint8_t *o_ice_array,
				      ssize_t array_size);

	/* request from sphpb to set ice to ring and ice ratio */
	int (*request_ice_dvfs_values)(uint32_t ice_index,
				       uint32_t ddr_bw,
				       uint16_t ring_divisor_fx,
				       uint16_t ratio_fx);

	/* set ice active state */
	int (*set_power_state)(uint32_t ice_index, bool bOn);

	/* unregister power balancer driver */
	void  (*unregister_driver)(void);
};

const struct sphpb_callbacks *sph_power_balancer_register_driver(const struct sphpb_icedrv_callbacks *drv_data);

#endif //_INTEL_SPH_POWER_BALANCER_H_
