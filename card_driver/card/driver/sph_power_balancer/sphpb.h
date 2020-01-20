/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

/**
 * @file sphpb.h
 *
 * @brief Header file defining sphpb driver module
 *
 * This header file defines sphpb module.
 *
 */

#ifndef _INTEL_SPHPB_H_
#define _INTEL_SPHPB_H_

#include <linux/list.h>
#include <linux/mutex.h>
#include "intel_sphpb.h"
#include "sphpb_punit.h"

#define SPHPB_MAX_ICEBO_COUNT 6
#define SPHPB_MAX_ICE_COUNT 12
#define SPHPB_MAX_ICE_PER_ICEBO 2

#define SPHPB_MIN_RING_POSSIBLE_VALUE	8195

struct kobject;

/*
 * struct used for sorting ices
 */
struct sphpb_ice_node {
	struct list_head		node;
	uint32_t			ice_index;
	uint32_t			score;
};

struct sphpb_ice_info {
	/* ice requrested ring ratio */
	uint16_t		ring_divisor;
	/* ddr bw request - MB/s*/
	uint32_t		ddr_bw_req;
	/* ice busy bit */
	bool			bEnable;
};


struct sphpb_icebo_info {
	/* mask indicate busy ices in icebo */
	uint32_t	enabled_ices_mask;
	/* icebo ratio selected */
	uint16_t	ratio;
	/* icebo ring divisor selected */
	uint16_t	ring_divisor;
	/* index of ice in icebo with highest ring divisor value, -1 if not set */
	int             ring_divisor_idx;
	/* per ice meta date in icebo */
	struct sphpb_ice_info ice[SPHPB_MAX_ICE_PER_ICEBO];
};

struct sphpb_throttle_info {
	uint64_t ring_clock_ticks;
	struct cpu_perfstat *cpu_stat;
	uint64_t time_us;
	uint8_t curr_state;
};


struct sphpb_pb {
	/* callback from sphpb driver - set on init */
	struct sphpb_callbacks callbacks;

	/* callback sphpb get from ice driver */
	const struct sphpb_icedrv_callbacks *icedrv_cb;

	/* metadata per icebo */
	struct sphpb_ice_node array_sort_nodes[SPHPB_MAX_ICE_COUNT];

	/* fixed array used for sorting metadata */
	struct sphpb_icebo_info icebo[SPHPB_MAX_ICEBO_COUNT];

	/* global icebo ring divisor */
	uint16_t icebo_ring_divisor;
	/* orig icebo ring divisor - set on driver register*/
	uint16_t orig_icebo_ring_divisor;

	/* accumalte ddr bw request for all ices */
	int32_t ddr_bw_req;

	/* save ddr request value, in case of throttle - value will be
	 * ignored and restored when throttle done.
	 */
	uint32_t request_ddr_value;

	struct sphpb_throttle_info throttle_data;
	struct kobject *kobj;
	struct kobject *ia_kobj_root;
	struct kobject **ia_kobj;
	void __iomem *bios_mailbox_base;
	int bios_mailbox_locked;
	struct mutex bios_mutex_lock;
	struct mutex mutex_lock;
	bool debug_log;
};

struct cpu_perfstat {
	u64 aperf;
	u64 mperf;
};

void aperfmperf_snapshot_khz(void *dummy);

int do_throttle(struct sphpb_pb *sphpb,
		uint32_t avg_power_mW,
		uint32_t power_limit1_mW);

int sphpb_mng_get_efficient_ice_list(struct sphpb_pb *sphpb,
				     uint32_t ice_mask,
				     uint16_t ice_to_ring_ratio,
				     uint16_t fx_ice_ice_ratio,
				     uint8_t *o_ice_array,
				     ssize_t array_size);

int sphpb_mng_set_icebo_enable(struct sphpb_pb *sphpb,
			       uint32_t ice_index,
			       bool bEnable);

int sphpb_mng_request_ice_dvfs_values(struct sphpb_pb *sphpb,
				      uint32_t ice_index,
				      uint32_t ddr_bw_req,
				      uint16_t ring_divisor,
				      uint32_t ice_ratio);

/* sysfs interfaces */
int sphpb_iccp_table_sysfs_init(struct sphpb_pb *sphpb);
void sphpb_iccp_table_sysfs_deinit(struct sphpb_pb *sphpb);

int sphpb_ring_freq_sysfs_init(struct sphpb_pb *sphpb);
void sphpb_ring_freq_sysfs_deinit(struct sphpb_pb *sphpb);

int sphpb_ia_cycles_sysfs_init(struct sphpb_pb *sphpb);
void sphpb_ia_cycles_sysfs_deinit(struct sphpb_pb *sphpb);

int sphpb_icebo_sysfs_init(struct sphpb_pb *sphpb);
void sphpb_icebo_sysfs_deinit(struct sphpb_pb *sphpb);

int sphpb_power_overshoot_sysfs_init(struct sphpb_pb *sphpb);
void sphpb_power_overshoot_sysfs_deinit(struct sphpb_pb *sphpb);






/*===================================================*/

extern struct sphpb_pb *g_the_sphpb;

#endif //_INTEL_SPHPB_H_
