/********************************************
 * Copyright (C) 2019 Intel Corporation
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
#include "intel_sphpb.h"
#include "sphpb_punit.h"

#define SPHPB_MAX_ICEBO_COUNT 6
#define SPHPB_MAX_ICE_COUNT 12
#define SPHPB_MAX_ICE_PER_ICEBO 2

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
	/* ice requested ratio */
	uint16_t		ratio;
	/* ice requrested ring ratio */
	uint16_t		ring_divisor;
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
	/* ice number with highest ring divisor value, -1 if not set */
	int      max_ring_divisor_ice_num;

	struct kobject *kobj;
	struct kobject *ia_kobj_root;
	struct kobject **ia_kobj;
	struct kobject *icebo_kobj_root;
	struct kobject **icebo_kobj;
	void __iomem *idc_mailbox_base;
	spinlock_t lock;
};


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






/*===================================================*/

extern struct sphpb_pb *g_the_sphpb;

#endif //_INTEL_SPHPB_H_
