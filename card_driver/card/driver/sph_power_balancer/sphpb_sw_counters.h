/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#ifndef __SPHPB_SW_COUNTERS_H
#define __SPHPB_SW_COUNTERS_H

#include "sw_counters.h"

enum SPHCS_SW_COUNTERS_GROUPS {
	SPHCS_SW_COUNTERS_GROUP_POWER
};

static const struct sph_sw_counters_group_info g_sphcs_sw_counters_groups_info[] = {
	/* SPHCS_SW_COUNTERS_GROUP_POWER */
	{"power", "group for entire power management sw counters"}
};

enum SPHCS_SW_COUNTERS_GLOBAL {
	SPHCS_SW_COUNTERS_IPC_THROTTLING_TIME
};


static const struct sph_sw_counter_info g_sphcs_sw_counters_info[] = {
	/* SPHCS_SW_COUNTERS_IPC_THROTTLING_TIME */
	{SPHCS_SW_COUNTERS_GROUP_POWER, "power.throttling_time",
	 "Total time the card was in throttling, in any level of throttling."},
};

static const struct sph_sw_counters_set g_sw_counters_set_global = {
	"sw_pb_counters",
	false,
	g_sphcs_sw_counters_info,
	ARRAY_SIZE(g_sphcs_sw_counters_info),
	g_sphcs_sw_counters_groups_info,
	ARRAY_SIZE(g_sphcs_sw_counters_groups_info)
};

extern void *g_hSwCountersInfo_global;
extern struct sph_sw_counters *g_sph_sw_pb_counters;



#endif // __SPHPB_SW_COUNTERS_H
