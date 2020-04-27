/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#ifndef __SPHPB_SW_COUNTERS_H
#define __SPHPB_SW_COUNTERS_H

#include "sw_counters.h"

enum SPHCS_SW_COUNTERS_GROUPS {
	SPHCS_SW_COUNTERS_GROUP_POWER_BALANCE
};

static const struct nnp_sw_counters_group_info g_sphcs_sw_counters_groups_info[] = {
	/* SPHCS_SW_COUNTERS_GROUP_POWER_BALANCE */
	{"power_balancer", "group for entire power management sw counters"}
};

enum SPHCS_SW_COUNTERS_GLOBAL {
	SPHCS_SW_COUNTERS_IPC_THROTTLING_TIME,
	SPHCS_SW_COUNTERS_IPC_OVERSHOOT_PROTECTION_TIME,
	SPHCS_SW_COUNTERS_IPC_PROCHOT_TIME,
	SPHCS_SW_COUNTERS_IPC_THERMAL_TIME,
	SPHCS_SW_COUNTERS_IPC_RESIDENCY_STATE_REG_TIME,
	SPHCS_SW_COUNTERS_IPC_RATL_TIME,
	SPHCS_SW_COUNTERS_IPC_OTHER_TIME,
	SPHCS_SW_COUNTERS_IPC_PL1_TIME,
	SPHCS_SW_COUNTERS_IPC_PL2_TIME,
};


static const struct nnp_sw_counter_info g_sphcs_sw_counters_info[] = {
	/* SPHCS_SW_COUNTERS_IPC_THROTTLING_TIME */
	{SPHCS_SW_COUNTERS_GROUP_POWER_BALANCE, "throttling_time",
	 "Total time[us] the card was in throttling for any reason."},
	/* SPHCS_SW_COUNTERS_IPC_OVERSHOOT_PROTECTION_TIME */
	{SPHCS_SW_COUNTERS_GROUP_POWER_BALANCE, "overshoot_protection_time",
	 "Total time[us] the card was in power overshoot protection throttling, in any level of throttling."},
	/* SPHCS_SW_COUNTERS_IPC_PROCHOT_TIME */
	{SPHCS_SW_COUNTERS_GROUP_POWER_BALANCE, "prochot_time",
	 "Total time[us](in resolution of refresh time window) the frequency was reduced below request due to assertion of external PROCHOT."},
	/* SPHCS_SW_COUNTERS_IPC_THERMAL_TIME */
	{SPHCS_SW_COUNTERS_GROUP_POWER_BALANCE, "thermal_time",
	 "Total time[us](in resolution of refresh time window) the frequency was reduced below request due to a thermal event."},
	/* SPHCS_SW_COUNTERS_IPC_RESIDENCY_STATE_REG_TIME */
	{SPHCS_SW_COUNTERS_GROUP_POWER_BALANCE, "residency_state_regulation_time",
	 "Total time[us](in resolution of refresh time window) the frequency was reduced below request due to residency state regulation limit."},
	/* SPHCS_SW_COUNTERS_IPC_RATL_TIME */
	{SPHCS_SW_COUNTERS_GROUP_POWER_BALANCE, "ratl_time",
	 "Total time[us](in resolution of refresh time window) the frequency was reduced below request due to Running Average Thermal Limit (RATL)."},
	/* SPHCS_SW_COUNTERS_IPC_OTHER_TIME */
	{SPHCS_SW_COUNTERS_GROUP_POWER_BALANCE, "other_reason_time",
	 "Total time[us](in resolution of refresh time window) the frequency was reduced below request due to"
	 " electrical or other constraints(PL4, ICCMAX...)."},
	/* SPHCS_SW_COUNTERS_IPC_PL1_TIME */
	{SPHCS_SW_COUNTERS_GROUP_POWER_BALANCE, "pl1_time",
	 "Total time[us](in resolution of refresh time window) the frequency was reduced below request due to package-level power limiting PL1."},
	/* SPHCS_SW_COUNTERS_IPC_PL2_TIME */
	{SPHCS_SW_COUNTERS_GROUP_POWER_BALANCE, "pl2_time",
	 "Total time[us](in resolution of refresh time window) the frequency was reduced below request due to package-level power limiting PL2."},
};

static const struct nnp_sw_counters_set g_sw_counters_set_global = {
	"sw_pb_counters",
	false,
	g_sphcs_sw_counters_info,
	ARRAY_SIZE(g_sphcs_sw_counters_info),
	g_sphcs_sw_counters_groups_info,
	ARRAY_SIZE(g_sphcs_sw_counters_groups_info)
};

extern void *g_hSwCountersInfo_global;
extern struct nnp_sw_counters *g_sph_sw_pb_counters;



#endif // __SPHPB_SW_COUNTERS_H
