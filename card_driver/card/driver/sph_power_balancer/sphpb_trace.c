/********************************************
 * Copyright (C) 2019-2021 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#define CREATE_TRACE_POINTS
#include "sphpb_trace.h"

char *sph_trace_op_to_str[SPH_TRACE_OP_STATUS_NUM + 1];

char *sph_trace_power_set_to_str[SPH_TRACE_OP_POWER_SET_NUM + 1];

char *sph_ddr_bw_to_str[SPH_TRACE_DDR_BW_NUM + 1];

void sphpb_trace_init(void)
{
	// fill sph_trace_op_to_str array
	sph_trace_op_to_str[SPH_TRACE_OP_STATUS_START]		= SPH_TRACE_STR_POWER_START;
	sph_trace_op_to_str[SPH_TRACE_OP_STATUS_STOP]		= SPH_TRACE_STR_POWER_STOP;
	sph_trace_op_to_str[SPH_TRACE_OP_STATUS_NUM]		= SPH_TRACE_STR_UNDEFINED;

	// fill sph_trace_power_set_to_str
	sph_trace_power_set_to_str[SPH_TRACE_OP_POWER_SET_ICEBO2RING]	= SPH_TRACE_STR_ICEBO2RING;
	sph_trace_power_set_to_str[SPH_TRACE_OP_POWER_SET_DRAM_LEVEL]	= SPH_TRACE_STR_DRAM_LEVEL;
	sph_trace_power_set_to_str[SPH_TRACE_OP_POWER_SET_THROTTLE]	= SPH_TRACE_STR_THROTTLE;
	sph_trace_power_set_to_str[SPH_TRACE_OP_POWER_SET_NUM]		= SPH_TRACE_STR_UNDEFINED;

	// fill sph_ddr_bw_to_str array
	sph_ddr_bw_to_str[SPH_TRACE_DDR_BW_DYNAMIC]	= SPH_TRACE_STR_DDR_BW_DYNAMIC;
	sph_ddr_bw_to_str[SPH_TRACE_DDR_BW_LOW]		= SPH_TRACE_STR_DDR_BW_LOW;
	sph_ddr_bw_to_str[SPH_TRACE_DDR_BW_MID]		= SPH_TRACE_STR_DDR_BW_MID;
	sph_ddr_bw_to_str[SPH_TRACE_DDR_BW_HIGH]	= SPH_TRACE_STR_DDR_BW_HIGH;
	sph_ddr_bw_to_str[SPH_TRACE_DDR_BW_NUM]		= SPH_TRACE_STR_UNDEFINED;
}

