/********************************************
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#ifndef _SPHPB_TRACE_DEFS_H
#define _SPHPB_TRACE_DEFS_H

enum sph_trace_op_us_enum  {
	SPH_TRACE_OP_STATUS_START	= 0, //SPH_TRACE_STR_POWER_START
	SPH_TRACE_OP_STATUS_STOP	= 1, //SPH_TRACE_STR_POWER_STOP
	SPH_TRACE_OP_STATUS_NUM		= 2, //SPH_TRACE_STR_UNDEFINED
};

enum sph_trace_op_power_set_enum  {
	SPH_TRACE_OP_POWER_SET_ICEBO2RING	= 0, //SPH_TRACE_STR_ICEBO2RING_START
	SPH_TRACE_OP_POWER_SET_DRAM_LEVEL	= 1, //SPH_TRACE_STR_DRAM_LEVEL_START
	SPH_TRACE_OP_POWER_SET_THROTTLE		= 2, //SPH_TRACE_STR_THROTTLE_START
	SPH_TRACE_OP_POWER_SET_NUM		= 3, //SPH_TRACE_STR_UNDEFINED
};


enum sph_trace_ddr_bw_enum  {
	SPH_TRACE_DDR_BW_DYNAMIC	= 0, //SPH_TRACE_STR_DDR_BW_DYNAMIC
	SPH_TRACE_DDR_BW_LOW		= 1, //SPH_TRACE_STR_DDR_BW_LOW
	SPH_TRACE_DDR_BW_MID		= 2, //SPH_TRACE_STR_DDR_BW_MID
	SPH_TRACE_DDR_BW_HIGH		= 3, //SPH_TRACE_STR_DDR_BW_HIGH
	SPH_TRACE_DDR_BW_NUM		= 4, //SPH_TRACE_STR_UNDEFINED
};

extern char *sph_trace_op_to_str[];
extern char *sph_trace_power_set_to_str[];
extern char *sph_ddr_bw_to_str[];

#endif /* _SPHPB_TRACE_DEFS_H */
