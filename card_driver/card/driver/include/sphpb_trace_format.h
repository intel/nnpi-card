/********************************************
 * Copyright (C) 2019-2021 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/
#ifndef _SPHPB_TRACE_FORMAT_H
#define _SPHPB_TRACE_FORMAT_H

#define SPHPB_TRACE_POWER_REQUEST		_power_request
#define SPHPB_TRACE_POWER_SET			_power_set

#define SPH_TRACE_STR_POWER_START		"s"   //start	- power setting setup start
#define SPH_TRACE_STR_POWER_STOP		"c"   //stop	- power setting setup stop

#define SPH_TRACE_STR_ICE_REQUEST	"ice_request"		//state - request power settings for a given ice
#define SPH_TRACE_STR_ICEBO2RING	"icebo_to_ring"		//state - start set global LLC ratio from ICEBO
#define SPH_TRACE_STR_DRAM_LEVEL	"dram_level"		//state - set DRAM frequency level
#define SPH_TRACE_STR_THROTTLE		"power_throttle"	//state - throttling mode
#define SPH_TRACE_STR_UNDEFINED		"undefined"		//state - undefined


#define SPH_TRACE_STR_DDR_BW_DYNAMIC		"DYNAMIC"
#define SPH_TRACE_STR_DDR_BW_LOW		"LOW"
#define SPH_TRACE_STR_DDR_BW_MID		"MEDIUM"
#define SPH_TRACE_STR_DDR_BW_HIGH		"HIGH"


#endif /* _SPHPB_TRACE_FORMAT_H */
