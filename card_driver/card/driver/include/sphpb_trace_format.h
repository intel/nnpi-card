/*******************************************************************************
 * INTEL CORPORATION CONFIDENTIAL Copyright(c) 2017-2020 Intel Corporation. All Rights Reserved.
 *
 * The source code contained or described herein and all documents related to the
 * source code ("Material") are owned by Intel Corporation or its suppliers or
 * licensors. Title to the Material remains with Intel Corporation or its suppliers
 * and licensors. The Material contains trade secrets and proprietary and
 * confidential information of Intel or its suppliers and licensors. The Material
 * is protected by worldwide copyright and trade secret laws and treaty provisions.
 * No part of the Material may be used, copied, reproduced, modified, published,
 * uploaded, posted, transmitted, distributed, or disclosed in any way without
 * Intel's prior express written permission.
 *
 * No license under any patent, copyright, trade secret or other intellectual
 * property right is granted to or conferred upon you by disclosure or delivery of
 * the Materials, either expressly, by implication, inducement, estoppel or
 * otherwise. Any license under such intellectual property rights must be express
 * and approved by Intel in writing.
 ********************************************************************************/

#ifndef _SPHPB_TRACE_FORMAT_H
#define _SPHPB_TRACE_FORMAT_H

#define SPHPB_TRACE_POWER_REQUEST		power_request
#define SPHPB_TRACE_POWER_SET			power_set

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
