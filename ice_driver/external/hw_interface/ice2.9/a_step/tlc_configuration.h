/*******************************************************************************
INTEL CORPORATION CONFIDENTIAL Copyright(c) 2017-2020 Intel Corporation. All Rights Reserved.

The source code contained or described herein and all documents related to the
source code ("Material") are owned by Intel Corporation or its suppliers or
licensors. Title to the Material remains with Intel Corporation or its suppliers
and licensors. The Material contains trade secrets and proprietary and
confidential information of Intel or its suppliers and licensors. The Material
is protected by worldwide copyright and trade secret laws and treaty provisions.
No part of the Material may be used, copied, reproduced, modified, published,
uploaded, posted, transmitted, distributed, or disclosed in any way without
Intel's prior express written permission.

No license under any patent, copyright, trade secret or other intellectual
property right is granted to or conferred upon you by disclosure or delivery of
the Materials, either expressly, by implication, inducement, estoppel or
otherwise. Any license under such intellectual property rights must be express
and approved by Intel in writing.
*******************************************************************************/

/*
 * tlc_configuration.h
 *
 *  Created on: Apr 11, 2016
 *      Author: ziwalter
 */

#ifndef _TLC_CONFIGURATION_H_
#define _TLC_CONFIGURATION_H_

#include <stdint.h>
#include "CVEParams.h"
#include "ice_address_map.h"
#if (CVE_VERSION_MAJOR != 2)
#include "ICE_ADDRESS_MAPParams.h"
#endif //CVE_VERSION_
//typedef uint32_t u32;

// MMIO Registers HUB - file generated from RDL description
//#include "mmio_hub_regs.h"
#include "cve_cbbid.h"
const uint32_t TLC_MAX_FATAL_ERROR_COUNT=3;

//Interrupt number 3, connected to pin BInterrupt[3]
//#define US_NOT_EMPTY_INT_NUM 3
//Interrupt number 12, connected to pin BInterrupt[8]. Level 3, level-triggered
#define US_NOT_EMPTY_INT_NUM 12
//Interrupt number 14, connected to pin BInterrupt[10]. Level 3, level-triggered
#define CREDIT_ACC_DONE_INT_NUM 14
//Interrupt number 18, connected to pin BInterrupt[14]. Level 1, edge-triggered
#define UBP_INT_NUM 18
#ifndef NO_DIRECT_INTERRUPTS
	//Interrupt number 15, connected to pin BInterrupt[11]. Level 1, edge-triggered
	#define HOST2TLC_INT_NUM 15
	//Interrupt number 16, connected to pin BInterrupt[12]. Level 1, edge-triggered
	#define IVP2TLC_INT_NUM 16
	//Interrupt number 17, connected to pin BInterrupt[13]. Level 1, edge-triggered
	#define ASIP2TLC_INT_NUM 17
#endif //#ifndef NO_DIRECT_INTERRUPTS

#if (CVE_VERSION_MAJOR==2)
#define IS_ADDRESS_CACHEABLE(x) ((uint32_t)x<(uint32_t)SCRATCHPAD_BASE_ADDRESS)
#else
#define IS_ADDRESS_CACHEABLE(x) ( ( ((uint32_t)x>=(uint32_t)ICE_ADDRESS_MAP_DSP_TCM_START_ADDRESS)&&((uint32_t)x<(uint32_t)(ICE_ADDRESS_MAP_DSP_TCM_START_ADDRESS+ICE_ADDRESS_MAP_TCM_SIZE)) ) || ( ((uint32_t)x>=(uint32_t)ICE_ADDRESS_MAP_BAR1_START_ADDRESS)&&((uint32_t)x<=(uint32_t)ICE_ADDRESS_MAP_BAR1_END_ADDRESS) ) )
#endif //CVE_VERSION
typedef enum {
    IS_DS_FIFO_FULL_MASK       = 0x1,
    IS_DS_FIFO_EMPTY_MASK      = 0x2,
    IS_US_LP_FIFO_EMPTY_MASK   = 0x4,
    IS_US_HP_FIFO_EMPTY_MASK   = 0x8
} CNC_STATUS_MASK_T;

#define STALL_ON_FULL_DS_FIFO
//-------------------------------------------
#define SOFT_FIFO_SIZE ((IN_FLIGHT_LIMIT+1)*MAX_NUM_CBB)
#define IN_FLIGHT_LIMIT 10
//#define CBB_LATENCY 50

//This value should match the pins values in the RTL!
//Note that in software runs, this gets a different value, and we take advantage of that. However, be warned - use this only to detect environment, not to change functional behavior!
#define TLC_HW_PRID (0x1)


#if ((CVE_VERSION_MAJOR==2) &&(CVE_VERSION_MINOR==0))
	#define CVE_INTERRUPT_BIT_DUMP_COMPLETED	(1<<MMIO_HUB_MEM_INTERRUPT_MASK_TLC_RESERVED_LSB)
	#error "Interrupt bit conflict - please fix"
#else
	#define CVE_INTERRUPT_BIT_DUMP_COMPLETED	(1<<MMIO_HUB_MEM_INTERRUPT_STATUS_DUMP_COMPLETED_LSB)
#endif //CVE version

#define CVE_INTERRUPT_BIT_BARRIER_WATCH_BP 		(1<<MMIO_HUB_MEM_INTERRUPT_STATUS_TLC_RESERVED_LSB)

//this is defined in $MODEL_ROOT/source/cv/rtl_v/top/cve_logic.sv
typedef enum {
	TLC_DEASSERT_INT	= 0x0,
	TLC_PANIC_SIGNAL	= 0x1,
	TLC_TO_IVP			= 0x2,
	TLC_TO_ASIP			= 0x4,
	TLC_NOTCONNECTED	= 0x8,
} OUTGOING_INT_MASK_t;



#endif // _TLC_CONFIGURATION_H_
