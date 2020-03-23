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
 * cve_dump.h
 *
 *  Created on: Jan 2, 2017
 *      Author: ziwalter
 */

#ifndef CVE_DUMP_H
#define CVE_DUMP_H

#include "ComputeClusterParams.h"
#include "credit_router_config.h"

//TBD: remove this
#include "configuration.h"
//#include "tlc_configuration.h"
//#include <xtensa/xtruntime.h>

const uint32_t FIELD_MARKER=0xCAFE0000;
//const uint32_t TRAX_HEADER_SIZE_IN_BYTES=256; //[FIXME][FIX ME]: this should be taken from Tensilica header file (TRAX_HEADER_SIZE)
#define  TRAX_HEADER_SIZE_IN_BYTES 256 

//TBD: more to a more appropriate place
typedef struct __attribute__((aligned(64))){
	uint8_t		tlcRawDram[TLC_DRAM_SIZE] __attribute__((aligned(64)));
	uint8_t 	scratchPad[COMPUTECLUSTER_SP_SIZE_IN_KB*1024] __attribute__((aligned(64)));
	uint8_t		tlcTraceMem[TLC_TRAX_MEM_SIZE+TRAX_HEADER_SIZE_IN_BYTES] __attribute__((aligned(64))); //Leave room (256B) for header
	uint8_t		creditAccRegisters[(CNC_CR_NUMBER_OF_BIDS*CNC_CR_NUM_OF_REGS_PER_BID+CNC_CR_NUM_OF_REGS)*CREDIT_ACC_REG_SIZE] __attribute__((aligned(64)));
	uint32_t	sectionID __attribute__((aligned(64)));
	uint32_t	creditAccBidCnt;
	uint32_t	caShadeReg;
	uint32_t	caSyncVal;
	uint32_t	isCbbReadyMaskLow;
	uint32_t	isCbbReadyMaskHigh;
	uint32_t	fifoStatusMask;
	uint32_t	cveId;
	uint32_t	reserved[8];
	uint32_t	controlRegValue __attribute__((aligned(64)));
	uint32_t	dumpReason;
	uint32_t	marker;
	uint32_t	dumpCounter;
	uint32_t	cycleCount;
	uint32_t	cveVersion;
	uint32_t	profile;
	uint32_t	compilationDate;
	uint32_t	compilationTime;
	uint32_t	fwVersion;
	uint32_t 	magicValue[6]; //TBD: use HAL value
}cveCoreBlob_t;


#endif /*CVE_DUMP_H*/
