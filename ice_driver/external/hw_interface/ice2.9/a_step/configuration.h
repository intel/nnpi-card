/*******************************************************************************
INTEL CORPORATION CONFIDENTIAL Copyright(c) 2014-2019 Intel Corporation. All Rights Reserved.

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
 * configuration.h
 *
 *  Created on: Feb 23, 2014
 *      Author: ziwalter
 */

#ifndef CONFIGURATION_H
#define CONFIGURATION_H

//#include "cve_hw.h_forSw"
#include "cve_cbbid.h"

//#define CBBID_MMIO CBBID_MMIO_MMU
#define CBBID_MMIO_MMU CBBID_MMIO
//#define CBBID_MMU CBBID_MMIO
#define CBBID_INVALID (MAX_NUM_CBB - 1)
#define INVALID_CBB_ID CBBID_INVALID


//Max number of BIDs the TLC can support
#define MAX_HW_BID (192)


#define MAX_NUM_CBB 64
//Maximal number of BIDs
#define MAX_NUM_BID 128
#define INVALID_BID (MAX_NUM_BID-1)
//Largest BID/MID index that can be used with TLC walking
#define MAX_WALKABLE_BID 32
#define MAX_NUM_CONSUMERS_PER_BID 8
#define IN_FLIGHT_LIMIT 10
#define MAX_BID_PER_DMA_CMD 1
#define MAX_CONSUMERS_PER_CMD 4
#define NUM_AUX_INDICES_WALK_DESC_CMD (4)
#define NUM_AUX_INDICES_WALK_DESC2_CMD (8)
#define NUM_GP_REGISTERS 64
#define NUM_SP_REGISTERS 32
#define NUM_TLC_REGISTERS (NUM_GP_REGISTERS+NUM_SP_REGISTERS)
#define MAX_PATCH_CODE 	4
#define MAX_PATCH_UID	16
#define PATCH_STATE_AND_PARAM_SIZE (1024)


//Lowest BID number that can be assigned to the CreditAcc
#define CREDIT_ACC_BASE_BID		16

//TLC physical properties. These should not be used by the TLC FW itself (which should rely on the proper HAL macros), and are defined only for other clients (e.g., SW and Coral)
#define TLC_DRAM_SIZE (32*1024)
#define TLC_DRAM_ADDRESS (0xD0020000)
#define TLC_TRAX_MEM_SIZE (1024)

#define CREDIT_ACC_REG_SIZE (8)

#endif /*CONFIGURATION_H*/
