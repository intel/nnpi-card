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

#ifndef CREDIT_ROUTER_CONFIG_H
#define CREDIT_ROUTER_CONFIG_H

#include "credit_router_config_values.h"

#define CNC_CR_NUM_OF_REGS 	1
#define CNC_REGS_OFFSET 	0x100

#define CNC_CR_BID_WIDTH   4
#define CNC_CR_CONSUMERS_PER_BID 8
#define CNC_CR_NUM_OF_REGS_PER_BID 8
#define CNC_CR_BID_ADDR_OFFSET 0
#define CNC_CR_BID_ADDR_OVERALL_CREDITS_OFFSET 5
#define CNC_CR_BID_ADDR_CONSUMER_RETURNED_CREDITS_OFFSET 6

#define CNC_CR_NUMBER_OF_BIDS (1<<CNC_CR_BID_WIDTH)
#define CNC_CR_ENTRIES_PER_BID (CNC_CR_CONSUMERS_PER_BID+1)

#define CNC_CR_MAX_PROCESSED_CREDITS 0xFFFF
#define CNC_CR_BID_OFFSET_REGISTER_ADDR 0xFF

//#define CNC_CR_FIRST_SUPPORTED_BID 0
#endif
