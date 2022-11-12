/*******************************************************************************
INTEL CORPORATION CONFIDENTIAL Copyright(c) 2014-2021 Intel Corporation. All Rights Reserved.

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

#ifndef CREDIT_ROUTER_CONFIG_VALUES_H
#define CREDIT_ROUTER_CONFIG_VALUES_H


typedef enum {
    CNC_CR_CONFIG_READ  	= 0,
    CNC_CR_CONFIG_WRITE 	= 1,
    CNC_CR_CONFIG_CONTROL 	= 2,
    CNC_CR_CONFIG_NR,
} CNC_CR_CONFIG_e; 


typedef enum {
    CNC_CR_COMMAND_NULL     = 0,
    CNC_CR_COMMAND_RUN      = 1,
    CNC_CR_COMMAND_COLLECT  = 2,
    CNC_CR_COMMAND_PAUSE    = 3,
    CNC_CR_COMMAND_RESET    = 4,
    CNC_CR_COMMAND_NR
} CNC_CR_COMMAND_e; 


typedef enum {
    CNC_CR_STATE_IDLE               = 0,
    CNC_CR_STATE_DISPATCHING        = 1,
    CNC_CR_STATE_LAST_PRODUCED      = 2,
    CNC_CR_STATE_LAST_CONSUMING     = 3,
    CNC_CR_STATE_DONE               = 4,
    CNC_CR_STATE_NR
} CNC_CR_STATE_e; 


typedef enum {
	OPCODE_SYNC				= 8, //NUM_GLOBAL_CONTROL_OPCODES
	OPCODE_TLC_SYNC			= 8, //NUM_GLOBAL_CONTROL_OPCODES
	OPCODE_CR_SYNC			= 9, //NUM_GLOBAL_CONTROL_OPCODES
} CNC_CR_OPCODE_e;


#endif
