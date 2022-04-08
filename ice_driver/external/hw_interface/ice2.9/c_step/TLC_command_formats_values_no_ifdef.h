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

//
// TLC_Command_formats_values.h
//
//  Created on: Jan 26, 2015
//      Author: rroni
//

// begin TLC_COMMAND_FORMATS_VALUES_H

/////////////////////////////////////////////////////////////////////////////////////////////////
//*************** value (enum) definitions ***************

// command classes

typedef enum {
	//Error signaling over the CnC. Not to be used in the driver->TLC CB API!
    ERROR_CMD = 0,
	// CBB execution
    EXEC_CMD,
	// CBB configuration
    CONFIGURATION_CMD,
	// barrier - commands that come after a barrier command must complete before
	// starting the commands that come after the barrier
    CONTROL_CMD,
	// DSE CnC uCmds> Not to be used by the driver->API!
    DMA_CMD,
	// TLC control over the CnC. Not to be used in the driver->TLC CB API!
    DRIVER_CMD,
	// Internal HW - for validation only. Not to be used in the driver->TLC CB API!
    DEBUG_CMD,
	// Internal HW - for validation only. Not for driver use
    DTF_CMD,
    // WARNING!!! CmdClass from 8 and above cannot be sent on CnC! (CnC has only 3 class bits)
    // BID Descriptor
    BID_DESC_CMD=16,
    // MID Descriptor
    MID_DESC_CMD,
    // Extra BID/MID info
    WALK_DESC_CMD,
    //BID Patching info
    PATCH_CMD,
    //Auxiliary services provided by the TLC
    AUXILIARY_CMD,
    // Pass general information to CVE (e.g., API version number)
    INFO_CMD,
    INVALID_CMD,
    // Additional walk parameters
    WALK_DESC2_CMD,
    // Pass raw messages to be dispatched over the CnC
    RAW_CMD,
    // For quick sending of credits
    EXPRESS_EXEC_CMD,
    // TLC logic BARRIER
    BARRIER_CMD,
    // keep as last item
    CVE_CMD_CLASS_LAST
} CmdClass_e;

// access types to CBB configuration registers
// this opcode is passed to the CBB for execution
typedef enum {
	// not for driver use - unpredictable behaviour
	OPCODE_CFG_INVALID=0,
	// read a config register
	OPCODE_REG_READ,
	// write one config register
	OPCODE_REG_WRITE,
    // write 2 config registers at once
    OPCODE_DOUBLE_REG_WRITE,

	// keep as last item
	OPCODE_CFG_OPCODE_NR
} ConfigOpcode_e;

// TLC configuration control
// this opcode adds information needed by the TLC about CBB configuration commands
typedef enum {
	// not for driver use - unpredictable behavior
	OPCODE_TLC_CFG_INVALID=0,
	// read a configuration register from a CBB to some memory/SP location
	OPCODE_CFG_READ_TO_PTR,
	// read a configuration register from a CBB to a TLC register
	OPCODE_CFG_READ_TO_TLC,
	// writes a CBB configuration register, data is taken from the immediate
	// field of the instruction
	OPCODE_CFG_WRITE_CBB_FROM_IMM,
	// writes a CBB configuration register, data is taken from a register
	// of the TLC
	OPCODE_CFG_WRITE_CBB_FROM_TLC,
	// writes a CBB configuration register, data is taken from the pointer to memory/scratch-pad
	OPCODE_CFG_WRITE_CBB_FROM_PTR,
	// write to CreditAcc, data is taken from the immediate
	OPCODE_CFG_WRITE_CREDIT_ACC,
	// write to CreditAcc, data is taken from the pointer to memory/scratch-pad
	OPCODE_CFG_WRITE_CREDIT_ACC_FROM_PTR,
	// keep as last item
	OPCODE_TLC_CFG_NR
} tlcConfigOpcode_e;


// Provide CB information
typedef enum {
	// not for driver use - unpredictable behaviour
	OPCODE_INFO_INVALID=0,
	//Emit {key,val} as DTF
	OPCODE_INFO_DTF,
	//Silently ignore the {key,val} pair
	OPCODE_INFO_NO_DTF,
	OPCODE_INFO_OPCODE_NR
} InfoOpcode_e;

// TLC internal for debug purposes
typedef enum {
	OPCODE_CMP_GP_REG = 0,
	OPCODE_DEBUG_TICK_MARKER,
	OPCODE_DEBUG_TOCK_MARKER,
	OPCODE_TEST_TRACE_MEM,
	OPCODE_TEST_ASYNC_REG_ACCESS,
	OPCODE_DEBUG_PHASE_MARKER,
	OPCODE_DEBUG_MEM_LINE_ACCESS,
	OPCODE_DEBUG_GENERAL_MARKER = 10,
	// keep as last item
	OPCODE_DEBUG_NR
} tlcDebugOpcode_e;

// opcodes for barrier and fence commands
typedef enum {
	// not for driver use - unpredictable behaviour
	OPCODE_TLC_CONTROL_INVALID = 0,
	// barrier - this is a TLC only command.
	// all the commands prior to the barrier must run to completion
	// before the TLC can continue execution pass this command
	RESERVED_OPCODE_TLC_CONTROL_EXECUTION_BARRIER,
	// memory fence - write all dirty lines in the cache to system memory, 
	// so that they are made visible to all readers in the system
	RESERVED_OPCODE_TLC_CONTROL_MEMORY_FENCE,
	// like the fence command + mark all the cache lines as invalid, so that
	// all subsequent accesses will be forced to go all the way to system
	// memory
	RESERVED_OPCODE_TLC_CONTROL_MEMORY_FENCE_AND_CACHE_INVALIDATE,
	//For operations on TLC virtual registers, loop control, etc.
	OPCODE_TLC_CONTROL_LOGIC,
	// Make sure there are no credits are owned by a producer.
	// TO be used for non-mustComplete BID generated by the DSE
	OPCODE_TLC_CONTROL_WAIT_FOR_PRODUCER_CREDITS,
	// keep as last item
	OPCODE_CONTROL_NR
}tlcControlOpcode_e;


typedef enum {
	// not for driver use - unpredictable behavior
	OPCODE_TLC_BARRIER_INVALID = 0,
	//Wait until all previous EXEC CMDs are retired
	OPCODE_TLC_BARRIER_WAIT_FOR_EXEC,
	//Wait until all previous non-EXEC CMD are retired
	OPCODE_TLC_BARRIER_WAIT_FOR_NON_EXEC,
	//Wait until all previous non-EXEC CMD are retired and trigger credit accelerator work
	OPCODE_TLC_BARRIER_WAIT_FOR_NON_EXEC_AND_LAUNCH_CREDIT_ACC,
	OPCODE_TLC_BARRIER_NR
}tlcBarrierOpcode_e;


// partitions of the TLC internal register spaces
typedef enum {
	// not for driver use - unpredictable behaviour
	INVALID_REG_SPACE = 0,
	// SPI configuration register space. 
	CREDIT_ACC_PORT,
	// general purpose - all other registers
	TLC_REG_SPACE,
	
	// keep as last item
	TLC_CFG_SPACE_NR
} tlcCfgSpace_e;

// opcodes of the commands to the TLC itself, which are not passed to another CBB
//(command class DRIVER_CMD)
typedef enum {
	// commands which require high privilege level are not allowed pass this command
	OPCODE_DRIVER_DEPRIVILEGE = 0,

	// keep last
	OPCODE_DRIVER_NR
} tlcDriverOpcode_e;

// whether TLC should expect the CBB to signal completion
// used in the isPosted field below
typedef enum {
	NOT_POSTED = 0,
	POSTED 
} postedType_e;


// order of walking on a 3d surface - which of the dimensions walk first and which second - x-horizontal, y-vertical, z-depth
typedef enum {
	WALKTYPE_INVALID = 0,
	WALKTYPE_X_Y_Z,
	WALKTYPE_Y_X_Z,
	WALKTYPE_X_Z_Y,
	WALKTYPE_Z_X_Y,
	WALKTYPE_Y_Z_X,
	WALKTYPE_Z_Y_X,
	WALKTYPE_GENERIC_3D,
	WALKTYPE_GENERIC_3D_EXTENDED,
	WALKTYPE_3D_NR
} walkType3D_e;

// walking pattern - the order by which the image tiles are iterated
typedef enum {
	WALKTYPE_ROW_MAJOR = WALKTYPE_3D_NR,
	WALKTYPE_COLUMN_MAJOR,
	WALKTYPE_INVERSE_ROW_MAJOR,
	WALKTYPE_INVERSE_COLUMN_MAJOR,
	WALKTYPE_NESTED_ROW, 		//Repeats X walk Z times, before increasing Y
	WALKTYPE_NESTED_COLUMN, 	//Repeats Y walk Z times, before increasing X
	WALKTYPE_COMPOSITE_NESTED_ROW_OVER_Y,	//Composite walk: internal: vertical, external: WALKTYPE_NESTED_ROW
	WALKTYPE_NO_WALK,			//No auto-walk
	WALKTYPE_2D_NR
} walkType2D_e;

typedef enum {
	WALKTYPE_D1_D2_D3_D4 = WALKTYPE_2D_NR,
	WALKTYPE_D4_D1_D2_D3,
	WALKTYPE_4D_NR
} walkType4D_e;

typedef enum {
	GLOBAL_CONTROL_OPCODE_RESET_CBB = 0,
	NUM_GLOBAL_CONTROL_OPCODES = 8
} globalControlOpcode_e;


typedef enum{
	CONDITION_CODE_INVALID,
	CONDITION_CODE_VTR_IS_ZERO, 	//(VTR_A == 0)?
	CONDITION_CODE_VTR_NOT_ZERO, 	//(VTR_A != 0)?
	CONDITION_CODE_A_EQ_B,			//(VTR_A == VTR_B)?
	CONDITION_CODE_A_GE_B,			//(VTR_A >= VTR_B)?
	CONDITION_CODE_A_GR_B,			//(VTR_A >  VTR_B)?
	CONDITION_CHECK_TLC_MAILBOX,	//(TLC_MAILBOX_DOORBELL[0] == 0)? Note: This check also clears the mailbox register
	CONDITION_CODE_NR				//Keep last
} tlcConditionCode_e;


/*
typedef enum{
	AUX_OPCODE_COPY,
	AUX_OPCODE_COPY_AND_READBACK, 	//(VTR_A) == 0?
	AUX_OPCODE_NR					//Keep last
} auxiliaryOpcode_e;
*/


typedef enum{
	VTR_OPCODE_INVALID,
	VTR_OPCODE_ZERO,                 //VTR_DST =  0
	VTR_OPCODE_INC,                  //VTR_DST++
	VTR_OPCODE_DEC,                  //VTR_DST--
	VTR_OPCODE_ADD,                  //VTR_DST += VTR_SRC
	VTR_OPCODE_SUB,                  //VTR_DST -= VTR_SRC
	VTR_OPCODE_MUL,                  //VTR_DST *= VTR_SRC
	VTR_OPCODE_AND,                  //VTR_DST &= VTR_SRC
	VTR_OPCODE_OR,                   //VTR_DST |= VTR_SRC
	VTR_OPCODE_MOVE,                 //VTR_DST =  VTR_SRC
	VTR_OPCODE_LOAD_CBD_REG,         //VTR_DST =  CBD_REG[0]
	VTR_OPCODE_MOVE_IMM,             //VTR_DST =  IMM
	VTR_OPCODE_MOVE_PAYLOAD,         //VTR_DST =  PAYLOAD
	VTR_OPCODE_LOAD_MEM,             //VTR_DST =  VTR_SRC[VTR_SRC2]
	VTR_OPCODE_LOAD_MEM_PAYLOAD,     //VTR_DST =  [PAYLOAD]
	VTR_OPCODE_STORE_MEM,            //VTR_DST[VTR_SRC2] = VTR_SRC
	VTR_OPCODE_STORE_MEM_PAYLOAD,    //[PAYLOAD] = VTR_SRC
	VTR_OPCODE_WRITE_TPC,            //BID.totalProdcuerCredits = VTR_SRC
	VTR_OPCODE_READ_TLC_MAILBOX,     //VTR_DST =  TLC_MAILBOX_DOORBELL[0]. Note: This operation also clears the mailbox register
	VTR_OPCODE_STORE_PAYLOAD_TO_MEM, //[VTR_DST] = PAYLOAD
	VTR_OPCODE_ONE,                  //VTR_DST =  1
	VTR_OPCODE_SUM_ARRAY,            //VTR_DST =  Sigma_i(VTR_SRC[i]), where 0<=i<VTR_SRC2. Note: array items are signed int32_t
	VTR_OPCODE_MAX,                  //VTR_DST =  MIN(VTR_SRC,VTR_SRC2)
	VTR_OPCODE_NR                    //Keep last
} tlcVtrOpCode_e;

typedef enum{
	SRC_VALUE_IMMEDIATE,	//Use immediate value specified
	SRC_VALUE_VTR, 			//Take value from virtual TLC register
	SRC_VALUE_RESERVED		//reserved (value from indirect pointer)
} srcValueEncoding_e;

typedef enum{
	BRANCH_INTRA_CB,		//Branch to CMD in current CB
	BRANCH_INTER_CB			//Re-execute/skip CB(s)
} branchType_e;


typedef enum{
	ACCEL_OPTIONAL,			//local TLC heuristics to decide
	ACCEL_MANDATORY, 		//Use HW credit accelerator, TLC will generate the required CreditAcc configuration
	ACCEL_DISABLED,			//Do not use HW credit accelerator
	ACCEL_GC_CONFIGURED,	//Use HW credit accelerator, CreditAcc configuration is created by the graph-compiler
	ACCEL_NA			//Reserved
} accelerationFlags_e;

typedef enum {
	CREDIT_ACC_CONTROL_MODE_GRAPH_COMPILER	= 0,		//GC control BID allocation to credit accelerator
	CREDIT_ACC_CONTROL_MODE_GRAPH_COMPILER_CONFIGURED,	//GC control BID allocation to credit accelerator, and generates required configuration
	CREDIT_ACC_CONTROL_MODE_TLC,				//TLC controls BID allocation to credit accelerator
	CREDIT_ACC_CONTROL_MODE_DISABLED			//Disabled
} CREDIT_ACC_CONTROL_REG_VALUES_e;

typedef enum {
	PATCH_PRE_OUTPUT_DISPATCH	= 1<<0,	//Just before dispatching an output credit message
	PATCH_POST_OUTPUT_DISPATCH	= 1<<1, //Immediately after dispatching an output credit message
	PATCH_PRE_INPUT_DISPATCH	= 1<<2, //Just before dispatching an input credit message
	PATCH_POST_INPUT_DISPATCH	= 1<<3, //Immediately after dispatching an input credit message
	PATCH_OUTPUT_RETURN			= 1<<4, //Immediately after receiving an output credit message
	PATCH_INPUT_RETURN			= 1<<5  //Immediately after receiving an input credit message
} patchTrigger_e;

typedef enum {
	GENERATOR_INVALID		= 0,
	GENERATOR_CG,
	GENERATOR_PRECOMIPLED,
	GENERATOR_CORAL			= 128,
	GENERATOR_OTHER
} generatorId_e;

typedef enum {
	INFO_KEY_INVALID		= 0,
	INFO_KEY_CB_MARKER		= 1,
	INFO_KEY_TLC_DATE		= 2,
	INFO_KEY_TLC_TIME		= 3,
	INFO_KEY_LAYER_NUMBER 	= 10,
	INFO_KEY_NETWORK_ID		= 11
} infoKey_e;


typedef enum {
	DUMP_CVE_NEVER		= 	0,
	DUMP_CVE_ON_ERROR 	=	1<<0,	//Dump upon TLC ERROR
	DUMP_CVE_NOW 		=	1<<1,	//Dump now (once)
	DUMP_CVE_ON_MARKER	=	1<<2,	//Dump when hitting a specific CB marker
	DUMP_CVE_ALL_MARKER	=	1<<3	//DUMP on all CB markers
} dumpTriggers_e;

typedef enum {
	STOP_ALL_BARRIERS   = 	0,		//The debugger will stop in each barrier
	STOP_ON_SECTION_ID 	=	1<<0,	//The debugger will stop in a specific barrier (defined in sectionID)
	RESUME 				=	1<<1
} watchModes_e;

typedef enum {
	BLOCK_INCOMING_CNC_MESSAGES   = 	0,		//The debugger will stop in each barrier
	SERVE_INCOMING_CNC_MESSAGES	  =	    1<<0	//Enable service and after reaching barrier, TLC will continue to handle commands within the same section
} tlcModes_e;


// end TLC_COMMAND_FORMATS_VELUES_H

