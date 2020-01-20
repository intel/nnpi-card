/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/
#ifndef _IPC_CHAN_PROTOCOL_ULT_H
#define _IPC_CHAN_PROTOCOL_ULT_H

#ifdef ULT
#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdbool.h>
#endif
#include "ipc_chan_protocol.h"

#pragma pack(push, 1)

/*************************************************************************************/
/* Protocol for ULT tests                                                            */
/*************************************************************************************/
enum ult2Opcodes {
	SPH_IPC_ULT2_OP_CARD_HWQ_MSG = 0,
	SPH_IPC_ULT2_OP_DMA_PING = 1,
	SPH_IPC_ULT2_NUM_OPCODES
};
SPH_STATIC_ASSERT(SPH_IPC_ULT2_NUM_OPCODES <= 16, "Opcode ID overflow for ULT2 opcodes");

union ULT2HwQMsg {
	struct {
		u64 opcode       :  6;
		u64 channelID    : SPH_IPC_CHANNEL_BITS;
		u64 ultOpcode    :  4;
		u64 ultMsgId     :  5;
		u64 ultMsgsNum   : 16;
		u64 ultMsgSeqNum : 16;
		u64 reserved     :  7;
	};

	u64 value;
};
CHECK_MESSAGE_SIZE(union ULTHwQMsg, 1);

union ULT2DmaPingMsg {
	struct {
		u64 opcode       :  6;
		u64 channelID    : SPH_IPC_CHANNEL_BITS;
		u64 ultOpcode    :  4;
		u64 rbID         :  1;
		u64 seq          : 16;
		u64 size         : 12;
		u64 reserved     : 15;
	};

	u64 value;
};
CHECK_MESSAGE_SIZE(union ULTHwQMsg, 1);

#pragma pack(pop)

#endif

#endif
