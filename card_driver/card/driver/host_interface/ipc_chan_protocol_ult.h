/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/
#ifndef _IPC_CHAN_PROTOCOL_ULT_H
#define _IPC_CHAN_PROTOCOL_ULT_H

#ifdef ULT
#include <linux/types.h>
#include "ipc_chan_protocol.h"

#pragma pack(push, 1)

/*************************************************************************************/
/* Protocol for ULT tests                                                            */
/*************************************************************************************/
enum ult2Opcodes {
	NNP_IPC_ULT2_OP_CARD_HWQ_MSG = 0,
	NNP_IPC_ULT2_OP_DMA_PING = 1,
	NNP_IPC_ULT2_NUM_OPCODES
};
NNP_STATIC_ASSERT(NNP_IPC_ULT2_NUM_OPCODES <= 16, "Opcode ID overflow for ULT2 opcodes");

union ULT2HwQMsg {
	struct {
		__le64 opcode       :  6;
		__le64 channelID    : NNP_IPC_CHANNEL_BITS;
		__le64 ultOpcode    :  4;
		__le64 ultMsgId     :  5;
		__le64 ultMsgsNum   : 16;
		__le64 ultMsgSeqNum : 16;
		__le64 reserved     :  7;
	};

	__le64 value;
};
CHECK_MESSAGE_SIZE(union ULT2HwQMsg, 1);

union ULT2DmaPingMsg {
	struct {
		__le64 opcode       :  6;
		__le64 channelID    : NNP_IPC_CHANNEL_BITS;
		__le64 ultOpcode    :  4;
		__le64 rbID         :  1;
		__le64 seq          : 16;
		__le64 size         : 12;
		__le64 reserved     : 15;
	};

	__le64 value;
};
CHECK_MESSAGE_SIZE(union ULT2HwQMsg, 1);

#pragma pack(pop)

#endif

#endif
