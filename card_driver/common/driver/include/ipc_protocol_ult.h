/********************************************
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/
#ifndef _IPC_PROTOCOL_ULT_H
#define _IPC_PROTOCOL_ULT_H

#ifdef ULT
#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdbool.h>
#endif
#include "ipc_protocol.h"

#pragma pack(push, 1)

/*************************************************************************************/
/* Protocol for ULT tests                                                            */
/*************************************************************************************/
enum ultOpcodes {
	SPH_IPC_ULT_OP_DMA_SINGLE = 0,
	SPH_IPC_ULT_OP_CARD_HWQ_MSG,
	SPH_IPC_ULT_OP_DMA_BANDWIDTH,
	SPH_IPC_ULT_OP_DOORBELL,
	SPH_IPC_ULT_OP_BOOT_OVER_PCI,
	SPH_IPC_ULT_OP_RSYSLOG,
	SPH_IPC_ULT_NUM_OPCODES
};
SPH_STATIC_ASSERT(SPH_IPC_ULT_NUM_OPCODES <= 64, "Opcode ID overflow for ULT opcodes");

struct ult_dma_single_packet_header {
	u64 clientHandle;
	u64 dstHostDmaPfn;
	u32 hostPageHandle;
	u32 h2cDmaTime;
};
SPH_STATIC_ASSERT(sizeof(struct ult_dma_single_packet_header) <= 24,
		  "struct dma_single_packet_header is too large, need to update ult test dma_ping_ult");

enum dma_ult_mode {
	DMA_MODE_CONTIG,
	DMA_MODE_CONTIG_WITH_POLLING,
	DMA_MODE_SG_EQUAL_SIZE,
	DMA_MODE_SG_BIG_CHUNCK,
	DMA_MODE_SG_SIZE_MISMATCH,
	DMA_MODE_SG_SIZE_MISMATCH_BIG_CHUNCK,
	DMA_MODE_SG_EQUAL_SIZE_NON_CONTINUOUS,
	DMA_MODE_SG_SIZE_MISMATCH_NON_CONTINUOUS,
	DMA_MODE_SG_BIG_CHUNCK_NON_CONTINUOUS,
	DMA_MODE_SG_SIZE_MISMATCH_BIG_CHUNCK_NON_CONTINUOUS,
};

static inline bool is_contiguous(enum dma_ult_mode dma_ult_mode)
{
	return (dma_ult_mode == DMA_MODE_CONTIG ||
			dma_ult_mode == DMA_MODE_CONTIG_WITH_POLLING);
}


static inline bool is_scattered(enum dma_ult_mode dma_ult_mode)
{
	return (dma_ult_mode >= DMA_MODE_SG_EQUAL_SIZE &&
			dma_ult_mode <= DMA_MODE_SG_SIZE_MISMATCH_BIG_CHUNCK_NON_CONTINUOUS);
}

static inline bool is_scattered_non_continuous_chunks(enum dma_ult_mode dma_ult_mode)
{
	return (dma_ult_mode >= DMA_MODE_SG_EQUAL_SIZE_NON_CONTINUOUS &&
			dma_ult_mode <= DMA_MODE_SG_SIZE_MISMATCH_BIG_CHUNCK_NON_CONTINUOUS);
}

#define ULT_DMA_SIZE_UNIT 128
#define PROTO_ALIGN_BUFF_SIZE(x) ((ALIGN(x, ULT_DMA_SIZE_UNIT) / ULT_DMA_SIZE_UNIT) - 1 )

union h2c_ULTDMASingleMsg {
	struct {
		u64 opcode : 5;
		u64 ultOpcode : 5;
		u64 size : 5; /* size in units defined by ULT_DMA_SIZE_UNIT */
		u64 dma_ult_mode : 4;
		u64 dma_pfn : SPH_IPC_DMA_PFN_BITS;
	};

	u64 value;
};
CHECK_MESSAGE_SIZE(union h2c_ULTDMASingleMsg, 1);

union c2h_ULTDMASingleMsgReply {
	struct {
		u64 opcode         :  5;
		u64 ultOpcode      :  5;
		u64 c2hDmaTime     : 32;
		u64 reserved       : 14;
		u64 hostPageHandle : PAGE_HANDLE_BITS;
	};

	u64 value;
};
CHECK_MESSAGE_SIZE(union c2h_ULTDMASingleMsgReply, 1);

union ULTHwQMsg {
	struct {
		u64 opcode       :  5;
		u64 ultOpcode    :  5;
		u64 ultMsgId     :  5;
		u64 ultMsgsNum   : 16;
		u64 ultMsgSeqNum : 16;
		u64 reserved     : 17;
	};

	u64 value;
};
CHECK_MESSAGE_SIZE(union ULTHwQMsg, 1);

struct ult_dma_bandwidth_packet_header {
	u64 clientHandle;
	u64 dstHostDmaPfn;
	u32 hostPageHandle;
	u32 responseLength;
	u32 dmaBandwidthRequestInfoCount;
	u32 host_page_size;
};

SPH_STATIC_ASSERT(sizeof(struct ult_dma_bandwidth_packet_header) <= 32,
		  "struct dma_badwidth_packet_header is too large, need to update ult test dma_ping_ult");
enum ult_dma_bandwidth_direction {
	ULT_DMA_BANDWIDTH_CARD_TO_HOST,
	ULT_DMA_BANDWIDTH_HOST_TO_CARD
};

enum ult_dma_bandwidth_priority {
	ULT_DMA_BANDWIDTH_HIGH,
	ULT_DMA_BANDWIDTH_NORMAL,
	ULT_DMA_BANDWIDTH_LOW
};

union ult_dma_bandwidth_request_info {
	struct {
		enum ult_dma_bandwidth_direction direction;
		enum ult_dma_bandwidth_priority priority;
		uint32_t bufSize;
		int repeat_count;
		uint32_t dtf_mode;
		uint32_t sg_mode;
		uint32_t dma_addr_count;
		uint32_t dma_page_size;
		uint8_t noWait;
	} in;
	struct {
		u32 dma_timeUS;
		u32 cpu_timeUS;
	} out;
};

union h2c_ULTDMABandwidthMsg {
	struct {
		u64 opcode : 5;
		u64 ultOpcode : 6;
		u64 size : 8;
		u64 dma_pfn : SPH_IPC_DMA_PFN_BITS;
	};

	u64 value;
};
CHECK_MESSAGE_SIZE(union h2c_ULTDMABandwidthMsg, 1);

union ULTDoorbell {
	struct {
		u64 opcode       :  5;
		u64 ultOpcode    :  5;  // SPH_IPC_ULT_OP_DOORBELL
		u64 reserved     : 22;
		u64 db_val       : 32;
	};

	u64 value;
};
CHECK_MESSAGE_SIZE(union ULTDoorbell, 1);

#define ULT_IMAGE_SIZE_FACTOR  65536 //64K

union ULTBootOverPCIReplay {
	struct {
		u64 opcode       :  5;
		u64 ultOpcode    :  5;  // SPH_IPC_ULT_OP_BOOT_OVER_PCI
		u32 descriptor_addr : 32; //32 low address bits
		u32 image_size      : 16; //64K units
		u64 reserved        : 6;
	};

	u64 value;
};
CHECK_MESSAGE_SIZE(union ULTBootOverPCIReplay, 1);

#pragma pack(pop)

#endif

#endif
