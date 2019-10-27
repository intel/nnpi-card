/********************************************
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/
#ifndef _IPC_PROTOCOL_H
#define _IPC_PROTOCOL_H

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/dma-mapping.h>
#include "sph_debug.h"
#include "ipc_c2h_events.h"

#define CHECK_MESSAGE_SIZE(t, nQW) SPH_STATIC_ASSERT(sizeof(t) == 8*(nQW), "Size of " #t " Does not match!!")
#else
#define CHECK_MESSAGE_SIZE(t, nQW)
#define SPH_STATIC_ASSERT(t, nQW)
typedef unsigned long int u64;
typedef unsigned int  u32;
typedef unsigned short u16;
typedef unsigned char  u8;
#endif

#define SPH_MSG_SIZE(msg) (sizeof(msg) / sizeof(u64))
/*
 * We use 4096 since host and card can use different PAGE_SIZE.
 * Possible improvement might be to negotiate PAGE_SIZE with card during startup
 * and pick smallest size to be used by both sides
 */
#define SPH_PAGE_SHIFT 12
#define SPH_PAGE_SIZE (1<<SPH_PAGE_SHIFT)

SPH_STATIC_ASSERT(SPH_PAGE_SHIFT <= PAGE_SHIFT, "SPH_PAGE_SIZE is bigger than PAGE_SIZE");

/* The crash dump buffer size is PAGE-SIZE*2^SPH_CRASH_DUMP_SIZE_PAGE_ORDER or
 * 2^(PAGE_SHIFT+SPH_CRASH_DUMP_SIZE_PAGE_ORDER)
 */
#define SPH_CRASH_DUMP_SIZE_PAGE_ORDER 2

#define SPH_VERSION_MAJOR(ver) (((ver) >> 10) & 0x1f)
#define SPH_VERSION_MINOR(ver) (((ver) >> 5) & 0x1f)
#define SPH_VERSION_DOT(ver) ((ver) & 0x1f)
#define SPH_MAKE_VERSION(major, minor, dot) (((major) & 0x1f) << 10 | \
					     ((minor) & 0x1f) << 5 | \
					     ((dot) & 0x1f))

#define SPH_IPC_PROTOCOL_VERSION SPH_MAKE_VERSION(2, 5, 0)

/* Maximumum of free pages, which device can hold at any time */
#define MAX_HOST_RESPONSE_PAGES 32

/* Minimum number of free pages left to device. When the number of free pages */
/* is less than this threshold, another list of free pages should be resend */
#define MIN_HOST_RESPONSE_PAGES 8

#define PAGE_HANDLE_BITS __CHAR_BIT__
#define SPH_NET_SKB_HANDLE_BITS __CHAR_BIT__

#define SPH_IPC_DMA_PFN_BITS    45   /* number of bits for dma physical address in the protocol */
#define SPH_DMA_ADDR_ALIGN_BITS SPH_PAGE_SHIFT  /* number of zero LSBs in dma physical address */
#define SPH_IPC_DMA_PFN_MASK              (((1ULL) << SPH_IPC_DMA_PFN_BITS) - 1)
#define SPH_IPC_DMA_ADDR_ALIGN_MASK       (((1ULL) << SPH_DMA_ADDR_ALIGN_BITS) - 1)
#define SPH_IPC_DMA_ADDR_TO_PFN(dma_adr)  ((dma_adr >> SPH_DMA_ADDR_ALIGN_BITS) & SPH_IPC_DMA_PFN_MASK)
#define SPH_IPC_DMA_PFN_TO_ADDR(dma_pfn)  (((u64)(dma_pfn)) << SPH_DMA_ADDR_ALIGN_BITS)

#define SPH_IPC_GENMSG_BAD_CLIENT_ID   0xFFF

#define SPH_IPC_INF_CONTEXT_BITS 8  /* number of bits in protocol for inference context ID */
#define SPH_IPC_INF_CMDS_BITS 16  /* number of bits in protocol for device resource */
#define SPH_IPC_INF_DEVRES_BITS 16  /* number of bits in protocol for device resource */
#define SPH_IPC_INF_DEVNET_BITS 16  /* number of bits in protocol for device network */
#define SPH_IPC_INF_COPY_BITS 16    /* number of bits in protocol for copy handler */
#define SPH_IPC_INF_REQ_BITS 16     /* number of bits in protocol for inf req */
#define SPH_IPC_CHANNEL_BITS  10     /* number of bits in protocol for channel ID */
#define SPH_IPC_MAX_CHANNEL_RINGBUFS 2 /* maximum number of data ring buffers for each channel (per-direction) */

#pragma pack(push, 1)

/***************************************************************************
 * Structures used inside data packets transfered in the protocol
 ***************************************************************************/
struct response_list_entry {
	u64 unused1   : (sizeof(u64) * __CHAR_BIT__ - SPH_IPC_DMA_PFN_BITS - SPH_DMA_ADDR_ALIGN_BITS);
	u64 dma_pfn   : SPH_IPC_DMA_PFN_BITS;
	u64 unused2   : (SPH_DMA_ADDR_ALIGN_BITS - PAGE_HANDLE_BITS);
	u64 page_hdl  : PAGE_HANDLE_BITS;
};

struct dma_chain_header {
	u64 dma_next;
	u32 total_nents;
	u64 size;
};

#define DMA_CHAIN_ENTRY_NPAGES_BITS (sizeof(u64) * __CHAR_BIT__ - SPH_IPC_DMA_PFN_BITS)
#define SPH_MAX_CHUNK_SIZE (((1lu << DMA_CHAIN_ENTRY_NPAGES_BITS) - 1) << SPH_PAGE_SHIFT)
struct dma_chain_entry {
	u64 dma_chunk_pfn  : SPH_IPC_DMA_PFN_BITS;
	u64 n_pages        : DMA_CHAIN_ENTRY_NPAGES_BITS;
};

#define NENTS_PER_PAGE ((SPH_PAGE_SIZE - sizeof(struct dma_chain_header)) / sizeof(struct dma_chain_entry))

/***************************************************************************
 * IPC messages layout definition
 ***************************************************************************/
union c2h_QueryVersionReplyMsg {
	struct {
		u64 opcode          :  6;  /* SPH_IPC_C2H_OP_QUERY_VERSION_REPLY */
		u64 driverVersion   : 16;
		u64 fwVersion       : 16;
		u64 protocolVersion : 16;
		u64 reserved        : 10;
	};

	u64 value;
};
CHECK_MESSAGE_SIZE(union c2h_QueryVersionReplyMsg, 1);

union c2h_ServiceListMsg {
	struct {
		u64 opcode           :  6;   /* SPH_IPC_C2H_OP_SERVICE_LIST */
		u64 failure          :  3;   /* 0=Valid 1=DmaFailed 2=PullFull 3=TooBig */
		u64 resp_page_handle : PAGE_HANDLE_BITS;
		u64 size             : 12;
		u64 reserved         :  3;
		u64 num_services     : 32;
	};

	u64 value;
};
CHECK_MESSAGE_SIZE(union c2h_ServiceListMsg, 1);

union c2h_GenericMessaging {
	struct {
		u64 opcode          :  6; /* SPH_IPC_C2H_OP_GENERIC_MSG_PACKET */
		u64 size            : 12;
		u64 connect         :  1;
		u64 free_page       :  1;
		u64 no_such_service :  1;
		u64 hangup          :  1;
		u64 host_client_id  : 12;
		u64 card_client_id  : 12;
		u64 reserved        : 10;
		u64 host_page_hndl  : PAGE_HANDLE_BITS;
	};

	u64 value;
};
CHECK_MESSAGE_SIZE(union c2h_GenericMessaging, 1);

union c2h_EventReport {
	struct {
		u32 opcode     :  6;  /* SPH_IPC_C2H_OP_EVENT_REPORT */
		u32 eventCode  :  7;
		u32 contextID  : SPH_IPC_INF_CONTEXT_BITS;
		u32 objID      : 16;
		u32 objID_2    : SPH_IPC_INF_REQ_BITS;
		u32 eventVal   :  8;
		u32 ctxValid   :  1;
		u32 objValid   :  1;
		u32 objValid_2 :  1;
	};
	u64 value;
};
CHECK_MESSAGE_SIZE(union c2h_EventReport, 1);

#ifdef _DEBUG
/*
 * debug function to log c2h event report - implemented in
 * common/ipc_c2h_events.c
 */
void log_c2h_event(const char *msg, const union c2h_EventReport *ev);
#else
#define log_c2h_event(x, y)
#endif

union c2h_EthernetMsgDscr {
	struct {
		u64 opcode      :  6; /* SPH_IPC_C2H_OP_ETH_MSG_DSCR */
		u64 size        : 12;
		u64 is_ack      :  1;
		u64 page_handle : PAGE_HANDLE_BITS;
		u64 skb_handle	: SPH_NET_SKB_HANDLE_BITS;
		u64 reserved    : 29;
		u64 dma_addr;
	};

	u64 value[2];
};
CHECK_MESSAGE_SIZE(union c2h_EthernetMsgDscr, 2);

union c2h_SyncDone {
	struct {
		u64 opcode      : 6; /* SPH_IPC_C2H_OP_SYNC_DONE */
		u32 contextID   : SPH_IPC_INF_CONTEXT_BITS;
		u32 syncSeq     : 16;
		u64 reserved    : 34;
	};

	u64 value;
};
CHECK_MESSAGE_SIZE(union c2h_SyncDone, 1);

union c2h_SubResourceLoadReply {
	struct {
		u64 opcode      : 6;  /* SPH_IPC_C2H_OP_INF_SUBRES_LOAD_REPLY */
		u32 contextID   : SPH_IPC_INF_CONTEXT_BITS;
		u32 sessionID   : 16;
		u32 host_pool_index : 2;
		u64 reserved    : 32;
	};

	u64  value;
};
CHECK_MESSAGE_SIZE(union c2h_SubResourceLoadReply, 1);

union c2h_SubResourceLoadCreateSessionReply {
	struct {
		u64 opcode        : 6; /* SPH_IPC_C2H_OP_INF_SUBRES_LOAD_CREATE_REMOVE_SESSION_REPLY */
		u32 contextID     : SPH_IPC_INF_CONTEXT_BITS;
		u32 sessionID     : 16;
		u64 reserved      : 34;
	};

	u64 value;
};
CHECK_MESSAGE_SIZE(union c2h_SubResourceLoadCreateSessionReply, 1);

union c2h_DmaPageHandleFree {
	struct {
		u64 opcode          :  6; /* SPH_IPC_C2H_OP_DMA_PAGE_HANDLE_FREE */
		u64 is_response_page:  1;
		u64 is_net_response_page: 1;
		u64 reserved        : 48;
		u64 host_page_hndl  : PAGE_HANDLE_BITS;
	};

	u64 value;
};
CHECK_MESSAGE_SIZE(union c2h_DmaPageHandleFree, 1);

union c2h_EthernetConfig {
	struct {
		u64 opcode      :  6; /* SPH_IPC_C2H_OP_ETH_CONFIG */
		u64 reserved    : 26;
		u64 card_ip	: 32;
	};

	u64 value;
};
CHECK_MESSAGE_SIZE(union c2h_EthernetConfig, 1);

union c2h_SysInfo {
	struct {
		u64 opcode          :  6; /* SPH_IPC_C2H_OP_SYS_INFO */
		u64 reserved        :  3;
		u64 host_page_hndl  :  PAGE_HANDLE_BITS;
		u64 reserved2       :  47;
	};

	u64 value;
};
CHECK_MESSAGE_SIZE(union c2h_EthernetConfig, 1);

union h2c_QueryVersionMsg {
	struct {
		u64 opcode     :  6;   /* SPH_IPC_H2C_OP_QUERY_VERSION */
		u64 reserved   : 58;
	};

	u64 value;
};
CHECK_MESSAGE_SIZE(union h2c_QueryVersionMsg, 1);

#define SPH_MAIN_RESPONSE_POOL_INDEX 0
#define SPH_NET_RESPONSE_POOL_INDEX 1

union h2c_HostResponsePagesMsg {
	struct {
		u64 opcode            : 6;   /* SPH_IPC_H2C_OP_HOST_RESPONSE_PAGES */
		u64 num_pages         : PAGE_HANDLE_BITS;
		u64 response_pool_index  : 2;
		u64 reserved          : 3;
		u64 host_pfn          : SPH_IPC_DMA_PFN_BITS;  /* page content is array of struct response_list_entry */
	};

	u64 value;
};
CHECK_MESSAGE_SIZE(union h2c_HostResponsePagesMsg, 1);

union h2c_GenericMessaging {
	struct {
		u64 opcode   :  6;   /* SPH_IPC_H2C_OP_GENERIC_MSG_PACKET */
		u64 size     : 12;
		u64 connect  :  1;
		u64 hangup   :  1;
		u64 host_pfn : SPH_IPC_DMA_PFN_BITS;

		u64 host_client_id  : 12;
		u64 card_client_id  : 12;
		u64 host_page_hndl  :  8;
		u64 reserved        : 29;
		u64 service_list_req:  1;
		u64 privileged      :  1;
	};

	u64 value[2];
};
CHECK_MESSAGE_SIZE(union h2c_GenericMessaging, 2);

union h2c_EthernetMsgDscr {
	struct {
		u64 opcode      :  6; /* SPH_IPC_H2C_OP_ETH_MSG_DSCR */
		u64 size        : 12;
		u64 is_ack      :  1;
		u64 skb_handle : SPH_NET_SKB_HANDLE_BITS;
		u64 reserved    : 37;
		u64 dma_addr;
	};

	u64 value[2];
};
CHECK_MESSAGE_SIZE(union h2c_EthernetMsgDscr, 2);

union h2c_InferenceContextOp {
	struct {
		u64 opcode     : 6;  /* SPH_IPC_H2C_OP_INF_CONTEXT */
		u64 ctxID      : SPH_IPC_INF_CONTEXT_BITS;
		u64 destroy    : 1;
		u64 recover    : 1;
		u64 cflags     : 8;
		u64 reserved   : 8;
		u64 uid        :32;
	};

	u64 value;
};
CHECK_MESSAGE_SIZE(union h2c_InferenceContextOp, 1);

union h2c_EthernetConfig {
	struct {
		u64 opcode      :  6; /* SPH_IPC_H2C_OP_ETH_CONFIG */
		u64 reserved    : 27;
		u64 card_ip     : 32;

		u64 reserved2   : 15;
		u64 card_mac    : 48;  // at value[10-15]
	};

	u8 value[16];
};
CHECK_MESSAGE_SIZE(union h2c_EthernetConfig, 2);

union ClockSyncMsg { //QUERY TIME
	struct {
		u64 opcode       : 6; /* SPH_IPC_H2C_OP_CLOCK_SYNC */
		u64 iteration    : 8;
		u64 reserved     : 50;
		u64 o_card_ts;
	};

	u64 value[2];
};
CHECK_MESSAGE_SIZE(union ClockSyncMsg, 2);

union h2c_InferenceResourceOp {
	struct {
		u64 opcode      : 6;  /* SPH_IPC_H2C_OP_INF_RESOURCE */
		u64 ctxID       : SPH_IPC_INF_CONTEXT_BITS;
		u64 resID       : SPH_IPC_INF_DEVRES_BITS;
		u64 destroy     : 1;
		u64 is_input    : 1;
		u64 is_output   : 1;

		u64 is_network  : 1;
		u64 is_force_4G : 1;
		u64 is_ecc      : 1;
		u64 is_p2p_dst  : 1;
		u64 is_p2p_src  : 1;
		u64 depth       : 8;
		u64 reserved    : 18;

		u64 size        : 64;
	};

	u64 value[2];
};
CHECK_MESSAGE_SIZE(union h2c_InferenceResourceOp, 2);

union h2c_InferenceCmdListOp {
	struct {
		u64 opcode      :  5;  /* SPH_IPC_H2C_OP_INF_CMDLIST */
		u64 ctxID       : SPH_IPC_INF_CONTEXT_BITS;
		u64 cmdID       : SPH_IPC_INF_CMDS_BITS;
		u64 destroy     :  1;
		u64 unused      : 34;

		u64 host_pfn    : SPH_IPC_DMA_PFN_BITS;
		u64 size        : (sizeof(u64) * __CHAR_BIT__ - SPH_IPC_DMA_PFN_BITS);
	};

	u64 value[2];
};
CHECK_MESSAGE_SIZE(union h2c_InferenceCmdListOp, 2);

union h2c_InferenceNetworkOp {
	struct {
		u64 opcode        : 6; /* SPH_IPC_H2C_OP_INF_NETWORK */
		u64 ctxID         : SPH_IPC_INF_CONTEXT_BITS;
		u64 netID         : SPH_IPC_INF_DEVNET_BITS;
		u64 destroy       : 1;
		u64 create        : 1;
		u64 num_res       :24;
		u64 dma_page_hndl : 8;

		u64 host_pfn      : SPH_IPC_DMA_PFN_BITS;
		u64 size          : 18;
		u64 chained       : 1;
	};

	u64 value[2];
};
CHECK_MESSAGE_SIZE(union h2c_InferenceNetworkOp, 2);

union h2c_InferenceNetworkResourceReservation {
	struct {
		u64 opcode        : 6; /* SPH_IPC_H2C_OP_INF_NETWORK_RESOURCE_RESERVATION */
		u64 ctxID         : SPH_IPC_INF_CONTEXT_BITS;
		u64 netID         : SPH_IPC_INF_DEVNET_BITS;
		u64 not_used      : 1;
		u64 reserve       : 1; //reserve or release
		u64 timeout       : 32;
	};

	u64 value[1];
};
CHECK_MESSAGE_SIZE(union h2c_InferenceNetworkResourceReservation, 1);

union h2c_setup_crash_dump_msg {
	struct {
		u64 opcode    :  6;   /* SPH_IPC_H2C_OP_SETUP_CRASH_DUMP */
		u64 reserved  :  13;
		/*dma_addr of the first page*/
		u64 dma_addr  : SPH_IPC_DMA_PFN_BITS;
		u64 membar_addr : 64;
	};

	u64 value[2];
};
CHECK_MESSAGE_SIZE(union h2c_setup_crash_dump_msg, 2);

union h2c_InferenceCopyOp {
	struct {
		u64 opcode     :  6;  /* SPH_IPC_H2C_OP_COPY_OP */
		u64 ctxID      : SPH_IPC_INF_CONTEXT_BITS;
		u64 protResID  : 16;
		u64 protCopyID : 16;
		u64 d2d        :  1;
		u64 c2h        :  1; /* if d2d = 0, c2h defines the copy direction */
		u64 destroy    :  1;
		u64 reserved1  : 15;
		u64 hostPtr    : SPH_IPC_DMA_PFN_BITS;
		u64 reserved2  : 19;
	};

	u64 value[2];
};
CHECK_MESSAGE_SIZE(union h2c_InferenceCopyOp, 2);

union h2c_InferenceSchedCopy {
	struct {
		u64 opcode     : 6;  /* SPH_IPC_H2C_OP_SCHEDULE_COPY */
		u64 ctxID      : SPH_IPC_INF_CONTEXT_BITS;
		u64 protCopyID : 16;
		u64 copySize   : 32;
		u64 priority   : 2;  /* TBD: change back to 3 in new proto */
	};

	u64 value;
};
CHECK_MESSAGE_SIZE(union h2c_InferenceSchedCopy, 1);

union h2c_Sync {
	struct {
		u64 opcode      : 6; /* SPH_IPC_H2C_OP_SYNC */
		u32 contextID   : SPH_IPC_INF_CONTEXT_BITS;
		u32 syncSeq     : 16;
		u64 reserved    : 34;
	};

	u64 value;
};
CHECK_MESSAGE_SIZE(union h2c_Sync, 1);

union h2c_SubResourceLoadOp {
	struct {
		u64 opcode       : 6; /* SPH_IPC_H2C_OP_INF_SUBRES_LOAD */
		u32 contextID    : SPH_IPC_INF_CONTEXT_BITS;
		u64 sessionID    : 16;
		u32 host_pool_index : 2;
		u64 host_pool_dma_address  : SPH_IPC_DMA_PFN_BITS;
		u32 n_pages : 8;
		u32 byte_size : 12;
		u64 reserved : 31;
		u64 res_offset : 64;
	};

	u64 value[3];
};
CHECK_MESSAGE_SIZE(union h2c_SubResourceLoadOp, 3);

union h2c_SubResourceLoadCreateRemoveSession {
	struct {
		u64 opcode        : 6; /* SPH_IPC_H2C_OP_INF_SUBRES_LOAD_CREATE_REMOVE_SESSION */
		u32 contextID     : SPH_IPC_INF_CONTEXT_BITS;
		u32 sessionID     : 16;
		u32 remove        : 1;
		u64 resID         : SPH_IPC_INF_DEVRES_BITS;
		u64 reserved      : 17;
	};

	u64 value;
};
CHECK_MESSAGE_SIZE(union h2c_SubResourceLoadCreateRemoveSession, 1);

union h2c_InferenceReqOp {
	struct {
		u64 opcode            :  6; /* SPH_IPC_H2C_OP_INF_REQ_OP */
		u64 host_page_hndl    : PAGE_HANDLE_BITS;
		u64 host_pfn          : SPH_IPC_DMA_PFN_BITS;
		u64 destroy           :  1;
		u64 reserved1         :  4;

		u64 ctxID             : SPH_IPC_INF_CONTEXT_BITS;
		u64 netID             : SPH_IPC_INF_DEVNET_BITS;
		u64 infreqID          : SPH_IPC_INF_REQ_BITS;
		u64 size              : 12;
		u64 reserved2         : 12;
	};

	u64 value[2];
};
CHECK_MESSAGE_SIZE(union h2c_InferenceReqOp, 2);

union h2c_InferenceReqSchedule {
	struct {
		u64 opcode            :  6; /* SPH_IPC_H2C_OP_SCHEDULE_INF_REQ */
		u64 netID             : SPH_IPC_INF_DEVNET_BITS;
		u64 infreqID          : SPH_IPC_INF_REQ_BITS;
		u64 reserved          : 26;

		u64 ctxID             : SPH_IPC_INF_CONTEXT_BITS;
		//schedParams
		u64 batchSize         : 16;
		u64 priority          :  8; /* 0 == normal, 1 == high */
		u64 debugOn           :  1;
		u64 collectInfo       :  1;
		u64 schedParamsIsNull :  1;
		u64 reserve           : 29;
	};

	u64 value[2];
};
CHECK_MESSAGE_SIZE(union h2c_InferenceReqSchedule, 2);


union h2c_HwTraceAddResource {
	struct {
		u64 opcode          : 6;  /* SPH_IPC_H2C_OP_HWTRACE_ADD_RESOURCE */
		u64 descriptor_addr : SPH_IPC_DMA_PFN_BITS;
		u64 resourceIndex   : 8;  /* resource index */
		u64 reserved1       : 5;
		u64 reserved	    : 32;
		u64 resource_size   : 32;
	};

	u64 value[2];
};
CHECK_MESSAGE_SIZE(union h2c_HwTraceAddResource, 2);

union h2c_ChannelOp {
	struct {
		u64 opcode         :  6;  /* SPH_IPC_H2C_OP_CHANNEL_OP */
		u64 protocolID     : SPH_IPC_CHANNEL_BITS;
		u64 destroy        :  1;
		u64 reserved       : 14;
		u64 privileged     :  1;
		u64 uid            : 32;
	};

	u64 value;
};
CHECK_MESSAGE_SIZE(union h2c_ChannelOp, 1);

union h2c_ChannelDataRingbufOp {
	struct {
		u64 opcode         :  6;  /* SPH_IPC_H2C_OP_CHANNEL_RB_OP */
		u64 chanID         : SPH_IPC_CHANNEL_BITS;
		u64 h2c            :  1;
		u64 rbID           :  1;
		u64 destroy        :  1;
		u64 hostPtr        : SPH_IPC_DMA_PFN_BITS;
	};

	u64 value;
};
CHECK_MESSAGE_SIZE(union h2c_ChannelDataRingbufOp, 1);

union h2c_ChannelHostresOp {
	struct {
		u64 opcode         :  6;  /* SPH_IPC_H2C_OP_CHANNEL_HOSTRES_OP */
		u64 chanID         : SPH_IPC_CHANNEL_BITS;
		u64 hostresID      : 16;
		u64 unmap          :  1;
		u64 reserved       : 31;

		u64 hostPtr        : SPH_IPC_DMA_PFN_BITS;
		u64 reserved2      : 19;
	};

	u64 value[2];
};
CHECK_MESSAGE_SIZE(union h2c_ChannelHostresOp, 2);

union c2h_HwTraceState {
	struct {
		u64 opcode		: 6;  /* SPH_IPC_C2H_OP_HWTRACE_STATE */
		u64 reserved		: 5;
		u64 subOpcode		: 5;
		u64 val1		: 32;
		u64 val2		: 8;
		u64 err			: 8;
	};

	u64 value;
};
CHECK_MESSAGE_SIZE(union c2h_HwTraceState, 1);

union h2c_HwTraceState {
	struct {
		u64 opcode		: 6;  /* SPH_IPC_H2C_OP_HWTRACE_STATE */
		u64 reserved		: 21;
		u64 subOpcode		: 5;
		u64 val			: 32;
	};

	u64 value;
};
CHECK_MESSAGE_SIZE(union h2c_HwTraceState, 1);

union h2c_P2PDev {
	struct {
		u64 opcode		: 6;  /* SPH_IPC_H2C_OP_P2P_DEV */
		u64 destroy		: 1;
		u64 dev_id		: 5;
		u64 is_producer		: 1;
		u64 db_addr		: 57;
		u64 cr_fifo_addr	: SPH_IPC_DMA_PFN_BITS;
		u64 reserved		: 13;
	};
	u64 value[2];
};
CHECK_MESSAGE_SIZE(union h2c_P2PDev, 2);

union h2c_PeerBuf {
	struct {
		u64 opcode     :  6;  /* SPH_IPC_H2C_OP_PEER_BUF */
		u64 buf_id     :  5;
		u64 is_src_buf :  1;
		u64 dev_id     :  5;
		u64 peer_buf_id:  5;
		u64 destroy    :  1;
		u64 reserved1  : 41;
	};

	u64 value;
};
CHECK_MESSAGE_SIZE(union h2c_PeerBuf, 1);

union h2c_GetCrFIFO {
	struct {
		u64 opcode      : 6;  /* SPH_IPC_H2C_GET_CR_FIFO */
		u64 tr_id       : 8;
		u64 peer_id     : 5;
		u64 fw_fifo     : 1;/* fw fifo or relase fifo */
		u64 reserved    : 44;
	};

	u64 value;
};
CHECK_MESSAGE_SIZE(union h2c_GetCrFIFO, 1);

#ifdef ULT
union ult_message {
	struct {
		u64 opcode       :  6;
		u64 ultOpcode    :  4;
		u64 reserved     : 54;
	};

	u64 value;
};
CHECK_MESSAGE_SIZE(union ult_message, 1);
#endif

/***************************************************************************
 * IPC messages opcodes and related utility macros
 ***************************************************************************/
#define H2C_OPCODE_NAME(name)          SPH_IPC_H2C_OP_ ## name
#define C2H_OPCODE_NAME(name)          SPH_IPC_C2H_OP_ ## name
#define IPC_OPCODE_HANDLER(name) \
	__sph_ipc_handler_ ## name
#define CALL_IPC_OPCODE_HANDLER(name, type, ctx, msg) \
	IPC_OPCODE_HANDLER(name)(ctx, (type *)(msg))

#define H2C_OPCODE(name, val, type)    H2C_OPCODE_NAME(name) = (val), /* SPH_IGNORE_STYLE_CHECK */
enum sph_h2c_opcode {
	#include "ipc_h2c_opcodes.h"
};
#undef H2C_OPCODE


#define C2H_OPCODE(name, val, type)    C2H_OPCODE_NAME(name) = (val), /* SPH_IGNORE_STYLE_CHECK */
enum sph_c2h_opcode {
	#include "ipc_c2h_opcodes.h"
};
#undef C2H_OPCODE

/* Check that all opcodes are within 6 bits range */
#define H2C_OPCODE(name, val, type)    SPH_STATIC_ASSERT((val)<64, "opcode " #name " range overflow"); /* SPH_IGNORE_STYLE_CHECK */
#define C2H_OPCODE(name, val, type)    SPH_STATIC_ASSERT((val)<64, "opcode " #name " range overflow"); /* SPH_IGNORE_STYLE_CHECK */
#include "ipc_h2c_opcodes.h"
#include "ipc_c2h_opcodes.h"
#undef H2C_OPCODE
#undef C2H_OPCODE

#if defined(_SPHCS_TRACE_H) || defined(_SPHDRV_TRACE_H)

#define H2C_OPCODE(name, val, type) /* SPH_IGNORE_STYLE_CHECK */\
	case (val):                   \
	return #name;

static inline const char *H2C_HWQ_MSG_STR(u8 x)
{
	switch (x) {
	#include "ipc_h2c_opcodes.h"
	default:
		return "not found";
	}
}
#undef H2C_OPCODE

#define C2H_OPCODE(name, val, type) /* SPH_IGNORE_STYLE_CHECK */\
	case (val):                   \
	return #name;

static inline const char *C2H_HWQ_MSG_STR(u8 x)
{
	switch (x) {
	#include "ipc_c2h_opcodes.h"
	default:
		return "not found";
	}
}
#undef C2H_OPCODE

#endif

/***************************************************************************
 * IPC messages protocol between the host driver and BIOS
 ***************************************************************************/
#define SPH_IPC_C2H_OP_BIOS_PROTOCOL    31
#define SPH_IPC_H2C_OP_BIOS_PROTOCOL    31

enum sph_bios_c2h_msg_types {
	SPH_IPC_C2H_TYPE_BIOS_VERSION  = 0x1
};

enum sph_bios_h2c_msg_types {
	SPH_IPC_H2C_TYPE_BOOT_IMAGE_READY  = 0x10,
	SPH_IPC_H2C_TYPE_SYSTEM_INFO_REQ   = 0x11
};

union sph_bios_ipc_header {
	struct {
		u64 opcode       :  6;  // SPH_IPC_C2H_OP_BIOS_PROTOCOL
		u64 reserved1    :  2;
		u64 msgType      :  8;  // bios message type
		u64 size         : 16;  // message size in bytes
		u64 reserved2    : 32;
	};

	u64 value;
};
CHECK_MESSAGE_SIZE(union sph_bios_ipc_header, 1);

struct sph_c2h_bios_version {
	u16 board_id[7];
	u16 board_rev;
	u16 dot1;
	u16 board_ext[3];
	u16 dot2;
	u16 version_major[4];
	u16 dot3;
	u16 build_type;
	u16 version_minor[2];
	u16 dot4;
	u16 time_stamp[10];
	u16 null_terminator;
};

struct sph_c2h_bios_fw_ver_ack_data {
	u32  CodeMinor   : 16;
	u32  CodeMajor   : 16;
	u32  CodeBuildNo : 16;
	u32  CodeHotFix  : 16;
	u32  RcvyMinor   : 16;
	u32  RcvyMajor   : 16;
	u32  RcvyBuildNo : 16;
	u32  RcvyHotFix  : 16;
	u32  FitcMinor   : 16;
	u32  FitcMajor   : 16;
	u32  FitcBuildNo : 16;
	u32  FitcHotFix  : 16;
};

struct sph_c2h_fw_version {
	u16  Major;
	u16  Minor;
	u16  Hotfix;
	u16  Build;
};

struct sph_c2h_cpu_info {
	u32 CpuFamily;      // for SPH = LceLake AIPG = 0x000906D0
	u8  CpuStepping;    // CPU Stepping
	u8  CpuSku;         // CPU SKU
	u16 CpuDid;         // for SPH range 0x4580-0x45FF (depends on CPU SKU)
	u16 CpuCoreCount;   // Number of enabled cores
	u16 CpuThreadCount; // Number of threads
};

struct sph_c2h_ice_info {
	u16 IceCount;
	u32 IceAvaliableMask;
};

struct sph_c2h_system_info {
	u8  Version; // SPH_SYSTEM_INFO structure version
	u16 BoardID; // Board identification- for SPH RVP = 0x25
	u8  FabID;   // Board Revision identification
	u8  BomID;   // Board Bill Of Material identification
	u8  PlatformType;   // For SPH RVP= 0x2, SPH M.2 = 0x3
	u8  PlatformFlavor; // For SPH = 0x5- Embedded
	struct sph_c2h_cpu_info CpuInfo; // CPU Information
	struct sph_c2h_ice_info IceInfo; // ICE Information
	struct sph_c2h_bios_version BiosVer; // BIOS version string - BIOS Revision Identification Specification", Rev. 2.0, 01/30/2015
	//PcodeRevision; // Pcode revision information
	struct sph_c2h_bios_fw_ver_ack_data CsmeVersion;
	struct sph_c2h_fw_version PmcVersion;
};

#define SPH_BIOS_VERSION_LEN    (sizeof(struct sph_c2h_bios_version) / sizeof(u16))
#define SPH_BOARD_NAME_LEN      72
#define SPH_IMAGE_VERSION_LEN   128

struct sph_sys_info {
	uint32_t ice_mask;
	char bios_version[SPH_BIOS_VERSION_LEN];
	char board_name[SPH_BOARD_NAME_LEN];
	char image_version[SPH_IMAGE_VERSION_LEN];
	u16  fpga_rev;
	uint64_t totalUnprotectedMemory;
	uint64_t totalEccMemory;
};

/*
 * this is the structure needed to be sent to the command h/w q when
 * a boot or bios image is loaded and ready in memory
 */
union h2c_BootImageReady {
	struct {
		u64 opcode          :  6;  // SPH_IPC_C2H_OP_BIOS_PROTOCOL
		u64 reserved1       :  2;
		u64 msgType         :  8;  // SPH_IPC_H2C_TYPE_BOOT_IMAGE_READY
		u64 size            : 16;  // message size in bytes
		u64 reserved2       : 32;
		u64 descriptor_addr : 64;
		u32 descriptor_size : 32;
		u32 image_size      : 32;
	};

	u64 value[3];
};
CHECK_MESSAGE_SIZE(union h2c_BootImageReady, 3);

union h2c_BiosSystemInfoReq {
	struct {
		u64 opcode          :  6;  // SPH_IPC_C2H_OP_BIOS_PROTOCOL
		u64 reserved1       :  2;
		u64 msgType         :  8;  // SPH_IPC_H2C_TYPE_SYSTEM_INFO_REQ
		u64 size            : 16;  // message size in bytes
		u64 reserved2       : 32;
		u64 sysinfo_addr    : 64;
		u32 sysinfo_size    : 32;
		u32 reserved3       : 32;
	};

	u64 value[3];
};
CHECK_MESSAGE_SIZE(union h2c_BiosSystemInfoReq, 3);

#pragma pack(pop)

#endif
