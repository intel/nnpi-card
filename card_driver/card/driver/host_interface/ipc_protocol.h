/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/
#ifndef _IPC_PROTOCOL_H
#define _IPC_PROTOCOL_H

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/dma-mapping.h>
#include "nnp_debug.h"
#include "ipc_c2h_events.h"
#include "nnp_inbound_mem.h"

#define CHECK_MESSAGE_SIZE(t, nQW) NNP_STATIC_ASSERT(sizeof(t) == sizeof(u64)*(nQW), "Size of " #t " Does not match!!")
#else
#define CHECK_MESSAGE_SIZE(t, nQW)
#define NNP_STATIC_ASSERT(cond, msg)
typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t  u8;
#endif

#define IPC_OP_MAX 64
#define NNP_IPC_OPCODE_MASK (IPC_OP_MAX - 1)

#define NNP_MSG_SIZE(msg) (sizeof(msg) / sizeof(u64))
/*
 * We use 4096 since host and card can use different PAGE_SIZE.
 * Possible improvement might be to negotiate PAGE_SIZE with card during startup
 * and pick smallest size to be used by both sides
 */
#ifndef NNP_PAGE_SHIFT
#define NNP_PAGE_SHIFT 12
#endif
#define NNP_PAGE_SIZE (1<<NNP_PAGE_SHIFT)

NNP_STATIC_ASSERT(NNP_PAGE_SHIFT <= PAGE_SHIFT, "NNP_PAGE_SIZE is bigger than PAGE_SIZE");

#define NNP_VERSION_MAJOR(ver) (((ver) >> 10) & 0x1f)
#define NNP_VERSION_MINOR(ver) (((ver) >> 5) & 0x1f)
#define NNP_VERSION_DOT(ver) ((ver) & 0x1f)
#define NNP_MAKE_VERSION(major, minor, dot) (((major) & 0x1f) << 10 | \
					     ((minor) & 0x1f) << 5 | \
					     ((dot) & 0x1f))

#define NNP_IPC_PROTOCOL_VERSION NNP_MAKE_VERSION(3, 1, 0)

#define NNP_IPC_DMA_PFN_BITS    45   /* number of bits for dma physical address in the protocol */
#define NNP_DMA_ADDR_ALIGN_BITS NNP_PAGE_SHIFT  /* number of zero LSBs in dma physical address */
#define NNP_IPC_DMA_PFN_MASK              (((1ULL) << NNP_IPC_DMA_PFN_BITS) - 1)
#define NNP_IPC_DMA_ADDR_ALIGN_MASK       (((1ULL) << NNP_DMA_ADDR_ALIGN_BITS) - 1)
#define NNP_IPC_DMA_ADDR_TO_PFN(dma_adr)  (((dma_adr) >> NNP_DMA_ADDR_ALIGN_BITS) & NNP_IPC_DMA_PFN_MASK)
#define NNP_IPC_DMA_PFN_TO_ADDR(dma_pfn)  (((u64)(dma_pfn)) << NNP_DMA_ADDR_ALIGN_BITS)

#define NNP_IPC_INF_CONTEXT_BITS 8  /* number of bits in protocol for inference context ID */
#define NNP_IPC_CHANNEL_BITS  10     /* number of bits in protocol for channel ID */
#define NNP_IPC_MAX_CHANNEL_RINGBUFS 2 /* maximum number of data ring buffers for each channel (per-direction) */

#pragma pack(push, 1)

/***************************************************************************
 * Structures used inside data packets transfered in the protocol
 ***************************************************************************/
struct dma_chain_header {
	u64 dma_next;
	u32 total_nents;
	u32 start_offset;
	u64 size;
};

#define DMA_CHAIN_ENTRY_NPAGES_BITS (sizeof(u64) * __CHAR_BIT__ - NNP_IPC_DMA_PFN_BITS)
#define NNP_MAX_CHUNK_SIZE (((1lu << DMA_CHAIN_ENTRY_NPAGES_BITS) - 1) << NNP_PAGE_SHIFT)
struct dma_chain_entry {
	u64 dma_chunk_pfn  : NNP_IPC_DMA_PFN_BITS;
	u64 n_pages        : DMA_CHAIN_ENTRY_NPAGES_BITS;
};

#define NENTS_PER_PAGE ((NNP_PAGE_SIZE - sizeof(struct dma_chain_header)) / sizeof(struct dma_chain_entry))

/***************************************************************************
 * IPC messages layout definition
 ***************************************************************************/
union c2h_QueryVersionReplyMsg {
	struct {
		u64 opcode          :  6;  /* NNP_IPC_C2H_OP_QUERY_VERSION_REPLY */
		u64 driverVersion   : 16;
		u64 fwVersion       : 16;
		u64 protocolVersion : 16;
		u64 reserved        : 10;
	};

	u64 value;
};
CHECK_MESSAGE_SIZE(union c2h_QueryVersionReplyMsg, 1);

union c2h_QueryVersionReply2Msg {
	struct {
		u64 opcode          :  6;  /* NNP_IPC_C2H_OP_QUERY_VERSION_REPLY2 */
		u64 driverVersion   : 16;
		u64 fwVersion       : 16;
		u64 protocolVersion : 16;
		u64 reserved        : 10;

		u64 chanRespOpSize  : 64; /* two bits for each possible response opcode specifying its size */
	};

	u64 value[2];
};
CHECK_MESSAGE_SIZE(union c2h_QueryVersionReply2Msg, 2);

union c2h_EventReport {
	struct {
		u32 opcode     :  6;  /* NNP_IPC_C2H_OP_EVENT_REPORT */
		u32 eventCode  :  7;
		u32 contextID  : NNP_IPC_INF_CONTEXT_BITS;
		u32 objID      : 16;//devres, infreq, copy
		u32 objID_2    : 16;//devnet, cmdlist
		u32 eventVal   :  8;
		u32 ctxValid   :  1;
		u32 objValid   :  1;
		u32 objValid_2 :  1;
	};
	u64 value;
};
CHECK_MESSAGE_SIZE(union c2h_EventReport, 1);

union c2h_SysInfo {
	struct {
		u64 opcode          :  6; /* NNP_IPC_C2H_OP_SYS_INFO */
		u64 reserved        :  58;
	};

	u64 value;
};
CHECK_MESSAGE_SIZE(union c2h_SysInfo, 1);

union h2c_QueryVersionMsg {
	struct {
		u64 opcode     :  6;   /* NNP_IPC_H2C_OP_QUERY_VERSION */
		u64 reserved   : 58;
	};

	u64 value;
};
CHECK_MESSAGE_SIZE(union h2c_QueryVersionMsg, 1);

#define NNP_NET_RESPONSE_POOL_INDEX 0

union ClockSyncMsg { //QUERY TIME
	struct {
		u64 opcode       : 6; /* NNP_IPC_H2C_OP_CLOCK_SYNC */
		u64 iteration    : 8;
		u64 reserved     : 50;
		u64 o_card_ts;
	};

	u64 value[2];
};
CHECK_MESSAGE_SIZE(union ClockSyncMsg, 2);

union h2c_setup_crash_dump_msg {
	struct {
		u64 opcode    :  6;   /* NNP_IPC_H2C_OP_SETUP_CRASH_DUMP */
		u64 reserved  :  13;
		/*dma_addr of the first page*/
		u64 dma_addr  : NNP_IPC_DMA_PFN_BITS;
		u64 membar_addr : 64;
	};

	u64 value[2];
};
CHECK_MESSAGE_SIZE(union h2c_setup_crash_dump_msg, 2);

union h2c_setup_sys_info_page {
	struct {
		u64 opcode    :  6;   /* NNP_IPC_H2C_OP_SETUP_SYS_INFO_PAGE */
		u64 reserved  :  13;
		u64 dma_addr  : NNP_IPC_DMA_PFN_BITS;
	};

	u64 value;
};
CHECK_MESSAGE_SIZE(union h2c_setup_sys_info_page, 1);

union h2c_ChannelOp {
	struct {
		u64 opcode         :  6;  /* NNP_IPC_H2C_OP_CHANNEL_OP */
		u64 protocolID     : NNP_IPC_CHANNEL_BITS;
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
		u64 opcode         :  6;  /* NNP_IPC_H2C_OP_CHANNEL_RB_OP */
		u64 chanID         : NNP_IPC_CHANNEL_BITS;
		u64 h2c            :  1;
		u64 rbID           :  1;
		u64 destroy        :  1;
		u64 hostPtr        : NNP_IPC_DMA_PFN_BITS;
	};

	u64 value;
};
CHECK_MESSAGE_SIZE(union h2c_ChannelDataRingbufOp, 1);

union h2c_ChannelHostresOp {
	struct {
		u64 opcode         :  6;  /* NNP_IPC_H2C_OP_CHANNEL_HOSTRES_OP */
		u64 chanID         : NNP_IPC_CHANNEL_BITS;
		u64 hostresID      : 16;
		u64 unmap          :  1;
		u64 reserved       : 31;

		u64 hostPtr        : NNP_IPC_DMA_PFN_BITS;
		u64 reserved2      : 19;
	};

	u64 value[2];
};
CHECK_MESSAGE_SIZE(union h2c_ChannelHostresOp, 2);

union h2c_P2PDev {
	struct {
		u64 opcode		: 6;  /* NNP_IPC_H2C_OP_P2P_DEV */
		u64 destroy		: 1;
		u64 dev_id		: 5;
		u64 is_producer		: 1;
		u64 db_addr		: 57;
		u64 cr_fifo_addr	: NNP_IPC_DMA_PFN_BITS;
		u64 reserved		: 13;
	};
	u64 value[2];
};
CHECK_MESSAGE_SIZE(union h2c_P2PDev, 2);

union h2c_PeerBuf {
	struct {
		u64 opcode     :  6;  /* NNP_IPC_H2C_OP_PEER_BUF */
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

union ClockStampMsg { //QUERY TIME
	struct {
		u8 opcode : 6; /* NNP_IPC_H2C_OP_CLOCK_STAMP */
		u8 unused : 2;
		u8 i_type[7];
		u64 i_clock;
	};

	u64 value[2];
};
CHECK_MESSAGE_SIZE(union ClockStampMsg, 2);

/***************************************************************************
 * IPC messages opcodes and related utility macros
 ***************************************************************************/
#define H2C_OPCODE_NAME(name)          NNP_IPC_H2C_OP_ ## name
#define H2C_OPCODE_NAME_STR(name)      #name
#define C2H_OPCODE_NAME(name)          NNP_IPC_C2H_OP_ ## name
#define C2H_OPCODE_NAME_STR(name)      #name
#define IPC_OPCODE_HANDLER(name) \
	__nnp_ipc_handler_ ## name
#define CALL_IPC_OPCODE_HANDLER(name, type, ctx, msg) \
	IPC_OPCODE_HANDLER(name)(ctx, (type *)(msg))

/***************************************************************************
 * Define Host-to-card opcodes  (valid range is 0 - 31)
 ***************************************************************************/
enum nnp_h2c_opcodes {
	H2C_OPCODE_NAME(QUERY_VERSION)       = 0,
	H2C_OPCODE_NAME(CLOCK_STAMP)         = 2,
	H2C_OPCODE_NAME(SETUP_CRASH_DUMP)    = 6,
	H2C_OPCODE_NAME(SETUP_SYS_INFO_PAGE) = 7,
	H2C_OPCODE_NAME(CLOCK_SYNC)          = 15,
	H2C_OPCODE_NAME(CHANNEL_OP)          = 22,
	H2C_OPCODE_NAME(CHANNEL_RB_OP)       = 23,
	H2C_OPCODE_NAME(CHANNEL_HOSTRES_OP)  = 24,

	H2C_OPCODE_NAME(BIOS_PROTOCOL)       = 31,
	H2C_OPCODE_NAME(LAST)                = NNP_IPC_H2C_OP_BIOS_PROTOCOL
};

/***************************************************************************
 * Define Card-to-host opcodes
 ***************************************************************************/
enum nnp_c2h_opcodes {
	NNP_IPC_C2H_OP_QUERY_VERSION_REPLY  = 0,
	NNP_IPC_C2H_OP_QUERY_VERSION_REPLY2 = 1,
	NNP_IPC_C2H_OP_EVENT_REPORT         = 4,
	NNP_IPC_C2H_OP_CLOCK_SYNC           = 9,
	NNP_IPC_C2H_OP_SYS_INFO             = 11,

	NNP_IPC_C2H_OP_BIOS_PROTOCOL        = 31,
	NNP_IPC_C2H_OPCODE_LAST             = NNP_IPC_C2H_OP_BIOS_PROTOCOL
};

/***************************************************************************
 * IPC messages protocol between the host driver and BIOS
 ***************************************************************************/

enum nnp_bios_c2h_msg_types {
	NNP_IPC_C2H_TYPE_BIOS_VERSION  = 0x1
};

enum nnp_bios_h2c_msg_types {
	NNP_IPC_H2C_TYPE_BOOT_IMAGE_READY  = 0x10,
	NNP_IPC_H2C_TYPE_SYSTEM_INFO_REQ   = 0x11
};

union nnp_bios_ipc_header {
	struct {
		u64 opcode       :  6;  // NNP_IPC_C2H_OP_BIOS_PROTOCOL
		u64 reserved1    :  2;
		u64 msgType      :  8;  // bios message type
		u64 size         : 16;  // message size in bytes
		u64 reserved2    : 32;
	};

	u64 value;
};
CHECK_MESSAGE_SIZE(union nnp_bios_ipc_header, 1);

struct nnp_c2h_bios_version {
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

struct nnp_c2h_bios_fw_ver_ack_data {
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

struct nnp_c2h_fw_version {
	u16  Major;
	u16  Minor;
	u16  Hotfix;
	u16  Build;
};

struct nnp_c2h_cpu_info {
	u32 CpuFamily;      // for SPH = LceLake AIPG = 0x000906D0
	u8  CpuStepping;    // CPU Stepping
	u8  CpuSku;         // CPU SKU
	u16 CpuDid;         // for SPH range 0x4580-0x45FF (depends on CPU SKU)
	u16 CpuCoreCount;   // Number of enabled cores
	u16 CpuThreadCount; // Number of threads
};

struct nnp_c2h_ice_info {
	u16 IceCount;
	u32 IceAvaliableMask;
};

struct nnp_c2h_system_info {
	u8  Version; // SPH_SYSTEM_INFO structure version
	u16 BoardID; // Board identification- for SPH RVP = 0x25
	u8  FabID;   // Board Revision identification
	u8  BomID;   // Board Bill Of Material identification
	u8  PlatformType;   // For SPH RVP= 0x2, SPH M.2 = 0x3
	u8  PlatformFlavor; // For SPH = 0x5- Embedded
	struct nnp_c2h_cpu_info CpuInfo; // CPU Information
	struct nnp_c2h_ice_info IceInfo; // ICE Information
	struct nnp_c2h_bios_version BiosVer; // BIOS version string - BIOS Revision Identification Specification", Rev. 2.0, 01/30/2015
	//PcodeRevision; // Pcode revision information
	struct nnp_c2h_bios_fw_ver_ack_data CsmeVersion;
	struct nnp_c2h_fw_version PmcVersion;
};

/*
 * this is the structure needed to be sent to the command h/w q when
 * a boot or bios image is loaded and ready in memory
 */
union h2c_BootImageReady {
	struct {
		u64 opcode          :  6;  // NNP_IPC_C2H_OP_BIOS_PROTOCOL
		u64 reserved1       :  2;
		u64 msgType         :  8;  // NNP_IPC_H2C_TYPE_BOOT_IMAGE_READY
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
		u64 opcode          :  6;  // NNP_IPC_C2H_OP_BIOS_PROTOCOL
		u64 reserved1       :  2;
		u64 msgType         :  8;  // NNP_IPC_H2C_TYPE_SYSTEM_INFO_REQ
		u64 size            : 16;  // message size in bytes
		u64 reserved2       : 32;
		u64 sysinfo_addr    : 64;
		u32 sysinfo_size    : 32;
		u32 reserved3       : 32;
	};

	u64 value[3];
};
CHECK_MESSAGE_SIZE(union h2c_BiosSystemInfoReq, 3);

#define NNP_BIOS_VERSION_LEN    (sizeof(struct nnp_c2h_bios_version) / sizeof(u16))
#define NNP_BOARD_NAME_LEN      72
#define NNP_IMAGE_VERSION_LEN   128
#define NNP_PRD_SERIAL_LEN      16
#define NNP_PART_NUM_LEN        12

struct nnp_sys_info {
	uint32_t ice_mask;
	char bios_version[NNP_BIOS_VERSION_LEN];
	char board_name[NNP_BOARD_NAME_LEN];
	char image_version[NNP_IMAGE_VERSION_LEN];
	char prd_serial[NNP_PRD_SERIAL_LEN];
	char brd_part_no[NNP_PART_NUM_LEN];
	u16  fpga_rev;
	uint64_t totalUnprotectedMemory;
	uint64_t totalEccMemory;
	u8 stepping;
};

/*************************************************
 * Define header structure for all "channel" message protocols.
 * This protocol defines communication between host UMD and card.
 **************************************************/
union h2c_ChanMsgHeader {
	struct {
		u64 opcode		: 6;
		u64 chanID              : NNP_IPC_CHANNEL_BITS;
		u64 reserved            : 48;
	};

	u64 value;
};

union c2h_ChanMsgHeader {
	struct {
		u64 opcode		: 6;
		u64 chanID              : NNP_IPC_CHANNEL_BITS;
		u64 reserved            : 48;
	};

	u64 value;
};

#pragma pack(pop)

#endif
