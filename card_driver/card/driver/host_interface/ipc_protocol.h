/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/
#ifndef _IPC_PROTOCOL_H
#define _IPC_PROTOCOL_H

#include <linux/types.h>

#ifdef __KERNEL__
#include <linux/dma-mapping.h>
#include "nnp_debug.h"
#include "ipc_c2h_events.h"
#include "nnp_inbound_mem.h"

#define CHECK_MESSAGE_SIZE(t, n_qw) \
	NNP_STATIC_ASSERT(sizeof(t) == sizeof(__le64) * (n_qw), \
			  "Size of " #t " Does not match!!")
#else
#define CHECK_MESSAGE_SIZE(t, n_qw)
#define NNP_STATIC_ASSERT(cond, msg)
#define BIT(x) (1u << (x))
#endif

#define IPC_OP_MAX 64
#define NNP_IPC_OPCODE_MASK (IPC_OP_MAX - 1)

#define NNP_MSG_SIZE(msg) (sizeof(msg) / sizeof(__le64))
/*
 * We use 4096 since host and card can use different PAGE_SIZE.
 * Possible improvement might be to negotiate PAGE_SIZE with card during startup
 * and pick smallest size to be used by both sides
 */
#ifndef NNP_PAGE_SHIFT
#define NNP_PAGE_SHIFT 12
#endif
#define NNP_PAGE_SIZE BIT(NNP_PAGE_SHIFT)

NNP_STATIC_ASSERT(NNP_PAGE_SHIFT <= PAGE_SHIFT,
		  "NNP_PAGE_SIZE is bigger than PAGE_SIZE");

#define NNP_VERSION_MAJOR(ver) (((ver) >> 10) & 0x1f)
#define NNP_VERSION_MINOR(ver) (((ver) >> 5) & 0x1f)
#define NNP_VERSION_DOT(ver) ((ver) & 0x1f)
#define NNP_MAKE_VERSION(major, minor, dot) (((major) & 0x1f) << 10 | \
					     ((minor) & 0x1f) << 5 | \
					     ((dot) & 0x1f))

#define NNP_IPC_PROTOCOL_VERSION NNP_MAKE_VERSION(4, 1, 0)

#define NNP_IPC_DMA_PFN_BITS    45   /* size of physical address in protocol */
#define NNP_DMA_ADDR_ALIGN_BITS NNP_PAGE_SHIFT
#define NNP_IPC_DMA_PFN_MASK         (((1ULL) << NNP_IPC_DMA_PFN_BITS) - 1)
#define NNP_IPC_DMA_ADDR_ALIGN_MASK    \
	(((1ULL) << NNP_DMA_ADDR_ALIGN_BITS) - 1)
#define NNP_IPC_DMA_ADDR_TO_PFN(dma_adr)  \
	(((dma_adr) >> NNP_DMA_ADDR_ALIGN_BITS) & NNP_IPC_DMA_PFN_MASK)
#define NNP_IPC_DMA_PFN_TO_ADDR(dma_pfn)  \
	(((__le64)(dma_pfn)) << NNP_DMA_ADDR_ALIGN_BITS)

#define NNP_IPC_INF_CONTEXT_BITS 8
#define NNP_IPC_CHANNEL_BITS     10
#define NNP_IPC_MAX_CHANNEL_RB   2

#pragma pack(push, 1)

/***************************************************************************
 * Structures used inside data packets transferred in the protocol
 ***************************************************************************/
struct dma_chain_header {
	__le64 dma_next;
	__le32 total_nents;
	__le32 start_offset;
	__le64 size;
};

#define DMA_CHAIN_ENTRY_NPAGES_BITS \
	(sizeof(__le64) * __CHAR_BIT__ - NNP_IPC_DMA_PFN_BITS)
#define NNP_MAX_CHUNK_SIZE \
	(((1lu << DMA_CHAIN_ENTRY_NPAGES_BITS) - 1) << NNP_PAGE_SHIFT)

struct dma_chain_entry {
	__le64 dma_chunk_pfn  : NNP_IPC_DMA_PFN_BITS;
	__le64 n_pages        : DMA_CHAIN_ENTRY_NPAGES_BITS;
};

#define NENTS_PER_PAGE ((NNP_PAGE_SIZE - sizeof(struct dma_chain_header)) / \
			sizeof(struct dma_chain_entry))

/***************************************************************************
 * IPC messages layout definition
 ***************************************************************************/
/* NNP_IPC_C2H_OP_QUERY_VERSION_REPLY */
union c2h_query_version_reply_msg {
	struct {
		__le64 opcode          :  6;
		__le64 protocolversion : 16;
		__le64 fw_version       : 16;
		__le64 chan_protocol_ver : 16;
		__le64 reserved        : 10;
	};

	__le64 value;
};

CHECK_MESSAGE_SIZE(union c2h_query_version_reply_msg, 1);

/* NNP_IPC_C2H_OP_QUERY_VERSION_REPLY2 */
union c2h_query_version_reply2_msg {
	struct {
		__le64 opcode          :  6;
		__le64 protocolversion : 16;
		__le64 fw_version       : 16;
		__le64 chan_protocol_ver : 16;
		__le64 reserved        : 10;

		/*
		 * two bits for each possible response opcode
		 * specifying its size
		 */
		__le64 chan_resp_op_size  : 64;
	};

	__le64 value[2];
};

CHECK_MESSAGE_SIZE(union c2h_query_version_reply2_msg, 2);

/* NNP_IPC_C2H_OP_QUERY_VERSION_REPLY3 */
union c2h_query_version_reply3_msg {
	struct {
		__le64 opcode          :  6;
		__le64 protocolversion : 16;
		__le64 fw_version       : 16;
		__le64 chan_protocol_ver : 16;
		__le64 reserved        : 10;

		/*
		 * two bits for each possible response opcode
		 * specifying its size
		 */
		__le64 chan_resp_op_size  : 64;

		/*
		 * two bits for each possible command opcode
		 * specifying its size
		 */
		__le64 chan_cmd_op_size   : 64;
	};

	__le64 value[3];
};

CHECK_MESSAGE_SIZE(union c2h_query_version_reply3_msg, 3);

/* NNP_IPC_C2H_OP_EVENT_REPORT */
union c2h_event_report {
	struct {
		__le32 opcode     :  6;
		__le32 event_code  :  7;
		__le32 context_id  : NNP_IPC_INF_CONTEXT_BITS;
		__le32 obj_id      : 16;/* devres, infreq, copy */
		__le32 obj_id_2    : 16;/* devnet, cmdlist */
		__le32 event_val   :  8;
		__le32 ctx_valid   :  1;
		__le32 obj_valid   :  1;
		__le32 obj_valid_2 :  1;
	};
	__le64 value;
};

CHECK_MESSAGE_SIZE(union c2h_event_report, 1);

/* NNP_IPC_C2H_OP_SYS_INFO */
union c2h_sys_info {
	struct {
		__le64 opcode          :  6;
		__le64 reserved        :  58;
	};

	__le64 value;
};

CHECK_MESSAGE_SIZE(union c2h_sys_info, 1);

/* NNP_IPC_H2C_OP_QUERY_VERSION */
union h2c_query_version_msg {
	struct {
		__le64 opcode     :  6;
		__le64 reserved   : 58;
	};

	__le64 value;
};

CHECK_MESSAGE_SIZE(union h2c_query_version_msg, 1);

#define NNP_NET_RESPONSE_POOL_INDEX 0

/* NNP_IPC_H2C_OP_SETUP_CRASH_DUMP */
union h2c_setup_crash_dump_msg {
	struct {
		__le64 opcode    :  6;
		__le64 reserved  :  13;
		/*dma_addr of the first page*/
		__le64 dma_addr  : NNP_IPC_DMA_PFN_BITS;
		__le64 membar_addr : 64;
	};

	__le64 value[2];
};

CHECK_MESSAGE_SIZE(union h2c_setup_crash_dump_msg, 2);

/* NNP_IPC_H2C_OP_SETUP_SYS_INFO_PAGE */
union h2c_setup_sys_info_page {
	struct {
		__le64 opcode    :  6;
		__le64 num_page  :  10;
		__le64 reserved  :  3;
		__le64 dma_addr  : NNP_IPC_DMA_PFN_BITS;
	};

	__le64 value;
};

CHECK_MESSAGE_SIZE(union h2c_setup_sys_info_page, 1);

/* NNP_IPC_H2C_OP_CHANNEL_OP */
union h2c_channel_op {
	struct {
		__le64 opcode         :  6;
		__le64 protocol_id     : NNP_IPC_CHANNEL_BITS;
		__le64 destroy        :  1;
		__le64 reserved       : 14;
		__le64 privileged     :  1;
		__le64 uid            : 32;
	};

	__le64 value;
};

CHECK_MESSAGE_SIZE(union h2c_channel_op, 1);

/* NNP_IPC_H2C_OP_CHANNEL_RB_OP */
union h2c_channel_data_ringbuf_op {
	struct {
		__le64 opcode         :  6;
		__le64 chan_id         : NNP_IPC_CHANNEL_BITS;
		__le64 h2c            :  1;
		__le64 rb_id           :  1;
		__le64 destroy        :  1;
		__le64 host_ptr        : NNP_IPC_DMA_PFN_BITS;
	};

	__le64 value;
};

CHECK_MESSAGE_SIZE(union h2c_channel_data_ringbuf_op, 1);

/* NNP_IPC_H2C_OP_CHANNEL_HOSTRES_OP */
union h2c_channel_hostres_op {
	struct {
		__le64 opcode         :  6;
		__le64 chan_id         : NNP_IPC_CHANNEL_BITS;
		__le64 hostres_id      : 16;
		__le64 unmap          :  1;
		__le64 reserved       : 31;

		__le64 host_ptr        : NNP_IPC_DMA_PFN_BITS;
		__le64 reserved2      : 19;
	};

	__le64 value[2];
};

CHECK_MESSAGE_SIZE(union h2c_channel_hostres_op, 2);

/* NNP_IPC_H2C_OP_P2P_DEV */
union h2c_p2_pdev {
	struct {
		__le64 opcode		: 6;
		__le64 destroy		: 1;
		__le64 dev_id		: 5;
		__le64 is_producer	: 1;
		__le64 db_addr		: 57;
		__le64 cr_fifo_addr	: NNP_IPC_DMA_PFN_BITS;
		__le64 reserved		: 13;
	};
	__le64 value[2];
};

CHECK_MESSAGE_SIZE(union h2c_p2_pdev, 2);

/* NNP_IPC_H2C_OP_PEER_BUF */
union h2c_peer_buf {
	struct {
		__le64 opcode     :  6;
		__le64 buf_id     :  5;
		__le64 is_src_buf :  1;
		__le64 dev_id     :  5;
		__le64 peer_buf_id:  5;
		__le64 destroy    :  1;
		__le64 reserved1  : 41;
	};

	__le64 value;
};

CHECK_MESSAGE_SIZE(union h2c_peer_buf, 1);

/* SPH_IPC_H2C_GET_CR_FIFO */
union h2c_get_cr_fifo {
	struct {
		__le64 opcode      : 6;
		__le64 tr_id       : 8;
		__le64 peer_id     : 5;
		__le64 fw_fifo     : 1;/* fw fifo or relase fifo */
		__le64 reserved    : 44;
	};

	__le64 value;
};

CHECK_MESSAGE_SIZE(union h2c_get_cr_fifo, 1);

/* NNP_IPC_H2C_OP_CLOCK_STAMP */
union clock_stamp_msg {
	struct {
		__u8 opcode : 6;
		__u8 unused : 2;
		__u8 i_type[7];
		__le64 i_clock;
	};

	__le64 value[2];
};

CHECK_MESSAGE_SIZE(union clock_stamp_msg, 2);

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
	NNP_IPC_C2H_OP_QUERY_VERSION_REPLY3 = 2,
	NNP_IPC_C2H_OP_EVENT_REPORT         = 4,
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

/* NNP_IPC_C2H_OP_BIOS_PROTOCOL */
union nnp_bios_ipc_header {
	struct {
		__le64 opcode       :  6;
		__le64 reserved1    :  2;
		__le64 msg_type      :  8;  /* bios message type */
		__le64 size         : 16;  /* message size in bytes */
		__le64 reserved2    : 32;
	};

	__le64 value;
};

CHECK_MESSAGE_SIZE(union nnp_bios_ipc_header, 1);

/* BIOS Revision Identification Specification, Rev. 2.0, 01/30/2015 */
struct nnp_c2h_bios_version {
	__le16 board_id[7];
	__le16 board_rev;
	__le16 dot1;
	__le16 board_ext[3];
	__le16 dot2;
	__le16 version_major[4];
	__le16 dot3;
	__le16 build_type;
	__le16 version_minor[2];
	__le16 dot4;
	__le16 time_stamp[10];
	__le16 null_terminator;
};

struct nnp_c2h_bios_fw_ver_ack_data {
	__le32  code_minor   : 16;
	__le32  code_major   : 16;
	__le32  code_build_no : 16;
	__le32  code_hot_fix  : 16;
	__le32  rcvyminor   : 16;
	__le32  rcvymajor   : 16;
	__le32  rcvybuildno : 16;
	__le32  rcvy_hot_fix  : 16;
	__le32  fitc_minor   : 16;
	__le32  fitc_major   : 16;
	__le32  fitcbuildno : 16;
	__le32  fitc_hot_fix  : 16;
};

struct nnp_c2h_fw_version {
	__le16  major;
	__le16  minor;
	__le16  hotfix;
	__le16  build;
};

struct nnp_c2h_cpu_info {
	__le32 cpu_family;      /* for SPH = LceLake AIPG = 0x000906D0 */
	__u8  cpu_stepping;    /* CPU Stepping */
	__u8  cpu_sku;         /* CPU SKU */
	__le16 cpu_did;         /* for SPH range 0x4580-0x45FF */
	__le16 cpu_core_count;   /* Number of enabled cores */
	__le16 cpu_thread_count; /* Number of threads */
};

struct nnp_c2h_ice_info {
	__le16 ice_count;
	__le32 ice_available_mask;
};

struct nnp_c2h_system_info {
	__u8  version; /* SPH_SYSTEM_INFO structure version */
	__le16 board_id; /* Board identification- for SPH RVP = 0x25 */
	__u8  fab_id;   /* Board Revision identification */
	__u8  bom_id;   /* Board Bill Of Material identification */
	__u8  platform_type;   /* For SPH RVP= 0x2, SPH M.2 = 0x3 */
	__u8  platform_flavor; /* For SPH = 0x5- Embedded */
	struct nnp_c2h_cpu_info cpu_info; /* CPU Information */
	struct nnp_c2h_ice_info ice_info; /* ICE Information */
	struct nnp_c2h_bios_version bios_ver; /* BIOS version string */
	struct nnp_c2h_bios_fw_ver_ack_data csme_version;
	struct nnp_c2h_fw_version pmc_version;
};

/*
 * this is the structure needed to be sent to the command h/w q when
 * a boot or bios image is loaded and ready in memory
 */
union h2c_boot_image_ready {
	struct {
		/* NNP_IPC_C2H_OP_BIOS_PROTOCOL */
		__le64 opcode          :  6;
		__le64 reserved1       :  2;
		/* NNP_IPC_H2C_TYPE_BOOT_IMAGE_READY */
		__le64 msg_type         :  8;
		/* message size in bytes */
		__le64 size            : 16;
		__le64 reserved2       : 32;
		__le64 descriptor_addr : 64;
		__le32 descriptor_size : 32;
		__le32 image_size      : 32;
	};

	__le64 value[3];
};

CHECK_MESSAGE_SIZE(union h2c_boot_image_ready, 3);

union h2c_bios_system_info_req {
	struct {
		/* NNP_IPC_C2H_OP_BIOS_PROTOCOL */
		__le64 opcode          :  6;
		__le64 reserved1       :  2;
		/* NNP_IPC_H2C_TYPE_SYSTEM_INFO_REQ */
		__le64 msg_type         :  8;
		/* message size in bytes */
		__le64 size            : 16;
		__le64 reserved2       : 32;
		__le64 sysinfo_addr    : 64;
		__le32 sysinfo_size    : 32;
		__le32 reserved3       : 32;
	};

	__le64 value[3];
};

CHECK_MESSAGE_SIZE(union h2c_bios_system_info_req, 3);

#define NNP_BIOS_VERSION_LEN    (sizeof(struct nnp_c2h_bios_version) / \
				 sizeof(__le16))
#define NNP_BOARD_NAME_LEN      72
#define NNP_IMAGE_VERSION_LEN   128
#define NNP_PRD_SERIAL_LEN      16
#define NNP_PART_NUM_LEN        12

struct nnp_sys_info {
	__le32 ice_mask;
	char bios_version[NNP_BIOS_VERSION_LEN];
	char board_name[NNP_BOARD_NAME_LEN];
	char image_version[NNP_IMAGE_VERSION_LEN];
	char prd_serial[NNP_PRD_SERIAL_LEN];
	char brd_part_no[NNP_PART_NUM_LEN];
	__le16  fpga_rev;
	__le64 total_unprotected_memory;
	__le64 total_ecc_memory;
	__u8 stepping;
};

/*************************************************
 * Define header structure for all "channel" message protocols.
 * This protocol defines communication between host UMD and card.
 **************************************************/
union h2c_chan_msg_header {
	struct {
		__le64 opcode		: 6;
		__le64 chan_id           : NNP_IPC_CHANNEL_BITS;
		__le64 reserved         : 48;
	};

	__le64 value;
};

union c2h_chan_msg_header {
	struct {
		__le64 opcode		: 6;
		__le64 chan_id           : NNP_IPC_CHANNEL_BITS;
		__le64 reserved         : 48;
	};

	__le64 value;
};

#pragma pack(pop)

#endif
