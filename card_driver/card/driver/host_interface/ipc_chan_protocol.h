/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/
#ifndef _IPC_CHAN_PROTOCOL_H
#define _IPC_CHAN_PROTOCOL_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdbool.h>
#endif
#include "ipc_protocol.h"

#define NNP_IPC_CHAN_PROTOCOL_VERSION NNP_MAKE_VERSION(1, 1, 0)

#define NNP_IPC_GENMSG_BAD_CLIENT_ID   0xFFF

#define NNP_IPC_INF_CMDS_BITS 16  /* number of bits in protocol for device resource */
#define NNP_IPC_INF_DEVRES_BITS 16  /* number of bits in protocol for device resource */
#define NNP_IPC_INF_DEVNET_BITS 16  /* number of bits in protocol for device network */
#define NNP_IPC_INF_COPY_BITS 16    /* number of bits in protocol for copy handler */
#define NNP_IPC_INF_REQ_BITS 16     /* number of bits in protocol for inf req */
#define NNP_NET_SKB_HANDLE_BITS  8   /* number of bits for skb handle in eth protocol */

//
// Command type codes used in command list elements
//
enum CmdListCommandType {
	CMDLIST_CMD_INFREQ   = 0,
	CMDLIST_CMD_COPY     = 1,
	CMDLIST_CMD_COPYLIST = 2
};

/**
 * @brief Network properties
 */
enum  netPropertiesType {
	NNP_SERIAL_INF_EXECUTION,    /**< Serial inference execution */
	NNP_NETWORK_RESOURCES_RESERVATION /**< Network resources reservation */
};

#pragma pack(push, 1)

//
// Command execution error list buffer sent from card to host
// is an array of ipc_exec_error_desc, where error_msg_size bytes of
// the error message follows each element.
//
struct ipc_exec_error_desc {
	uint8_t                 cmd_type;
	uint16_t                obj_id;
	uint16_t                devnet_id;
	uint16_t                eventVal;
	uint32_t                error_msg_size;
};

/***************************************************************************
 * IPC messages layout definition
 *    All messages must start with opcode and chanID as defined by:
 *    union h2c_ChanMsgHeader / union c2h_ChanMsgHeader
 ***************************************************************************/
union h2c_ChanRingBufUpdate {
	struct {
		u64 opcode		: 6; /* NNP_IPC_H2C_OP_CHANNEL_RB_UPDATE */
		u64 chanID              : NNP_IPC_CHANNEL_BITS;
		u64 rbID                :  1;
		u64 reserved            : 15;
		u32 size                : 32;
	};

	u64 value;
};
CHECK_MESSAGE_SIZE(union h2c_ChanRingBufUpdate, 1);

union h2c_ChanGenericMessaging {
	struct {
		u64 opcode          :  6;   /* NNP_IPC_H2C_OP_CHAN_GENERIC_MSG_PACKET */
		u64 chanID          : NNP_IPC_CHANNEL_BITS;
		u64 rbID            :  1;
		u64 connect         :  1;
		u64 hangup          :  1;
		u64 service_list_req:  1;
		u64 size            : 12;
		u64 card_client_id  : 12;
		u64 reserved        : 20;
	};

	u64 value;
};
CHECK_MESSAGE_SIZE(union h2c_ChanGenericMessaging, 1);

union h2c_ChanInferenceContextOp {
	struct {
		u64 opcode     : 6;  /* NNP_IPC_H2C_OP_CHAN_INF_CONTEXT */
		u64 chanID     : NNP_IPC_CHANNEL_BITS;
		u64 rbID       : 1;
		u64 destroy    : 1;
		u64 recover    : 1;
		u64 cflags     : 8;
		u64 reserved   :37;
	};

	u64 value;
};
CHECK_MESSAGE_SIZE(union h2c_ChanInferenceContextOp, 1);

union h2c_ChanInferenceResourceOp {
	struct {
		u64 opcode      : 6;  /* NNP_IPC_H2C_OP_CHAN_INF_RESOURCE */
		u64 chanID      : NNP_IPC_CHANNEL_BITS;
		u64 rbID        : 1;
		u64 resID       : NNP_IPC_INF_DEVRES_BITS;
		u64 destroy     : 1;
		u64 is_input    : 1;
		u64 is_output   : 1;

		u64 is_network  : 1;
		u64 is_force_4G : 1;
		u64 is_ecc      : 1;
		u64 is_p2p_dst  : 1;
		u64 is_p2p_src  : 1;
		u64 depth       : 7;
		u64 align       : 16;

		u64 size        : 64;
	};

	u64 value[2];
};
CHECK_MESSAGE_SIZE(union h2c_ChanInferenceResourceOp, 2);

union h2c_ChanMarkInferenceResource {
	struct {
		u64 opcode      : 6;  /* NNP_IPC_H2C_OP_CHAN_MARK_INF_RESOURCE */
		u64 chanID      : NNP_IPC_CHANNEL_BITS;
		u64 resID       : NNP_IPC_INF_DEVRES_BITS;
		u64 reserved    : 32;
	};

	u64 value;
};
CHECK_MESSAGE_SIZE(union h2c_ChanMarkInferenceResource, 1);

union h2c_ChanInferenceCopyOp {
	struct {
		u64 opcode     :  6;  /* NNP_IPC_H2C_OP_CHAN_COPY_OP */
		u64 chanID     : NNP_IPC_CHANNEL_BITS;
		u64 protResID  : 16;
		u64 protCopyID : 16;
		u64 d2d        :  1;
		u64 c2h        :  1; /* if d2d = 0, c2h defines the copy direction */
		u64 destroy    :  1;
		u64 hostres    : NNP_IPC_DMA_PFN_BITS;
		u64 subres_copy : 1;
		u64 reserved2  : 18;
	};

	u64 value[2];
};
CHECK_MESSAGE_SIZE(union h2c_ChanInferenceCopyOp, 2);

union h2c_ChanInferenceSchedCopy {
	struct {
		u64 opcode     : 6;  /* NNP_IPC_H2C_OP_CHAN_SCHEDULE_COPY */
		u64 chanID     : NNP_IPC_CHANNEL_BITS;
		u64 protCopyID : 16;
		u64 copySize   : 30;
		u64 priority   : 2;  /* TBD: change back to 3 in new proto */
	};

	u64 value;
};
CHECK_MESSAGE_SIZE(union h2c_ChanInferenceSchedCopy, 1);

union h2c_ChanInferenceSchedCopyLarge {
	struct {
		u64 opcode     : 6;  /* NNP_IPC_H2C_OP_CHAN_SCHEDULE_COPY_LARGE */
		u64 chanID     : NNP_IPC_CHANNEL_BITS;
		u64 protCopyID : 16;
		u64 priority   : 8;  /* TBD: change back to 3 in new proto */
		u64 reserved   : 24;

		u64 copySize   : 64;
	};

	u64 value[2];
};
CHECK_MESSAGE_SIZE(union h2c_ChanInferenceSchedCopyLarge, 2);

union h2c_ChanInferenceSchedCopySubres {
	struct {
		u64 opcode     : 6;  /* NNP_IPC_H2C_OP_CHAN_SCHEDULE_COPY_SUBRES */
		u64 chanID     : NNP_IPC_CHANNEL_BITS;
		u64 protCopyID : 16;
		u64 hostresID  : 16;
		u64 copySize   : 16;
		u64 dstOffset  : 64;
	};

	u64 value[2];
};
CHECK_MESSAGE_SIZE(union h2c_ChanInferenceSchedCopySubres, 2);

union h2c_ChanInferenceNetworkOp {
	struct {
		u64 opcode        : 6; /* NNP_IPC_H2C_OP_CHAN_INF_NETWORK */
		u64 chanID        : NNP_IPC_CHANNEL_BITS;
		u64 netID         : NNP_IPC_INF_DEVNET_BITS;
		u64 rbID          : 1;
		u64 destroy       : 1;
		u64 create        : 1;
		u64 num_res       :24;
		u64 reserved      : 5;

		u64 size          : 32;
		u64 start_res_idx : 24;
		u64 reserved2     :  7;
		u64 chained       : 1;
	};

	u64 value[2];
};
CHECK_MESSAGE_SIZE(union h2c_ChanInferenceNetworkOp, 2);

union h2c_ChanInferenceReqOp {
	struct {
		u64 opcode            :  6; /* NNP_IPC_H2C_OP_CHAN_INF_REQ_OP */
		u64 chanID            : NNP_IPC_CHANNEL_BITS;
		u64 netID             : NNP_IPC_INF_DEVNET_BITS;
		u64 infreqID          : NNP_IPC_INF_REQ_BITS;
		u64 size              : 12;
		u64 rbID              :  1;
		u64 destroy           :  1;
		u64 reserved1         :  2;
	};

	u64 value;
};
CHECK_MESSAGE_SIZE(union h2c_ChanInferenceReqOp, 1);

union h2c_ChanInferenceReqSchedule {
	struct {
		u64 opcode            :  6; /* NNP_IPC_H2C_OP_CHAN_SCHEDULE_INF_REQ */
		u64 chanID            : NNP_IPC_CHANNEL_BITS;
		u64 netID             : NNP_IPC_INF_DEVNET_BITS;
		u64 infreqID          : NNP_IPC_INF_REQ_BITS;
		u64 reserved          : 16;

		//schedParams
		u64 batchSize         : 16;
		u64 priority          :  8; /* 0 == normal, 1 == high */
		u64 debugOn           :  1;
		u64 collectInfo       :  1;
		u64 schedParamsIsNull :  1;
		u64 reserve           : 37;
	};

	u64 value[2];
};
CHECK_MESSAGE_SIZE(union h2c_ChanInferenceReqSchedule, 2);

union h2c_ChanSync {
	struct {
		u64 opcode      : 6; /* NNP_IPC_H2C_OP_CHAN_SYNC */
		u64 chanID      : NNP_IPC_CHANNEL_BITS;
		u32 syncSeq     : 16;
		u64 reserved    : 32;
	};

	u64 value;
};
CHECK_MESSAGE_SIZE(union h2c_ChanSync, 1);

union h2c_ChanInferenceNetworkSetProperty {
	struct {
		u64 opcode        : 6; /* NNP_IPC_H2C_OP_CHAN_NETWORK_PROPERTY */
		u64 chanID        : NNP_IPC_CHANNEL_BITS;
		u64 netID         : NNP_IPC_INF_DEVNET_BITS;
		u64 timeout       : 32;
		u64 property	  : 32;
		u64 property_val  : 32;
	};

	u64 value[2];
};
CHECK_MESSAGE_SIZE(union h2c_ChanInferenceNetworkSetProperty, 2);

union h2c_ChanInferenceCmdListOp {
	struct {
		u64 opcode      :  6;  /* NNP_IPC_H2C_OP_CHAN_INF_CMDLIST or
					* NNP_IPC_H2C_OP_CHAN_SCHEDULE_CMDLIST
					*/
		u64 chanID      : NNP_IPC_CHANNEL_BITS;
		u64 cmdID       : NNP_IPC_INF_CMDS_BITS;
		u64 destroy     :  1;
		u64 is_first    :  1;
		u64 is_last     :  1;
		u64 opt_dependencies : 1;
		u64 size        : 16;
		u64 unused      : 12;
	};

	u64 value;
};
CHECK_MESSAGE_SIZE(union h2c_ChanInferenceCmdListOp, 1);

union h2c_ExecErrorList {
	struct {
		u64 opcode      : 6; /* NNP_IPC_H2C_OP_CHAN_EXEC_ERROR_LIST */
		u64 chanID      : NNP_IPC_CHANNEL_BITS;
		u64 cmdID       : NNP_IPC_INF_CMDS_BITS;
		u64 cmdID_valid : 1;
		u64 clear       : 1;
		u64 reserved    : 30;
	};

	u64 value;
};
CHECK_MESSAGE_SIZE(union h2c_ExecErrorList, 1);

union h2c_ChanEthernetConfig {
	struct {
		u64 opcode      :  6; /* NNP_IPC_H2C_OP_CHAN_ETH_CONFIG */
		u64 chanID      : NNP_IPC_CHANNEL_BITS;
		u64 reserved    : 16;
		u64 card_ip     : 32;

		u64 reserved2   : 16;
		u64 card_mac    : 48;  // at value[10-15]
	};

	u8 value[16];
};
CHECK_MESSAGE_SIZE(union h2c_ChanEthernetConfig, 2);

union h2c_ChanEthernetMsgDscr {
	struct {
		u64 opcode      :  6; /* NNP_IPC_H2C_OP_CHAN_ETH_MSG_DSCR */
		u64 chanID      : NNP_IPC_CHANNEL_BITS;
		u64 size        : 12;
		u64 skb_handle : NNP_NET_SKB_HANDLE_BITS;
		u64 is_ack      :  1;
		u64 reserved    : 27;
	};

	u64 value;
};
CHECK_MESSAGE_SIZE(union h2c_ChanEthernetMsgDscr, 1);


union c2h_ChanRingBufUpdate {
	struct {
		u64 opcode		: 6; /* NNP_IPC_C2H_OP_CHANNEL_RB_UPDATE */
		u64 chanID              : NNP_IPC_CHANNEL_BITS;
		u64 rbID                :  1;
		u64 reserved            : 15;
		u32 size                : 32;
	};

	u64 value;
};
CHECK_MESSAGE_SIZE(union c2h_ChanRingBufUpdate, 1);

union c2h_ChanGenericMessaging {
	struct {
		u64 opcode          :  6; /* NNP_IPC_C2H_OP_CHAN_GENERIC_MSG_PACKET */
		u64 chanID          : NNP_IPC_CHANNEL_BITS;
		u64 rbID            :  1;
		u64 size            : 12;
		u64 connect         :  1;
		u64 no_such_service :  1;
		u64 hangup          :  1;
		u64 card_client_id  : 12;
		u64 reserved        : 18;
	};

	u64 value;
};
CHECK_MESSAGE_SIZE(union c2h_ChanGenericMessaging, 1);

union c2h_ChanServiceListMsg {
	struct {
		u64 opcode           :  6;   /* NNP_IPC_C2H_OP_CHAN_SERVICE_LIST */
		u64 chanID           : NNP_IPC_CHANNEL_BITS;
		u64 rbID             :  1;
		u64 failure          :  3;   /* 0=Valid 1=DmaFailed 2=PullFull 3=TooBig */
		u64 size             : 12;
		u64 num_services     : 32;
	};

	u64 value;
};
CHECK_MESSAGE_SIZE(union c2h_ChanServiceListMsg, 1);

union c2h_ChanSyncDone {
	struct {
		u64 opcode      : 6; /* NNP_IPC_C2H_OP_CHAN_SYNC_DONE */
		u64 chanID      : NNP_IPC_CHANNEL_BITS;
		u32 syncSeq     : 16;
		u64 reserved    : 32;
	};

	u64 value;
};
CHECK_MESSAGE_SIZE(union c2h_ChanSyncDone, 1);

union c2h_ChanInfReqFailed {
	struct {
		u64 opcode      : 6; /* NNP_IPC_C2H_OP_CHAN_INFREQ_FAILED */
		u64 chanID      : NNP_IPC_CHANNEL_BITS;
		u64 netID       : NNP_IPC_INF_DEVNET_BITS;
		u64 infreqID    : NNP_IPC_INF_REQ_BITS;
		u64 cmdID       : NNP_IPC_INF_CMDS_BITS;
		u64 reason      : 16;
		u64 cmdID_valid :  1;
		u64 reserved    : 47;
	};

	u64 value[2];
};
CHECK_MESSAGE_SIZE(union c2h_ChanInfReqFailed, 2);

union c2h_ExecErrorList {
	struct {
		u64 opcode      : 6; /* NNP_IPC_C2H_OP_CHAN_EXEC_ERROR_LIST */
		u64 chanID      : NNP_IPC_CHANNEL_BITS;
		u64 cmdID       : NNP_IPC_INF_CMDS_BITS;
		u64 cmdID_valid : 1;
		u64 clear_status: 2;
		u64 pkt_size    : 12;
		u64 total_size  : 16;  /* total buffer size of error eventVal if is_error */
		u64 is_error    : 1;
	};

	u64 value;
};
CHECK_MESSAGE_SIZE(union c2h_ExecErrorList, 1);

union c2h_ChanEthernetConfig {
	struct {
		u64 opcode      :  6; /* NNP_IPC_C2H_OP_CHAN_ETH_CONFIG */
		u64 chanID      : NNP_IPC_CHANNEL_BITS;
		u64 reserved    : 16;
		u64 card_ip	: 32;
	};

	u64 value;
};
CHECK_MESSAGE_SIZE(union c2h_ChanEthernetConfig, 1);

union c2h_ChanEthernetMsgDscr {
	struct {
		u64 opcode      :  6; /* NNP_IPC_C2H_OP_CHAN_ETH_MSG_DSCR */
		u64 chanID      : NNP_IPC_CHANNEL_BITS;
		u64 size        : 12;
		u64 skb_handle	: NNP_NET_SKB_HANDLE_BITS;
		u64 is_ack      :  1;
		u64 reserved    : 27;
	};

	u64 value;
};
CHECK_MESSAGE_SIZE(union c2h_ChanEthernetMsgDscr, 1);

union h2c_ChanHwTraceAddResource {
	struct {
		u64 opcode          : 6;  /* NNP_IPC_H2C_OP_CHAN_HWTRACE_ADD_RESOURCE */
		u64 chanID          : NNP_IPC_CHANNEL_BITS;
		u64 mapID           : 16;
		u64 resourceIndex   : 8;  /* resource index */
		u64 resource_size   : 32;
		u64 reserved	    : 56;
	};

	u64 value[2];
};
CHECK_MESSAGE_SIZE(union h2c_ChanHwTraceAddResource, 2);

union c2h_ChanHwTraceState {
	struct {
		u64 opcode		: 6;  /* NNP_IPC_C2H_OP_CHAN_HWTRACE_STATE */
		u64 chanID              : NNP_IPC_CHANNEL_BITS;
		u64 subOpcode		: 5;
		u64 val1		: 32;
		u64 val2		: 8;
		u64 val3		: 32;
		u64 err			: 8;
		u64 reserved		: 27;
	};

	u64 value[2];
};
CHECK_MESSAGE_SIZE(union c2h_ChanHwTraceState, 2);

union h2c_ChanHwTraceState {
	struct {
		u64 opcode		: 6;  /* NNP_IPC_H2C_OP_CHAN_HWTRACE_STATE */
		u64 chanID              : NNP_IPC_CHANNEL_BITS;
		u64 reserved		: 11;
		u64 subOpcode		: 5;
		u64 val			: 32;
	};

	u64 value;
};
CHECK_MESSAGE_SIZE(union h2c_ChanHwTraceState, 1);

union h2c_ChanGetCrFIFO {
	struct {
		u64 opcode      : 6;  /* NNP_IPC_H2C_OP_CHAN_GET_CR_FIFO */
		u64 chanID      : NNP_IPC_CHANNEL_BITS;
		u64 p2p_tr_id   : 16;
		u64 peer_id     : 5;
		u64 fw_fifo     : 1;/* fw fifo or relase fifo */
		u64 reserved    : 26;
	};

	u64 value;
};
CHECK_MESSAGE_SIZE(union h2c_ChanGetCrFIFO, 1);

union h2c_ChanConnectPeers {
	struct {
		u64 opcode      : 6;  /* NNP_IPC_H2C_OP_CHAN_P2P_CONNECT_PEERS */
		u64 chanID      : NNP_IPC_CHANNEL_BITS;
		u64 p2p_tr_id   : 16;
		u64 buf_id      : 8;
		u64 is_src_buf  : 1;
		u64 peer_dev_id : 5;
		u64 peer_buf_id : 8;
		u64 reserved    : 10;
	};

	u64 value;
};
CHECK_MESSAGE_SIZE(union h2c_ChanGetCrFIFO, 1);

union h2c_ChanUpdatePeerDev {
	struct {
		u64 opcode		: 6;  /* NNP_IPC_H2C_OP_CHAN_P2P_UPDATE_PEER_DEV */
		u64 chanID		: NNP_IPC_CHANNEL_BITS;
		u64 p2p_tr_id		: 16;
		u64 dev_id		: 5;
		u64 is_producer		: 1;
		u64 db_addr		: 57;
		u64 cr_fifo_addr	: NNP_IPC_DMA_PFN_BITS;
		u64 reserved		: 52;
	};
	u64 value[3];
};
CHECK_MESSAGE_SIZE(union h2c_ChanUpdatePeerDev, 3);

#define USER_DATA_MAX_KEY_SIZE 6
union h2c_ChanTraceUserData {
	struct {
		u64 opcode		: 6;  /* NNP_IPC_H2C_OP_CHAN_TRACE_USER_DATA */
		u64 chanID		: NNP_IPC_CHANNEL_BITS;
		u64 key			: USER_DATA_MAX_KEY_SIZE * 8;

		u64 user_data;
	};
	u64 value[2];
};
CHECK_MESSAGE_SIZE(union h2c_ChanTraceUserData, 2);

enum InfContextObjType {
	INF_OBJ_TYPE_CONTEXT = 0,
	INF_OBJ_TYPE_DEVRES,
	INF_OBJ_TYPE_COPY,
	INF_OBJ_TYPE_DEVNET,
	INF_OBJ_TYPE_INFREQ,
	INF_OBJ_TYPE_CMD,
	INF_OBJ_TYPE_P2P,
	INF_OBJ_TYPE_INVALID_OBJ_TYPE = 99
};

union h2c_ChanIdsMap {
	struct {
		u64 opcode		: 6;  /* NNP_IPC_H2C_OP_CHAN_IDS_MAP */
		u64 chanID		: NNP_IPC_CHANNEL_BITS;
		u64 objType		: 16; //InfContextObjType
		u64 val1		: NNP_IPC_INF_DEVNET_BITS;
		u64 val2		: NNP_IPC_INF_DEVNET_BITS;

		u64 user_handle;
	};
	u64 value[2];
};
CHECK_MESSAGE_SIZE(union h2c_ChanIdsMap, 2);

#ifdef ULT
union ult2_message {
	struct {
		u64 opcode       :  6;    /* SPH_IPC_ULT2_OP */
		u64 channelID    : NNP_IPC_CHANNEL_BITS;
		u64 ultOpcode    :  4;
		u64 reserved     : 44;
	};

	u64 value;
};
CHECK_MESSAGE_SIZE(union ult2_message, 1);
#endif

#define H2C_OPCODE(name, val, type)    H2C_OPCODE_NAME(name) = (val), /* SPH_IGNORE_STYLE_CHECK */
enum nnp_chan_h2c_opcode {
	#include "ipc_chan_h2c_opcodes.h"
};
#undef H2C_OPCODE


#define C2H_OPCODE(name, val, type)    C2H_OPCODE_NAME(name) = (val),  /* SPH_IGNORE_STYLE_CHECK */
enum nnp_chan_c2h_opcode {
	#include "ipc_chan_c2h_opcodes.h"
};
#undef C2H_OPCODE

/* Check that all opcodes are within 6 bits range */
#define H2C_OPCODE(name, val, type)    NNP_STATIC_ASSERT((val) < 64, "opcode " #name " range overflow"); /* SPH_IGNORE_STYLE_CHECK */
#define C2H_OPCODE(name, val, type)    NNP_STATIC_ASSERT((val) >= 32 && (val) < 64, "opcode " #name " range overflow"); /* SPH_IGNORE_STYLE_CHECK */
#include "ipc_chan_h2c_opcodes.h"
#include "ipc_chan_c2h_opcodes.h"
#undef H2C_OPCODE
#undef C2H_OPCODE

/* Check that all c2h messages size is max of 3*u64 */
#define C2H_OPCODE(name, val, type)  NNP_STATIC_ASSERT(sizeof(type) <= sizeof(u64)*3, "Size of " #type " Must be LE 3*64!!"); /* SPH_IGNORE_STYLE_CHECK */
#include "ipc_chan_c2h_opcodes.h"
#undef C2H_OPCODE

#pragma pack(pop)

#endif

