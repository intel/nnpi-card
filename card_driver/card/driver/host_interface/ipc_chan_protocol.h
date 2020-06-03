/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/
#ifndef _IPC_CHAN_PROTOCOL_H
#define _IPC_CHAN_PROTOCOL_H

#include <linux/types.h>
#include "ipc_protocol.h"

#define NNP_IPC_CHAN_PROTOCOL_VERSION NNP_MAKE_VERSION(1, 3, 0)

#define NNP_IPC_GENMSG_BAD_CLIENT_ID   0xFFF

#define NNP_IPC_INF_CMDS_BITS 16  /* number of bits in protocol for device resource */
#define NNP_IPC_INF_DEVRES_BITS 16  /* number of bits in protocol for device resource */
#define NNP_IPC_INF_DEVNET_BITS 16  /* number of bits in protocol for device network */
#define NNP_IPC_INF_COPY_BITS 16    /* number of bits in protocol for copy handler */
#define NNP_IPC_INF_REQ_BITS 16     /* number of bits in protocol for inf req */
#define NNP_NET_SKB_HANDLE_BITS  8   /* number of bits for skb handle in eth protocol */
#define NNP_IPC_MAX_CHANNEL_RINGBUFS 2 /* maximum number of data ring buffers for each channel (per-direction) */

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
	__u8                 cmd_type;
	__le16               obj_id;
	__le16               devnet_id;
	__le16               event_val;
	__le32               error_msg_size;
};

/***************************************************************************
 * IPC messages layout definition
 *    All messages must start with opcode and chan_id as defined by:
 *    union h2c_chan_msg_header / union c2h_chan_msg_header
 ***************************************************************************/
union h2c_ChanRingBufUpdate {
	struct {
		__le64 opcode		: 6; /* NNP_IPC_H2C_OP_CHANNEL_RB_UPDATE */
		__le64 chan_id              : NNP_IPC_CHANNEL_BITS;
		__le64 rb_id                :  1;
		__le64 reserved            : 15;
		__le32 size                : 32;
	};

	__le64 value;
};
CHECK_MESSAGE_SIZE(union h2c_ChanRingBufUpdate, 1);

union h2c_ChanGenericMessaging {
	struct {
		__le64 opcode          :  6;   /* NNP_IPC_H2C_OP_CHAN_GENERIC_MSG_PACKET */
		__le64 chan_id          : NNP_IPC_CHANNEL_BITS;
		__le64 rb_id            :  1;
		__le64 connect         :  1;
		__le64 hangup          :  1;
		__le64 service_list_req:  1;
		__le64 size            : 12;
		__le64 card_client_id  : 12;
		__le64 reserved        : 20;
	};

	__le64 value;
};
CHECK_MESSAGE_SIZE(union h2c_ChanGenericMessaging, 1);

union h2c_ChanInferenceContextOp {
	struct {
		__le64 opcode     : 6;  /* NNP_IPC_H2C_OP_CHAN_INF_CONTEXT */
		__le64 chan_id     : NNP_IPC_CHANNEL_BITS;
		__le64 rb_id       : 1;
		__le64 destroy    : 1;
		__le64 recover    : 1;
		__le64 cflags     : 8;
		__le64 reserved   :37;
	};

	__le64 value;
};
CHECK_MESSAGE_SIZE(union h2c_ChanInferenceContextOp, 1);

union h2c_ChanInferenceResourceOp {
	struct {
		__le64 opcode      : 6;  /* NNP_IPC_H2C_OP_CHAN_INF_RESOURCE */
		__le64 chan_id      : NNP_IPC_CHANNEL_BITS;
		__le64 rb_id        : 1;
		__le64 resID       : NNP_IPC_INF_DEVRES_BITS;
		__le64 destroy     : 1;
		__le64 is_input    : 1;
		__le64 is_output   : 1;

		__le64 is_network  : 1;
		__le64 is_force_4G : 1;
		__le64 is_ecc      : 1;
		__le64 is_p2p_dst  : 1;
		__le64 is_p2p_src  : 1;
		__le64 depth       : 7;
		__le64 align       : 16;

		__le64 size        : 64;
	};

	__le64 value[2];
};
CHECK_MESSAGE_SIZE(union h2c_ChanInferenceResourceOp, 2);

union h2c_ChanMarkInferenceResource {
	struct {
		__le64 opcode      : 6;  /* NNP_IPC_H2C_OP_CHAN_MARK_INF_RESOURCE */
		__le64 chan_id      : NNP_IPC_CHANNEL_BITS;
		__le64 resID       : NNP_IPC_INF_DEVRES_BITS;
		__le64 reserved    : 32;
	};

	__le64 value;
};
CHECK_MESSAGE_SIZE(union h2c_ChanMarkInferenceResource, 1);

union h2c_ChanInferenceCopyOp {
	struct {
		__le64 opcode     :  6;  /* NNP_IPC_H2C_OP_CHAN_COPY_OP */
		__le64 chan_id     : NNP_IPC_CHANNEL_BITS;
		__le64 protResID  : 16;
		__le64 protCopyID : 16;
		__le64 d2d        :  1;
		__le64 c2h        :  1; /* if d2d = 0, c2h defines the copy direction */
		__le64 destroy    :  1;
		__le64 hostres    : NNP_IPC_DMA_PFN_BITS;
		__le32 subres_copy   : 1;
		/* data for peer to peer operation: */
		__le32 peerChanID    : NNP_IPC_CHANNEL_BITS; /* if d2d=1, contextID of the destination resource */
		__le32 peerProtResID : 16; /* if d2d=1, destination device resource ID */
		__le32 peerDevID     : 5; /* if d2d=1, destication device ID */
	};

	__le64 value[2];
};
CHECK_MESSAGE_SIZE(union h2c_ChanInferenceCopyOp, 2);

union h2c_ChanInferenceSchedCopy {
	struct {
		__le64 opcode     : 6;  /* NNP_IPC_H2C_OP_CHAN_SCHEDULE_COPY */
		__le64 chan_id     : NNP_IPC_CHANNEL_BITS;
		__le64 protCopyID : 16;
		__le64 copySize   : 30;
		__le64 priority   : 2;  /* TBD: change back to 3 in new proto */
	};

	__le64 value;
};
CHECK_MESSAGE_SIZE(union h2c_ChanInferenceSchedCopy, 1);

union h2c_ChanInferenceSchedCopyLarge {
	struct {
		__le64 opcode     : 6;  /* NNP_IPC_H2C_OP_CHAN_SCHEDULE_COPY_LARGE */
		__le64 chan_id     : NNP_IPC_CHANNEL_BITS;
		__le64 protCopyID : 16;
		__le64 priority   : 8;  /* TBD: change back to 3 in new proto */
		__le64 reserved   : 24;

		__le64 copySize   : 64;
	};

	__le64 value[2];
};
CHECK_MESSAGE_SIZE(union h2c_ChanInferenceSchedCopyLarge, 2);

union h2c_ChanInferenceSchedCopySubres {
	struct {
		__le64 opcode     : 6;  /* NNP_IPC_H2C_OP_CHAN_SCHEDULE_COPY_SUBRES */
		__le64 chan_id     : NNP_IPC_CHANNEL_BITS;
		__le64 protCopyID : 16;
		__le64 hostres_id  : 16;
		__le64 copySize   : 16;
		__le64 dstOffset  : 64;
	};

	__le64 value[2];
};
CHECK_MESSAGE_SIZE(union h2c_ChanInferenceSchedCopySubres, 2);

union h2c_ChanInferenceNetworkOp {
	struct {
		__le64 opcode        : 6; /* NNP_IPC_H2C_OP_CHAN_INF_NETWORK */
		__le64 chan_id        : NNP_IPC_CHANNEL_BITS;
		__le64 netID         : NNP_IPC_INF_DEVNET_BITS;
		__le64 rb_id          : 1;
		__le64 destroy       : 1;
		__le64 create        : 1;
		__le64 num_res       :24;
		__le64 reserved      : 5;

		__le64 size          : 32;
		__le64 start_res_idx : 24;
		__le64 reserved2     :  7;
		__le64 chained       : 1;
	};

	__le64 value[2];
};
CHECK_MESSAGE_SIZE(union h2c_ChanInferenceNetworkOp, 2);

union h2c_ChanInferenceReqOp {
	struct {
		__le64 opcode            :  6; /* NNP_IPC_H2C_OP_CHAN_INF_REQ_OP */
		__le64 chan_id            : NNP_IPC_CHANNEL_BITS;
		__le64 netID             : NNP_IPC_INF_DEVNET_BITS;
		__le64 infreqID          : NNP_IPC_INF_REQ_BITS;
		__le64 size              : 12;
		__le64 rb_id              :  1;
		__le64 destroy           :  1;
		__le64 reserved1         :  2;
	};

	__le64 value;
};
CHECK_MESSAGE_SIZE(union h2c_ChanInferenceReqOp, 1);

union h2c_ChanInferenceReqSchedule {
	struct {
		__le64 opcode            :  6; /* NNP_IPC_H2C_OP_CHAN_SCHEDULE_INF_REQ */
		__le64 chan_id            : NNP_IPC_CHANNEL_BITS;
		__le64 netID             : NNP_IPC_INF_DEVNET_BITS;
		__le64 infreqID          : NNP_IPC_INF_REQ_BITS;
		__le64 reserved          : 16;

		//schedParams
		__le64 batchSize         : 16;
		__le64 priority          :  8; /* 0 == normal, 1 == high */
		__le64 debugOn           :  1;
		__le64 collectInfo       :  1;
		__le64 schedParamsIsNull :  1;
		__le64 reserve           : 37;
	};

	__le64 value[2];
};
CHECK_MESSAGE_SIZE(union h2c_ChanInferenceReqSchedule, 2);

union h2c_ChanSync {
	struct {
		__le64 opcode      : 6; /* NNP_IPC_H2C_OP_CHAN_SYNC */
		__le64 chan_id      : NNP_IPC_CHANNEL_BITS;
		__le32 syncSeq     : 16;
		__le64 reserved    : 32;
	};

	__le64 value;
};
CHECK_MESSAGE_SIZE(union h2c_ChanSync, 1);

union h2c_ChanInferenceNetworkSetProperty {
	struct {
		__le64 opcode        : 6; /* NNP_IPC_H2C_OP_CHAN_NETWORK_PROPERTY */
		__le64 chan_id        : NNP_IPC_CHANNEL_BITS;
		__le64 netID         : NNP_IPC_INF_DEVNET_BITS;
		__le64 timeout       : 32;
		__le64 property	  : 32;
		__le64 property_val  : 32;
	};

	__le64 value[2];
};
CHECK_MESSAGE_SIZE(union h2c_ChanInferenceNetworkSetProperty, 2);

union h2c_ChanInferenceCmdListOp {
	struct {
		__le64 opcode      :  6;  /* NNP_IPC_H2C_OP_CHAN_INF_CMDLIST or
					* NNP_IPC_H2C_OP_CHAN_SCHEDULE_CMDLIST
					*/
		__le64 chan_id      : NNP_IPC_CHANNEL_BITS;
		__le64 cmdID       : NNP_IPC_INF_CMDS_BITS;
		__le64 destroy     :  1;
		__le64 is_first    :  1;
		__le64 is_last     :  1;
		__le64 opt_dependencies : 1;
		__le64 size        : 16;
		__le64 unused      : 12;
	};

	__le64 value;
};
CHECK_MESSAGE_SIZE(union h2c_ChanInferenceCmdListOp, 1);

union h2c_ExecErrorList {
	struct {
		__le64 opcode      : 6; /* NNP_IPC_H2C_OP_CHAN_EXEC_ERROR_LIST */
		__le64 chan_id      : NNP_IPC_CHANNEL_BITS;
		__le64 cmdID       : NNP_IPC_INF_CMDS_BITS;
		__le64 cmdID_valid : 1;
		__le64 clear       : 1;
		__le64 reserved    : 30;
	};

	__le64 value;
};
CHECK_MESSAGE_SIZE(union h2c_ExecErrorList, 1);

union h2c_ChanEthernetConfig {
	struct {
		__le64 opcode      :  6; /* NNP_IPC_H2C_OP_CHAN_ETH_CONFIG */
		__le64 chan_id      : NNP_IPC_CHANNEL_BITS;
		__le64 reserved    : 16;
		__le64 card_ip     : 32;

		__le64 reserved2   : 16;
		__le64 card_mac    : 48;  // at value[10-15]
	};

	__u8 value[16];
};
CHECK_MESSAGE_SIZE(union h2c_ChanEthernetConfig, 2);

union h2c_ChanEthernetMsgDscr {
	struct {
		__le64 opcode      :  6; /* NNP_IPC_H2C_OP_CHAN_ETH_MSG_DSCR */
		__le64 chan_id      : NNP_IPC_CHANNEL_BITS;
		__le64 size        : 12;
		__le64 skb_handle : NNP_NET_SKB_HANDLE_BITS;
		__le64 is_ack      :  1;
		__le64 reserved    : 27;
	};

	__le64 value;
};
CHECK_MESSAGE_SIZE(union h2c_ChanEthernetMsgDscr, 1);


union c2h_ChanRingBufUpdate {
	struct {
		__le64 opcode		: 6; /* NNP_IPC_C2H_OP_CHANNEL_RB_UPDATE */
		__le64 chan_id              : NNP_IPC_CHANNEL_BITS;
		__le64 rb_id                :  1;
		__le64 reserved            : 15;
		__le32 size                : 32;
	};

	__le64 value;
};
CHECK_MESSAGE_SIZE(union c2h_ChanRingBufUpdate, 1);

union c2h_ChanGenericMessaging {
	struct {
		__le64 opcode          :  6; /* NNP_IPC_C2H_OP_CHAN_GENERIC_MSG_PACKET */
		__le64 chan_id          : NNP_IPC_CHANNEL_BITS;
		__le64 rb_id            :  1;
		__le64 size            : 12;
		__le64 connect         :  1;
		__le64 no_such_service :  1;
		__le64 hangup          :  1;
		__le64 card_client_id  : 12;
		__le64 reserved        : 18;
	};

	__le64 value;
};
CHECK_MESSAGE_SIZE(union c2h_ChanGenericMessaging, 1);

union c2h_ChanServiceListMsg {
	struct {
		__le64 opcode           :  6;   /* NNP_IPC_C2H_OP_CHAN_SERVICE_LIST */
		__le64 chan_id           : NNP_IPC_CHANNEL_BITS;
		__le64 rb_id             :  1;
		__le64 failure          :  3;   /* 0=Valid 1=DmaFailed 2=PullFull 3=TooBig */
		__le64 size             : 12;
		__le64 num_services     : 32;
	};

	__le64 value;
};
CHECK_MESSAGE_SIZE(union c2h_ChanServiceListMsg, 1);

union c2h_ChanSyncDone {
	struct {
		__le64 opcode      : 6; /* NNP_IPC_C2H_OP_CHAN_SYNC_DONE */
		__le64 chan_id      : NNP_IPC_CHANNEL_BITS;
		__le32 syncSeq     : 16;
		__le64 reserved    : 32;
	};

	__le64 value;
};
CHECK_MESSAGE_SIZE(union c2h_ChanSyncDone, 1);

union c2h_ChanInfReqFailed {
	struct {
		__le64 opcode      : 6; /* NNP_IPC_C2H_OP_CHAN_INFREQ_FAILED */
		__le64 chan_id      : NNP_IPC_CHANNEL_BITS;
		__le64 netID       : NNP_IPC_INF_DEVNET_BITS;
		__le64 infreqID    : NNP_IPC_INF_REQ_BITS;
		__le64 cmdID       : NNP_IPC_INF_CMDS_BITS;
		__le64 reason      : 16;
		__le64 cmdID_valid :  1;
		__le64 reserved    : 47;
	};

	__le64 value[2];
};
CHECK_MESSAGE_SIZE(union c2h_ChanInfReqFailed, 2);

union c2h_ExecErrorList {
	struct {
		__le64 opcode      : 6; /* NNP_IPC_C2H_OP_CHAN_EXEC_ERROR_LIST */
		__le64 chan_id      : NNP_IPC_CHANNEL_BITS;
		__le64 cmdID       : NNP_IPC_INF_CMDS_BITS;
		__le64 cmdID_valid : 1;
		__le64 clear_status: 2;
		__le64 pkt_size    : 12;
		__le64 total_size  : 16;  /* total buffer size of error event_val if is_error */
		__le64 is_error    : 1;
	};

	__le64 value;
};
CHECK_MESSAGE_SIZE(union c2h_ExecErrorList, 1);

union c2h_ChanEthernetConfig {
	struct {
		__le64 opcode      :  6; /* NNP_IPC_C2H_OP_CHAN_ETH_CONFIG */
		__le64 chan_id      : NNP_IPC_CHANNEL_BITS;
		__le64 reserved    : 16;
		__le64 card_ip	: 32;
	};

	__le64 value;
};
CHECK_MESSAGE_SIZE(union c2h_ChanEthernetConfig, 1);

union c2h_ChanEthernetMsgDscr {
	struct {
		__le64 opcode      :  6; /* NNP_IPC_C2H_OP_CHAN_ETH_MSG_DSCR */
		__le64 chan_id      : NNP_IPC_CHANNEL_BITS;
		__le64 size        : 12;
		__le64 skb_handle	: NNP_NET_SKB_HANDLE_BITS;
		__le64 is_ack      :  1;
		__le64 reserved    : 27;
	};

	__le64 value;
};
CHECK_MESSAGE_SIZE(union c2h_ChanEthernetMsgDscr, 1);

union h2c_ChanHwTraceAddResource {
	struct {
		__le64 opcode          : 6;  /* NNP_IPC_H2C_OP_CHAN_HWTRACE_ADD_RESOURCE */
		__le64 chan_id          : NNP_IPC_CHANNEL_BITS;
		__le64 mapID           : 16;
		__le64 resourceIndex   : 8;  /* resource index */
		__le64 resource_size   : 32;
		__le64 reserved	    : 56;
	};

	__le64 value[2];
};
CHECK_MESSAGE_SIZE(union h2c_ChanHwTraceAddResource, 2);

union c2h_ChanHwTraceState {
	struct {
		__le64 opcode		: 6;  /* NNP_IPC_C2H_OP_CHAN_HWTRACE_STATE */
		__le64 chan_id              : NNP_IPC_CHANNEL_BITS;
		__le64 subOpcode		: 5;
		__le64 val1		: 32;
		__le64 val2		: 8;
		__le64 val3		: 32;
		__le64 err			: 8;
		__le64 reserved		: 27;
	};

	__le64 value[2];
};
CHECK_MESSAGE_SIZE(union c2h_ChanHwTraceState, 2);

union h2c_ChanHwTraceState {
	struct {
		__le64 opcode		: 6;  /* NNP_IPC_H2C_OP_CHAN_HWTRACE_STATE */
		__le64 chan_id              : NNP_IPC_CHANNEL_BITS;
		__le64 reserved		: 11;
		__le64 subOpcode		: 5;
		__le64 val			: 32;
	};

	__le64 value;
};
CHECK_MESSAGE_SIZE(union h2c_ChanHwTraceState, 1);

union h2c_ChanGetCrFIFO {
	struct {
		__le64 opcode      : 6;  /* NNP_IPC_H2C_OP_CHAN_GET_CR_FIFO */
		__le64 chan_id      : NNP_IPC_CHANNEL_BITS;
		__le64 p2p_tr_id   : 16;
		__le64 peer_id     : 5;
		__le64 fw_fifo     : 1;/* fw fifo or relase fifo */
		__le64 reserved    : 26;
	};

	__le64 value;
};
CHECK_MESSAGE_SIZE(union h2c_ChanGetCrFIFO, 1);

union h2c_ChanConnectPeers {
	struct {
		__le64 opcode      : 6;  /* NNP_IPC_H2C_OP_CHAN_P2P_CONNECT_PEERS */
		__le64 chan_id      : NNP_IPC_CHANNEL_BITS;
		__le64 p2p_tr_id   : 16;
		__le64 buf_id      : 8;
		__le64 is_src_buf  : 1;
		__le64 peer_dev_id : 5;
		__le64 peer_buf_id : 8;
		__le64 reserved    : 10;
	};

	__le64 value;
};
CHECK_MESSAGE_SIZE(union h2c_ChanGetCrFIFO, 1);

union h2c_ChanUpdatePeerDev {
	struct {
		__le64 opcode		: 6;  /* NNP_IPC_H2C_OP_CHAN_P2P_UPDATE_PEER_DEV */
		__le64 chan_id		: NNP_IPC_CHANNEL_BITS;
		__le64 p2p_tr_id		: 16;
		__le64 dev_id		: 5;
		__le64 is_producer		: 1;
		__le64 db_addr		: 57;
		__le64 cr_fifo_addr	: NNP_IPC_DMA_PFN_BITS;
		__le64 reserved		: 52;
	};
	__le64 value[3];
};
CHECK_MESSAGE_SIZE(union h2c_ChanUpdatePeerDev, 3);

#define USER_DATA_MAX_KEY_SIZE 6
union h2c_ChanTraceUserData {
	struct {
		__le64 opcode		: 6;  /* NNP_IPC_H2C_OP_CHAN_TRACE_USER_DATA */
		__le64 chan_id		: NNP_IPC_CHANNEL_BITS;
		__le64 key			: USER_DATA_MAX_KEY_SIZE * 8;

		__le64 user_data;
	};
	__le64 value[2];
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

enum CopyCmdUserHandleMsgType {
	COPY_USER_HANDLE_TYPE_COPY = 0,
	COPY_USER_HANDLE_TYPE_HOSTRES = 1
};

union h2c_ChanIdsMap {
	struct {
		__le64 opcode		: 6;  /* NNP_IPC_H2C_OP_CHAN_IDS_MAP */
		__le64 chan_id		: NNP_IPC_CHANNEL_BITS;
		__le64 objType		: 16; //InfContextObjType
		__le64 val1		: NNP_IPC_INF_DEVNET_BITS;
		__le64 val2		: NNP_IPC_INF_DEVNET_BITS;

		__le64 user_handle;
	};
	__le64 value[2];
};
CHECK_MESSAGE_SIZE(union h2c_ChanIdsMap, 2);

#ifdef ULT
union ult2_message {
	struct {
		__le64 opcode       :  6;    /* SPH_IPC_ULT2_OP */
		__le64 channelID    : NNP_IPC_CHANNEL_BITS;
		__le64 ultOpcode    :  4;
		__le64 reserved     : 44;
	};

	__le64 value;
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

/* Check that all c2h messages size is max of 3*__le64 */
#define C2H_OPCODE(name, val, type)  NNP_STATIC_ASSERT(sizeof(type) <= sizeof(__le64)*3, "Size of " #type " Must be LE 3*64!!"); /* SPH_IGNORE_STYLE_CHECK */
#include "ipc_chan_c2h_opcodes.h"
#undef C2H_OPCODE

#pragma pack(pop)

#endif

