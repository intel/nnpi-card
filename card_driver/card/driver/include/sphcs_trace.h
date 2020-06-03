/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/


#undef TRACE_SYSTEM
#define TRACE_INCLUDE_PATH .
#define TRACE_INCLUDE_FILE sphcs_trace
#define TRACE_SYSTEM sphcs

#if !defined(_NNPCS_TRACE_H) || defined(TRACE_HEADER_MULTI_READ)
#define _NNPCS_TRACE_H

#include "sphcs_trace_defs.h"
#include "nnp_trace_format.h"
#include "nnp_time.h"
#include "ipc_protocol.h"
#include <linux/tracepoint.h>
#include "ipc_protocol.h"

#ifdef TRACE
#define DO_TRACE(x) (x)
#define DO_TRACE_IF(cond, x) do {\
	if (cond) {\
		x; } \
	} while (0)
#else
#define DO_TRACE(x)
#define DO_TRACE_IF(cond, x)
#endif

void sphcs_trace_init(void);

#define NNP_TP_STRUCT__entry TP_STRUCT__entry
#define NNP_TP_fast_assign   TP_fast_assign
#define NNP_TP_printk        TP_printk

/* Define functions to convert protocol opcode codes to names */
#ifndef TRACE_HEADER_MULTI_READ
#define H2C_OPCODE(name, val, type) /* SPH_IGNORE_STYLE_CHECK */\
	case (val):                   \
	return #name;

static inline const char *H2C_HWQ_MSG_STR(u8 x)
{
	switch (x) {
	#include "ipc_chan_h2c_opcodes.h"
	case H2C_OPCODE_NAME(QUERY_VERSION):
		return H2C_OPCODE_NAME_STR(QUERY_VERSION);
	case H2C_OPCODE_NAME(CLOCK_STAMP):
		return H2C_OPCODE_NAME_STR(CLOCK_STAMP);
	case H2C_OPCODE_NAME(SETUP_CRASH_DUMP):
		return H2C_OPCODE_NAME_STR(SETUP_CRASH_DUMP);
	case H2C_OPCODE_NAME(SETUP_SYS_INFO_PAGE):
		return H2C_OPCODE_NAME_STR(SETUP_SYS_INFO_PAGE);
	case H2C_OPCODE_NAME(CHANNEL_OP):
		return H2C_OPCODE_NAME_STR(CHANNEL_OP);
	case H2C_OPCODE_NAME(CHANNEL_RB_OP):
		return H2C_OPCODE_NAME_STR(CHANNEL_RB_OP);
	case H2C_OPCODE_NAME(CHANNEL_HOSTRES_OP):
		return H2C_OPCODE_NAME_STR(CHANNEL_HOSTRES_OP);
	case H2C_OPCODE_NAME(BIOS_PROTOCOL):
		return H2C_OPCODE_NAME_STR(BIOS_PROTOCOL);
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
	#include "ipc_chan_c2h_opcodes.h"
	case C2H_OPCODE_NAME(EVENT_REPORT):
		return C2H_OPCODE_NAME_STR(EVENT_REPORT);
	case C2H_OPCODE_NAME(QUERY_VERSION_REPLY):
		return C2H_OPCODE_NAME_STR(QUERY_VERSION_REPLY);
	case C2H_OPCODE_NAME(QUERY_VERSION_REPLY2):
		return C2H_OPCODE_NAME_STR(QUERY_VERSION_REPLY2);
	case C2H_OPCODE_NAME(QUERY_VERSION_REPLY3):
		return C2H_OPCODE_NAME_STR(QUERY_VERSION_REPLY3);
	case C2H_OPCODE_NAME(SYS_INFO):
		return C2H_OPCODE_NAME_STR(SYS_INFO);
	case C2H_OPCODE_NAME(BIOS_PROTOCOL):
		return C2H_OPCODE_NAME_STR(BIOS_PROTOCOL);
	default:
		return "not found";
	}
}
#undef C2H_OPCODE
#endif

TRACE_EVENT(SPH_TRACE_INFREQ,
	TP_PROTO(u8 state, u32 ctxID, u32 netID, u32 reqID, u32 cmdlistID),
	TP_ARGS(state, ctxID, netID, reqID, cmdlistID),
	NNP_TP_STRUCT__entry(
			__field(u32, ctxID)
			__field(u32, netID)
			__field(u32, reqID)
			__field(u32, cmdlistID)
			__field(u8, state)
	),
	NNP_TP_fast_assign(
		       __entry->state = state;
		       __entry->ctxID = ctxID;
		       __entry->netID = netID;
		       __entry->reqID = reqID;
		       __entry->cmdlistID = cmdlistID;
	),
	NNP_TP_printk("state=%s ctxID=%u netID=%u reqID=%u cmdlistID=%u",
		  sph_trace_op_to_str[__entry->state],
		  __entry->ctxID,
		  __entry->netID,
		  __entry->reqID,
		  __entry->cmdlistID)
);


TRACE_EVENT(SPH_TRACE_COPY,
	TP_PROTO(u8 state, u32 ctxID, u32 copyID, int cmdlistID, u8 isC2H, int p2pDevID, u64 size, int n_copies, u8 n_dma, u32 n_elems),
	TP_ARGS(state, ctxID, copyID, cmdlistID, isC2H, p2pDevID, size, n_copies, n_dma, n_elems),
	NNP_TP_STRUCT__entry(
			__field(u64, size)
			__field(u32, ctxID)
			__field(u32, copyID)
			__field(int, cmdlistID)
			__field(int, n_copies)
			__field(u8, isC2H)
			__field(int, p2pDevID)
			__field(u8, state)
			__field(u8, n_dma)
			__field(u32, n_elems)
	),
	NNP_TP_fast_assign(
			__entry->state = state;
			__entry->ctxID = ctxID;
			__entry->copyID = copyID;
			__entry->cmdlistID = cmdlistID;
			__entry->isC2H = isC2H;
			__entry->p2pDevID = p2pDevID;
			__entry->size = size;
			__entry->n_copies = n_copies;
			__entry->n_dma = n_dma;
			__entry->n_elems = n_elems;
	),
	NNP_TP_printk("state=%s ctxID=%u copyID=%u cmdlistID=%d isC2H=%d p2pDevID=%d size=%llu n_copies=%d n_dma=%d n_elems=%u",
		  sph_trace_op_to_str[__entry->state],
		  __entry->ctxID,
		  __entry->copyID,
		  __entry->cmdlistID,
		  __entry->isC2H,
		  __entry->p2pDevID,
		  __entry->size,
		  __entry->n_copies,
		  __entry->n_dma,
		  __entry->n_elems)
);

TRACE_EVENT(SPH_TRACE_CREDIT,
	TP_PROTO(u32 ctxID, u16 devresID, u8 bufID, u8 srcDevID),
	TP_ARGS(ctxID, devresID, bufID, srcDevID),
	NNP_TP_STRUCT__entry(
			__field(u32, ctxID)
			__field(u16, devresID)
			__field(u8, bufID)
			__field(u8, srcDevID)
	),
	NNP_TP_fast_assign(
			__entry->ctxID = ctxID;
			__entry->devresID = devresID;
			__entry->bufID = bufID;
			__entry->srcDevID = srcDevID;
	),
	NNP_TP_printk("ctxID=%u devresID=%u bufID=%u srcDevID=%u",
		  __entry->ctxID,
		  __entry->devresID,
		  __entry->bufID,
		  __entry->srcDevID)
);

TRACE_EVENT(SPH_TRACE_CMDLIST,
	TP_PROTO(u8 state, u32 ctxID, u32 cmdlistID),
	TP_ARGS(state, ctxID, cmdlistID),
	NNP_TP_STRUCT__entry(
			__field(u64, state)
			__field(u32, ctxID)
			__field(u32, cmdlistID)
	),
	NNP_TP_fast_assign(
			__entry->state = state;
			__entry->ctxID = ctxID;
			__entry->cmdlistID = cmdlistID;
	),
	NNP_TP_printk("state=%s ctxID=%u cmdlistID=%u",
			sph_trace_op_to_str[__entry->state],
			__entry->ctxID,
			__entry->cmdlistID)
);

TRACE_EVENT(SPH_TRACE_CPYLIST_CREATE,
	TP_PROTO(u8 state, u32 ctxID, u32 cmdlistID, u32 cpylist_idx),
	TP_ARGS(state, ctxID, cmdlistID, cpylist_idx),
	NNP_TP_STRUCT__entry(
			__field(u64, state)
			__field(u32, ctxID)
			__field(u32, cmdlistID)
			__field(u32, cpylist_idx)
	),
	NNP_TP_fast_assign(
			__entry->state = state;
			__entry->ctxID = ctxID;
			__entry->cmdlistID = cmdlistID;
			__entry->cpylist_idx = cpylist_idx;
	),
	NNP_TP_printk("state=%s ctxID=%u cmdlistID=%u cpylist_idx=%u",
			sph_trace_op_to_str[__entry->state],
			__entry->ctxID,
			__entry->cmdlistID,
			__entry->cpylist_idx)
);

TRACE_EVENT(SPH_TRACE_DMA,
	TP_PROTO(u8 state, u8 isC2H, u64 size, int hw_channel, u32 priority, u64 req),
	TP_ARGS(state, isC2H, size, hw_channel, priority, req),
	NNP_TP_STRUCT__entry(
			__field(u64, req)
			__field(u64, size)
			__field(u32, priority)
			__field(int, hw_channel)
			__field(u8, state)
			__field(u8, isC2H)
	),
	NNP_TP_fast_assign(
			__entry->state = state;
			__entry->isC2H = isC2H;
			__entry->size = size;
			__entry->hw_channel = hw_channel;
			__entry->priority = priority;
			__entry->req = req;
	),
	NNP_TP_printk("state=%s isC2H=%d size=%llu channel=%d prio=%d req=0x%llx",
		  sph_trace_op_to_str[__entry->state],
		  __entry->isC2H,
		  __entry->size,
		  __entry->hw_channel,
		  __entry->priority,
		  __entry->req)
);

TRACE_EVENT(SPH_TRACE_INF_CREATE,
	TP_PROTO(u8 command, u16 ctxId, u16 id, u8 state, int obj1, int obj2),
	TP_ARGS(command, ctxId, id, state, obj1, obj2),
	NNP_TP_STRUCT__entry(
			__field(u8, command)
			__field(u16, ctxId)
			__field(u16, id)
			__field(int, obj1)
			__field(int, obj2)
			__field(u8, state)
	),
	NNP_TP_fast_assign(
			__entry->command = command;
			__entry->ctxId = ctxId;
			__entry->id = id;
			__entry->state = state;
			__entry->obj1 = obj1;
			__entry->obj2 = obj2;
	),
	NNP_TP_printk("command=create_%s ctxID=%u id=%u obj1=%d obj2=%d state=%s",
		  sph_trace_inf_to_str[__entry->command],
		  __entry->ctxId,
		  __entry->id,
		  __entry->obj1,
		  __entry->obj2,
		  sph_trace_op_to_str[__entry->state])
);

TRACE_EVENT(SPH_TRACE_COPY_CREATE,
	TP_PROTO(bool c2h, bool p2p, u16 ctxId, u16 copyID, u8 state, u16 devresID, u16 hostresMapID, u16 p2pDevresID, u16 p2pCtxID, u8 p2pDevID),
	TP_ARGS(c2h, p2p, ctxId, copyID, state, devresID, hostresMapID, p2pDevresID, p2pCtxID, p2pDevID),
	NNP_TP_STRUCT__entry(
			__field(bool, c2h)
			__field(bool, p2p)
			__field(u16, ctxId)
			__field(u16, copyID)
			__field(u16, devresID)
			__field(u16, hostresMapID)
			__field(u16, p2pDevresID)
			__field(u16, p2pCtxID)
			__field(u8, p2pDevID)
			__field(u8, state)
	),
	NNP_TP_fast_assign(
			__entry->c2h = c2h;
			__entry->p2p = p2p;
			__entry->ctxId = ctxId;
			__entry->copyID = copyID;
			__entry->state = state;
			__entry->devresID = devresID;
			__entry->hostresMapID = hostresMapID;
			__entry->p2pDevresID = p2pDevresID;
			__entry->p2pCtxID = p2pCtxID;
			__entry->p2pDevID = p2pDevID;
	),
	NNP_TP_printk("command=create_%s state=%s ctxID=%u copyID=%u devresID=%u res2ID=%u p2pCtxID=%d p2pDevID=%d",
		  (__entry->p2p ? SPH_TRACE_STR_P2P_COPY_HANDLE : (__entry->c2h ? SPH_TRACE_STR_C2H_COPY_HANDLE : SPH_TRACE_STR_H2C_COPY_HANDLE)),
		  sph_trace_op_to_str[__entry->state],
		  __entry->ctxId,
		  __entry->copyID,
		  __entry->devresID,
		  (__entry->p2p ? __entry->p2pDevresID : __entry->hostresMapID),
		  (__entry->p2p ? __entry->p2pCtxID    : -1),
		  (__entry->p2p ? __entry->p2pDevID    : -1))
);

TRACE_EVENT(SPH_TRACE_USER_DATA,
	TP_PROTO(u64 key, u16 ctxID, u64 user_data),
	TP_ARGS(key, ctxID, user_data),
	NNP_TP_STRUCT__entry(
			__field(u64, key)
			__field(u16, ctxID)
			__field(u64, user_data)
	),
	NNP_TP_fast_assign(
		       __entry->key = key;
		       __entry->ctxID = ctxID;
		       __entry->user_data = user_data;
	),
	NNP_TP_printk("key=%s ctxID=%u user_data=%llu",
		  (char *)(&__entry->key),
		  __entry->ctxID,
		  __entry->user_data)
);

TRACE_EVENT(SPH_TRACE_IDS_MAP,
	TP_PROTO(u16 type, u16 ctxID, u16 id1, u16 id2, u64 user_handle),
	TP_ARGS(type, ctxID, id1, id2, user_handle),
	NNP_TP_STRUCT__entry(
			__field(u16, type)
			__field(u16, ctxID)
			__field(u16, id1)
			__field(u16, id2)
			__field(u64, user_handle)
	),
	NNP_TP_fast_assign(
		       __entry->type = type;
		       __entry->ctxID = ctxID;
		       __entry->id1 = id1;
		       __entry->id2 = id2;
		       __entry->user_handle = user_handle;
	),
	NNP_TP_printk("type=%s ctxID=%u userHandle=%llu id1=%u id2=%u",
		  sph_trace_inf_to_str[__entry->type],
		  __entry->ctxID,
		  __entry->user_handle,
		  __entry->id1,
		  __entry->id2)
);

TRACE_EVENT(NNP_TRACE_CLOCK_STAMP,
	TP_PROTO(char *type, u64 clock),
	TP_ARGS(type, clock),
	NNP_TP_STRUCT__entry(
			__field(char, type[8])
			__field(u64, clock)
	),
	NNP_TP_fast_assign(
			__entry->type[0] = type[0];
			__entry->type[1] = type[1];
			__entry->type[2] = type[2];
			__entry->type[3] = type[3];
			__entry->type[4] = type[4];
			__entry->type[5] = type[5];
			__entry->type[6] = type[6];
			__entry->type[7] = type[7];
			__entry->clock = clock;
	),
	NNP_TP_printk("type=%s clock=%llu",
		  __entry->type,
		  __entry->clock)
);

TRACE_EVENT(NNP_TRACE_IPC,
	TP_PROTO(u8 dir, u64 *msg, u32 size),
	TP_ARGS(dir, msg, size),
	NNP_TP_STRUCT__entry(
			__field(u64, msg[4])
			__field(u32, size)
			__field(u8, dir)
	),
	NNP_TP_fast_assign(
		       __entry->msg[0] = msg[0];
		       __entry->msg[1] = (size > 1 ? msg[1] : 0);
		       __entry->msg[2] = (size > 2 ? msg[2] : 0);
		       __entry->msg[3] = (size > 3 ? msg[3] : 0);
		       __entry->size = size;
		       __entry->dir = dir
	),
	NNP_TP_printk("dir=%s op=%s size=%u payload=0x%llx,0x%llx,0x%llx,0x%llx",
		  __entry->dir == 0 ? "command" : "response",
		  __entry->dir == 0 ? H2C_HWQ_MSG_STR(__entry->msg[0] & NNP_IPC_OPCODE_MASK) :
				      C2H_HWQ_MSG_STR(__entry->msg[0] & NNP_IPC_OPCODE_MASK),
		  __entry->size,
		  __entry->msg[0],
		  __entry->msg[1],
		  __entry->msg[2],
		  __entry->msg[3])
);

/*TRACE_EVENT(NNP_TRACE_MMIO,
	TP_PROTO(char op, u32 offset, u32 val),
	TP_ARGS(op, offset, val),
	NNP_TP_STRUCT__entry(
			__field(u32,  offset)
			__field(u32,  val)
			__field(char, op)
	),
	NNP_TP_fast_assign(
			__entry->op     = op;
			__entry->offset = offset;
			__entry->val    = val
	),
	NNP_TP_printk("op=%c off=0x%x val=0x%x",
		__entry->op,
		__entry->offset,
		__entry->val)
);
*/

#endif /* if !defined(_TRACE_SYNC_H) || defined(TRACE_HEADER_MULTI_READ) */

/* This part must be outside protection */
#include <trace/define_trace.h>
