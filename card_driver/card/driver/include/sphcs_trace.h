/********************************************
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/


#undef TRACE_SYSTEM
#define TRACE_INCLUDE_PATH .
#define TRACE_INCLUDE_FILE sphcs_trace
#define TRACE_SYSTEM sphcs

#if !defined(_SPHCS_TRACE_H) || defined(TRACE_HEADER_MULTI_READ)
#define _SPHCS_TRACE_H

#include "sphcs_trace_defs.h"
#include "sph_trace_format.h"
#include "sph_time.h"
#include "ipc_protocol.h"
#include <linux/tracepoint.h>
#include "ipc_protocol.h"

#ifdef TRACE
#define DO_TRACE(x) (x)
#define DO_TRACE_IF(cond, x) do {\
	if (cond) \
		x; \
	} while (0)
#else
#define DO_TRACE(x)
#define DO_TRACE_IF(cond, x)
#endif

void sphcs_trace_init(void);

#define SPH_TP_STRUCT__entry TP_STRUCT__entry
#define SPH_TP_fast_assign   TP_fast_assign
#define SPH_TP_printk        TP_printk

TRACE_EVENT(SPH_TRACE_INFREQ,
	TP_PROTO(u8 state, u32 ctxID, u32 netID, u32 reqID, u32 cmdlistID),
	TP_ARGS(state, ctxID, netID, reqID, cmdlistID),
	SPH_TP_STRUCT__entry(
			__field(u32, ctxID)
			__field(u32, netID)
			__field(u32, reqID)
			__field(u32, cmdlistID)
			__field(u8, state)
	),
	SPH_TP_fast_assign(
		       __entry->state = state;
		       __entry->ctxID = ctxID;
		       __entry->netID = netID;
		       __entry->reqID = reqID;
		       __entry->cmdlistID = cmdlistID;
	),
	SPH_TP_printk("state=%s ctxID=%u netID=%u reqID=%u cmdlistID=%u",
		  sph_trace_op_to_str[__entry->state],
		  __entry->ctxID,
		  __entry->netID,
		  __entry->reqID,
		  __entry->cmdlistID)
);


TRACE_EVENT(SPH_TRACE_COPY,
	TP_PROTO(u8 state, u32 ctxID, u32 copyID, int cmdlistID, u8 isC2H, u64 size, int n_copies),
	TP_ARGS(state, ctxID, copyID, cmdlistID, isC2H, size, n_copies),
	SPH_TP_STRUCT__entry(
			__field(u64, size)
			__field(u32, ctxID)
			__field(u32, copyID)
			__field(int, cmdlistID)
			__field(int, n_copies)
			__field(u8, isC2H)
			__field(u8, state)
	),
	SPH_TP_fast_assign(
			__entry->state = state;
			__entry->ctxID = ctxID;
			__entry->copyID = copyID;
			__entry->cmdlistID = cmdlistID;
			__entry->isC2H = isC2H;
			__entry->size = size;
			__entry->n_copies = n_copies;
	),
	SPH_TP_printk("state=%s ctxID=%u copyID=%u cmdlistID=%d isC2H=%d size=0x%llx, n_copies=%d",
		  sph_trace_op_to_str[__entry->state],
		  __entry->ctxID,
		  __entry->copyID,
		  __entry->cmdlistID,
		  __entry->isC2H,
		  __entry->size,
		  __entry->n_copies)
);

TRACE_EVENT(SPH_TRACE_CMDLIST,
	TP_PROTO(u8 state, u32 ctxID, u32 cmdlistID),
	TP_ARGS(state, ctxID, cmdlistID),
	SPH_TP_STRUCT__entry(
			__field(u64, state)
			__field(u32, ctxID)
			__field(u32, cmdlistID)
	),
	SPH_TP_fast_assign(
			__entry->state = state;
			__entry->ctxID = ctxID;
			__entry->cmdlistID = cmdlistID;
	),
	SPH_TP_printk("state=%s ctxID=%u cmdlistID=%u",
			sph_trace_op_to_str[__entry->state],
			__entry->ctxID,
			__entry->cmdlistID)
);

TRACE_EVENT(SPH_TRACE_CPYLIST_CREATE,
	TP_PROTO(u8 state, u32 ctxID, u32 cmdlistID, u32 cpylist_idx),
	TP_ARGS(state, ctxID, cmdlistID, cpylist_idx),
	SPH_TP_STRUCT__entry(
			__field(u64, state)
			__field(u32, ctxID)
			__field(u32, cmdlistID)
			__field(u32, cpylist_idx)
	),
	SPH_TP_fast_assign(
			__entry->state = state;
			__entry->ctxID = ctxID;
			__entry->cmdlistID = cmdlistID;
			__entry->cpylist_idx = cpylist_idx;
	),
	SPH_TP_printk("state=%s ctxID=%u cmdlistID=%u cpylist_idx=%u",
			sph_trace_op_to_str[__entry->state],
			__entry->ctxID,
			__entry->cmdlistID,
			__entry->cpylist_idx)
);

TRACE_EVENT(SPH_TRACE_DMA,
	TP_PROTO(u8 state, u8 isC2H, u64 size, int hw_channel, u32 priority, u64 req),
	TP_ARGS(state, isC2H, size, hw_channel, priority, req),
	SPH_TP_STRUCT__entry(
			__field(u64, req)
			__field(u64, size)
			__field(u32, priority)
			__field(int, hw_channel)
			__field(u8, state)
			__field(u8, isC2H)
	),
	SPH_TP_fast_assign(
			__entry->state = state;
			__entry->isC2H = isC2H;
			__entry->size = size;
			__entry->hw_channel = hw_channel;
			__entry->priority = priority;
			__entry->req = req;
	),
	SPH_TP_printk("state=%s isC2H=%d size=%llu channel=%d prio=%d req=0x%llx",
		  sph_trace_op_to_str[__entry->state],
		  __entry->isC2H,
		  __entry->size,
		  __entry->hw_channel,
		  __entry->priority,
		  __entry->req)
);

TRACE_EVENT(SPH_TRACE_INF_CREATE,
	TP_PROTO(u32 command, u32 ctxId, u32 id, u8 state, int obj1, int obj2),
	TP_ARGS(command, ctxId, id, state, obj1, obj2),
	SPH_TP_STRUCT__entry(
			__field(u32, command)
			__field(u32, ctxId)
			__field(u32, id)
			__field(int, obj1)
			__field(int, obj2)
			__field(u8, state)
	),
	SPH_TP_fast_assign(
			__entry->command = command;
			__entry->ctxId = ctxId;
			__entry->id = id;
			__entry->state = state;
			__entry->obj1 = obj1;
			__entry->obj2 = obj2;
	),
	SPH_TP_printk("command=create_%s ctxID=%u id=%u obj1=%d obj2=%d state=%s",
		  sph_trace_inf_create_to_str[__entry->command],
		  __entry->ctxId,
		  __entry->id,
		  __entry->obj1,
		  __entry->obj2,
		  sph_trace_op_to_str[__entry->state])
);

TRACE_EVENT(SPH_TRACE_INF_NET_SUBRES,
	TP_PROTO(u32 ctxId, u32 sessionId, u64 offset, u8 host_pool_idx, u64 size, u64 dma_addr, u8 state),
	TP_ARGS(ctxId, sessionId, offset, host_pool_idx, size, dma_addr, state),
	SPH_TP_STRUCT__entry(
			__field(u64, offset)
			__field(u64, size)
			__field(u64, dma_addr)
			__field(u32, ctxId)
			__field(u32, sessionId)
			__field(u8, host_pool_idx)
			__field(u8, state)
	),
	SPH_TP_fast_assign(
			__entry->ctxId = ctxId;
			__entry->sessionId = sessionId;
			__entry->offset = offset;
			__entry->host_pool_idx = host_pool_idx;
			__entry->size = size;
			__entry->dma_addr = dma_addr;
			__entry->state = state;
	),
	SPH_TP_printk("state=%s ctxID=%u sessionID=%u offset=0x%llx pool_idx=%u dma_size=0x%llx dma_src_addr=0x%llx",
		  sph_trace_op_to_str[__entry->state],
		  __entry->ctxId,
		  __entry->sessionId,
		  __entry->offset,
		  __entry->host_pool_idx,
		  __entry->size,
		  __entry->dma_addr)
);

TRACE_EVENT(SPH_TRACE_IPC,
	TP_PROTO(u8 dir, u64 *msg, u32 size),
	TP_ARGS(dir, msg, size),
	SPH_TP_STRUCT__entry(
			__field(u64, msg[4])
			__field(u32, size)
			__field(u8, dir)
	),
	SPH_TP_fast_assign(
		       __entry->msg[0] = msg[0];
		       __entry->msg[1] = (size > 1 ? msg[1] : 0);
		       __entry->msg[2] = (size > 2 ? msg[2] : 0);
		       __entry->msg[3] = (size > 3 ? msg[3] : 0);
		       __entry->size = size;
		       __entry->dir = dir
	),
	SPH_TP_printk("dir=%s op=%s size=%u payload=0x%llx,0x%llx,0x%llx,0x%llx\n",
		  __entry->dir == 0 ? "command" : "response",
		  __entry->dir == 0 ? H2C_HWQ_MSG_STR(__entry->msg[0] & 0x1f) :
				      C2H_HWQ_MSG_STR(__entry->msg[0] & 0x1f),
		  __entry->size,
		  __entry->msg[0],
		  __entry->msg[1],
		  __entry->msg[2],
		  __entry->msg[3])
);

/*TRACE_EVENT(SPH_TRACE_MMIO,
	TP_PROTO(char op, u32 offset, u32 val),
	TP_ARGS(op, offset, val),
	SPH_TP_STRUCT__entry(
			__field(u32,  offset)
			__field(u32,  val)
			__field(char, op)
	),
	SPH_TP_fast_assign(
			__entry->op     = op;
			__entry->offset = offset;
			__entry->val    = val
	),
	SPH_TP_printk("op=%c off=0x%x val=0x%x\n",
		__entry->op,
		__entry->offset,
		__entry->val)
);
*/

#endif /* if !defined(_TRACE_SYNC_H) || defined(TRACE_HEADER_MULTI_READ) */

/* This part must be outside protection */
#include <trace/define_trace.h>
