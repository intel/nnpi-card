/*
 * NNP-I Linux Driver
 * Copyright (c) 2019, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 */


#undef TRACE_SYSTEM
#define TRACE_INCLUDE_PATH .
#define TRACE_INCLUDE_FILE icedrv_sw_trace
#define TRACE_SYSTEM icedrv

#if !defined(_ICEDRV_TRACE_H) || defined(TRACE_HEADER_MULTI_READ)
#define _ICEDRV_TRACE_H

#include "icedrv_sw_trace_defs.h"
#include "sph_sw_trace_format.h"
#include <linux/tracepoint.h>

#define DO_TRACE(x) (x)
#define DO_TRACE_IF(cond, x) do {\
	if (cond) \
	x; \
	} while (0)

void icedrv_sw_trace_init(void);

#define SPH_TP_STRUCT__entry TP_STRUCT__entry
#define SPH_TP_fast_assign   TP_fast_assign
#define SPH_TP_printk        TP_printk

TRACE_EVENT(SPH_TRACE_ICEDRV_CREATE_CONTEXT,
	TP_PROTO(u8 state, u64  ctxID, u8 status, int reason),
	TP_ARGS(state, ctxID, status, reason),
	SPH_TP_STRUCT__entry(
			__field(u8, state)
			__field(u64, ctxID)
			__field(u8, status)
			__field(int, reason)
	),
	SPH_TP_fast_assign(
			__entry->state = state;
			__entry->ctxID = ctxID;
			__entry->status = status;
			__entry->reason = reason;
	),
	SPH_TP_printk("state=%s ctxID=%llu status=%s reason=%d",
		sph_trace_op_state_to_str[__entry->state],
		__entry->ctxID,
		sph_trace_op_status_to_str[__entry->status],
		__entry->reason)
);

TRACE_EVENT(SPH_TRACE_ICEDRV_CREATE_NETWORK,
	TP_PROTO(u8 state, u64  ctxID,
			u64 netID, u32 *resource,
				u8 status, int reason),
	TP_ARGS(state, ctxID, netID, resource, status, reason),
	SPH_TP_STRUCT__entry(
			__field(u8, state)
			__field(u64, ctxID)
			__field(u64, netID)
			__array(u32, resource, 6)
			__field(u8, status)
			__field(int, reason)
	),
	SPH_TP_fast_assign(
			__entry->state = state;
			__entry->ctxID = ctxID;
			__entry->netID = netID;
			__memcpy(__entry->resource, resource, sizeof(u32)*6);
			__entry->status = status;
			__entry->reason = reason;
	),
	SPH_TP_printk(
		"state=%s ctxID=%llu netID=0x%llx resources:clos0=%u clos1=%u clos2=%u clos3=%u ice=%u counters=%u  status=%s reason=%d",
		sph_trace_op_state_to_str[__entry->state],
		__entry->ctxID,
		__entry->netID,
		__entry->resource[0],
		__entry->resource[1],
		__entry->resource[2],
		__entry->resource[3],
		__entry->resource[4],
		__entry->resource[5],
		sph_trace_op_status_to_str[__entry->status],
		__entry->reason)
);


TRACE_EVENT(SPH_TRACE_ICEDRV_EXECUTE_NETWORK,
	TP_PROTO(u8 state, u64  ctxID,
			u64 netID, u64 inferID, u8 status, int reason),
	TP_ARGS(state, ctxID, netID, inferID, status, reason),
	SPH_TP_STRUCT__entry(
			__field(u8, state)
			__field(u64, ctxID)
			__field(u64, netID)
			__field(u64, inferID)
			__field(u8, status)
			__field(int, reason)
	),
	SPH_TP_fast_assign(
			__entry->state = state;
			__entry->ctxID = ctxID;
			__entry->netID = netID;
			__entry->inferID = inferID;
			__entry->status = status;
			__entry->reason = reason;
	),
	SPH_TP_printk(
		"state=%s ctxID=%llu netID=0x%llx inferID=0x%llx status=%s reason=%d",
		sph_trace_op_state_to_str[__entry->state],
		__entry->ctxID,
		__entry->netID,
		__entry->inferID,
		sph_trace_op_status_to_str[__entry->status],
		__entry->reason)
);

TRACE_EVENT(SPH_TRACE_ICEDRV_EVENT_GENERATION,
	TP_PROTO(u8 state, u64  ctxID,
			u64 netID, u64 inferID, u8 status, int reason),
	TP_ARGS(state, ctxID, netID, inferID, status, reason),
	SPH_TP_STRUCT__entry(
			__field(u8, state)
			__field(u64, ctxID)
			__field(u64, netID)
			__field(u64, inferID)
			__field(u8, status)
			__field(int, reason)
	),
	SPH_TP_fast_assign(
			__entry->state = state;
			__entry->ctxID = ctxID;
			__entry->netID = netID;
			__entry->inferID = inferID;
			__entry->status = status;
			__entry->reason = reason;
	),
	SPH_TP_printk(
		"state=%s ctxID=%llu netID=0x%llx inferID=0x%llx status=%s reason=%d",
		sph_trace_op_state_to_str[__entry->state],
		__entry->ctxID,
		__entry->netID,
		__entry->inferID,
		sph_trace_op_status_to_str[__entry->status],
		__entry->reason)
);

TRACE_EVENT(SPH_TRACE_ICEDRV_NETWORK_RESOURCE,
	TP_PROTO(u64 ctxID, u64 netID, u64 icesReserved,
			u64 countersReserved, u32 *llcReserved),
	TP_ARGS(ctxID, netID, icesReserved, countersReserved,
				llcReserved),
	SPH_TP_STRUCT__entry(
		__field(u64, ctxID)
		__field(u64, netID)
		__field(u64, icesReserved)
		__field(u64, countersReserved)
		__array(u32, llcReserved, 4)
	),
	SPH_TP_fast_assign(
		__entry->ctxID = ctxID;
		__entry->netID = netID;
		__entry->icesReserved = icesReserved;
		__entry->countersReserved = countersReserved;
		memcpy(__entry->llcReserved, llcReserved, sizeof(u32)*4);
	),
	SPH_TP_printk(
		"ctxID=%llu netID=0x%llx Reserved (ICEMask=%llu, CounterMask=%llu, clos0=%u clos1=%u clos2=%u clos3=%u)",
		__entry->ctxID,
		__entry->netID,
		__entry->icesReserved,
		__entry->countersReserved,
		__entry->llcReserved[0],
		__entry->llcReserved[1],
		__entry->llcReserved[2],
		__entry->llcReserved[3])
);

TRACE_EVENT(SPH_TRACE_ICEDRV_DESTROY_NETWORK,
	TP_PROTO(u8 state, u64  ctxID,
			u64 netID, u8 status, int reason),
	TP_ARGS(state, ctxID, netID, status, reason),
	SPH_TP_STRUCT__entry(
			__field(u8, state)
			__field(u64, ctxID)
			__field(u64, netID)
			__field(u8, status)
			__field(int, reason)
	),
	SPH_TP_fast_assign(
			__entry->state = state;
			__entry->ctxID = ctxID;
			__entry->netID = netID;
			__entry->status = status;
			__entry->reason = reason;
	),
	SPH_TP_printk(
		"state=%s ctxID=%llu netID=0x%llx status=%s reason=%d",
		sph_trace_op_state_to_str[__entry->state],
		__entry->ctxID,
		__entry->netID,
		sph_trace_op_status_to_str[__entry->status],
		__entry->reason)
);

TRACE_EVENT(SPH_TRACE_ICEDRV_DESTROY_CONTEXT,
	TP_PROTO(u8 state, u64  ctxID, u8 status, int reason),
	TP_ARGS(state, ctxID, status, reason),
	SPH_TP_STRUCT__entry(
			__field(u8, state)
			__field(u64, ctxID)
			__field(u8, status)
			__field(int, reason)
	),
	SPH_TP_fast_assign(
			__entry->state = state;
			__entry->ctxID = ctxID;
			__entry->status = status;
			__entry->reason = reason;
	),
	SPH_TP_printk("state=%s ctxID=%llu status=%s reason=%d",
		sph_trace_op_state_to_str[__entry->state],
		__entry->ctxID,
		sph_trace_op_status_to_str[__entry->status],
		__entry->reason)
);

#endif /* if !defined(_TRACE_SYNC_H) || defined(TRACE_HEADER_MULTI_READ) */

/* This part must be outside protection */
#include <trace/define_trace.h>
