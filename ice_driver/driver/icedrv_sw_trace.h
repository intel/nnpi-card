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
	TP_PROTO(u32 command, u8 state, u64  contextID, u8 status, int reason),
	TP_ARGS(command, state, contextID, status, reason),
	SPH_TP_STRUCT__entry(
			__field(u32, command)
			__field(u8, state)
			__field(u64, contextID)
			__field(u8, status)
			__field(int, reason)
	),
	SPH_TP_fast_assign(
			__entry->command = command;
			__entry->state = state;
			__entry->contextID = contextID;
			__entry->status = status;
			__entry->reason = reason;
	),
	SPH_TP_printk("command=%s state=%s contextID=%llu status=%s reason=%d",
		sph_trace_drv_command_to_str[__entry->command],
		sph_trace_op_state_to_str[__entry->state],
		__entry->contextID,
		sph_trace_op_status_to_str[__entry->status],
		__entry->reason)
);

TRACE_EVENT(SPH_TRACE_ICEDRV_CREATE_NETWORK,
	TP_PROTO(u32 command, u8 state, u64  contextID,
			u64 networkID, u32 *resource,
				u8 status, int reason),
	TP_ARGS(command, state, contextID, networkID, resource, status, reason),
	SPH_TP_STRUCT__entry(
			__field(u32, command)
			__field(u8, state)
			__field(u64, contextID)
			__field(u64, networkID)
			__array(u32, resource, 3)
			__field(u8, status)
			__field(int, reason)
	),
	SPH_TP_fast_assign(
			__entry->command = command;
			__entry->state = state;
			__entry->contextID = contextID;
			__entry->networkID = networkID;
			__memcpy(__entry->resource, resource, sizeof(u32)*3);
			__entry->status = status;
			__entry->reason = reason;
	),
	SPH_TP_printk(
		"command=%s state=%s contextID=%llu networkID=0x%llx resources:ice=%u llc=%u counters=%u  status=%s reason=%d",
		sph_trace_drv_command_to_str[__entry->command],
		sph_trace_op_state_to_str[__entry->state],
		__entry->contextID,
		__entry->networkID,
		__entry->resource[0],
		__entry->resource[1],
		__entry->resource[2],
		sph_trace_op_status_to_str[__entry->status],
		__entry->reason)
);


TRACE_EVENT(SPH_TRACE_ICEDRV_EXECUTE_NETWORK,
	TP_PROTO(u32 command, u8 state, u64  contextID,
			u64 networkID, u64 inferID, u8 status, int reason),
	TP_ARGS(command, state, contextID, networkID, inferID, status, reason),
	SPH_TP_STRUCT__entry(
			__field(u32, command)
			__field(u8, state)
			__field(u64, contextID)
			__field(u64, networkID)
			__field(u64, inferID)
			__field(u8, status)
			__field(int, reason)
	),
	SPH_TP_fast_assign(
			__entry->command = command;
			__entry->state = state;
			__entry->contextID = contextID;
			__entry->networkID = networkID;
			__entry->inferID = inferID;
			__entry->status = status;
			__entry->reason = reason;
	),
	SPH_TP_printk(
		"command=%s state=%s contextID=%llu networkID=0x%llx inferID=0x%llx status=%s reason=%d",
		sph_trace_drv_command_to_str[__entry->command],
		sph_trace_op_state_to_str[__entry->state],
		__entry->contextID,
		__entry->networkID,
		__entry->inferID,
		sph_trace_op_status_to_str[__entry->status],
		__entry->reason)
);

TRACE_EVENT(SPH_TRACE_ICEDRV_NETWORK_RESOURCE,
	TP_PROTO(u32 command, u64 networkID, u64 icesReserved,
			u64 countersReserved, u64 llcReserved),
	TP_ARGS(command, networkID, icesReserved, countersReserved,
				llcReserved),
	SPH_TP_STRUCT__entry(
			__field(u32, command)
			__field(u64, networkID)
			__field(u64, icesReserved)
			__field(u64, countersReserved)
			__field(u64, llcReserved)
	),
	SPH_TP_fast_assign(
			__entry->command = command;
			__entry->networkID = networkID;
			__entry->icesReserved = icesReserved;
			__entry->countersReserved = countersReserved;
			__entry->llcReserved = llcReserved;
	),
	SPH_TP_printk(
		"command=%s networkID=0x%llx Reserved (ICEMask=%llu, CounterMask=%llu, llc=%llu)",
		sph_trace_drv_command_to_str[__entry->command],
		__entry->networkID,
		__entry->icesReserved,
		__entry->countersReserved,
		__entry->llcReserved)
);

TRACE_EVENT(SPH_TRACE_ICEDRV_DESTROY_NETWORK,
	TP_PROTO(u32 command, u8 state, u64  contextID,
			u64 networkID, u8 status, int reason),
	TP_ARGS(command, state, contextID, networkID, status, reason),
	SPH_TP_STRUCT__entry(
			__field(u32, command)
			__field(u8, state)
			__field(u64, contextID)
			__field(u64, networkID)
			__field(u8, status)
			__field(int, reason)
	),
	SPH_TP_fast_assign(
			__entry->command = command;
			__entry->state = state;
			__entry->contextID = contextID;
			__entry->networkID = networkID;
			__entry->status = status;
			__entry->reason = reason;
	),
	SPH_TP_printk(
		"command=%s state=%s contextID=%llu networkID=0x%llx status=%s reason=%d",
		sph_trace_drv_command_to_str[__entry->command],
		sph_trace_op_state_to_str[__entry->state],
		__entry->contextID,
		__entry->networkID,
		sph_trace_op_status_to_str[__entry->status],
		__entry->reason)
);

TRACE_EVENT(SPH_TRACE_ICEDRV_DESTROY_CONTEXT,
	TP_PROTO(u32 command, u8 state, u64  contextID, u8 status, int reason),
	TP_ARGS(command, state, contextID, status, reason),
	SPH_TP_STRUCT__entry(
			__field(u32, command)
			__field(u8, state)
			__field(u64, contextID)
			__field(u8, status)
			__field(int, reason)
	),
	SPH_TP_fast_assign(
			__entry->command = command;
			__entry->state = state;
			__entry->contextID = contextID;
			__entry->status = status;
			__entry->reason = reason;
	),
	SPH_TP_printk("command=%s state=%s contextID=%llu status=%s reason=%d",
		sph_trace_drv_command_to_str[__entry->command],
		sph_trace_op_state_to_str[__entry->state],
		__entry->contextID,
		sph_trace_op_status_to_str[__entry->status],
		__entry->reason)
);

#endif /* if !defined(_TRACE_SYNC_H) || defined(TRACE_HEADER_MULTI_READ) */

/* This part must be outside protection */
#include <trace/define_trace.h>
