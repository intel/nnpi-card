/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/




#undef TRACE_SYSTEM
#define TRACE_INCLUDE_PATH .
#define TRACE_INCLUDE_FILE icedrv_sw_trace
#define TRACE_SYSTEM icedrv

#if !defined(_ICEDRV_TRACE_H) || defined(TRACE_HEADER_MULTI_READ)
#define _ICEDRV_TRACE_H

#include "icedrv_sw_trace_defs.h"
#include "sph_sw_trace_format.h"

#ifndef RING3_VALIDATION
#include <linux/tracepoint.h>
#endif

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
	TP_PROTO(u8 state, u64 ctxID, u64 internalctxId,
		u8 status, int reason),
	TP_ARGS(state, ctxID, internalctxId, status, reason),
	SPH_TP_STRUCT__entry(
			__field(u8, state)
			__field(u64, ctxID)
			__field(u64, internalctxId)
			__field(u8, status)
			__field(int, reason)
	),
	SPH_TP_fast_assign(
			__entry->state = state;
			__entry->ctxID = ctxID;
			__entry->internalctxId = internalctxId;
			__entry->status = status;
			__entry->reason = reason;
	),
	SPH_TP_printk("state=%s ctxID=%llu(%llu) status=%s reason=%d",
		sph_trace_op_state_to_str[__entry->state],
		__entry->ctxID, __entry->internalctxId,
		sph_trace_op_status_to_str[__entry->status],
		__entry->reason)
);

TRACE_EVENT(SPH_TRACE_ICEDRV_CREATE_NETWORK,
	TP_PROTO(u8 state, u64  ctxID,
			u64 netID, u64 subNetId, u64 internalNetId,
			u32 *resource, u8 status, int reason),
	TP_ARGS(state, ctxID, netID, subNetId, internalNetId,
		resource, status, reason),
	SPH_TP_STRUCT__entry(
			__field(u8, state)
			__field(u64, ctxID)
			__field(u64, netID)
			__field(u64, subNetId)
			__field(u64, internalNetId)
			__array(u32, resource, 6)
			__field(u8, status)
			__field(int, reason)
	),
	SPH_TP_fast_assign(
			__entry->state = state;
			__entry->ctxID = ctxID;
			__entry->netID = netID;
			__entry->subNetId = subNetId;
			__entry->internalNetId = internalNetId;
			__memcpy(__entry->resource, resource, sizeof(u32)*6);
			__entry->status = status;
			__entry->reason = reason;
	),
	SPH_TP_printk(
		"state=%s ctxID=%llu netID=0x%llx subNetId=0x%llx(0x%llx) resource:clos{C0=%u C1=%u C2=%u C3=%u} ice=%u counter=%u  %s:%d",
		sph_trace_op_state_to_str[__entry->state],
		__entry->ctxID,
		__entry->netID,
		__entry->subNetId,
		__entry->internalNetId,
		__entry->resource[0],
		__entry->resource[1],
		__entry->resource[2],
		__entry->resource[3],
		__entry->resource[4],
		__entry->resource[5],
		sph_trace_op_status_to_str[__entry->status],
		__entry->reason)
);

/*	========CreateInfer ============*/

TRACE_EVENT(SPH_TRACE_ICEDRV_CREATE_INFER,
	TP_PROTO(u8 state, u64 ctxID,
		u64 netID, u64 subNetId, u64 internalNetId,
		u64 inferID, u8 status, int reason),
	TP_ARGS(state, ctxID, netID, subNetId, internalNetId,
		inferID, status, reason),
	SPH_TP_STRUCT__entry(
			__field(u8, state)
			__field(u64, ctxID)
			__field(u64, netID)
			__field(u64, subNetId)
			__field(u64, internalNetId)
			__field(u64, inferID)
			__field(u8, status)
			__field(int, reason)
	),
	SPH_TP_fast_assign(
			__entry->state = state;
			__entry->ctxID = ctxID;
			__entry->netID = netID;
			__entry->subNetId = subNetId;
			__entry->internalNetId = internalNetId;
			__entry->inferID = inferID;
			__entry->status = status;
			__entry->reason = reason;
	),
	SPH_TP_printk(
		"state=%s ctxID=%llu netID=0x%llx subNetId=0x%llx(0x%llx) inferID=0x%llx status=%s reason=%d",
		sph_trace_op_state_to_str[__entry->state],
		__entry->ctxID,
		__entry->netID,
		__entry->subNetId,
		__entry->internalNetId,
		__entry->inferID,
		sph_trace_op_status_to_str[__entry->status],
		__entry->reason)
);

/*	======== ResourceRelease ============*/

TRACE_EVENT(SPH_TRACE_ICEDRV_RESOURCE_RELEASE,
	TP_PROTO(u8 state, u64 ctxID, u64 netID,
		u64 subNetId, u64 internalNetId, u8 resResource,
		u64 icesReserved, u64 countersReserved, u32 *llcReserved),
	TP_ARGS(state, ctxID, netID, subNetId, internalNetId, resResource,
		icesReserved, countersReserved, llcReserved),
	SPH_TP_STRUCT__entry(
		__field(u8, state)
		__field(u64, ctxID)
		__field(u64, netID)
		__field(u64, subNetId)
		__field(u64, internalNetId)
		__field(u8, resResource)
		__field(u64, icesReserved)
		__field(u64, countersReserved)
		__array(u32, llcReserved, 4)
	),
	SPH_TP_fast_assign(
		__entry->state = state;
		__entry->ctxID = ctxID;
		__entry->netID = netID;
		__entry->subNetId = subNetId;
		__entry->internalNetId = internalNetId;
		__entry->resResource = resResource;
		__entry->icesReserved = icesReserved;
		__entry->countersReserved = countersReserved;
		memcpy(__entry->llcReserved, llcReserved, sizeof(u32)*4);
	),
	SPH_TP_printk(
		"state=%s ctxID=%llu netID=0x%llx subNetId=0x%llx(0x%llx) resResourceFlag=%d Released (ICEMask=0x%llx, CounterMask=0x%llx, clos{C0=%u C1=%u C2=%u C3=%u})",
		sph_trace_op_state_to_str[__entry->state],
		__entry->ctxID,
		__entry->netID,
		__entry->subNetId,
		__entry->internalNetId,
		__entry->resResource,
		__entry->icesReserved,
		__entry->countersReserved,
		__entry->llcReserved[0],
		__entry->llcReserved[1],
		__entry->llcReserved[2],
		__entry->llcReserved[3])
);


TRACE_EVENT(SPH_TRACE_ICEDRV_EXECUTE_NETWORK,
	TP_PROTO(u8 state, u64 ctxID, u64 netID,
		u64 subNetId, u64 internalNetId,
		u64 inferID, u8 status, s64 reason),
	TP_ARGS(state, ctxID, netID, subNetId, internalNetId,
		inferID, status, reason),
	SPH_TP_STRUCT__entry(
			__field(u8, state)
			__field(u64, ctxID)
			__field(u64, netID)
			__field(u64, subNetId)
			__field(u64, internalNetId)
			__field(u64, inferID)
			__field(u8, status)
			__field(s64, reason)
	),
	SPH_TP_fast_assign(
			__entry->state = state;
			__entry->ctxID = ctxID;
			__entry->netID = netID;
			__entry->subNetId = subNetId;
			__entry->internalNetId = internalNetId;
			__entry->inferID = inferID;
			__entry->status = status;
			__entry->reason = reason;
	),
	SPH_TP_printk(
		"state=%s ctxID=%llu netID=0x%llx subNetId=0x%llx(0x%llx) inferID=0x%llx %s=0x%llx",
		sph_trace_op_state_to_str[__entry->state],
		__entry->ctxID,
		__entry->netID,
		__entry->subNetId,
		__entry->internalNetId,
		__entry->inferID,
		sph_trace_op_status_to_str[__entry->status],
		__entry->reason)
);

TRACE_EVENT(SPH_TRACE_ICEDRV_EVENT_GENERATION,
	TP_PROTO(u8 state, u64 ctxID, u64 netID,
		u64 subNetId, u64 internalNetId,
		u64 inferID, u8 status, s64 reason),
	TP_ARGS(state, ctxID, netID, subNetId, internalNetId,
		inferID, status, reason),
	SPH_TP_STRUCT__entry(
			__field(u8, state)
			__field(u64, ctxID)
			__field(u64, netID)
			__field(u64, subNetId)
			__field(u64, internalNetId)
			__field(u64, inferID)
			__field(u8, status)
			__field(s64, reason)
	),
	SPH_TP_fast_assign(
			__entry->state = state;
			__entry->ctxID = ctxID;
			__entry->netID = netID;
			__entry->subNetId = subNetId;
			__entry->internalNetId = internalNetId;
			__entry->inferID = inferID;
			__entry->status = status;
			__entry->reason = reason;
	),
	SPH_TP_printk(
		"state=%s ctxID=%llu netID=0x%llx subNetId=0x%llx(0x%llx) inferID=0x%llx %s=%lld",
		sph_trace_op_state_to_str[__entry->state],
		__entry->ctxID,
		__entry->netID,
		__entry->subNetId,
		__entry->internalNetId,
		__entry->inferID,
		sph_trace_op_status_to_str[__entry->status],
		__entry->reason)
);

TRACE_EVENT(SPH_TRACE_ICEDRV_NETWORK_RESOURCE,
	TP_PROTO(u8 state, u64 ctxID, u64 netID,
		u64 subNetId, u64 internalNetId,
		u64 icesReserved, u64 countersReserved, u32 *llcReserved),
	TP_ARGS(state, ctxID, netID, subNetId, internalNetId,
		icesReserved, countersReserved, llcReserved),
	SPH_TP_STRUCT__entry(
		__field(u8, state)
		__field(u64, ctxID)
		__field(u64, netID)
		__field(u64, subNetId)
		__field(u64, internalNetId)
		__field(u64, icesReserved)
		__field(u64, countersReserved)
		__array(u32, llcReserved, 4)
	),
	SPH_TP_fast_assign(
		__entry->state = state;
		__entry->ctxID = ctxID;
		__entry->netID = netID;
		__entry->subNetId = subNetId;
		__entry->internalNetId = internalNetId;
		__entry->icesReserved = icesReserved;
		__entry->countersReserved = countersReserved;
		memcpy(__entry->llcReserved, llcReserved, sizeof(u32)*4);
	),
	SPH_TP_printk(
		"state=%s ctxID=%llu netID=0x%llx subNetId=0x%llx(0x%llx) Reserved (ICEMask=0x%llx, CounterMask=0x%llx, clos{C0=%u C1=%u C2=%u C3=%u})",
		sph_trace_op_state_to_str[__entry->state],
		__entry->ctxID,
		__entry->netID,
		__entry->subNetId,
		__entry->internalNetId,
		__entry->icesReserved,
		__entry->countersReserved,
		__entry->llcReserved[0],
		__entry->llcReserved[1],
		__entry->llcReserved[2],
		__entry->llcReserved[3])
);

TRACE_EVENT(SPH_TRACE_ICEDRV_DESTROY_NETWORK,
	TP_PROTO(u8 state, u64 ctxID, u64 netID,
		u64 subNetId, u64 internalNetId,
		u8 status, int reason),
	TP_ARGS(state, ctxID, netID, subNetId, internalNetId, status, reason),
	SPH_TP_STRUCT__entry(
			__field(u8, state)
			__field(u64, ctxID)
			__field(u64, netID)
			__field(u64, subNetId)
			__field(u64, internalNetId)
			__field(u8, status)
			__field(int, reason)
	),
	SPH_TP_fast_assign(
			__entry->state = state;
			__entry->ctxID = ctxID;
			__entry->netID = netID;
			__entry->subNetId = subNetId;
			__entry->internalNetId = internalNetId;
			__entry->status = status;
			__entry->reason = reason;
	),
	SPH_TP_printk(
		"state=%s ctxID=%llu netID=0x%llx subNetId=0x%llx(0x%llx) status=%s reason=%d",
		sph_trace_op_state_to_str[__entry->state],
		__entry->ctxID,
		__entry->netID,
		__entry->subNetId,
		__entry->internalNetId,
		sph_trace_op_status_to_str[__entry->status],
		__entry->reason)
);

TRACE_EVENT(SPH_TRACE_ICEDRV_DESTROY_CONTEXT,
	TP_PROTO(u8 state, u64 ctxID, u64 internalctxId, u8 status, int reason),
	TP_ARGS(state, ctxID, internalctxId, status, reason),
	SPH_TP_STRUCT__entry(
			__field(u8, state)
			__field(u64, ctxID)
			__field(u64, internalctxId)
			__field(u8, status)
			__field(int, reason)
	),
	SPH_TP_fast_assign(
			__entry->state = state;
			__entry->ctxID = ctxID;
			__entry->internalctxId = internalctxId;
			__entry->status = status;
			__entry->reason = reason;
	),
	SPH_TP_printk("state=%s ctxID=%llu(%llx) status=%s reason=%d",
		sph_trace_op_state_to_str[__entry->state],
		__entry->ctxID, __entry->internalctxId,
		sph_trace_op_status_to_str[__entry->status],
		__entry->reason)
);

TRACE_EVENT(SPH_TRACE_ICEDRV_TOP_HALF,
	TP_PROTO(u8 state, u64 icedc_status,
			u32 ice_status, u32 ice_error, u8 status, int reason),
	TP_ARGS(state, icedc_status, ice_status, ice_error, status, reason),
	SPH_TP_STRUCT__entry(
			__field(u8, state)
			__field(u64, icedc_status)
			__field(u32, ice_status)
			__field(u32, ice_error)
			__field(u8, status)
			__field(int, reason)
	),
	SPH_TP_fast_assign(
			__entry->state = state;
			__entry->icedc_status = icedc_status;
			__entry->ice_status = ice_status;
			__entry->ice_error = ice_error;
			__entry->status = status;
			__entry->reason = reason;
	),
	SPH_TP_printk(
		"state=%s icedc_status=0x%llx ice_status=0x%x ice_error=0x%x %s=%d",
		sph_trace_op_state_to_str[__entry->state],
		__entry->icedc_status, __entry->ice_status, __entry->ice_error,
		sph_trace_op_status_to_str[__entry->status],
		__entry->reason)
);

TRACE_EVENT(SPH_TRACE_ICEDRV_BOTTOM_HALF,
	TP_PROTO(u8 state, u64 icedc_status,
			u32 ice_status, u32 ice_error, u8 status, int reason),
	TP_ARGS(state, icedc_status, ice_status, ice_error, status, reason),
	SPH_TP_STRUCT__entry(
			__field(u8, state)
			__field(u64, icedc_status)
			__field(u32, ice_status)
			__field(u32, ice_error)
			__field(u8, status)
			__field(int, reason)
	),
	SPH_TP_fast_assign(
			__entry->state = state;
			__entry->icedc_status = icedc_status;
			__entry->ice_status = ice_status;
			__entry->ice_error = ice_error;
			__entry->status = status;
			__entry->reason = reason;
	),
	SPH_TP_printk(
		"state=%s icedc_status=0x%llx ice_status=0x%x ice_error=0x%x %s=%d",
		sph_trace_op_state_to_str[__entry->state],
		__entry->icedc_status, __entry->ice_status, __entry->ice_error,
		sph_trace_op_status_to_str[__entry->status],
		__entry->reason)
);


TRACE_EVENT(SPH_TRACE_ICEDRV_SCHEDULE_INFER,
	TP_PROTO(u8 state, u64  ctxID,
			u64 netID, u64 subNetId, u64 internalNetId,
			u64 inferID, u8 status, int reason),
	TP_ARGS(state, ctxID, netID, subNetId, internalNetId,
		inferID, status, reason),
	SPH_TP_STRUCT__entry(
			__field(u8, state)
			__field(u64, ctxID)
			__field(u64, netID)
			__field(u64, subNetId)
			__field(u64, internalNetId)
			__field(u64, inferID)
			__field(u8, status)
			__field(int, reason)
	),
	SPH_TP_fast_assign(
			__entry->state = state;
			__entry->ctxID = ctxID;
			__entry->netID = netID;
			__entry->subNetId = subNetId;
			__entry->internalNetId = internalNetId;
			__entry->inferID = inferID;
			__entry->status = status;
			__entry->reason = reason;
	),
	SPH_TP_printk(
		"state=%s ctxID=%llu netID=0x%llx subNetId=0x%llx(0x%llx) inferID=0x%llx %s=0x%x",
		sph_trace_op_state_to_str[__entry->state],
		__entry->ctxID,
		__entry->netID,
		__entry->subNetId,
		__entry->internalNetId,
		__entry->inferID,
		sph_trace_op_status_to_str[__entry->status],
		__entry->reason)
);

TRACE_EVENT(SPH_TRACE_ICEDRV_SCHEDULE_JOB,
	TP_PROTO(u8 state, u32 iceID, u64 ctxId,
			u64 netID, u64 subNetId, u64 internalNetId,
			u64 inferID, void *jobId,
			u8 status, int64_t reason),
	TP_ARGS(state, iceID, ctxId, netID, subNetId, internalNetId, inferID,
		jobId, status, reason),
	SPH_TP_STRUCT__entry(
			__field(u8, state)
			__field(u32, iceID)
			__field(u64, ctxId)
			__field(u64, netID)
			__field(u64, subNetId)
			__field(u64, internalNetId)
			__field(u64, inferID)
			__field(void *, jobId)
			__field(u8, status)
			__field(int64_t, reason)
	),
	SPH_TP_fast_assign(
			__entry->state = state;
			__entry->iceID = iceID;
			__entry->ctxId = ctxId;
			__entry->netID = netID;
			__entry->subNetId = subNetId;
			__entry->internalNetId = internalNetId;
			__entry->inferID = inferID;
			__entry->jobId = jobId;
			__entry->status = status;
			__entry->reason = reason;
	),
	SPH_TP_printk(
		"state=%s iceId=%u ctx=0x%llx netID=0x%llx subNetId=0x%llx(0x%llx) inferID=0x%llx jobId=0x%p %s=%lld",
		sph_trace_op_state_to_str[__entry->state],
		__entry->iceID, __entry->ctxId,
		__entry->netID, __entry->subNetId, __entry->internalNetId,
		__entry->inferID, __entry->jobId,
		sph_trace_op_status_to_str[__entry->status],
		__entry->reason)
);

TRACE_EVENT(SPH_TRACE_ICEDRV_POWER_ON,
	TP_PROTO(u8 state, u32 iceID, u64 ctxId,
			u64 netID, u64 subNetId, u64 internalNetId,
			u64 inferID, u64 timeStamp,
			u8 status, char *marker),
	TP_ARGS(state, iceID, ctxId, netID, subNetId, internalNetId, inferID,
		timeStamp, status, marker),
	SPH_TP_STRUCT__entry(
			__field(u8, state)
			__field(u32, iceID)
			__field(u64, ctxId)
			__field(u64, netID)
			__field(u64, subNetId)
			__field(u64, internalNetId)
			__field(u64, inferID)
			__field(u64, timeStamp)
			__field(u8, status)
			__array(char, marker, 12)

	),
	SPH_TP_fast_assign(
			__entry->state = state;
			__entry->iceID = iceID;
			__entry->ctxId = ctxId;
			__entry->netID = netID;
			__entry->subNetId = subNetId;
			__entry->internalNetId = internalNetId;
			__entry->inferID = inferID;
			__entry->timeStamp = timeStamp;
			__entry->status = status;
			memcpy(__entry->marker, marker, 12);
	),
	SPH_TP_printk(
		"state=%s iceId=%u ctx=0x%llx netID=0x%llx subNetId=0x%llx(0x%llx) inferID=0x%llx timeStamp=0x%llx status=%s syncMarker=%s",
		sph_trace_op_state_to_str[__entry->state],
		__entry->iceID, __entry->ctxId,
		__entry->netID, __entry->subNetId, __entry->internalNetId,
		__entry->inferID, __entry->timeStamp,
		sph_trace_op_status_to_str[__entry->status],
		__entry->marker)
);
#endif /* if !defined(_TRACE_SYNC_H) || defined(TRACE_HEADER_MULTI_READ) */

/* This part must be outside protection */
#include <trace/define_trace.h>
