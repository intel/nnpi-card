/********************************************
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/


#undef TRACE_SYSTEM
#define TRACE_INCLUDE_PATH .
#define TRACE_INCLUDE_FILE sphpb_trace
#define TRACE_SYSTEM sphpb

#if !defined(_SPHPB_TRACE_H) || defined(TRACE_HEADER_MULTI_READ)
#define _SPHPB_TRACE_H

#include "sphpb_trace_defs.h"
#include "sphpb_trace_format.h"
#include "sph_time.h"
#include <linux/tracepoint.h>

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

void sphpb_trace_init(void);

#define SPH_TP_STRUCT__entry TP_STRUCT__entry
#define SPH_TP_fast_assign   TP_fast_assign
#define SPH_TP_printk        TP_printk

TRACE_EVENT(SPHPB_TRACE_POWER_REQUEST,
	    TP_PROTO(u32 iceID, u32 ring_divisor, u32 ddr_bw),
	    TP_ARGS(iceID, ring_divisor, ddr_bw),
	    SPH_TP_STRUCT__entry(
				 __field(u32, iceID)
				 __field(u32, ring_divisor)
				 __field(u32, ddr_bw)
				 ),
	    SPH_TP_fast_assign(
			       __entry->iceID = iceID;
			       __entry->ring_divisor = ring_divisor;
			       __entry->ddr_bw = ddr_bw;
			       ),
	    SPH_TP_printk("state=s iceID=%u iceboToRingRatio=%u DRAM_BW=%u",
			  __entry->iceID,
			  __entry->ring_divisor,
			  __entry->ddr_bw)
	    );

TRACE_EVENT(SPHPB_TRACE_POWER_SET,
	    TP_PROTO(u8 state, u8 opcode, u32 ring_divisor, u32 ddr_bw),
	    TP_ARGS(state, opcode, ring_divisor, ddr_bw),
	    SPH_TP_STRUCT__entry(
				 __field(u32, ring_divisor)
				 __field(u32, ddr_bw)
				 __field(u8, opcode)
				 __field(u8, state)
				 ),
	    SPH_TP_fast_assign(
			       __entry->state = state;
			       __entry->opcode = opcode;
			       __entry->ring_divisor = ring_divisor;
			       __entry->ddr_bw = ddr_bw;
			       ),
	    SPH_TP_printk("state=%s opcode=%s iceboToRingRatio=%u DRAM_Level=%s",
			  sph_trace_op_to_str[__entry->state],
			  sph_trace_power_set_to_str[__entry->opcode],
			  __entry->ring_divisor,
			  sph_ddr_bw_to_str[__entry->ddr_bw])
	    );


#endif /* if !defined(_TRACE_SYNC_H) || defined(TRACE_HEADER_MULTI_READ) */

/* This part must be outside protection */
#include <trace/define_trace.h>
