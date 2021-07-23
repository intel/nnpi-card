/* SPDX-License-Identifier: GPL-2.0-or-later */

/********************************************
 * Copyright (C) 2019-2021 Intel Corporation
 ********************************************/
#undef TRACE_SYSTEM
#define TRACE_INCLUDE_PATH .
#define TRACE_INCLUDE_FILE nnpdrv_trace
#define TRACE_SYSTEM nnpdrv

#if !defined(_NNPDRV_TRACE_H) || defined(TRACE_HEADER_MULTI_READ)
#define _NNPDRV_TRACE_H

#include "trace_defs.h"
#include <linux/tracepoint.h>
#include "ipc_protocol.h"
#include "device.h"

#ifdef TRACE
#define DO_TRACE(x) (x)
#else
#define DO_TRACE(x)
#endif

#define NNP_TP_STRUCT__entry TP_STRUCT__entry
#define NNP_TP_fast_assign   TP_fast_assign
#define NNP_TP_printk        TP_printk

/* Define functions to convert protocol opcode codes to names */
#ifndef TRACE_HEADER_MULTI_READ
static inline const char *H2C_HWQ_MSG_STR(u8 x)
{
	switch (x) {
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

static inline const char *C2H_HWQ_MSG_STR(u8 x)
{
	switch (x) {
	case C2H_OPCODE_NAME(EVENT_REPORT):
		return C2H_OPCODE_NAME_STR(EVENT_REPORT);
	case C2H_OPCODE_NAME(QUERY_VERSION_REPLY):
		return C2H_OPCODE_NAME_STR(QUERY_VERSION_REPLY);
	case C2H_OPCODE_NAME(QUERY_VERSION_REPLY2):
		return C2H_OPCODE_NAME_STR(QUERY_VERSION_REPLY2);
	case C2H_OPCODE_NAME(SYS_INFO):
		return C2H_OPCODE_NAME_STR(SYS_INFO);
	case C2H_OPCODE_NAME(BIOS_PROTOCOL):
		return C2H_OPCODE_NAME_STR(BIOS_PROTOCOL);
	default:
		return "not found";
	}
}
#endif

TRACE_EVENT(hostres,
	    TP_PROTO(u32 lock_state, u32 is_user,
		     u64 handle, int readers, u32 is_read),
	    TP_ARGS(lock_state, is_user, handle, readers, is_read),
	    NNP_TP_STRUCT__entry(__field(u64, handle)
				 __field(u32, lock_state)
				 __field(u32, is_user)
				 __field(u32, is_read)
				 __field(int, readers)),
	    NNP_TP_fast_assign(__entry->lock_state = lock_state;
			       __entry->is_user = is_user;
			       __entry->handle  = handle;
			       __entry->readers = readers;
			       __entry->is_read = is_read;),
	    NNP_TP_printk(
		"lock_state=%s is_user=%d handle=0x%llx readers=%d is_read=%d",
		__NNP_TRACE_LOCK_STR(__entry->lock_state),
		__entry->is_user,
		__entry->handle,
		__entry->readers,
		__entry->is_read)
);

TRACE_EVENT(NNP_TRACE_IPC,
	    TP_PROTO(u8 dir, u64 *msg, u32 size, u8 card_id),
	    TP_ARGS(dir, msg, size, card_id),
	    NNP_TP_STRUCT__entry(__field(u64, msg[4])
				 __field(u32, size)
				 __field(u8, dir)
				 __field(u8, card_id)),
	    NNP_TP_fast_assign(__entry->msg[0] = msg[0];
			       __entry->msg[1] = (size > 1 ? msg[1] : 0);
			       __entry->msg[2] = (size > 2 ? msg[2] : 0);
			       __entry->msg[3] = (size > 3 ? msg[3] : 0);
			       __entry->size = size;
			       __entry->card_id = card_id;
			       __entry->dir = dir),
	    NNP_TP_printk(
		"card_id=%u dir=%s op=%s size=%u payload=0x%llx,0x%llx,0x%llx,0x%llx",
		__entry->card_id,
		__entry->dir == 0 ? "command" : "response",
		__entry->dir == 0 ?
		H2C_HWQ_MSG_STR(__entry->msg[0] & NNP_IPC_OPCODE_MASK) :
		C2H_HWQ_MSG_STR(__entry->msg[0] & NNP_IPC_OPCODE_MASK),
		__entry->size,
		__entry->msg[0],
		__entry->msg[1],
		__entry->msg[2],
		__entry->msg[3])
);

TRACE_EVENT(NNP_TRACE_CLOCK_STAMP,
	    TP_PROTO(char *type, u64 clock, u8 card_id),
	    TP_ARGS(type, clock, card_id),
	    NNP_TP_STRUCT__entry(__field(char, type[8])
				 __field(u64, clock)
				 __field(u8, card_id)),
	    NNP_TP_fast_assign(__entry->type[0] = type[0];
			       __entry->type[1] = type[1];
			       __entry->type[2] = type[2];
			       __entry->type[3] = type[3];
			       __entry->type[4] = type[4];
			       __entry->type[5] = type[5];
			       __entry->type[6] = type[6];
			       __entry->type[7] = type[7];
			       __entry->clock = clock;
			       __entry->card_id = card_id;),
	NNP_TP_printk("card_id=%u type=%s clock=%llu",
		      __entry->card_id,
		      __entry->type,
		      __entry->clock)
);

#endif /* if !defined(_TRACE_SYNC_H) || defined(TRACE_HEADER_MULTI_READ) */

/* This part must be outside protection */
#include <trace/define_trace.h>
