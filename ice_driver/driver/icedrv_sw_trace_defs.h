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

#ifndef _ICEDRV_TRACE_DEFS_H
#define _ICEDRV_TRACE_DEFS_H


enum sph_trace_op_state_enum  {
	SPH_TRACE_OP_STATE_QUEUED       = 0, /*SPH_TRACE_STR_QUEUED*/
	SPH_TRACE_OP_STATE_START        = 1, /*SPH_TRACE_STR_START*/
	SPH_TRACE_OP_STATE_COMPLETE     = 2, /*SPH_TRACE_STR_COMPLETE*/
	SPH_TRACE_OP_STATE_ABORT        = 3, /*SPH_TRACE_STR_ABORT*/
	SPH_TRACE_OP_STATE_NUM          = 4  /*SPH_TRACE_STR_UNDEF*/
};

enum sph_trace_op_status_enum {
	SPH_TRACE_OP_STATUS_PASS        = 0, /*SPH_TRACE_STR_PASS*/
	SPH_TRACE_OP_STATUS_FAIL        = 1, /*SPH_TRACE_STR_FAIL*/
	SPH_TRACE_OP_STATUS_NULL        = 2, /*SPH_TRACE_STR_NULL*/
	SPH_TRACE_OP_STATUS_NUM         = 3  /*SPH_TRACE_STR_UNDEF*/
};


extern char *sph_trace_op_state_to_str[];
extern char *sph_trace_op_status_to_str[];
#endif /* _SPHCS_TRACE_DEFS_H */

