/********************************************
 * Copyright (C) 2019-2021 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/



#ifndef _ICEDRV_TRACE_DEFS_H
#define _ICEDRV_TRACE_DEFS_H


enum sph_trace_op_state_enum  {
	SPH_TRACE_OP_STATE_QUEUED       = 0, /*SPH_TRACE_STR_QUEUED*/
	SPH_TRACE_OP_STATE_START        = 1, /*SPH_TRACE_STR_START*/
	SPH_TRACE_OP_STATE_COMPLETE     = 2, /*SPH_TRACE_STR_COMPLETE*/
	SPH_TRACE_OP_STATE_ABORT        = 3, /*SPH_TRACE_STR_ABORT*/
	SPH_TRACE_OP_STATE_DB           = 4, /*SPH_TRACE_STR_DB*/
	SPH_TRACE_OP_STATE_REQ          = 5, /*SPH_TRACE_STR_REQ*/
	SPH_TRACE_OP_STATE_ADD          = 6, /*SPH_TRACE_STR_ADD add data to Q*/
	SPH_TRACE_OP_STATE_BH           = 7, /*SPH_TRACE_STR_BH*/
	SPH_TRACE_OP_STATE_PO           = 8, /*SPH_TRACE_STR_PO*/
	SPH_TRACE_OP_STATE_NUM          = 9  /*SPH_TRACE_STR_UNDEF*/
};

enum sph_trace_op_status_enum {
	SPH_TRACE_OP_STATUS_PASS        = 0, /*SPH_TRACE_STR_PASS*/
	SPH_TRACE_OP_STATUS_FAIL        = 1, /*SPH_TRACE_STR_FAIL*/
	SPH_TRACE_OP_STATUS_NULL        = 2, /*SPH_TRACE_STR_NULL*/
	SPH_TRACE_OP_STATUS_MAX         = 3, /*SPH_TRACE_STR_MAX*/
	SPH_TRACE_OP_STATUS_ICE         = 4, /*SPH_TRACE_STR_ICE*/
	SPH_TRACE_OP_STATUS_PRIORITY    = 5, /*SPH_TRACE_STR_PRIORITY*/
	SPH_TRACE_OP_STATUS_TIME        = 6, /*SPH_TRACE_STR_TIME*/
	SPH_TRACE_OP_STATUS_LOCATION    = 7, /*SPH_TRACE_STR_LOCATION*/
	SPH_TRACE_OP_STATUS_PERF        = 8, /*SPH_TRACE_STR_PERF */
	SPH_TRACE_OP_STATUS_Q_HEAD      = 9, /* SPH_TRACE_STR_Q_HEAD */
	SPH_TRACE_OP_STATUS_Q_TAIL      = 10, /* SPH_TRACE_STR_Q_TAIL */
	SPH_TRACE_OP_STATUS_EXEC_TYPE   = 11, /* SPH_TRACE_STR_EXEC_TYPE */
	SPH_TRACE_OP_STATUS_CDYN_VAL    = 12, /* SPH_TRACE_STR_CDYN_VAL */
	SPH_TRACE_OP_STATUS_POWERED_ON  = 13, /* SPH_TRACE_STR_POWERED_ON */
	SPH_TRACE_OP_STATUS_NUM         = 14  /*SPH_TRACE_STR_UNDEF*/
};


extern char *sph_trace_op_state_to_str[];
extern char *sph_trace_op_status_to_str[];
#endif /* _SPHCS_TRACE_DEFS_H */

