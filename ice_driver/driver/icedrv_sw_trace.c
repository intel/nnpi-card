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

#define CREATE_TRACE_POINTS
#include "icedrv_sw_trace.h"

char *sph_trace_op_state_to_str[SPH_TRACE_OP_STATE_NUM + 1];
char *sph_trace_op_status_to_str[SPH_TRACE_OP_STATUS_NUM + 1];

void icedrv_sw_trace_init(void)
{
/*fill sph_trace_op_state_to_str array*/
sph_trace_op_state_to_str[SPH_TRACE_OP_STATE_QUEUED]  = SPH_TRACE_STR_QUEUED;
sph_trace_op_state_to_str[SPH_TRACE_OP_STATE_START]   = SPH_TRACE_STR_START;
sph_trace_op_state_to_str[SPH_TRACE_OP_STATE_COMPLETE] = SPH_TRACE_STR_COMPLETE;
sph_trace_op_state_to_str[SPH_TRACE_OP_STATE_ABORT]   = SPH_TRACE_STR_ABORT;
sph_trace_op_state_to_str[SPH_TRACE_OP_STATE_DB]   = SPH_TRACE_STR_DB;
sph_trace_op_state_to_str[SPH_TRACE_OP_STATE_ADD]   = SPH_TRACE_STR_ADD;
sph_trace_op_state_to_str[SPH_TRACE_OP_STATE_REQ]   = SPH_TRACE_STR_REQ;
sph_trace_op_state_to_str[SPH_TRACE_OP_STATE_BH]   = SPH_TRACE_STR_BH;
sph_trace_op_state_to_str[SPH_TRACE_OP_STATE_NUM]     = SPH_TRACE_STR_UNDEF;

/*fill sph_trace_op_status_to_str array*/
sph_trace_op_status_to_str[SPH_TRACE_OP_STATUS_PASS]   = SPH_TRACE_STR_PASS;
sph_trace_op_status_to_str[SPH_TRACE_OP_STATUS_FAIL]   = SPH_TRACE_STR_FAIL;
sph_trace_op_status_to_str[SPH_TRACE_OP_STATUS_NULL]   = SPH_TRACE_STR_NULL;
sph_trace_op_status_to_str[SPH_TRACE_OP_STATUS_MAX] = SPH_TRACE_STR_MAX;
sph_trace_op_status_to_str[SPH_TRACE_OP_STATUS_ICE] = SPH_TRACE_STR_ICE;
sph_trace_op_status_to_str[SPH_TRACE_OP_STATUS_PRIORITY] =
	SPH_TRACE_STR_PRIORITY;
sph_trace_op_status_to_str[SPH_TRACE_OP_STATUS_TIME] = SPH_TRACE_STR_TIME;
sph_trace_op_status_to_str[SPH_TRACE_OP_STATUS_LOCATION] =
	SPH_TRACE_STR_LOCATION;
sph_trace_op_status_to_str[SPH_TRACE_OP_STATUS_PERF] = SPH_TRACE_STR_PERF;
sph_trace_op_status_to_str[SPH_TRACE_OP_STATUS_Q_HEAD] = SPH_TRACE_STR_Q_HEAD;
sph_trace_op_status_to_str[SPH_TRACE_OP_STATUS_Q_TAIL] = SPH_TRACE_STR_Q_TAIL;
sph_trace_op_status_to_str[SPH_TRACE_OP_STATUS_EXEC_TYPE] =
	SPH_TRACE_STR_EXEC_TYPE;
sph_trace_op_status_to_str[SPH_TRACE_OP_STATUS_CDYN_VAL] =
	SPH_TRACE_STR_CDYN_VAL;
sph_trace_op_status_to_str[SPH_TRACE_OP_STATUS_NUM]    = SPH_TRACE_STR_UNDEF;

}