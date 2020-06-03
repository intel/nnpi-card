/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#define CREATE_TRACE_POINTS
#include "sphcs_trace.h"

char *sph_trace_op_to_str[SPH_TRACE_OP_STATUS_NUM + 1];
char *sph_trace_inf_to_str[SPH_TRACE_INF_NUM + 1];

void sphcs_trace_init(void)
{
	// fill sph_trace_op_to_str array
	sph_trace_op_to_str[SPH_TRACE_OP_STATUS_QUEUED]		= SPH_TRACE_STR_QUEUED;
	sph_trace_op_to_str[SPH_TRACE_OP_STATUS_START]		= SPH_TRACE_STR_START;
	sph_trace_op_to_str[SPH_TRACE_OP_STATUS_COMPLETE]	= SPH_TRACE_STR_COMPLETE;
	sph_trace_op_to_str[SPH_TRACE_OP_STATUS_CB_START]	= SPH_TRACE_STR_CB_START;
	sph_trace_op_to_str[SPH_TRACE_OP_STATUS_CB_COMPLETE]	= SPH_TRACE_STR_CB_COMPLETE;
	sph_trace_op_to_str[SPH_TRACE_OP_STATUS_CB_NW_COMPLETE]	= SPH_TRACE_STR_CB_NW_COMPLETE;
	sph_trace_op_to_str[SPH_TRACE_OP_STATUS_NUM]		= SPH_TRACE_STR_UNDEFINED;


	// fill sph_trace_inf_to_str array
	sph_trace_inf_to_str[SPH_TRACE_INF_CONTEXT]		= SPH_TRACE_STR_CONTEXT;
	sph_trace_inf_to_str[SPH_TRACE_INF_DEVRES]		= SPH_TRACE_STR_DEVRES;
	sph_trace_inf_to_str[SPH_TRACE_INF_COPY]		= SPH_TRACE_STR_COPY;
	sph_trace_inf_to_str[SPH_TRACE_INF_HOSTRES]		= SPH_TRACE_STR_HOSTRES;
	sph_trace_inf_to_str[SPH_TRACE_INF_H2C_COPY_HANDLE]	= SPH_TRACE_STR_H2C_COPY_HANDLE;
	sph_trace_inf_to_str[SPH_TRACE_INF_C2H_COPY_HANDLE]	= SPH_TRACE_STR_C2H_COPY_HANDLE;
	sph_trace_inf_to_str[SPH_TRACE_INF_P2P_COPY_HANDLE]	= SPH_TRACE_STR_P2P_COPY_HANDLE;
	sph_trace_inf_to_str[SPH_TRACE_INF_NETWORK]		= SPH_TRACE_STR_NETWORK;
	sph_trace_inf_to_str[SPH_TRACE_INF_INF_REQ]		= SPH_TRACE_STR_INF_REQ;
	sph_trace_inf_to_str[SPH_TRACE_INF_INF_SYNC]		= SPH_TRACE_STR_INF_SYNC;
	sph_trace_inf_to_str[SPH_TRACE_INF_COMMAND_LIST]	= SPH_TRACE_STR_COMMAND_LIST;
	sph_trace_inf_to_str[SPH_TRACE_INF_ADD_TO_COPY_LIST]	= SPH_TRACE_STR_ADD_TO_COPY_LIST;
	sph_trace_inf_to_str[SPH_TRACE_INF_NUM]			= SPH_TRACE_STR_UNDEFINED;
}
