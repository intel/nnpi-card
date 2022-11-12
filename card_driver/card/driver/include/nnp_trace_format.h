/********************************************
 * Copyright (C) 2019-2021 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/
#ifndef _NNP_TRACE_FORMAT_H
#define _NNP_TRACE_FORMAT_H


#define SPH_TRACE_COPY			 copy
#define SPH_TRACE_CREDIT		 credit
#define SPH_TRACE_INFREQ		 infreq
#define SPH_TRACE_CMDLIST		 cmdlist
#define SPH_TRACE_CPYLIST_CREATE cpylist_create
#define SPH_TRACE_DMA			 dma
#define SPH_TRACE_INF_CREATE		 infer_create
#define SPH_TRACE_COPY_CREATE		 copy_create
#define NNP_TRACE_IPC			 _ipc
#define NNP_TRACE_MMIO			 pep_mmio
#define SPH_TRACE_USER_DATA		 user_data
#define SPH_TRACE_IDS_MAP		 ids_map
#define NNP_TRACE_CLOCK_STAMP		 clock_stamp
#define SPH_TRACE_HWTRACE		 hwtrace

#define SPH_TRACE_FIELD_STATE		"state"

#define SPH_TRACE_STR_QUEUED    "q"	// state - q: operation is in queue
#define SPH_TRACE_STR_START     "s"	// state - s: operation has began
#define SPH_TRACE_STR_COMPLETE  "c"	// state - c: operation has completed
#define SPH_TRACE_STR_CB_START		"cbs"   // state - cbs: callback function of operation has began
#define SPH_TRACE_STR_CB_COMPLETE	"cbc"   // state - cbc: callback function of operation has completed
#define SPH_TRACE_STR_CB_NW_COMPLETE	"cbnwc" // state - cbnwc: callback ran from the interrupt and completed

// inf create command
#define SPH_TRACE_STR_CONTEXT			"context"
#define SPH_TRACE_STR_DEVRES			"device_resource"
#define SPH_TRACE_STR_COPY			"copy"
#define SPH_TRACE_STR_HOSTRES			"host_resourse"
#define SPH_TRACE_STR_H2C_COPY_HANDLE		"h2c_copy_handle"
#define SPH_TRACE_STR_C2H_COPY_HANDLE		"c2h_copy_handle"
#define SPH_TRACE_STR_P2P_COPY_HANDLE		"p2p_copy_handle"
#define SPH_TRACE_STR_NETWORK			"network"
#define SPH_TRACE_STR_INF_REQ			"inf_req"
#define SPH_TRACE_STR_SUBRES_CREATE_SESSION	"subres_remote_session"
#define SPH_TRACE_STR_INF_SYNC			"sync"
#define SPH_TRACE_STR_COMMAND_LIST		"cmd_list"
#define SPH_TRACE_STR_ADD_TO_COPY_LIST	"add_to_cpylist"
#define SPH_TRACE_STR_UNDEFINED "undefined"


#endif /* _NNP_TRACE_FORMAT_H */
