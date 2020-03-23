



/*******************************************************************************
 * INTEL CORPORATION CONFIDENTIAL Copyright(c) 2017-2020 Intel Corporation. All Rights Reserved.
 *
 * The source code contained or described herein and all documents related to the
 * source code ("Material") are owned by Intel Corporation or its suppliers or
 * licensors. Title to the Material remains with Intel Corporation or its suppliers
 * and licensors. The Material contains trade secrets and proprietary and
 * confidential information of Intel or its suppliers and licensors. The Material
 * is protected by worldwide copyright and trade secret laws and treaty provisions.
 * No part of the Material may be used, copied, reproduced, modified, published,
 * uploaded, posted, transmitted, distributed, or disclosed in any way without
 * Intel's prior express written permission.
 *
 * No license under any patent, copyright, trade secret or other intellectual
 * property right is granted to or conferred upon you by disclosure or delivery of
 * the Materials, either expressly, by implication, inducement, estoppel or
 * otherwise. Any license under such intellectual property rights must be express
 * and approved by Intel in writing.
 ********************************************************************************/

#ifndef _SPH_TRACE_FORMAT_H
#define _SPH_TRACE_FORMAT_H


#define SPH_TRACE_COPY			 copy
#define SPH_TRACE_INFREQ		 infreq
#define SPH_TRACE_CMDLIST		 cmdlist
#define SPH_TRACE_CPYLIST_CREATE cpylist_create
#define SPH_TRACE_DMA			 dma
#define SPH_TRACE_INF_CREATE	 infer_create
#define SPH_TRACE_INF_NET_SUBRES inf_net_subres
#define SPH_TRACE_IPC			 _ipc
#define SPH_TRACE_MMIO			 pep_mmio
#define SPH_TRACE_USER_DATA		 user_data

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
#define SPH_TRACE_STR_H2C_COPY_HANDLE		"h2c_copy_handle"
#define SPH_TRACE_STR_C2H_COPY_HANDLE		"c2h_copy_handle"
#define SPH_TRACE_STR_NETWORK			"network"
#define SPH_TRACE_STR_INF_REQ			"inf_req"
#define SPH_TRACE_STR_SUBRES_CREATE_SESSION	"subres_remote_session"
#define SPH_TRACE_STR_INF_SYNC			"sync"
#define SPH_TRACE_STR_COMMAND_LIST		"cmd_list"
#define SPH_TRACE_STR_ADD_TO_COPY_LIST	"add_to_cpylist"
#define SPH_TRACE_STR_UNDEFINED "undefined"


#endif /* _SPH_TRACE_FORMAT_H */
