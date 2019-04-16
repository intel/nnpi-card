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

#ifndef _SPH_TRACE_FORMAT_H
#define _SPH_TRACE_FORMAT_H

#define SPH_TRACE_ICEDRV_CREATE_CONTEXT           icedrvCreateContext
#define SPH_TRACE_ICEDRV_CREATE_NETWORK           icedrvCreateNetwork
#define SPH_TRACE_ICEDRV_EXECUTE_NETWORK          icedrvExecuteNetwork
#define SPH_TRACE_ICEDRV_NETWORK_RESOURCE         icedrvNetworkResource
#define SPH_TRACE_ICEDRV_DESTROY_NETWORK          icedrvDestroyNetwork
#define SPH_TRACE_ICEDRV_DESTROY_CONTEXT          icedrvDestroyContext

#define SPH_TRACE_FIELD_STATE           "state"

#define SPH_TRACE_STR_QUEUED    "q"    /* state - q: operation is in queue*/
#define SPH_TRACE_STR_START     "s"    /* state - s: operation has began*/
#define SPH_TRACE_STR_COMPLETE  "c"    /* state - c: operation has completed*/
#define SPH_TRACE_STR_ABORT     "a"    /* state - a: operation has aborted*/
#define SPH_TRACE_STR_PASS      "pass" /* status - pass: operation passed*/
#define SPH_TRACE_STR_FAIL      "fail" /* status - fail: operation failed */

/*driver commands*/

#define SPH_TRACE_STR_CREATE_CTXT               "create_context"
#define SPH_TRACE_STR_CREATE_NTW                "create_network"
#define SPH_TRACE_STR_EXECUTE_NTW               "execute_network"
#define SPH_TRACE_STR_NTW_RESOURCE              "network_resource"
#define SPH_TRACE_STR_DESTROY_NTW               "destroy_network"
#define SPH_TRACE_STR_DESTROY_CTXT              "destroy_context"
#define SPH_TRACE_STR_UNDEF                     "undefined"
#define SPH_TRACE_STR_NULL                      "NULL"

#endif /* _SPH_TRACE_FORMAT_H */

