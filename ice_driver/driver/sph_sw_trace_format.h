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
#define SPH_TRACE_ICEDRV_CREATE_INFER             _icedrvCreateInfer
#define SPH_TRACE_ICEDRV_EXECUTE_NETWORK          icedrvExecuteNetwork
#define SPH_TRACE_ICEDRV_EVENT_GENERATION         icedrvEventGeneration
#define SPH_TRACE_ICEDRV_NETWORK_RESOURCE         icedrvNetworkResource
#define SPH_TRACE_ICEDRV_RESOURCE_RELEASE         _icedrvResourceRelease
#define SPH_TRACE_ICEDRV_DESTROY_NETWORK          icedrvDestroyNetwork
#define SPH_TRACE_ICEDRV_DESTROY_CONTEXT          icedrvDestroyContext
#define SPH_TRACE_ICEDRV_SCHEDULE_INFER           _icedrvScheduleInfer
#define SPH_TRACE_ICEDRV_SCHEDULE_JOB             icedrvScheduleJob
#define SPH_TRACE_ICEDRV_TOP_HALF                 _icedrvTopHalf
#define SPH_TRACE_ICEDRV_BOTTOM_HALF              _icedrvBottomHalf


#define SPH_TRACE_FIELD_STATE           "state"

#define SPH_TRACE_STR_QUEUED    "q"    /* state - q: operation is in queue*/
#define SPH_TRACE_STR_START     "s"    /* state - s: operation has began*/
#define SPH_TRACE_STR_COMPLETE  "c"    /* state - c: operation has completed*/
#define SPH_TRACE_STR_ABORT     "a"    /* state - a: operation has aborted*/
#define SPH_TRACE_STR_PASS      "pass" /* status - pass: operation passed*/
#define SPH_TRACE_STR_FAIL      "fail" /* status - fail: operation failed */
#define SPH_TRACE_STR_DB        "db"   /* state - db: doorbell done*/
#define SPH_TRACE_STR_REQ       "req"  /* state - request: */
#define SPH_TRACE_STR_AVG       "avg"  /* state - average: */
#define SPH_TRACE_STR_ICE       "ice"  /* state - ice number or ice mask */
#define SPH_TRACE_STR_PRIORITY  "prioLevel" /* state - priority of inference */
#define SPH_TRACE_STR_TIME      "time" /* state - time */
#define SPH_TRACE_STR_LOCATION  "line" /* state - line number in the function*/
#define SPH_TRACE_STR_ADD       "add"  /* state - add: add data to a Q*/
#define SPH_TRACE_STR_BH        "bh"    /* state - bh: in bottom half*/
#define SPH_TRACE_STR_PERF      "perf"  /* state - perf: ice cycles */
#define SPH_TRACE_STR_Q_HEAD    "qhead"  /* state - qhead: isr q head */
#define SPH_TRACE_STR_Q_TAIL    "qtail"  /* state - qtail: isr q tail */
#define SPH_TRACE_STR_EXEC_TYPE "cold" /* state - type of exection cold/warm */
#define SPH_TRACE_STR_CDYN_VAL "cdyn" /* state - cdyn request value */
/*driver commands*/

#define SPH_TRACE_STR_CREATE_CTXT               "create_context"
#define SPH_TRACE_STR_CREATE_NTW                "create_network"
#define SPH_TRACE_STR_EXECUTE_NTW               "execute_network"
#define SPH_TRACE_STR_EVENT_GENERATION          "event_generation"
#define SPH_TRACE_STR_NTW_RESOURCE              "network_resource"
#define SPH_TRACE_STR_DESTROY_NTW               "destroy_network"
#define SPH_TRACE_STR_DESTROY_CTXT              "destroy_context"
#define SPH_TRACE_STR_SCHEDULE_INFER            "sch_infer"
#define SPH_TRACE_STR_SCHEDULE_JOB              "sch_job"
#define SPH_TRACE_STR_TOP_HALF                  "top_half"
#define SPH_TRACE_STR_BOTTOM_HALF               "bottom_half"
#define SPH_TRACE_STR_UNDEF                     "undefined"
#define SPH_TRACE_STR_NULL                      "NULL"

#endif /* _SPH_TRACE_FORMAT_H */
