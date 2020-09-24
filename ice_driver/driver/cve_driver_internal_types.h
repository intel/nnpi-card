/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/



#ifndef _CVE_DRIVER_INTERNAL_TYPES_H_
#define _CVE_DRIVER_INTERNAL_TYPES_H_

#ifdef RING3_VALIDATION
#include <stdint.h>
#include <stdint_ext.h>
#endif

/* handles of module-specific objects */
typedef void *cve_dev_context_handle_t;
typedef void *cve_di_job_handle_t;
typedef void *cve_di_subjob_handle_t;
typedef void *cve_ds_job_handle_t;
typedef void *cve_mm_buffers_list_t;
typedef void *cve_mm_job_handle_t;
typedef void *cve_mm_allocation_t;

/* type of an arbitrary data item associated with a context */
typedef void *cve_private_data_t;
typedef u64 cve_context_id_t;
typedef u64 ice_pnetwork_id_t;
typedef u64 cve_network_id_t;
typedef u64 cve_infer_id_t;
typedef u64 cve_context_process_id_t;

/* type of timer-handle that is used for scheduling async operations */
typedef void *cve_os_timer_t;
/* type used for specified the period of time for timer expiration */
typedef u32 cve_timer_period_t;
/* type of parameter passed by the timer to the handler */
typedef u32 cve_timer_param_t;
/* type of the function that handles timer events */
typedef void(*cve_os_timer_function)(cve_timer_param_t param);

enum cve_job_status {
	/* unknown status */
	CVE_JOBSTATUS_EMPTY = 0x01,
	/* job is waiting to be sent to the device */
	CVE_JOBSTATUS_PENDING = 0x02,
	/* job was sent to the device */
	CVE_JOBSTATUS_DISPATCHED = 0x04,
	/* job is currently running on the device */
	CVE_JOBSTATUS_RUNNING = 0x08,
	/* job was completed successfully */
	CVE_JOBSTATUS_COMPLETED = 0x10,
	/* job was aborted */
	CVE_JOBSTATUS_ABORTED = 0x20,
};

#endif /* _CVE_DRIVER_INTERNAL_TYPES_H_ */

