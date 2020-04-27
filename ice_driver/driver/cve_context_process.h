/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/


#ifndef DRIVER_CVE_CONTEXT_PROCESS_H_
#define DRIVER_CVE_CONTEXT_PROCESS_H_

#include "cve_device.h"

/*
 * Create a process context.
 * inputs :
 * outputs:
 * context_process_id - return a context process id
 * returns: 0 on success, a negative error code on failure
 */
int cve_context_process_create(
		cve_context_process_id_t context_pid);


/*
 * Create a process context.
 * inputs :
 * outputs:
 * context_process_id - return a context process id
 * returns: 0 on success, a negative error code on failure
 */
int cve_context_process_destroy(
		cve_context_process_id_t context_pid);

/*
 * Get a process context based on process id.
 * inputs :
 * outputs:
 * out_process_context - return the context process
 * returns: 0 on success, a negative error code on failure
 */
int cve_context_process_get(
		cve_context_process_id_t context_pid,
		struct cve_context_process **out_process_context);

#endif /* DRIVER_CVE_CONTEXT_PROCESS_H_ */
