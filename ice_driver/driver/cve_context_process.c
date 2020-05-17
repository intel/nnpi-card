/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/




#include "cve_context_process.h"
#include "cve_driver_internal.h"
#include "cve_driver_internal_macros.h"
#include "os_interface.h"
#include "dispatcher.h"

/* Global list of processes */
struct cve_context_process *g_context_process_list;

static struct cve_context_process *
context_process_get(cve_context_process_id_t context_pid)
{
	struct cve_context_process *context_process = NULL;

	/* find the contex_pid to remove */
	context_process = cve_dle_lookup(
			g_context_process_list,
			list, context_pid,
			context_pid);

	return context_process;
}

int cve_context_process_create(
		cve_context_process_id_t context_pid)
{
	struct cve_context_process *context_process = NULL;
	int retval = cve_os_lock(&g_cve_driver_biglock, CVE_INTERRUPTIBLE);

	if (retval != 0) {
		retval = -ERESTARTSYS;
		goto out;
	}

	cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Created context_pid START\n");

	/* create the process context */
	retval = OS_ALLOC_ZERO(
			sizeof(*context_process),
			(void **)&context_process);
	if (retval != 0)
		goto failed_to_alloc;

	context_process->context_pid = context_pid;
	retval = cve_os_init_wait_que(&context_process->events_wait_queue);
#ifdef RING3_VALIDATION
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"events_wait_queue init failed  %d\n", retval);
		goto failed_to_init;
	}
#endif

	/* add the new context to the list */
	cve_dle_add_to_list_after(
			g_context_process_list,
			list,
			context_process);

	cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Created context_pid %lld\n",
			context_pid);

	/* success */
	cve_os_unlock(&g_cve_driver_biglock);
	return 0;

#ifdef RING3_VALIDATION
failed_to_init:
	OS_FREE(context_process, sizeof(*context_process));
#endif
failed_to_alloc:
	cve_os_unlock(&g_cve_driver_biglock);
out:
	return retval;
}

int cve_context_process_destroy(
		cve_context_process_id_t context_pid)
{
	struct cve_context_process *context_process = NULL;
	int retval = cve_os_lock(&g_cve_driver_biglock, CVE_NON_INTERRUPTIBLE);

	if (retval != 0) {
		retval = -ERESTARTSYS;
		goto out;
	}

	cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Destroy context_pid START\n");

	context_process = context_process_get(context_pid);
	if (!context_process) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"failed to get context_pid %d\n",
				retval);
		retval = -ICEDRV_KERROR_INVALID_DRV_HANDLE;
		goto out;
	}

	/* close all contexts from this process */
	while (context_process->list_contexts) {
		struct ds_context *ctx = context_process->list_contexts;

		cve_os_log(CVE_LOGLEVEL_ERROR,
				"WARNING: context_id %lld did not close properly\n",
				ctx->context_id);
		cve_destroy_context(context_process, ctx);
	}

	/* remove the process from the list */
	cve_dle_remove_from_list(
			g_context_process_list,
			list, context_process);

	cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Destroy context_pid %lld\n",
			context_pid);

	OS_FREE(context_process, sizeof(*context_process));

	/* success */
	retval = 0;
out:

	cve_os_unlock(&g_cve_driver_biglock);
	return retval;
}

int cve_context_process_get(
		cve_context_process_id_t context_pid,
		struct cve_context_process **out_process_context)
{
	int retval = CVE_DEFAULT_ERROR_CODE;
	struct cve_context_process *context_process = NULL;

	context_process = context_process_get(context_pid);
	if (!context_process) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"failed to get context_pid %d\n",
				retval);
		retval = -ICEDRV_KERROR_INVALID_DRV_HANDLE;
		goto out;
	}

	*out_process_context = context_process;

	/* success */
	retval = 0;
out:
	return retval;
}
