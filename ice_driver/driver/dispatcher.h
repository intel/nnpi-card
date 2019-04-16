/*
 * NNP-I Linux Driver
 * Copyright (c) 2017-2019, Intel Corporation.
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

#ifndef _DISPATCHER_H_
#define _DISPATCHER_H_

#ifdef RING3_VALIDATION
#include "linux_kernel_mock.h"
#else
#include <linux/completion.h>
#endif

#include "cve_driver_internal_types.h"
#include "cve_driver_internal.h"
#include "cve_driver.h"


enum pool_status {
	POOL_EXIST,
	POOL_ALLOCATED,
	POOL_EXHAUSTED
};

/*
 * starts a connection channel with a user
 * inputs :
 *	context_pid - the given process id
 *	cve_dg - device group id
 * outputs:
 *  out_context_id - the newely created dispatcher context id
 * returns: 0 on success, a negative error code on failure
 */
int cve_ds_open_context(
		cve_context_process_id_t context_pid,
		u64 *out_context_id);

/*
 * closes a connection channel with a user
 * inputs :
 * context_pid - the process id
 * context_id - the dispatcher context id
 * outputs:
 * returns: 0 on success, a negative error code on failure
 */
int cve_ds_close_context(
		cve_context_process_id_t context_pid,
		cve_context_id_t context_id);

/*
 * handle the IOCTL submit request
 * inputs :
 * context_pid - the process id
 * context_id - the dispatcher context id
 *          all the rest are the same as the ioctl declaration
 * outputs: out_jobid - system wide unique identifier of the submitted job
 * returns: same as defined in the ioctl declaration
 */
int cve_ds_handle_create_network(
		cve_context_process_id_t context_pid,
		cve_context_id_t context_id,
		struct ice_network_descriptor *network,
		u64 *ntw_id);

int cve_ds_handle_create_infer(
		cve_context_process_id_t context_pid,
		cve_context_id_t context_id,
		cve_network_id_t ntw_id,
		struct ice_infer_descriptor *inf_desc,
		u64 *inf_id);

int cve_ds_handle_execute_infer(
		cve_context_process_id_t context_pid,
		cve_context_id_t context_id,
		cve_network_id_t ntw_id,
		cve_infer_id_t inf_id,
		__u32 reserve_resource);

int cve_ds_handle_destroy_infer(
		cve_context_process_id_t context_pid,
		cve_context_id_t context_id,
		cve_network_id_t ntw_id,
		cve_infer_id_t inf_id);

int cve_ds_handle_destroy_network(
		cve_context_process_id_t context_pid,
		cve_context_id_t context_id,
		cve_network_id_t ntw_id);

/*
 * handle the IOCTL FW loading request
 * inputs :
 * context_pid - the process id
 * context_id - the dispatcher context id
 * fw_image - address to FW bin
 * fw_binmap - address to FW map information
 * fw_binmap_size_bytes  - sizeof FW map information
 * outputs: same as the ioctl declaration
 * returns: same as defined in the ioctl declaration
 */
int cve_ds_handle_fw_loading(
		cve_context_process_id_t context_pid,
		cve_context_id_t context_id,
		u64 fw_image,
		u64 fw_binmap,
		u32 fw_binmap_size_bytes);

/*
 * handle a job completion notification
 * inputs :
 *	cve_dev - CVE device object
 * outputs:
 * returns:
 */
void cve_ds_handle_job_completion(struct cve_device *dev,
		cve_ds_job_handle_t ds_job_handle,
		enum cve_job_status job_status,
		u64 exec_time);

void ice_ds_handle_ntw_error(struct cve_device *dev,
		u64 icedc_err_status, u8 cntr_overflow);

void ice_ds_handle_ice_error(struct cve_device *dev,
		u64 ice_err_status);

/*
 * dispatch a single job from this jobgroup
 * inputs :
 *	cve_dev - CVE device object
  *	jobgroup - the jobgroup to dispatch from
 * outputs:
 * returns:
 */
int cve_ds_dispatch_single_job(
		struct cve_device *cve_dev,
		struct jobgroup_descriptor *jobgroup);

/**
 * Destroy context.
 * This function will be called either by close context or
 * by destroy process context.
 * inputs:
 *	context_process - the parent context process
 *	context - the context to destroy
 * returns:
 */
void cve_destroy_context(
		struct cve_context_process *context_process,
		struct ds_context *context);
/**
 * Retrieve event
 * inputs:
 *	timeout_msec - [in] timeout (milliseconds)
 *	wait_status - [out] wait status
 *	jobs_group_id [out] completed jobs group id
 *	jobs_group_status [out] status of completed jobs group
 */
int cve_ds_wait_for_event(cve_context_process_id_t context_pid,
		struct cve_get_event *event);

/**
 * Get version
 * This function retrieve the version of CVE components such as KMD, TLC,
 * MFW and kernel banks.
 * inputs:
 *  context_pid - [in] process id
 *  context_id - [in] dispatcher context id
 *  out_versions - [out] struct of Version structs which contains
 *  the version of CVE components
 */
int cve_ds_get_version(cve_context_process_id_t context_pid,
		cve_context_id_t context_id,
		struct cve_components_version *out_versions);

/**
 * Get metadata
 * This function is a placeholder to provide metadata to user.
 * outputs:
 *  icemask - [out] bitmap of masked ICEs
 */
int cve_ds_get_metadata(u32 *icemask);

#ifdef RING3_VALIDATION
void *cve_ds_get_di_context(cve_context_id_t context_id);
#endif

#ifdef IDC_ENABLE
void free_assigned_counters(struct jobgroup_descriptor *jobgroup);
int set_hw_sync_regs(struct cve_device *cve_dev,
					struct jobgroup_descriptor *jobgroup);
u32 cve_ds_map_hw_cntr(struct jobgroup_descriptor *jobgroup);
void cve_ds_undo_map_hw_cntr(struct jobgroup_descriptor *jobgroup, u32 bitmap);
enum pool_status cve_ds_map_pool_context(struct ds_context *context);
void cve_ds_unmap_pool_context(struct ds_context *context);
#endif

int ice_ds_is_network_active(u64 network_id);

int ice_ds_ntw_resource_reserve(struct ice_network *ntw);
void ice_ds_ntw_resource_release(struct ice_network *ntw);

int ice_ds_debug_control(struct ice_debug_control_params *dc);

int ice_di_get_core_blob_sz(void);

#endif /* _DISPATCHER_H_ */
