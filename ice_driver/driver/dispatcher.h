/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/



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

struct resource_info {
	u32 num_ice;
	u32 num_cntr;
	u32 num_pool;
	u32 clos[ICE_CLOS_MAX];
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
		int64_t obj_id,
		u64 *out_context_id);

int config_ds_trace_node_sysfs(struct cve_device *dev, struct ice_network *ntw,
		struct job_descriptor *job, int id);
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
		struct ice_execute_infer_data *data);

int cve_ds_handle_shared_surfaces(
		cve_context_process_id_t context_pid,
		cve_context_id_t context_id,
		cve_network_id_t ntw_id,
		struct ice_ss_descriptor *ss_desc);

int cve_ds_handle_destroy_infer(
		cve_context_process_id_t context_pid,
		cve_context_id_t context_id,
		cve_network_id_t ntw_id,
		cve_infer_id_t inf_id);

int cve_ds_handle_manage_resource(
		cve_context_process_id_t context_pid,
		cve_context_id_t context_id,
		cve_network_id_t ntw_id,
		struct ice_resource_request *rreq);

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
		cve_network_id_t network_id,
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

void ice_ds_handle_ice_error(struct cve_device *dev,
		u64 ice_err_status);

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
 *  ntw_id - [in] network id
 *  out_versions - [out] struct of Version structs which contains
 *  the version of CVE components
 */
int cve_ds_get_version(cve_context_process_id_t context_pid,
		cve_context_id_t context_id,
		cve_network_id_t ntw_id,
		struct cve_components_version *out_versions);

/**
 * Get metadata
 * This function is a placeholder to provide metadata to user.
 * outputs:
 * metadata - [out] struct of metadata (icemask , icedumpbufsize)
 */
int cve_ds_get_metadata(struct cve_get_metadata_params *metadata);

int ice_ds_reset_network(
		cve_context_process_id_t context_pid,
		cve_context_id_t context_id,
		cve_network_id_t ntw_id);

#define _no_op_return_zero 0
#ifdef RING3_VALIDATION
void *cve_ds_get_di_context(cve_context_id_t context_id);

#define get_sw_id_from_context_pid(context_pid, context_id) __no_op_return_zero
#else
#define get_sw_id_from_context_pid(context_pid, context_id) \
	 __get_sw_id_from_context_pid(context_pid, context_id)
#endif
u64 __get_sw_id_from_context_pid(cve_context_process_id_t context_pid,
			cve_context_id_t context_id);


#ifdef IDC_ENABLE
void free_assigned_counters(struct jobgroup_descriptor *jobgroup);
enum pool_status cve_ds_map_pool_context(struct ds_context *context);
void cve_ds_unmap_pool_context(struct ds_context *context);
#endif

enum resource_status ice_ds_ntw_reserve_resource(struct ice_network *ntw);
void ice_ds_ntw_release_resource(struct ice_network *ntw);

enum resource_status ice_ds_ntw_borrow_resource(struct ice_network *ntw);
void ice_ds_ntw_return_resource(struct ice_network *ntw);

int ice_di_get_core_blob_sz(void);

int ice_ds_dispatch_jg(struct jobgroup_descriptor *jobgroup);

int ice_ds_raise_event(struct ice_network *ntw,
	enum cve_jobs_group_status status,
	bool reschedule);

int ice_iccp_license_request(struct cve_device *dev, bool throttling,
				uint16_t license_value);
void ice_ds_block_network(struct ice_network *ntw,
	cve_ds_job_handle_t ds_jobh, u32 status,
	bool is_ice_err);

#endif /* _DISPATCHER_H_ */
