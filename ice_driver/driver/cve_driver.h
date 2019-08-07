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

#ifndef _CVE_DRIVER_H_
#define _CVE_DRIVER_H_

#include "version.h"
#include "ice_driver_error.h"

#include <linux/types.h>
#include <linux/ioctl.h>

/* TODO - should be replaced with a valid seq num */
#define CVE_IOCTL_SEQ_NUM 0xFF
#define MAX_ICE_DEVICES 12
#define MAX_ICE_FREQ_PARAM 800
#define MIN_ICE_FREQ_PARAM 200
#define MAX_LLC_FREQ_PARAM 2400
#define MIN_LLC_FREQ_PARAM 400
#define ICE_FREQ_DIVIDER_FACTOR 25
#define LLC_FREQ_DIVIDER_FACTOR 100
#define ICEDRV_VALID_ICE_MASK 0xFFF

typedef __u64 cve_bufferid_t;

#pragma pack(1)

/*
 * IOCTL submit
 * Submit a command buffer for execution. This call is not blocking. It is not
 * guaranteed that command buffer execution is completed when the call returns.
 * Returns: 0 on success. The following negative error codes on failure :
 *	-ENOMEM : no sufficient memory in the driver to hold the submitted
 *		  command buffer.
 *	-EINVAL : invalid surface. happens if a surface index in the
 *		  descriptors list is not a valid index.
 *		  or if the number of descriptors exceeds the allowed max.
 *	-EFAULT : invalid address given for 'command_buffer' or 'descriptors'
 *	-EACCES : invalid address in the descriptor list
 */

/*
 * command buffer descriptor.
 * describes a single command buffer to be executed inside the device
 */
struct cve_command_buffer_descriptor {
	/* number of commands */
	__u16 commands_nr;
	/* buffer id for the cb. */
	cve_bufferid_t bufferid;
	__u8 is_reloadable;
};

enum ice_pp_type {
	ICE_PP_TYPE_SURFACE = 0,
	ICE_PP_TYPE_CNTR_SET,
	ICE_PP_TYPE_CNTR_INC,
	ICE_PP_TYPE_CNTR_NOTIFY,
	ICE_PP_TYPE_CNTR_NOTIFY_ADDR,
	ICE_PP_TYPE_INTER_CB
};

/*
 * patch point descriptor.
 * describes a single patch point inside the command buffer or inside a surface,
 * that needs to be replaced with the device virtual address.
 */
struct cve_patch_point_descriptor {
	/* index of the buffer in the buffer array within job group*/
	__u32 patching_buf_index;
	/* the id of the buffer to patch - for flushing operation */
	cve_bufferid_t bufferid;
	/* offset from Base Address where patching has to be done */
	__u32 byte_offset;
	/* the address of the patching place in memory */
	__u64 patch_address;
	/* the patch point bit offset inside the patching address. */
	__u16 bit_offset;
	/* the number of bits to patch */
	__u16 num_bits;
	union {
		/*index of the allocation in the buffer array within job group*/
		__u32 allocation_buf_index;

		__u16 cntr_id;
	};
	/* inter cb branch offset, valid only when path point type is
	 * ICE_PP_TYPE_INTER_CB
	 */
	__s16 inter_cb_offset;
	/* the id of the allocation asssociated with the patch point */
	cve_bufferid_t allocation_buffer_id;
	/* the offset to add to the allocation base address
	 * in bytes (could be negative)
	 */
	__s32 byte_offset_from_base;
	/* Patch point type */
	enum ice_pp_type patch_point_type;
	/* is patch point for the MSB address for 35 Bit VA default is 0 */
	__u8 is_msb;
};

/*
 * surface descriptor
 * describes an area in memory that is accessed by the command buffer
 * the dma configuration commands refer to this list. that is - instead of
 * providing the address in the command, the user provides the index
 * of the surface in the descriptor list
 */
enum cve_surface_direction {
	CVE_SURFACE_DIRECTION_IN = 0x01,
	CVE_SURFACE_DIRECTION_OUT = 0x02
};

#define CVE_SURFACE_DIRECTION_INOUT \
	(CVE_SURFACE_DIRECTION_IN | CVE_SURFACE_DIRECTION_OUT)

enum ice_surface_type {
	ICE_BUFFER_TYPE_SURFACE = 0,
	ICE_BUFFER_TYPE_SIMPLE_CB = 1,
	ICE_BUFFER_TYPE_DEEP_SRAM_CB = 2,
	/** Surface is of type CB and required reloading to be enabled */
	ICE_SURF_TYPE_CB_RELOAD = 3
};

enum ice_network_type {
	ICE_SIMPLE_NETWORK = 1,
	ICE_PRIORITY_NETWORK = 2,
	ICE_DEEPSRAM_NETWORK = 3,
	ICE_PRIORITY_DEEPSRAM_NETWORK = 4
};

enum idc_error_status {
	ILLEGAL_ACCESS = 0x01,
	ICE_READ_ERR = 0x02,
	ICE_WRITE_ERR = 0x04,
	ASF_ICE1_ERR = 0x08,
	ASF_ICE0_ERR = 0x10,
	CNTR_ERR = 0x20,
	SEM_ERR = 0x40,
	ATTN_ERR = 0x80,
	CNTR_OFLOW_ERR = 0x100
};

enum ice_error_status {
	TLC_ERR = 0x01,
	MMU_ERR = 0x02,
	PAGE_FAULT = 0x4,
	BUS_ERR = 0x8,
	INTERNAL_WD = 0x10,
	BTRS_WD = 0x20,
	TLC_PANIC = 0x40,
	DSRAM_SINGLE_ERR = 0x80,
	DSRAM_DOUBLE_ERR = 0x100,
	SRAM_PARITY_ERR = 0x200,
	DSRAM_UNMAPPED_ADDR = 0x400,
	/*last error so that it doesnt share HW error type*/
	ICE_READY_BIT_ERR = 0x80000000
};

enum icebo_req_type {
	ICEBO_DEFAULT = 0,
	ICEBO_MANDATORY,
	ICEBO_PREFERRED
};

enum ice_clos {
	ICE_CLOS_0 = 0,
	ICE_CLOS_1,
	ICE_CLOS_2,
	ICE_CLOS_3,
	ICE_CLOS_MAX
};

enum hw_config_type {
	ICE_FREQ = 0,
	LLC_FREQ = 2
};

enum ice_execute_infer_priority {
	EXE_INF_PRIORITY_0,
	EXE_INF_PRIORITY_1,
	EXE_INF_PRIORITY_MAX
};

struct cve_surface_descriptor {
	/** a unique integer ID for each surface from user for debugging
	 *  to be set to the crc32 of the surface name in the graph
	 */
	__u32 obj_id;
	/* id of the buffer, to be filled by kmd after network submission */
	cve_bufferid_t bufferid;
	/* the base address of the area in memory */
	__u64 base_address;
	/* fd is the file descriptor for given shared buffer */
	__u64 fd;
	/* indication if buffer is referring to allocated buffer */
	__u8 allocation_done;
	/* the size in bytes */
	__u64 size_bytes;
	/* actual the size of the surface as in the graph blob, in bytes */
	__u64 actual_size_bytes;
	/* llc policy index for this buffer */
	__u32 llc_policy;
	/* the direction of the surface */
	enum cve_surface_direction direction;
	/* Indication of CB type */
	enum ice_surface_type surface_type;
	/* Page Size recomendation, if 0, select default */
	__u32 page_sz;
	/* flag to request higher VA i.e. above 4GB.
	 * default is 0 i.e. below 4GB
	 */
	__u8 alloc_higher_va;
	/* Number of LSB patch points where this surface is referenced */
	__u32 low_pp_cnt;
	/* Number of MSB patch points where this surface is referenced */
	__u32 high_pp_cnt;
};

struct cve_infer_surface_descriptor {
	/** Object id from user for debug capability to identify each surface
	 *  uniquely suing the crc32 of the surface name in the graph
	 */
	__u32 obj_id;
	/* buffer index in corresponding network's buffer descriptor*/
	__u64 index;
	/* the base address of the area in memory */
	__u64 base_address;
	/* fd is the file descriptor for given shared buffer */
	__u64 fd;
};

struct cve_allocation_descriptor {
	/* id of the buffer that was created * */
	cve_bufferid_t bufferid;
	/* the direction of the surface */
	enum cve_surface_direction direction;
};

struct cve_job {
	/* Number of Buffer descriptors */
	__u32 cb_nr;
	/* List of indexes reffering to Buffer Descriptor Array
	 * in network descriptor containins CB for this job
	*/
	__u64 cb_buf_desc_list;
	/* number of command buffers */
	__u32 command_buffers_nr;
	/* address of list of command buffers to execute */
	/* should be casted to struct cve_command_buffer_descriptor* */
	__u64 command_buffers;
	/* number of surface descriptors */
	__u32 surfaces_nr;
	/* address of list of allocation descriptors in user space */
	/* should be casted to struct cve_allocation_descriptor* */
	__u64 surfaces;
	/* number of patch points descriptors */
	__u32 patch_points_nr;
	/* address of list of patch points in user space */
	/* should be casted to struct cve_patch_point_descriptor* */
	__u64 patch_points;
	/* should contain valid ICE ID when CB to ICE mapping is required */
	/* and -1 in case mapping is not necessary */
	__s8 graph_ice_id;
};

struct cve_job_group {
	/* number of jobs */
	__u32 jobs_nr;
	/* address of list of jobs to execute */
	/* should be casted to struct cve_job* */
	__u64 jobs;
	/* number of dependencies */
	__u32 dep_nr;
	/* address of list of indexes of dependent Job Group descriptors*/
	/* Each entry of the list should be used as an index to
	 * jg_desc_list array in network descriptor
	*/
	__u64 dependencies;
	/* num of CVEs required*/
	__u32 num_of_cves;
	/* amount of LLC (bytes) required*/
	__u32 LLC_size;
	/* number of counters required */
	__u32 num_of_idc_cntr;
	/* Completion event required*/
	__u32 produce_completion;
	/* user private data */
	__u64 user_data;
	/* out, job group id */
	__u64 out_job_group_id;
};

struct ice_network_descriptor {
	/** Object id from user for sw counters
	 *  Can be negative if driver generated ID to be used
	 */
	__s64 obj_id;
	/** parent object id, full network id w.r.t card
	 *  should be unique per context, can be -1 if driver generated id to
	 *  be used
	 */
	__s64 parent_obj_id;
	/* Num ICE requirement for this Network */
	__u8 num_ice;
	/* LLC requirement for this Network */
	__u32 llc_size[ICE_CLOS_MAX];
	/* List of Buffers used by this Network */
	struct cve_surface_descriptor *buf_desc_list;
	/* Number of entries in above list */
	__u32 num_buf_desc;
	/* List of JG Descriptors */
	struct cve_job_group *jg_desc_list;
	/* Number of entries in above list */
	__u32 num_jg_desc;
	/* Completion event required*/
	__u32 produce_completion;
	/* out, job group id */
	__u64 network_id;
	enum ice_network_type network_type;
	__u8 is_ice_dump_enabled;
	enum icebo_req_type icebo_req;
	__u8 shared_read;
	__u8 max_shared_distance;
	__u32 infer_buf_count;
};

struct ice_infer_descriptor {
	/** Object id from user for sw counters
	 *  Can be negative if driver generated ID to be used
	 */
	__s64 obj_id;
	/* List of Infer specific Buffer Descriptor */
	struct cve_infer_surface_descriptor *buf_desc_list;
	/* Number of infer Buffer Descriptors */
	__u32 num_buf_desc;
	/* out, Infer ID */
	__u64 infer_id;
	/* user private data */
	__u64 user_data;
};

/*
* parameter for IOCTL-submit
*/
struct cve_create_network {
	/*in, context id*/
	__u64 contextid;
	/*inout*/
	struct ice_network_descriptor network;
};

/*
 * parameter for IOCTL-create_infer
 */
struct cve_create_infer {
	/*in, context id*/
	__u64 contextid;
	/*in, network id*/
	__u64 networkid;
	/*inout*/
	struct ice_infer_descriptor infer;
};

struct ice_execute_infer_data {
	/*in*/
	__u8 enable_bp;
	/*in*/
	enum ice_execute_infer_priority priority;
};

/*
 * parameter for IOCTL-execute
 */
struct cve_execute_infer {
	/*in, context id*/
	__u64 contextid;
	/*in, network id*/
	__u64 networkid;
	/*in, job id*/
	__u64 inferid;
	/*in*/
	struct ice_execute_infer_data data;
};

/*
 * parameter for IOCTL-destroy_infer
 */
struct cve_destroy_infer {
	/*in, context id*/
	__u64 contextid;
	/*in, network id*/
	__u64 networkid;
	/*in, job id*/
	__u64 inferid;
};

struct ice_resource_request {
	__u8 is_reserve;
	__s32 timeout;
	__u32 num_ice;
	__u32 num_cntr;
	__u32 num_pool;
	__u32 clos[ICE_CLOS_MAX];
};

/*
 * parameter for IOCTL-manage_resource
 */
struct ice_manage_resource {
	/*in, context id*/
	__u64 contextid;
	/*in, network id*/
	__u64 networkid;
	/*inout*/
	struct ice_resource_request resource;
};

/*
 * parameter for IOCTL-destroy
 */
struct cve_destroy_network {
	/*in, context id*/
	__u64 contextid;
	/*in*/
	__u64 networkid;
};

struct ice_hw_config_llc_freq {
	/* in, min llc frequency to be set */
	__u32 llc_freq_min;
	/* in, max llc frequency to be set */
	__u32 llc_freq_max;
};

struct ice_hw_config_ice_freq {
	/* in, ICE for which frequency has to be set*/
	__u32 ice_num;
	/* in, frequency value to be set */
	__u32 ice_freq;
};
/*
 * IOCTL status
 * Check the status of a command buffer that was previously submitted to the
 * driver. A job's status is guaranteed to be kept in the driver's internal
 * structures until it is completed or aborted and its status is checked with
 * this API function. That is once this API returned either COMPLETED or
 * ABORTED for a certain job, the driver may remove the job's status from its
 * internal data structures. A consequent call to this API with the same job
 * identifier might return a 'job unknown' error.
 * Returns: 0 on success. The following negative error codes on failure :
 *  -EFAULT : invalid address given for 'out_status'
 *  -EINVAL : unknown job identifier
 *  -ETIME  : timeout expired
 */

/*
* IOCTL load-firmware
* loads a user-provided firmware image on demand
* Returns: 0 on success. The following negative error codes on failure :
*  -EACCESS : illegal pointer
*  -EPERM   : illegal firmware image
*  -EINVAL  : invalid mapping
*/

/*
* parameter for IOCTL-load-firmware
*/
struct cve_load_firmware_params {
	/* context id */
	__u64 contextid;
	/* address of the memory that holds the image */
	__u64 fw_image;
	/* size of the fw image */
	__u32 fw_image_size_bytes;
	/* address of the memory that holds the binary map */
	__u64 fw_binmap;
	/* size of the binary map */
	__u32 fw_binmap_size_bytes;
};

/*
* parameter for IOCTL-create-context
*/
struct cve_create_context_params {
	/** context id from user for sw counters, to be set negative value
	 * if driver generated id to be used
	 */
	__s64 obj_id;
	/*out, context ID of created context*/
	__u64 out_contextid;
};

/*
* parameter for IOCTL-destroy-context
*/
struct cve_destroy_context_params {
	/* in, id of the context to be destroyed */
	__u64 contextid;
};

enum cve_jobs_group_status {
	/*submitted or dispatching*/
	CVE_JOBSGROUPSTATUS_PENDING,
	/*Completely dispatched*/
	CVE_JOBSGROUPSTATUS_DISPATCHED,
	/* job group was completed successfully */
	CVE_JOBSGROUPSTATUS_COMPLETED,
	/* job group was aborted */
	CVE_JOBSGROUPSTATUS_ABORTED,
};

/*
 * parameter for IOCTL-get-event
 */
enum cve_wait_event_status {
	CVE_WAIT_EVENT_COMPLETE,
	CVE_WAIT_EVENT_TIMEOUT,
	CVE_WAIT_EVENT_ERROR
};

struct cve_get_event {
/*TODO: This macro should come from common location for UMD & KMD*/
#define KMD_NUM_ICE 12
	/*in, timeout in milliseconds */
	__u32 timeout_msec;
	/* in, id of the context */
	__u64 contextid;
	/*in, id of the network */
	__u64 networkid;
	/* out, wait status*/
	enum cve_wait_event_status wait_status;
	/* in/out, inference id */
	__u64 infer_id;
	/*out, job status*/
	enum cve_jobs_group_status jobs_group_status;
	/* out, user data*/
	__u64 user_data;
	/* IceDc error status*/
	__u64 icedc_err_status;
	/* CB exec time per ICE */
	__u64 total_time[KMD_NUM_ICE];
	/* Ice error status */
	__u64 ice_err_status;
	/* Shared read error status */
	__u32 shared_read_err_status;
};

/*
 * parameter for IOCTL-get-version
 */

struct cve_components_version {
	Version kmd_version;
	Version tlc_version;
	Version ivp_mfw_version;
	Version asip_mfw_version;
	Version ivp_bank0_version;
	Version ivp_bank1_version;
	Version asip_bank0_version;
	Version asip_bank1_version;
};

struct cve_get_version_params {
	/* in, context id */
	__u64 contextid;
	/* out, all components version */
	struct cve_components_version out_versions;
};

struct cve_get_metadata_params {
	/* out, icemask */
	__u32 icemask;
};

/*
 * parameter for IOCTL-hw-trace-config
 */
struct ice_observer_config {
	/* ICE number(bit mask) for which DSO regs to be configured */
	__u32 ice_number;
	/* Value for DSO_DTF_ENCODER_CONFIG_REG */
	__u32 dtf_encoder_config;
	/* Value for DSO_CFG_DTF_SRC_CONFIG_REG */
	__u32 cfg_dtf_src_config;
	/* Value for DSO_CFG_PTYPE_FILTER_CH0_REG */
	__u32 cfg_ptype_filter_ch0;
	/* Value for DSO_FILTER_MATCH_LOW_CH0_REG */
	__u32 filter_match_low_ch0;
	/* Value for DSO_FILTER_MATCH_HIGH_CH0_REG */
	__u32 filter_match_high_ch0;
	/* Value for DSO_FILTER_MASK_LOW_CH0_REG */
	__u32 filter_mask_low_ch0;
	/* Value for DSO_FILTER_MASK_HIGH_CH0_REG */
	__u32 filter_mask_high_ch0;
	/* Value for DSO_FILTER_INV_CH0_REG */
	__u32 filter_inv_ch0;
	/* Value for DSO_CFG_PTYPE_FILTER_CH1_REG */
	__u32 cfg_ptype_filter_ch1;
	/* Value for DSO_FILTER_MATCH_LOW_CH1_REG */
	__u32 filter_match_low_ch1;
	/* Value for DSO_FILTER_MATCH_HIGH_CH1_REG */
	__u32 filter_match_high_ch1;
	/* Value for DSO_FILTER_MASK_LOW_CH1_REG */
	__u32 filter_mask_low_ch1;
	/* Value for DSO_FILTER_MASK_HIGH_CH1_REG */
	__u32 filter_mask_high_ch1;
	/* Value DSO_FILTER_INV_CH1_REG */
	__u32 filter_inv_ch1;

};

struct ice_perf_counter_setup {
	/* ICE number(bit mask) for which counter setup registers to be set */
	__u32 ice_number;
	/* Counter Register offset */
	__u32 register_offset;
	/* Counter value */
	__u32 counter_value;
	/* Counter configuration mask */
	__u32 counter_config_mask;
};

struct ice_register_reader_daemon {
#define ICE_MAX_DAEMON_TABLE_LEN 32
	/* ICE number(bit mask) for which reader daemon to be configured */
	__u32 ice_number;
	/* Value of daemon_enable register */
	__u32 daemon_enable;
	/* Value of daemon_control register */
	__u32 daemon_control;
	/* Daemon register table length */
	__u32 daemon_table_len;
	/* Daemon register table */
	__u32 daemon_table[ICE_MAX_DAEMON_TABLE_LEN];
};

struct ice_hw_trace_config {
	/* in, num of observer configurations */
	__u32 ice_observer_count;
	/* in, num of performance related counter setup configurations */
	__u32 ice_perf_counter_setup_count;
	/* in, num of register reader daemon configurations */
	__u32 ice_reg_daemon_count;
	/* in, list of dso observer configurations */
	struct ice_observer_config *observer_list;
	/* in, list of performance related counter setup configurations */
	struct ice_perf_counter_setup *counter_setup_list;
	/* in, list of register reader daemon configurations */
	struct ice_register_reader_daemon *reg_daemon_list;
};

/*
 * parameter for IOCTL-get-debug-event
 */

enum ice_debug_event_type {
	ICE_DEBUG_EVENT_ICE_POWERED_ON = 0x1,
	ICE_DEBUG_EVENT_TLC_BP = 0x2
};

struct ice_debug_event_info_power_on {
	/*out,  indicate which ices are powered on */
	__u32 powered_on_ices;
	/*out,  indicate network_id associated with the ices */
	__u64 network_id;
};

struct ice_debug_event_info_bp {
	/*out, indicate which ice gave break point interrupt */
	__u32 ice_index;
	/*out,  indicate network_id associated with the ice */
	__u64 network_id;
};

struct ice_get_debug_event {
	/*in, timeout in milliseconds */
	__u32 timeout_msec;
	/* out, debug wait status*/
	enum cve_wait_event_status debug_wait_status;
	/* in,out, debug event type*/
	enum ice_debug_event_type debug_event;
	/* out, different event related info */
	union {
		struct ice_debug_event_info_power_on power_on_evt_info;
		struct ice_debug_event_info_bp bp_evt_info;
	};
};

/*
 * parameter for IOCTL-debug-control
 */
enum ice_debug_control_type {
	/* powered on ICE MASK */
	ICE_DEBUG_CONTROL_GET_POWERED_ON_ICEMASK = 1,
	/* Get ICE dump */
	ICE_DEBUG_CONTROL_GET_ICE_DUMP
};

enum ice_dump_status {
	/* ice dump completed succefully */
	ICE_DEBUG_ICE_DUMP_COMPLETE = 1,
	/* ice dump timedout */
	ICE_DEBUG_ICE_DUMP_TIMEOUT,
	/* ice dump failed */
	ICE_DEBUG_ICE_DUMP_ERROR
};

struct ice_debug_control_ice_mask {
	/* out, bit map to indicate which ices are powered on */
	__u32 powered_on_ice_mask;
};

struct ice_debug_control_ice_dump {
	/* in, bit map to indicate for which ices dump is required */
	__u32 ice_mask;
	/* in/out, list of virtual address of the buffer as seen by host CPU */
	__u64 base_addr;
	/* in, number of ICE dump buffer in the @c base_addr array */
	__u32 num_of_ice_dump;
	/* out, ice dump debug control status*/
	enum ice_dump_status ice_dump_status;
};

struct ice_debug_control_params {
	/* in/out, opaque holder */
	__u64 user_data;
	/* in, debug control type */
	enum ice_debug_control_type type;
};

struct ice_set_hw_config_params {
	/*in, different configs related info */
	union {
		struct ice_hw_config_llc_freq llc_freq_config;
		struct ice_hw_config_ice_freq ice_freq_config;
	};
	/*in, configuration type*/
	enum hw_config_type config_type;
};

/* a union of all the different parameters */
struct cve_ioctl_param {
	union {
		struct cve_create_context_params create_context;
		struct cve_destroy_context_params destroy_context;
		struct cve_create_network create_network;
		struct cve_create_infer create_infer;
		struct cve_execute_infer execute_infer;
		struct cve_destroy_infer destroy_infer;
		struct ice_manage_resource manage_resource;
		struct cve_destroy_network destroy_network;
		struct cve_load_firmware_params load_firmware;
		struct cve_get_event get_event;
		struct cve_get_version_params get_version;
		struct cve_get_metadata_params get_metadata;
		struct ice_hw_trace_config trace_cfg;
		struct ice_get_debug_event get_debug_event;
		struct ice_debug_control_params debug_control;
		struct ice_set_hw_config_params set_hw_config;
	};
};

#pragma pack()

/* IOCL numbers */
/* Data transfer is seen from the application's point of view;
 * _IOC_READ means reading from the device, so the driver must
 * write to user space
 */
#define CVE_IOCTL_CREATE_CONTEXT \
	_IOWR(CVE_IOCTL_SEQ_NUM, 0, struct cve_ioctl_param)
#define CVE_IOCTL_DESTROY_CONTEXT \
	_IOW(CVE_IOCTL_SEQ_NUM, 1, struct cve_ioctl_param)
#define CVE_IOCTL_DESTROY_INFER \
	_IOWR(CVE_IOCTL_SEQ_NUM, 5, struct cve_ioctl_param)
#define CVE_IOCTL_CREATE_INFER \
	_IOWR(CVE_IOCTL_SEQ_NUM, 6, struct cve_ioctl_param)
#define CVE_IOCTL_EXECUTE_INFER \
	_IOWR(CVE_IOCTL_SEQ_NUM, 7, struct cve_ioctl_param)
#define CVE_IOCTL_LOAD_FIRMWARE \
	_IOWR(CVE_IOCTL_SEQ_NUM, 10, struct cve_ioctl_param)
#define CVE_IOCTL_WAIT_FOR_EVENT \
	_IOWR(CVE_IOCTL_SEQ_NUM, 11, struct cve_ioctl_param)
#define CVE_IOCTL_GET_VERSION \
	_IOWR(CVE_IOCTL_SEQ_NUM, 12, struct cve_ioctl_param)
#define CVE_IOCTL_GET_METADATA \
	_IOR(CVE_IOCTL_SEQ_NUM, 13, struct cve_ioctl_param)

#define ICE_IOCTL_HW_TRACE_CONFIG \
	_IOW(CVE_IOCTL_SEQ_NUM, 14, struct cve_ioctl_param)

#define ICE_IOCTL_WAIT_FOR_DEBUG_EVENT \
	_IOWR(CVE_IOCTL_SEQ_NUM, 15, struct cve_ioctl_param)
#define ICE_IOCTL_DEBUG_CONTROL \
	_IOWR(CVE_IOCTL_SEQ_NUM, 16, struct cve_ioctl_param)
#define CVE_IOCTL_CREATE_NETWORK \
	_IOWR(CVE_IOCTL_SEQ_NUM, 17, struct cve_ioctl_param)
#define CVE_IOCTL_DESTROY_NETWORK \
	_IOWR(CVE_IOCTL_SEQ_NUM, 18, struct cve_ioctl_param)
#define CVE_IOCTL_MANAGE_RESOURCE \
	_IOWR(CVE_IOCTL_SEQ_NUM, 19, struct cve_ioctl_param)
#define ICE_IOCTL_SET_HW_CONFIG \
	_IOW(CVE_IOCTL_SEQ_NUM, 20, struct cve_ioctl_param)
#endif /* _CVE_DRIVER_H_ */
