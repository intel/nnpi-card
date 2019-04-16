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

#ifndef CVE_DEVICE_H_
#define CVE_DEVICE_H_

#include "cve_device_fifo.h"
#include "os_interface.h"
#include "cve_driver.h"
#include "cve_driver_internal_types.h"
#include "doubly_linked_list.h"
#include "cve_fw_structs.h"
#include "project_settings.h"

#define INVALID_ENTRY 255
#define INVALID_ICE_ID 255
#define INVALID_CTR_ID -1
#define INVALID_POOL_ID -1
#define INVALID_CONTEXT_ID 0
#define INVALID_NETWORK_ID 0
#define ICE_MAX_PMON_CONFIG 32

enum CVE_DEVICE_STATE {
	CVE_DEVICE_IDLE = 0,
	CVE_DEVICE_BUSY
};

enum ICE_POWER_STATE {
	/* ICE is powered on */
	ICE_POWER_ON,
	/* ICE is in power off queue */
	ICE_POWER_OFF_INITIATED,
	/* ICE is powered off */
	ICE_POWER_OFF,
	/* When driver starts then power state is unknown */
	ICE_POWER_UNKNOWN
};

enum ICEDC_DEVICE_STATE {
	ICEDC_STATE_NO_ERROR = 0,
	ICEDC_STATE_CARD_RESET_REQUIRED
};

/* Action required on SCB (Special CB) */
enum SCB_STATE {
	/* SCB is not present */
	SCB_STATE_ABSENT,
	/* SCB is present and has to be executed */
	SCB_STATE_RUN,
	/* SCB is present but should not be executed */
	SCB_STATE_SKIP
};

/* States of ICEBO */
enum ICEBO_STATE {
	/* Zero ICE available for NTW */
	NO_ICE = 0,
	/* One ICE available for NTW */
	ONE_ICE,
	/* Two ICE available for NTW */
	TWO_ICE
};

/*
 * device info exposed to the userland.
 * the information is supposed to be static - it is
 * read once on initializatoin time and not updated
 */
struct cve_version_info {
	/* format used by sprintf function for dispalying the info item */
	const char *format;
	u16 major;
	u16 minor;
};

struct cve_device_group;

#ifdef RING3_VALIDATION
#define DTF_REGS_DATA_ARRAY_SIZE 23
#else
#define DTF_REGS_DATA_ARRAY_SIZE 25
#endif /* RING3_VALIDATION */

struct di_cve_dump_buffer {
	/* cve dump buffer */
	void *cve_dump_buffer;
	/* cve dump enable/disable */
	u32 is_allowed_tlc_dump;
	/* flag to check whether ice dump buffer was programmed */
	/* for CVE_DUMP_NOW flag or not*/
	u32 is_dump_now;
	/* cve dump new content triggered*/
	u32 is_cve_dump_on_error;
	/* cve dump size*/
	u32 size_bytes;
	/* cve dump RAM to file wait queue*/
	cve_os_wait_que_t dump_wqs_que;
	/* cve dump dma handle */
	struct cve_dma_handle dump_dma_handle;
	/* ICE VA for this allocation */
	cve_virtual_address_t ice_vaddr;
};

struct cve_dso_reg_offset {
	/*  DSO register port */
	u8 port;
	/*  DSO register croffset */
	u16 croffset;
};

/* Trace HW register config status for DSO and performance monitor regs */
enum ICE_TRACE_HW_CONFIG_STATUS {
	TRACE_STATUS_DEFAULT = 0,
	TRACE_STATUS_USER_CONFIG_WRITE_PENDING,
	TRACE_STATUS_USER_CONFIG_WRITE_DONE,
	TRACE_STATUS_DEFAULT_CONFIG_WRITE_PENDING,
	TRACE_STATUS_DEFAULT_CONFIG_WRITE_DONE,
	TRACE_STATUS_HW_CONFIG_WRITE_PENDING,
	TRACE_STATUS_HW_CONFIG_WRITE_DONE,
	TRACE_STATUS_SYSFS_USER_CONFIG_WRITE_PENDING,
	TRACE_STATUS_SYSFS_USER_CONFIG_WRITE_DONE
};

struct ice_dso_regs_data {
#define MAX_DSO_CONFIG_REG 14
	/*  array of dso register offsets */
	struct cve_dso_reg_offset reg_offsets[MAX_DSO_CONFIG_REG];
	/*  array of dso register values */
	u32 reg_vals[MAX_DSO_CONFIG_REG];
	/* actual number of dso registers configured*/
	u32 reg_num;
	/* to specify if dso configuration status */
	enum ICE_TRACE_HW_CONFIG_STATUS dso_config_status;
	/* flag to specify if default or user configuration */
	bool is_default_config;
#ifndef RING3_VALIDATION
	/* Uncore callback functions*/
	struct icedrv_regbar_callbacks *regbar_cbs;
#endif
	/* BIOS allocated Save-restore page virtual address */
	void *sr_addr_base;
};

struct ice_read_daemon_config {
	struct ice_register_reader_daemon conf;
	bool is_default_config;
	enum ICE_TRACE_HW_CONFIG_STATUS daemon_config_status;
};

struct ice_perf_counter_config {
	struct ice_perf_counter_setup conf[ICE_MAX_PMON_CONFIG];
	enum ICE_TRACE_HW_CONFIG_STATUS perf_counter_config_status;
	u32 perf_counter_config_len;
	bool is_default_config;
};

struct cve_device {
	/* device index */
	u32 dev_index;
	/* link to Ntw ICEs */
	struct cve_dle_t owner_list;
	/* link to cve devices in an ICEBO */
	struct cve_dle_t bo_list;
	/* List of ICEs to be powered off */
	struct cve_dle_t poweroff_list;
	/* Timestamp of when Power Off request was raised */
	struct timespec poweroff_ts;
	/* Pointer to FIFO of current Network */
	struct di_fifo *fifo;
	struct di_cve_dump_buffer cve_dump_buf;
	/* ice dump buffer descriptor - for GET_ICE_DUMP_NOW debug control*/
	struct di_cve_dump_buffer debug_control_buf;
	u32 di_cve_needs_reset;
	u32 interrupts_status;
	struct cve_version_info version_info;
	void *platform_data;
	/* list of loaded fw sections */
	struct cve_fw_loaded_sections *fw_loaded_list;
	/* pointer to the associated device group */
	struct cve_device_group *dg;
	/* device state */
	enum CVE_DEVICE_STATE state;
	/* power state of device */
	enum ICE_POWER_STATE power_state;
	/* last context id that ran on this device */
	cve_context_id_t last_context_id;
	/* last network id that ran on this device */
	cve_network_id_t last_network_id;
	/* are hw counters enabled */
	u32 is_hw_counters_enabled;
	/* copy of DTF registers to maintain during device reset */
	u32 dtf_regs_data[DTF_REGS_DATA_ARRAY_SIZE];
	bool dtf_sem_bit_acquired;
#ifdef IDC_ENABLE
#ifdef NEXT_E2E
	struct cve_dma_handle bar1_dma_handle;
	cve_mm_allocation_t bar1_alloc_handle;
#endif
	/*
	 * In case of persistent NW an ICE is linked to one NW
	 * If (pnetwork_id != 0) then this ICE will be allocated
	 * to the Jobs of only given NW
	 */
	u64 pnetwork_id;
	struct ice_dso_regs_data dso;
	struct ice_read_daemon_config daemon;
	struct ice_observer_config observer;
	/*TODO:perf_counter_config array len has to
	 *evolve with debug code maturity
	 */
	struct ice_perf_counter_config perf_counter;
#endif

#ifndef RING3_VALIDATION
	/* SW Counter handle */
	void *hswc;
	/* SW Counter handle for infer_device_counter */
	void *hswc_infer;
	/* DTF sysfs related field */
	struct kobject *ice_kobj;
#endif
};

struct icebo_desc {
	/* icebo id */
	u8 bo_id;
	/* State of ICEBO */
	u32 state;
	/* link to the owner picebo/sicebo/dicebo list */
	struct cve_dle_t owner_list;
	/* List of devices - static list */
	struct cve_device *dev_list;
};

struct dg_dev_info {
	/* icebo list with two ICEs available */
	struct icebo_desc *picebo_list;
	/* icebo list with one ICE available but in non usable state */
	struct icebo_desc *sicebo_list;
	/* icebo list with one ICE available */
	struct icebo_desc *dicebo_list;
	/* for reference - static icebo list */
	struct icebo_desc *icebo_list;
	/* Number of ICEBO whose both the ICEs are idle, paired ICEBOs=picebo */
	u8 num_picebo;
	/* Number of ICEBO whose one ICE is idle but cannot be used by any ntw,
	 * single ICEBOs=sicebo
	 */
	u8 num_sicebo;
	/* Number of ICEBOs whose one ICE is idle and can be used by any ntw,
	 * don't care ICEBOs=dicebo
	 */
	u8 num_dicebo;
	/* Number of active devices */
	u32 active_device_nr;
};

struct cve_workqueue;
struct ds_dev_data;

/* TODO: In future DG can be rebranded as ResourcePool.
 * It contains ICEs, Counters, LLC and Pools info.
 */
struct cve_device_group {
	/* link to the global DG list */
	struct cve_dle_t list;
	/* device group id */
	u32 dg_id;
	/* expected device group size */
	u32 expected_devices_nr;
	/* amount of llc allocated for the DG */
	u32 llc_size;
	/* amount of free llc in the DG */
	u32 available_llc;
	/* hardware counter list */
	struct cve_hw_cntr_descriptor *hw_cntr_list;
	/* holds start address of hardware counter array */
	struct cve_hw_cntr_descriptor *base_addr_hw_cntr;
	/* actual count of free HW counters in the device group */
	u16 counters_nr;
	/* Pool to Context ID mapping */
	u64 pool_context_map[MAX_IDC_POOL_NR];
	/* dispatcher data */
	struct ds_dev_data *ds_data;
	/* IceDc state, whether card reset is required or not*/
	enum ICEDC_DEVICE_STATE icedc_state;
	/* device descriptor */
	struct dg_dev_info dev_info;
	/* Flag to start power-off thread */
	u8 start_poweroff_thread;
	/* Wait queue for power-off thread */
	cve_os_wait_que_t power_off_wait_queue;
	/* Power-off thread */
#ifdef RING3_VALIDATION
	pthread_t thread;
	u8 terminate_thread;
#else
	struct task_struct *thread;
#endif
	/* List of devices that are to be turned off */
	struct cve_device *poweroff_dev_list;
	/* Lock for accessing poweroff_dev_list */
	cve_os_lock_t poweroff_dev_list_lock;
};

/* Holds all the relevant IDs required for maintaining a map between
 * graph counter ID and hardware counter ID
 */
struct cve_hw_cntr_descriptor {
	/* link to the other counter in the DG */
	struct cve_dle_t list;
	/* Counter ID */
	u16 hw_cntr_id;
	/* Counter ID assigned by graph */
	u16 graph_cntr_id;
	/* list of jobgroup
	 * required to handle counter
	 * release after each JG completion
	 */
	struct cve_cntr_jg *jg_list;
	/* network ID to which this Counter is attached */
	u64 network_id;
	/* refcount used for counter sharing */
	u16 ref_count;
};

/* holds the reference of a jobgroup */
struct cve_cntr_jg {
	/* links to the jobgroups associated with a particular counter */
	struct cve_dle_t list;
	struct jobgroup_descriptor *jg;
};

enum cve_workqueue_state {
	WQ_STATE_ACTIVE,
	WQ_STATE_STOPPED,
	WQ_STATE_DRAINING,
};
struct jobgroup_descriptor;
struct ds_context;
struct job_descriptor;
struct cve_workqueue {
	/* workqueue id */
	u64 wq_id;
	/* pointer to the associated device group */
	struct cve_device_group *dg;
	/* pointer to the associated context */
	struct ds_context *context;
	/* workqueue state */
	enum cve_workqueue_state state;
	/* links to DG scheduler lists */
	struct cve_dle_t list;
	/* links to the context workqueues */
	struct cve_dle_t list_context_wqs;
	/* list of networks within this WQ*/
	struct ice_network *ntw_list;
	/* count of network requested for pool reservation */
	u32 num_ntw_reserving_pool;
};

/* hold information about a job
 * (a sequence of single command buffers)
 * that is passed to the device for execution
 */
struct job_descriptor {
	/* links to the jobs group list */
	struct cve_dle_t list;
	/* the parent jobgroup */
	struct jobgroup_descriptor *jobgroup;
	/* device interface's job handle */
	cve_di_job_handle_t di_hjob;
	/* num of allocations (cb & surfaces) associated with this job */
	u32 allocs_nr;
	/* array of allocation descriptors associated with this job */
	struct cve_allocation_descriptor *cve_alloc_desc;
	/* Graph ICE Id */
	u8 graph_ice_id;
	/* To indicate if SCB is present and should be executed or skipped */
	enum SCB_STATE scb_state;
	/* total counters patch point
	 * of all the jobs within this job
	 */
	u16 cntr_patch_points_nr;
	/* contains mirror image of patch point for counters*/
	struct cve_cntr_pp *counter_pp_desc_list;
};

/* hold information about a job group */
struct jobgroup_descriptor {
	/* links to the global jobgroups list */
	struct cve_dle_t list_global;


	/* links to one of the 3 lists:
	 * submitted / dispatching dispatched
	 */
	struct cve_dle_t list;

	/* system-wide unique identifier */
	u64 id;
	/* the workqueue that owns this job */
	struct cve_workqueue *wq;
	/* the network that owns this job group*/
	struct ice_network *network;
	/* list of jobs */
	struct job_descriptor *jobs;
	/* TODO: duplicate list for Jobs Array of jobs */
	struct job_descriptor *job_list;
	/* pointer to the next dispatched job */
	struct job_descriptor *next_dispatch;
	/* total job in this job group */
	u32 total_jobs;
	/* enable the flag if the JG is scheduled */
	uint8_t scheduled;
	/* enable the flag if the JG is completed */
	uint8_t completed;

	/* submitted jobs number */
	u32 submitted_jobs_nr;
	/* dispatched jobs number */
	u32 dispatched_jobs_nr;
	/* completed/aborted jobs number */
	u32 ended_jobs_nr;
	/* aborted jobs number */
	u32 aborted_jobs_nr;

	/* Completion event required*/
	u32 produce_completion;

	/* array of pointers to jobgroups that this jobgroup
	 * depends on
	 */
	struct jobgroup_descriptor **dependencies;

	/* number of dependencies */
	u32 dependencies_nr;

	/* ref count for total active dependencies */
	u32 cur_dep_count;

	/* available llc size requested
	 * in order to run this jobgroup.
	 */
	u32 llc_size;

	/* requirement of counters for this jobgroup*/
	u32 num_of_idc_cntr;

	/* Bit number indicates if that counter is being used */
	u32 cntr_bitmap;

	/* number of current cves executing this jobgroup. */
	u32 exe_num_of_cves;

};

/* hold information about a counter patch point */
struct cve_cntr_pp {
	/* Link to cve_cntr_pp list in the jobgroup*/
	struct cve_dle_t list;
	/* holds mirror image of patch point*/
	struct cve_patch_point_descriptor cntr_pp_desc_list;
};

struct dev_alloc {
	/* ICE VA for this allocation */
	ice_va_t ice_vaddr;
	/* For reclaiming the allocation */
	cve_mm_allocation_t alloc_handle;
};

/* Each Network keeps its own set of FIFO per ICE */
struct fifo_descriptor {
	/* Device specific allocation info of CBDT */
	struct dev_alloc fifo_alloc;
	/* Above CBDT allocation is associated with this FIFO */
	struct di_fifo fifo;
};

struct ntw_pjob_info {

	/* If N is the graph_ice_id then ice_id_map[N] is driver_ice_id  */
	u8 ice_id_map[MAX_CVE_DEVICES_NR];

	/* If N is the graph_ice_id then num_pjob[N] is the number of
	 * persistent jobs that are to be executed on this ICE
	 */
	u32 num_pjob[MAX_CVE_DEVICES_NR];
	u32 num_pjob_remaining[MAX_CVE_DEVICES_NR];
	/* picebo[N] is 1 only if both the ICE of ICEBOn
	 * belongs to this NTW
	 */
	u8 picebo[MAX_NUM_ICEBO];
	/* sicebo[N] contains index of the ICE which belongs to this NTW
	 * only if exactly one ICE from ICEBOn belongs to this NTW and the
	 * other ICE is blocked
	 */
	u8 sicebo[MAX_NUM_ICEBO];
	/* dicebo[N] contains index of the ICE which belongs to this NTW
	 * only if exactly one ICE from ICEBOn belongs to this NTW
	 */
	u8 dicebo[MAX_NUM_ICEBO];
};

struct ntw_cntr_info {

	/* If N is the graph_cntr_id then cntr_id_map[N] is driver_cntr_id */
	int8_t cntr_id_map[MAX_HW_COUNTER_NR];
};

enum ice_network_priority {
	NTW_PRIORITY_0,
	NTW_PRIORITY_1,
	NTW_PRIORITY_MAX
};

/* hold information about ice dump buffer */
struct ice_dump_desc {
	/* if total_dump_buf is not zero then dump_buf points to
	 * the last element in buf_list of ice_network struct
	 */
	struct cve_user_buffer *dump_buf;
	/* max ice dump allowed per ntw */
	u32 total_dump_buf;
	/* number of devices configured to generate ice dump */
	u32 allocated_buf_cnt;
	/* array of ice dump buffer (size = total_dump_buf) */
	struct di_cve_dump_buffer *ice_dump_buf;
};

enum ntw_exe_status {
	NTW_EXE_STATUS_IDLE,
	NTW_EXE_STATUS_QUEUED,
	NTW_EXE_STATUS_RUNNING,
	NTW_EXE_STATUS_ABORTED
};

/* hold information about a network */
struct ice_network {
	/* a monotonic id for reference count */
	u64 id;

	/* stores a reference to self, should always be first member */
	u64 network_id;

	/* Type of Network (Normal/Priority/DeepSRAM) */
	enum ice_network_priority p_type;

	/* links to a network within its wq */
	struct cve_dle_t list;

	/* list of networks to be executed */
	struct cve_dle_t exe_list;

	/* reference to buffer desc list from UMD,
	 * used only during network creation
	 */
	struct cve_surface_descriptor *buf_desc_list;

	/* array of buffer list after successful page table mapping
	 * this list has a reference in the context global buffer list
	 */
	struct cve_user_buffer *buf_list;

	/* ice dump buffer descriptor */
	struct ice_dump_desc *ice_dump;

	/* number of buffers in the network*/
	u32 num_buf;

	/* number of job group in the network*/
	u32 num_jg;

	/* number of job group executed*/
	u32 num_jg_completed;

	/* number of job group scheduled*/
	u32 num_jg_scheduled;

	/* list of job groups within the network */
	struct jobgroup_descriptor *jg_list;

	/* the workqueue that owns this job */
	struct cve_workqueue *wq;

	/* Completion event required*/
	u32 produce_completion;

	/* Max length of CBDT table */
	u32 max_cbdt_entries;

	/*** For Ntw wide Resource allocation ***/
	/** User inputs */
	u8 num_ice;
	u32 llc_size;
	u32 cntr_bitmap;
	/****/
	u8 has_resource;
	u8 num_ice_idle;
	struct cve_device *ice_list;
	struct cve_hw_cntr_descriptor *cntr_list;
	/******/

	/* For ICE book-keeping */
	struct ntw_pjob_info pjob_info;

	/* For Counter book-keeping */
	struct ntw_cntr_info cntr_info;

	/* Network specific FIFO allocation */
	struct fifo_descriptor fifo_desc[MAX_CVE_DEVICES_NR];

#ifndef RING3_VALIDATION
	/* SW Counter handle */
	void *hswc;
#endif
	/* set to true when atleast 1 job within the network has been
	 * scheduled
	 */
	u8 scheduled;

	/* Flag, set to true if deletion is initiated */
	uint8_t abort_ntw;

	/* IceDc error status*/
	u64 icedc_err_status;

	/* Ice error status*/
	u64 ice_err_status;

	/* Shared read error status */
	u32 shared_read_err_status;

	/* abort wait queue - signaled when pending interrupts are received,
	 * 1 per ICE
	 */
	cve_os_wait_que_t abort_wq;

	/* active ice executing a job from this network*/
	uint8_t active_ice;

	/* Execution time per ICE */
	u64 ntw_exec_time[MAX_CVE_DEVICES_NR];

	/* Indicates if the resouce needs to be reserved.
	 * Provided during ExecuteInfer call.
	 */
	u32 reserve_resource;
	/* paired ICE from ICEBO requirement */
	u8 num_picebo_req;
	/* single ICE from ICEBO requirement, but the other ICE
	 * cannot be allocated to some other NTW
	 */
	u8 num_sicebo_req;
	/* single ICE from ICEBO requirement, the other ICE is free
	 * to be allocated to other NTW
	 */
	u8 num_dicebo_req;
	/* icebo requirement type */
	enum icebo_req_type icebo_req;
	/* Network type deepsram/normal */
	enum ice_network_type network_type;
	u8 max_shared_distance;
	u8 shared_read;

	/* New Variables */
	struct ice_infer *curr_exe;
	struct ice_infer *inf_list;
	struct ice_infer *inf_exe_list;
	enum ntw_exe_status exe_status;
};

enum inf_exe_status {
	INF_EXE_STATUS_IDLE,
	/* In Scheduler Queue */
	INF_EXE_STATUS_QUEUED,
	/* When ICE is processing */
	INF_EXE_STATUS_RUNNING,
	/* Ctrl+C or DestroyInfer*/
	INF_EXE_STATUS_ABORTED
};

struct ice_infer {
	/* Infer Id */
	u64 infer_id;
	/* Parent ice_network */
	struct ice_network *ntw;
	/* List of Infer requests in a Network */
	struct cve_dle_t ntw_list;
	/* List of Infer requests in execution queue */
	struct cve_dle_t exe_list;
	/* List of Infer Buffers */
	struct cve_infer_buffer *buf_list;
	/* Buffer count */
	u32 num_buf;
	/* user data*/
	u64 user_data;
	/* execution status */
	enum inf_exe_status exe_status;
	/* Infer specific handle for PT info */
	void *inf_hdom;
};

/* hold information about user buffer allocation (surface or cb) */
struct cve_user_buffer {
	/* links to the list of the buffers context */
	struct cve_dle_t list;
	/* buffer id */
	cve_bufferid_t buffer_id;
	/* Surface/CB/DSRAM load CB/ Reloadable CB */
	enum ice_surface_type surface_type;
	/* the allocation which is associated with this buffer */
	cve_mm_allocation_t allocation;
};

struct cve_infer_buffer {
	/* buffer index in corresponding network's buffer descriptor*/
	u64 index;
	/* the base address of the area in memory */
	u64 base_address;
	/* fd is the file descriptor for given shared buffer */
	u64 fd;
	/* the allocation which is associated with this buffer */
	cve_mm_allocation_t allocation;
};

struct cve_context_process;
/* hold job information for a single context */
struct ds_context {
	cve_context_id_t context_id;
	/* cyclic list element inside the process context */
	struct cve_dle_t list;
	/* list of buffers allocated by user */
	struct cve_user_buffer *buf_list;
	/* list of per device per context data */
	cve_dev_context_handle_t dev_hctx_list;
	/* a queue for thread waitting for destroy all workqueues */
	cve_os_wait_que_t destroy_wqs_que;
	/* list of wqs in the context */
	struct cve_workqueue *wq_list;
	/* TBD: this field should be removed when
	 * moving to Many/Multi CVEs. In several CVEs
	 * the device group bind to a context.
	 */
	struct cve_device_group *dg;
	/* process the ds_context belongs to */
	struct cve_context_process *process;
	/* pool to which this context is mapped to */
	int8_t pool_id;
	/* SW Counter handle */
	void *hswc;
};

struct ds_dev_data {
	/* list of ready to dispatch workqueues.
	 * a ready workqueue is one that has pending jobs
	 */
	struct cve_workqueue *ready_workqueues;
	/* list of workqueues which does not
	 * have any pending jobs.
	 */
	struct cve_workqueue *idle_workqueues;
	/* the currently dispatching workqueues */
	struct cve_workqueue *dispatch_workqueues;
};

/* hold job information for a single context */
struct cve_context_process {
	/* cyclic list element */
	struct cve_dle_t list;
	/* process id */
	cve_context_process_id_t context_pid;
	/* cyclic list to contexts */
	struct ds_context *list_contexts;
	/* events wait queue - signaled when new event object created */
	cve_os_wait_que_t events_wait_queue;
	/* list of completion events*/
	struct cve_completion_event *events;
};

struct cve_completion_event {
	/* list element */
	struct cve_dle_t list;
	/* jobs group id */
	u64 jobs_group_id;
	/* job status*/
	enum cve_jobs_group_status jobs_group_status;
	/* user data*/
	u64 user_data;
	/* IceDc error state*/
	u64 icedc_err_status;
	/* Toal CB exec time per ICE */
	u64 total_time[MAX_CVE_DEVICES_NR];
	/* Ice error status*/
	u64 ice_err_status;
	/* Shared read error status */
	u32 shared_read_err_status;
};

struct ice_debug_event_bp {
	/* list element */
	struct cve_dle_t list;
	/* indicate which ice gave break point interrupt */
	u32 ice_index;
	/* indicate network_id associated with the ice */
	u64 network_id;
};

int cve_device_init(struct cve_device *dev, int index);
void cve_device_clean(struct cve_device *dev);

#endif /* CVE_DEVICE_H_ */
