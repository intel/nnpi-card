/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/



#ifndef CVE_DEVICE_H_
#define CVE_DEVICE_H_

#include "cve_device_fifo.h"
#include "os_interface.h"
#include "cve_driver.h"
#include "cve_driver_internal_types.h"
#include "doubly_linked_list.h"
#include "cve_fw_structs.h"
#include "project_settings.h"
#include "ice_safe_func.h"

#define INVALID_INDEX -1
#define INVALID_ENTRY 255
#define INVALID_ICE_ID 255
#define INVALID_CTR_ID -1
#define INVALID_POOL_ID -1
#define INVALID_CONTEXT_ID 0
#define INVALID_NETWORK_ID 0
#define ICE_MAX_PMON_CONFIG 32
#define ICE_MAX_MMU_PMON 10
#define ICE_MAX_DELPHI_PMON 10
#define ICE_MAX_A_STEP_DELPHI_PMON 2
#define EXE_ORDER_MAX 0xFFFFFFFFFFFFFFFF
#define DEFAULT_ID 0xFFFFFFFFFFFFFFFF

enum CVE_DEVICE_STATE {
	CVE_DEVICE_IDLE = 0,
	CVE_DEVICE_BUSY
};

enum ICE_POWER_STATE {
	/* ICE is powered off */
	ICE_POWER_OFF,
	/* ICE is powered on */
	ICE_POWER_ON,
	/* ICE is in power off queue */
	ICE_POWER_OFF_INITIATED,
	/* Invalid value */
	ICE_POWER_MAX
};

enum ICEDC_DEVICE_STATE {
	ICEDC_STATE_NO_ERROR = 0,
	ICEDC_STATE_CARD_RESET_REQUIRED
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

/** Structure to hold a unqiue sw id for different objects */
struct ice_swc_node {
	u64 parent_sw_id;
	u64 sw_id;
	void *parent;
};

/** Structure to hold reference to a actual network at card level
 *  Each full network may have multiple sub network to be executed either on
 *  IA or ICE. At ice driver level each network is refered to as a sub network
 *  within the full network at card level.
 *  This structure stores reference to all sub network within the full network.
 */
struct ice_user_full_ntw {
	/** Linked list at context level to store reference to full network */
	struct cve_dle_t list;
	/** its sw counter id w.r.t user*/
	u64 sw_id;
	/** Pointer to the parent */
	void *parent;
	/** Pointer to its sw counter object*/
	void *hswc;
	/** Total ICE network within this network */
	u64 total_ice_ntw;
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
	/*  array of dso register readback values */
	u32 reg_readback_vals[MAX_DSO_CONFIG_REG];
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
	struct ice_register_reader_daemon reset_conf;
	bool is_default_config;
	enum ICE_TRACE_HW_CONFIG_STATUS daemon_config_status;
	bool restore_needed_from_suspend;
};

struct ice_perf_counter_config {
	struct ice_perf_counter_setup conf[ICE_MAX_PMON_CONFIG];
	enum ICE_TRACE_HW_CONFIG_STATUS perf_counter_config_status;
	u32 perf_counter_config_len;
	bool is_default_config;
};

struct ice_pmon_config {
	const char *pmon_name;
	u32 pmon_value;
};

struct ice_reg_stored_config {
	/* MD5 sum of mmu config regs */
	u8 mmu_config_md5[ICEDRV_MD5_MAX_SIZE];
	u32 page_sz_reg[ICE_PAGE_SZ_CONFIG_REG_COUNT];
	u32 cbd_entries_nr;
};

struct cve_device {
	/* device index */
	u32 dev_index;
	/* validity of the device based on fuse value and user input */
	u8 is_valid;
	/* link to Ntw ICEs */
	struct cve_dle_t owner_list;
	/* link to cve devices in an ICEBO */
	struct cve_dle_t bo_list;
	/* List of ICEs to be powered off */
	struct cve_dle_t poweroff_list;
	/* Timestamp of when Power Off request was raised */
	unsigned long poff_jiffy;
	/* Pointer to FIFO Descriptor of current Network */
	struct fifo_descriptor *fifo_desc;
	struct di_cve_dump_buffer *cve_dump_buf;
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
	/* Power state of device. Use following functions to
	 * read/write this value:
	 *	a. ice_dev_set_power_state
	 *	b. ice_dev_get_power_state
	 */
	enum ICE_POWER_STATE power_state;
	/* last pnetwork id that ran on this device */
	cve_network_id_t dev_pntw_id;
	/* last network id that ran on this device */
	cve_network_id_t dev_ntw_id;
	/* last context id that ran on this device */
	cve_network_id_t dev_ctx_id;
	/* ice freq value */
	u32 frequency;
	/* copy of DTF registers to maintain during device reset */
	u32 dtf_regs_data[DTF_REGS_DATA_ARRAY_SIZE];
	bool dtf_sem_bit_acquired;
#ifdef NEXT_E2E
	struct cve_dma_handle bar1_dma_handle;
	cve_mm_allocation_t bar1_alloc_handle;
#endif
	bool logical_dso;
	struct ice_dso_regs_data dso;
	struct ice_read_daemon_config daemon;
	struct ice_observer_config observer;
	/*TODO:perf_counter_config array len has to
	 *evolve with debug code maturity
	 */
	struct ice_perf_counter_config perf_counter;

	/* SW Counter handle */
	void *hswc;
	/* SW Counter handle for infer_device_counter */
	void *hswc_infer;
	/* sw counter parent obj */
	void *parent;
	/* sw counter parent obj at network level*/
	void *infer_parent;
#ifndef RING3_VALIDATION
	/* DTF sysfs related field */
	struct kobject *ice_kobj;
	/* Freq sysfs related field */
	struct kobject *ice_config_kobj;
#endif
	/* in Jiffies */
	unsigned long db_jiffy;

	u32 db_cbd_id;
	u32 is_cold_run;
	void *hjob;
	u32 cbd_base_va;

	u64 idle_start_time;
	u64 busy_start_time;
	/* Is ICE in free pool */
	bool in_free_pool;
	struct ice_pmon_config mmu_pmon[ICE_MAX_MMU_PMON];
	struct ice_pmon_config delphi_pmon[ICE_MAX_DELPHI_PMON];

	/* store cdyn request value, if unchanged, dont request it */
	u16 cdyn_val;

	u32 cdyn_requested;
	u32 gp_reg14_val;
	u32 tlc_reg_val;

	struct ice_reg_stored_config prev_reg_config;

	/* To map software device context handle
	 * Each ICE to have a unique dev context
	 * mapped once ICEs are borrowed
	 */
	u32 mapped_dev_ctx_id;

};

struct llc_pmon_config {
	/*LLC PMON config reg 0 value */
	u64 pmon0_cfg;
	/*LLC PMON config reg 1 value */
	u64 pmon1_cfg;
	/*LLC PMON config reg 2 value */
	u64 pmon2_cfg;
	/*LLC PMON config reg 3 value */
	u64 pmon3_cfg;
	/*LLC PMON disable flag */
	bool disable_llc_pmon;
};

struct icebo_desc {
	/* icebo id */
	u8 bo_id;
	/* link to the owner picebo/sicebo/dicebo list */
	struct cve_dle_t owner_list;
	/* List of devices - static list */
	struct cve_device *dev_list;
	/*LLC PMON config struct */
	struct llc_pmon_config llc_pmon_cfg;
#ifndef RING3_VALIDATION
	/* LLC PMON sysfs related field */
	struct kobject *icebo_kobj;
#endif
	/* ICCP init settings per ICE-BO done */
	bool iccp_init_done;
	/* Number of ICEs in free pool */
	u8 in_pool_ice;
	/* Number of non reserved ices */
	u8 non_res_ice;
};

struct dg_dev_info {
	/* icebo list with two ICEs available */
	struct icebo_desc *picebo_list;
	/* icebo list with one ICE available */
	struct icebo_desc *dicebo_list;
	/* for reference - static icebo list */
	struct icebo_desc *icebo_list;
	/* Number of active devices */
	u32 active_device_nr;
};

struct cve_workqueue;
struct ds_dev_data;

#define CLOS_INVALID_SIZE (MAX_CLOS_SIZE_MB + 1)

/*
 * ------------------------------------
 * | CLOS 0 | CLOS 2 |--> <--| CLOS 1 |
 * ------------------------------------
*/
struct clos_manager {
	/* Total LLC size (in MB) */
	u32 size;
	/* Amount of free LLC (in MB) */
	u32 free;
	/* Total size per CLOS */
	u32 clos_size[ICE_CLOS_MAX];
	/* Free size in use per CLOS */
	u32 clos_free[ICE_CLOS_MAX];
	/* Reserved CLOS size */
	u32 clos_res[ICE_CLOS_MAX];
	/* Non-reserved CLOS_1 + CLOS_2 */
	u32 num_nonres_clos;
	/* Grows Up */
	u32 clos2_idx;
	/* Grows Down */
	u32 clos1_idx;
	/* -------------- */
	/* Default values */
	u64 clos_default[ICE_CLOS_MAX];
	u64 pqr_default;
	/* -------------- */
};
#ifndef RING3_VALIDATION
/*sph mailbox related structure*/
struct ice_sphmbox {
	/* Mailbox registers' base address */
	void __iomem *idc_mailbox_base;
	/* lock to protect concurrent access */
	spinlock_t lock;
};

/* sph power balancer related structure*/
struct ice_sphpb {
	/* Callback functions of power balancer module */
	const struct sphpb_callbacks *sphpb_cbs;
};
#else
/* Dummy sph power balancer related structure for ring3 */
struct ice_sphpb {
	/* Callback functions of power balancer module */
	const struct sphpb_callbacks *sphpb_cbs;
};
#endif

/* For sysfs enabled debug dump  */

struct debug_dump_conf {
	u8 pt_dump;
};

struct hwtrace_job {
	u8 job_id;
	struct ice_dso_regs_data dso;
	struct ice_read_daemon_config daemon;
	struct ice_perf_counter_config perf_counter;
};

struct trace_node_sysfs {
	u64 ctx_id;
	u64 ntw_id;
	u64 infer_num;
	u8 job_count;
	u8 job_list[MAX_CVE_DEVICES_NR];
	struct kobject *node_kobj;
	struct hwtrace_job job;
};

#define FW_SECTION_ALIGNED_SZ_32K (1024 * 32)
#define FW_SECTION_ALIGNED_SZ_4M (1024 * 1024 * 4)

enum ice_mem_cache_sz_type {
	ICE_MEM_CACHE_SZ_TYPE_32K,
	ICE_MEM_CACHE_SZ_TYPE_4M,
	ICE_MEM_CACHE_SZ_TYPE_MAX
};

enum ice_mem_cache_sz {
	ICE_MEM_CACHE_SZ_32K = (32 * 1024),
	ICE_MEM_CACHE_SZ_4M = (4 * 1024 * 1024)
};
#define ICE_MEM_CACHE_SZ_DEFAULT ICE_MEM_CACHE_SZ_4M

struct ice_mem_cache_node {
	/* link of cache nodes */
	struct cve_dle_t list;
	u32 size;
	/* handle to dma memory */
	struct cve_dma_handle dma_handle;
	u64 id;
	u8 in_use;
	u8 type;
};

struct ice_fw_mem_cache {
	struct ice_mem_cache_node *cache_free_head[ICE_MEM_CACHE_SZ_TYPE_MAX];
	struct ice_mem_cache_node *cache_used_head[ICE_MEM_CACHE_SZ_TYPE_MAX];
};


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
	/* hardware counter list */
	struct cve_hw_cntr_descriptor *hw_cntr_list;
	/* holds start address of hardware counter array */
	struct cve_hw_cntr_descriptor *base_addr_hw_cntr;
	/* number of counters in free pool */
	u16 num_avl_cntr;
	/* number of non-reserved counters */
	u16 num_nonres_cntr;
	/* Pool to Context ID mapping */
	u64 pool_context_map[MAX_IDC_POOL_NR];
	/* number of pool in free pool */
	u16 num_avl_pool;
	/* number of non-reserved pool */
	u16 num_nonres_pool;
	/* List of pntw holding resources */
	struct ice_pnetwork *pntw_with_resources;
	/* number of running networks */
	u32 num_running_ntw;
	/* Uniquely identifies last CLOS configuration */
	u32 clos_signature;
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
	struct ice_sphmbox sphmb;
#endif
	/* List of devices that are to be turned off */
	struct cve_device *poweroff_dev_list;
	/* Lock for accessing poweroff_dev_list */
	cve_os_lock_t poweroff_dev_list_lock;
	/* CLOS book keeping */
	struct clos_manager dg_clos_manager;
#ifdef _DEBUG
	/* Book keeping for Order of ExecuteInfer call */
	u64 dg_exe_order;
#endif
	struct ice_sphpb sphpb;
	/*The max llc freq is read from MSR_RING_RATIO_LIMIT
	 *(620H) [6:0] bits during driver module load after the
	 *power cycle and will be stored in llc_max_freq.
	 *
	 * This value varies depending on QDF of the SoC
	 * QDF/SSPEC	Max_freq_obtained
	 * Q3JN		1500 MHz
	 * Q3UP		1600 MHz
	 * QS9S		2600 MHz
	 *
	 */
	u32 llc_max_freq;
	/*The max ice freq is read from MSR_TURBO_RATIO_LIMIT
	 *(1ADH) [7:0] bits during driver module load after the
	 *and will be stored in ice_max_freq.
	 *
	 * This value varies depending on QDF of the SoC
	 * QDF/SSPEC	Max_freq_obtained
	 * Q3JN		800 MHz
	 * Q7QC		600 MHz
	 *
	 */
	u32 ice_max_freq;
	struct debug_dump_conf dump_conf;
	bool dump_ice_mmu_pmon;
	bool dump_ice_delphi_pmon;

	/* PBO = BO with two ICEs */
	/* Total PBO in system */
	u8 total_pbo;
	/* Num PBO in free pool */
	u8 in_pool_pbo;
	/* Num non reserved PBO */
	u8 non_res_pbo;

	/* DICE = Single ICE in BO */
	/* Total DICE in system */
	u8 total_dice;
	/* Num DICE in free pool */
	u8 in_pool_dice;
	/* Num non reserved DICE */
	u8 non_res_dice;

#if 0
	/*
	 * TODO: Enable in future. Not blocking.
	 * https://jira.devtools.intel.com/browse/ICE-26298
	 */

	u8 total_cntr;
	u8 in_pool_cntr;
	u8 non_res_cntr;
#endif
	u32 trace_node_cnt;
	int trace_update_status;
	struct trace_node_sysfs *node_group_sysfs;

	struct cve_fw_loaded_sections *loaded_cust_fw_sections;
	/* place holder to store all information related memory caching */
	struct ice_fw_mem_cache fw_mem_cache;

	/* cyclic list to contexts */
	struct ds_context *list_contexts;
};

/* Holds all the relevant IDs required for maintaining a map between
 * graph counter ID and hardware counter ID
 */
struct cve_hw_cntr_descriptor {
	/* link to the other counter in the DG/Network */
	struct cve_dle_t list;
	/* Counter ID */
	u16 hw_cntr_id;
	/* Counter ID assigned by graph */
	u16 graph_cntr_id;
	/* parent network ID to which this Counter is attached */
	u64 cntr_pntw_id;
	/* Is Counter in free pool */
	bool in_free_pool;
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
	struct ice_pnetwork *pntw_list;
	/* count of network using the pool */
	u32 num_ntw_using_pool;
	/* count of network requested for pool reservation */
	u32 num_ntw_reserving_pool;
	/* count of networks that are running on ICE */
	u32 num_ntw_running;
};

/* hold information about a job
 * (a sequence of single command buffers)
 * that is passed to the device for execution
 */
struct job_descriptor {
	/* Job ID, incremental counter starting from 0 */
	u8 id;
	/* links to the jobs group list */
	struct cve_dle_t list;
	/* the parent jobgroup */
	struct jobgroup_descriptor *jobgroup;
	/* link to paired job */
	struct job_descriptor *paired_job;
	/* device interface's job handle */
	cve_di_job_handle_t di_hjob;
	/* num of allocations (cb & surfaces) associated with this job */
	u32 allocs_nr;
	/* array of allocation descriptors associated with this job */
	struct cve_allocation_descriptor *cve_alloc_desc;
	/* Graph ICE Id */
	u8 graph_ice_id;
	/* ICE Id when a job doesnt have a valid graph id, this ensure
	 * that all jobs have one valid id. Either from blob or self generated.
	 * dummy ids are always exclusive of blob graph id
	 */
	u8 dummy_ice_id;
	/* Hw ICE Id. Actual ICE allocated by Driver */
	u8 hw_ice_id;
	/* contains mirror image of patch point for counters*/
	/* TODO: Move it to Ntw level and do just like InferBuffer patching */
	struct ice_pp_copy *job_cntr_pp_list;
	/* List of MMU Config registers */
	u32 *mmu_cfg_list;
	/* Number of MMU Config registers */
	u32 num_mmu_cfg_regs;
	/* SW device context */
	struct dev_context *dev_ctx;
	/* MD5 sum of mmu config regs */
	__u8 md5[ICEDRV_MD5_MAX_SIZE];
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
	/* submitted jobs number */
	u32 submitted_jobs_nr;
	/* completed/aborted jobs number */
	u32 ended_jobs_nr;
	/* aborted jobs number */
	u32 aborted_jobs_nr;

	/* Completion event required*/
	u32 produce_completion;

	/* available llc size requested
	 * in order to run this jobgroup.
	 */
	u32 llc_size;

	/* requirement of counters for this jobgroup*/
	u32 num_of_idc_cntr;

	/* Bit number indicates if that counter is being used */
	u32 cntr_bitmap;
};

/* hold copy of patch point descriptor */
struct ice_pp_copy {

	struct cve_dle_t list;
	/* holds mirror image of patch point*/
	struct cve_patch_point_descriptor pp_desc;
};

/* Holds IAVA and it's corresponding Value */
struct ice_pp_value {

	/* While patching, set dirty cache for this buffer */
	struct cve_ntw_buffer *ntw_buf;
	/* Patch point IAVA */
	u64 *pp_address;
	/* This value will be stored at pp_address */
	u64 pp_value;
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

struct ntw_cntr_info {

	/* If N is the graph_cntr_id then cntr_id_map[N] is driver_cntr_id */
	int8_t cntr_id_map[MAX_HW_COUNTER_NR];
};

/* hold information about ice dump buffer */
struct ice_dump_desc {
	/* if total_dump_buf is not zero then dump_buf points to
	 * the last element in buf_list of ice_network struct
	 */
	struct cve_ntw_buffer *dump_buf;
	/* max ice dump allowed per ntw */
	u32 total_dump_buf;
	/* number of devices configured to generate ice dump */
	u32 allocated_buf_cnt;
	/* array of ice dump buffer (size = total_dump_buf) */
	struct di_cve_dump_buffer *ice_dump_buf;
};

/* Possible outcome when someone requests resource */
enum resource_status {
	RESOURCE_OK,
	RESOURCE_BUSY,
	RESOURCE_INSUFFICIENT
};

/* Possible types of execution node */
enum node_type {
	NODE_TYPE_INFERENCE,
	NODE_TYPE_RESERVE,
	NODE_TYPE_RELEASE
};

struct execution_node {

	/* Inference, Reserve or Release */
	enum node_type ntype;

	struct cve_dle_t sch_list[EXE_INF_PRIORITY_MAX];
	struct cve_dle_t pntw_queue[EXE_INF_PRIORITY_MAX];

	/* Parent Ntw with which this node is associated */
	struct ice_pnetwork *pntw;
	/* Ntw with which this node is associated */
	struct ice_network *ntw;
	/* Is this node queued */
	bool is_queued;

	/* ------------------- */
	/* Valid for INFERENCE */
	/* ------------------- */
	struct ice_infer *inf;
	/* This flag is bypassed when resources are reserved */
	bool ready_to_run;
	/* Is this node added in Ntw's queue */
	bool in_pntw_queue;
	/* ------------------- */

	/* ------------------------- */
	/* Valid for RESERVE/RELEASE */
	/* ------------------------- */
	bool is_success;
	/* ------------------------- */

};

/* Possible types of ICE allocation policy */
enum pntw_ice_alloc_policy {
	PNTW_ICE_ALLOC_POLICY_UNUSED = 0,
	PNTW_ICE_ALLOC_POLICY_ANYTHING = 1,
	PNTW_ICE_ALLOC_POLICY_DONT_CARE = 2,
	PNTW_ICE_ALLOC_POLICY_BO = 3
};

struct pntw_ice_map {
	enum pntw_ice_alloc_policy policy;
	u8 hw_ice_id;
};

/* hold information about the parent network */
struct ice_pnetwork {
	/* stores a reference to self, should always be first member */
	u64 pntw_id;
	/* links to a parent network within its wq */
	struct cve_dle_t list;
	/* the workqueue that owns this parent network */
	struct cve_workqueue *wq;
	/* Is running */
	bool pntw_running;
	/* Current Executing Network */
	struct ice_network *curr_ntw;
	/* List of child networks */
	struct ice_network *ntw_list;

	/* total number of network */
	u32 ntw_count;

	/* Completion event required*/
	u32 produce_completion;

	/*Device specific domain data */
	cve_dev_context_handle_t dev_hctx_list;
	/* Place holder for software device context
	 * Max entries == Jobs. Each job to have a unique dev context
	 * to be mapped to actual ICE during execution
	 */
	struct dev_context *dev_ctx[MAX_CVE_DEVICES_NR];
	/* list of custom loaded fw sections per cve device */
	struct cve_fw_loaded_sections *loaded_cust_fw_sections;
	struct ice_fw_owner_info self_info[CVE_FW_END_TYPES];

	/*Duplicate */
	u8 num_ice;
	/* CLOS requirements */
	u32 clos[ICE_CLOS_MAX];
	u32 cntr_bitmap;
	u64 infer_buf_page_config[ICEDRV_PAGE_ALIGNMENT_MAX];
	/* If N is the graph_cntr_id then cntr_id_map[N] is driver_cntr_id */
	int8_t cntr_id_map[MAX_HW_COUNTER_NR];

	/* SW Counter handle */
	void *hswc;
	/* SW counter object */
	struct ice_swc_node swc_node;
	struct ice_user_full_ntw *user_full_ntw;

	/* ------------------------- */
	/* Exclusively for scheduler */
	/* ------------------------- */
	/* List of all Infer waiting for execution */
	struct execution_node *sch_queue[EXE_INF_PRIORITY_MAX];
	/* Multi back to back reserve/release will be rejected */
	/* Initialize to RELEASE */
	enum node_type last_request_type;
	/* Parent Network's Reservation node */
	struct execution_node pntw_res_node;
	/* Parent Network's Release node */
	struct execution_node pntw_rel_node;
	/* ------------------------- */

	/****************************************/
	u8 has_resource;
	/* PNtw using resources are added to dg->pntw_with_resources */
	struct cve_dle_t resource_list;
	/* Indicates if this Network needs to reserve the resources */
	bool res_resource;
	struct cve_device *ice_list;
	struct cve_hw_cntr_descriptor *cntr_list;
	s32 cur_ice_map[MAX_CVE_DEVICES_NR];
	u16 global_graph_id_mask;
	struct pntw_ice_map global_ice_map[MAX_CVE_DEVICES_NR];
	/****************************************/

	/* IceDc error status*/
	u64 icedc_err_status;

	/* Ice error status*/
	u64 ice_err_status;
	u32 ice_error_status[MAX_CVE_DEVICES_NR];
	s32 ice_vir_phy_map[MAX_CVE_DEVICES_NR];
	bool reset_ntw;
	bool reserved_on_error;

	/* Shared read error status */
	u32 shared_read_err_status;
	u8 max_shared_distance;
	u8 shared_read;

	/* Flag to disallow fw loading after exIR */
	u8 exIR_performed;

	u64 pntw_icemask;
	u64 pntw_cntrmask;

	/* paired ICE from ICEBO requirement */
	u8 org_pbo_req;
	u8 temp_pbo_req;
	u8 given_pbo_req;
	/* single ICE from ICEBO requirement, the other ICE is free
	 * to be allocated to other NTW
	 */
	u8 org_dice_req;
	u8 temp_dice_req;
	u8 given_dice_req;
	/* icebo requirement type */
	enum icebo_req_type org_icebo_req;
	enum icebo_req_type temp_icebo_req;
	enum icebo_req_type given_icebo_req;

	/* Initialize to NULL */
	struct execution_node *rr_node;

	/* Waitqueue for resource Reservation/Release request */
	cve_os_wait_que_t rr_wait_queue;

	u8 last_done;

	u64 ntw_buf_page_config[ICEDRV_PAGE_ALIGNMENT_MAX];
};

/* hold information about a network */
struct ice_network {
	/* stores a reference to self, should always be first member */
	u64 network_id;
	/* An unique monotonic ID to ensure its not repeated. To be used
	 * as a key
	 */
	u64 unique_id;
	/* links to a network within its wq */
	struct cve_dle_t list;

	/* list of networks to be executed */
	struct cve_dle_t exe_list;

	/* list of networks to be deleted */
	struct cve_dle_t del_list;

	/* reference to buffer desc list from UMD,
	 * used only during network creation
	 */
	struct cve_surface_descriptor *buf_desc_list;

	/* array of buffer list after successful page table mapping
	 * this list has a reference in the context global buffer list
	 */
	struct cve_ntw_buffer *buf_list;

	/* ice dump buffer descriptor */
	struct ice_dump_desc *ice_dump;

	/* number of buffers in the network*/
	u32 num_buf;

	/* number of job group in the network*/
	u32 num_jg;

	/* list of job groups within the network */
	struct jobgroup_descriptor *jg_list;

	/* reference to parent network*/
	struct ice_pnetwork *pntw;

	/* Completion event required*/
	u32 produce_completion;

	/* Max length of CBDT table */
	u32 max_cbdt_entries;

	/*** For Ntw wide Resource allocation ***/
	/** User inputs */
	u8 num_ice;
	u32 cntr_bitmap;
	/****/

	struct cve_device *ice_map[MAX_CVE_DEVICES_NR];

	/* To keep track of paired jobs */
	struct job_descriptor *pjob_list[MAX_CVE_DEVICES_NR];

	/* Network specific FIFO allocation */
	struct fifo_descriptor fifo_desc[MAX_CVE_DEVICES_NR];

	/************************/
	/* SW Counter handle */
	void *hswc;
	/* SW counter object */
	struct ice_swc_node swc_node;
	struct ice_user_full_ntw *user_full_ntw;

	/* ICE specific swc node array */
	void *dev_hswc[MAX_CVE_DEVICES_NR];
	void *dev_hswc_parent;
	/************************/

	/* IceDc error status*/
	u64 icedc_err_status;

	/* Ice error status*/
	u64 ice_err_status;
	u32 ice_error_status[MAX_CVE_DEVICES_NR];
	s32 ice_vir_phy_map[MAX_CVE_DEVICES_NR];
	bool reset_ntw;

	/* Shared read error status */
	u32 shared_read_err_status;

	/* active ice executing a job from this network*/
	uint8_t active_ice;

	/* Execution time per ICE */
	u64 ntw_exec_time[MAX_CVE_DEVICES_NR];

	/** Set breakpoint */
	bool ntw_enable_bp;

	/* paired ICE from ICEBO requirement */
	u8 org_pbo_req;
	/* single ICE from ICEBO requirement, the other ICE is free
	 * to be allocated to other NTW
	 */
	u8 org_dice_req;
	enum icebo_req_type org_icebo_req;

	/* Last Infer that was executed */
	struct ice_infer *curr_exe;
	/* List of all Infer created against this Ntw */
	struct ice_infer *inf_list;

	/* Is running */
	bool ntw_running;

	/* Array of indexes corresponding to inference buffer */
	u64 *infer_idx_list;
	u32 infer_buf_count;

	/* Infer buffer patch points */
	struct ice_pp_copy *ntw_surf_pp_list;
	u32 ntw_surf_pp_count;

	u64 ntw_icemask;

	/* Is Counter patching required? */
	bool patch_cntr;




	u64 infer_buf_page_config[ICEDRV_PAGE_ALIGNMENT_MAX];
	/* Number of buffers every CreateInfer desc must send */
	u32 num_inf_buf;

	/* Resource Mapped */
	u8 resource_mapped;
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
	struct cve_inf_buffer *buf_list;
	/* Buffer count */
	u32 num_buf;
	/* user data*/
	u64 user_data;
	/* Is running */
	bool inf_running;

	/******************************************************/
	/* Valid only when inf_queued=true || inf_running=true*/
	enum ice_execute_infer_priority inf_pr;
	/******************************************************/

	/* events wait queue - signaled when new event object added */
	cve_os_wait_que_t events_wait_queue;
	/* list of available event nodes */
	struct cve_completion_event *infer_events;
	/* Infer specific handle for PT per ICE */
	void *inf_hdom[MAX_CVE_DEVICES_NR];
	/* InferBuffer patch point array */
	struct ice_pp_value *inf_pp_arr;

	/************************/
	/* SW Counter handle */
	/************************/
	void *hswc;
	/* SW counter object */
	struct ice_swc_node swc_node;
	/************************/
	u64 process_pid;
	/* Scheduler's Inference node */
	struct execution_node inf_sch_node;

	/* Time stamp, when inference is slected for schedule
	 * Will be used to calculate network busy time
	 */
	u64 busy_start_time;
};

/* hold information about user buffer allocation (surface or cb) */
struct ice_pntw_buf_info {
	/* links to the list of the unique buffers */
	struct cve_dle_t list;
	/* Surface/CB/DSRAM load CB/ Reloadable CB */
	enum ice_surface_type surface_type;
	/* the allocation which is associated with this buffer */
	cve_mm_allocation_t buf_alloc;
};


/* hold information about user buffer allocation (surface or cb) */
struct cve_ntw_buffer {
	/* links to the list of the buffers context */
	struct cve_dle_t list;
	/* buffer id */
	cve_bufferid_t buffer_id;
	/* Surface/CB/DSRAM load CB/ Reloadable CB */
	enum ice_surface_type surface_type;
	/* the allocation which is associated with this buffer */
	cve_mm_allocation_t ntw_buf_alloc;
	/* If positive, then this is InferBuffer. Index in Infer list. */
	int index_in_inf;
	/* Is this a shared Infer surface*/
	bool is_shared_surf;
	u8 dump;
};

struct cve_inf_buffer {
	/* buffer index in corresponding network's buffer descriptor*/
	u64 index_in_ntw;
	/* the base address of the area in memory */
	u64 base_address;
	/* fd is the file descriptor for given shared buffer */
	u64 fd;
	/* the allocation which is associated with this buffer */
	cve_mm_allocation_t inf_buf_alloc;
};

struct cve_context_process;
/* hold job information for a single context */
struct ds_context {
	cve_context_id_t context_id;
	/* cyclic list element inside the process context */
	struct cve_dle_t list;
	/* cyclic list element inside the device_gruoup */
	struct cve_dle_t dg_list;
	/* list of buffers allocated by user */
	struct cve_ntw_buffer *buf_list;
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

	/**************************************/
	/* SW Counter handle */
	void *hswc;
	/* SW counter object */
	struct ice_swc_node swc_node;
	/* Monotonic counter for network*/
	u64 ntw_id_src;
	/* List of full networks within the context*/
	struct ice_user_full_ntw *user_full_ntw;
	/**************************************/
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
	/* events wait queue - signaled when new event object added */
	cve_os_wait_que_t events_wait_queue;
	/* list of available event nodes */
	struct cve_completion_event *events;
	/* list of allocated event nodes */
	struct cve_completion_event *alloc_events;
};

struct cve_completion_event {
	/* list of empty event nodes */
	struct cve_dle_t main_list;
	/* list of allocated event nodes */
	struct cve_dle_t sub_list;
	/* inference list of allocated event nodes */
	struct cve_dle_t infer_list;
	/* inference id */
	u64 infer_id;
	/* network id*/
	u64 ntw_id;
	/* job status*/
	enum cve_jobs_group_status jobs_group_status;
	/* user data*/
	u64 user_data;
	/* IceDc error state*/
	u64 icedc_err_status;
	/* Total CB exec time per ICE */
	u64 total_time[MAX_CVE_DEVICES_NR];
	/* Store max ICE cycles*/
	u64 max_ice_cycle;
	/* Ice error status*/
	u64 ice_err_status;
	/* Shared read error status */
	u32 shared_read_err_status;
	/* Ice error status*/
	u32 ice_error_status[MAX_CVE_DEVICES_NR];
	/* Ice Map; Virtual to physical */
	s32 ice_vir_phy_map[MAX_CVE_DEVICES_NR];
	/* Ntw reset / Card Reset / No Reset */
	enum ice_error_severity err_severity;
};

struct ice_debug_event_bp {
	/* list element */
	struct cve_dle_t list;
	/* indicate which ice gave break point interrupt */
	u32 ice_index;
	/* indicate network_id associated with the ice */
	u64 network_id;
};

int cve_device_init(struct cve_device *dev, int index, u64 pe_value);
void cve_device_clean(struct cve_device *dev);

enum ICE_POWER_STATE ice_dev_get_power_state(
	struct cve_device *dev);

void ice_dev_set_power_state(struct cve_device *dev,
	enum ICE_POWER_STATE pstate);

void ice_reset_prev_reg_config(struct ice_reg_stored_config *pconfig);

#endif /* CVE_DEVICE_H_ */
