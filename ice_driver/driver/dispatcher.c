/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/



#ifdef RING3_VALIDATION
#include <string.h>
#include <icedrv_sw_trace_stub.h>
#else
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/completion.h>
#include <linux/preempt.h>
#include <linux/trace_clock.h>
#include "icedrv_sw_trace.h"
#endif
#include "ice_sw_counters.h"

#include "cve_driver.h"
#include "cve_driver_internal.h"
#include "os_interface.h"
#include "dispatcher.h"
#include "memory_manager.h"
#include "device_interface.h"
#include "dev_context.h"
#include "doubly_linked_list.h"
#include "cve_firmware.h"
#include "cve_linux_internal.h"
#include "cve_device_group.h"
#include "cve_context_process.h"
#include "cve_driver_utils.h"
#include "version.h"
#include "project_settings.h"
#include "scheduler.h"
#include "device_interface_internal.h"
#include "ice_debug.h"
#include "ice_trace.h"
#include "icedrv_internal_sw_counter_funcs.h"
#include "ice_safe_func.h"


/* max number of Shared_Read requests from the leader, that */
/* were not yet matched by the follower. */
#define MAX_SHARED_DISTANCE 0x40
#define MAX_NUM_JG_DESC 1
#define CLOS_SIGNATURE_DEFAULT 0xFFFFFFFF

/* Since the physical memory is 16GB and the page size is 32KB then the
* MAX_BUFFER_COUNT will be equal to 16GB/32KB which is 524288 and this value
* will be taken as upper_bound for infer_buf_count, num_buf_desc
* and index_num
*/
#define MAX_BUFFER_COUNT 524288

/*Calculate average ice cycles */
#define __calc_ice_max_cycle(max_ice_cycle, total_time) \
do { \
	uint8_t idx = 0;\
	\
	max_ice_cycle = 0; \
	for (; idx < MAX_CVE_DEVICES_NR; idx++) { \
		max_ice_cycle = ((max_ice_cycle > (total_time[idx])) ?\
			 max_ice_cycle : (total_time[idx]));\
	} \
} while (0)


#if ICEDRV_ENABLE_HSLE_FLOW
#define __override_llc_config(llc_policy) { llc_policy = 0; }
#else
#define __override_llc_config(llc_policy) __no_op_stub
#endif /*ICEDRV_ENABLE_HSLE_FLOW*/

/* Global count of JGs that are active */
/* Power off all ICE when this count goes to 0 */
int g_jg_count;

/* UTILITY FUNCTIONS */

enum reset_type_flag {
	RESET_TYPE_HARD,
	RESET_TYPE_SOFT
};

static int __alloc_and_copy(void *base_address,
	size_t sz,
	void **kernel_copy);

static int __do_network_cleanup(struct ice_pnetwork *pntw);
static int __do_pnetwork_cleanup(struct cve_workqueue *wq);
static int __get_wq_from_contex_pid(cve_context_process_id_t context_pid,
		cve_context_id_t context_id,
		struct cve_workqueue **p_wq);
static struct ice_network *__get_network_from_id(
		cve_context_process_id_t context_pid,
		cve_context_id_t context_id,
		u64 ntw_id);
/**
 * This function is called when a network has an active ICE but has not
 * responded in a stipulated time. Its called during context cleanup
 */
static int __ntw_reserve_ice(struct ice_pnetwork *pntw);
static void __ntw_release_ice(struct ice_pnetwork *pntw);
static int __ntw_reserve_cntr(struct ice_pnetwork *pntw);
static void __ntw_release_cntr(struct ice_pnetwork *pntw);
static void __ntw_reset_cntr(struct ice_pnetwork *pntw);
static int __ntw_reserve_clos(struct ice_pnetwork *pntw);
static void __flush_ntw_buffers(struct ice_network *ntw);
static void __flush_inf_buffers(struct ice_infer *inf);
static void __destroy_infer_desc(struct ice_infer *inf);

static int __create_pntw(struct ice_pnetwork_descriptor *pntw_desc,
		struct cve_workqueue *wq, u64 *pntw);
static int __destroy_pntw(struct ice_pnetwork *pntw);
static void __pntw_update_ice_alloc_policy(struct ice_network *network,
		u8 is_last);
static int __map_resources_and_context(struct ice_pnetwork *pntw);
static int __map_dev_to_jobs(struct ice_pnetwork *pntw);
#if 0
/*Not required as soc arch ensures cache coherency*/
static void __flush_inf_cbs(struct ice_infer *inf);
#endif

#ifdef RING3_VALIDATION
/* For RING3 bypass caching logic */
static void __assign_fw_ownership(struct cve_device_group *dg,
		struct ice_pnetwork *pnetwork,
		struct cve_fw_loaded_sections *out_fw_sec, u8 *md5)
{
	cve_dle_add_to_list_after(
			pnetwork->loaded_cust_fw_sections,
			list, out_fw_sec);
}

#else

static void __assign_fw_ownership(struct cve_device_group *dg,
		struct ice_pnetwork *pnetwork,
		struct cve_fw_loaded_sections *out_fw_sec, u8 *md5)
{
	u8 i = 0;
	int ret = 0;

	/* store the MD5 sum*/
	for (; i < ICEDRV_MD5_MAX_SIZE; i++) {
		out_fw_sec->md5[i] = md5[i];

		ret = ice_snprintf_s_u(&out_fw_sec->md5_str[i * 2],
				sizeof(out_fw_sec->md5_str), "%02x", md5[i]);
		if (ret < 0)
			cve_os_log(CVE_LOGLEVEL_ERROR,
					"MD5 copy to string failed(%d)\n",
					ret);
	}
	out_fw_sec->md5_str[i*2] = '\0';

	if (out_fw_sec->cached_mem_used) {
		/* add new loaded dynamic fw to global struct */
		cve_dle_add_to_list_after(dg->loaded_cust_fw_sections,
				list, out_fw_sec);
		cve_os_log(CVE_LOGLEVEL_DEBUG,
				"Cached firmware fw_sec_struct:0x%p MD5:%s #FwCaching\n",
				out_fw_sec, out_fw_sec->md5_str);
	} else {
		cve_dle_add_to_list_after(
				pnetwork->loaded_cust_fw_sections,
				list, out_fw_sec);
		cve_os_log(CVE_LOGLEVEL_DEBUG,
				"PNTW:0x%p Adding custom firmware fw_sec_struct:0x%p MD5:%s #FwCaching\n",
				pnetwork, out_fw_sec, out_fw_sec->md5_str);
		ice_swc_counter_inc(g_sph_swc_global,
				ICEDRV_SWC_GLOBAL_COUNTER_FW_DYNAMIC_ALLOC);
	}

	ice_swc_counter_inc(g_sph_swc_global,
			ICEDRV_SWC_GLOBAL_COUNTER_FW_MD5_MISMATCH);
}

#endif

static void __cleanup_fw_loading(struct ice_pnetwork *pnetwork,
		struct cve_fw_loaded_sections *out_fw_sec,
		int md5_match)
{
	struct cve_device_group *dg = cve_dg_get();
	struct cve_fw_loaded_sections *fw_sec = out_fw_sec;

	if (out_fw_sec->cached_mem_used) {
		/* remove fw from global struct */
		cve_dle_remove_from_list(dg->loaded_cust_fw_sections,
				list, out_fw_sec);
		cve_os_log(CVE_LOGLEVEL_DEBUG,
				"PNTW:0x%llx release cached firmware fw_sec_struct:0x%p MD5:%s #FwCaching\n",
				pnetwork->pntw_id, out_fw_sec,
				out_fw_sec->md5_str);
	} else {
		cve_dle_remove_from_list(
				pnetwork->loaded_cust_fw_sections,
				list, out_fw_sec);
		cve_os_log(CVE_LOGLEVEL_DEBUG,
				"PNTW:0x%llx clean custom firmware fw_sec_struct:0x%p MD5:%s #FwCaching\n",
				pnetwork->pntw_id, out_fw_sec,
				out_fw_sec->md5_str);
	}
	cve_fw_unload(NULL, fw_sec);
}

static int __remove_pntw_from_fw_user(struct ice_pnetwork *pnetwork)
{
	int ret = 0, type = CVE_FW_TYPE_START;
	struct ice_fw_owner_info *owner_info;
	struct cve_fw_loaded_sections *prev_fw_sec;

	for (; type < CVE_FW_END_TYPES; type++) {
		owner_info = &pnetwork->self_info[type];
		/* Remove pnetwork from f/w owner list */
		prev_fw_sec = (struct cve_fw_loaded_sections *)
			owner_info->owner_fw;

		if (owner_info->owner_fw != NULL) {
			cve_dle_remove_from_list(prev_fw_sec->owners,
					owner_list, owner_info);
			cve_os_log(CVE_LOGLEVEL_DEBUG,
					"PNTW:0x%llx Remove pnetwork from fw:0x%p(user HEAD:0x%p) user list MD5:%s #FwCaching\n",
					pnetwork->pntw_id, prev_fw_sec,
					prev_fw_sec->owners,
					prev_fw_sec->md5_str);
		}
	}
	return ret;
}


static int __add_pntw_to_fw_user(struct ice_pnetwork *pnetwork,
		struct cve_fw_loaded_sections *out_fw_sec)
{
	int ret = 0;
	struct ice_fw_owner_info *owner_info;
	struct cve_fw_loaded_sections *prev_fw_sec;

	/* check if pnetwork already has a f/w cached
	 * if yes, then remove pnetwork from its owner list and add the new
	 * fw structure
	 */
	owner_info = &pnetwork->self_info[out_fw_sec->fw_type];
	prev_fw_sec = (struct cve_fw_loaded_sections *)owner_info->owner_fw;

	if (owner_info->owner_fw != NULL) {
		if (owner_info->owner_fw != out_fw_sec) {
			/* restore base f/w first as ownership of this
			 * loaded f/w is global
			 */
			ret = ice_dev_fw_map(pnetwork->dev_hctx_list,
					NULL, prev_fw_sec->fw_type);
			if (ret < 0) {
				cve_os_log_default(CVE_LOGLEVEL_ERROR,
						"PNTW:0x%llx fw_map(0x%p) MD5:%s failed:%d\n",
						pnetwork->pntw_id,
						prev_fw_sec,
						prev_fw_sec->md5_str, ret);
			}

			/* different f/w being requested for caching */
			cve_dle_remove_from_list(prev_fw_sec->owners,
					owner_list, owner_info);
			cve_os_log(CVE_LOGLEVEL_INFO,
					"PNTW:0x%llx Remove pnetwork from fw:0x%p(ListHead:0x%p) TypeCaching:%u MD5:%s #FwCaching\n",
					pnetwork->pntw_id, prev_fw_sec,
					prev_fw_sec->owners,
					prev_fw_sec->cached_mem_used,
					prev_fw_sec->md5_str);
		} else {
			/*same f/w, nothing to do */
			goto exit;
		}
	}

	/* add this pnetwork to the new f/w struct owner list
	 * this is to keep track of users during eviction of f/w from cached
	 * nodes
	 */
	owner_info->owner_fw = (void *)out_fw_sec;
	cve_dle_add_to_list_after(out_fw_sec->owners, owner_list, owner_info);
	cve_os_log(CVE_LOGLEVEL_DEBUG,
			"PNTW:0x%llx ADD pnetwork to fw:0x%p(user HEAD:0x%p) TypeCaching:%u MD5:%s #FwCaching\n",
			pnetwork->pntw_id, out_fw_sec,
			out_fw_sec->owners, out_fw_sec->cached_mem_used,
			out_fw_sec->md5_str);

exit:
	return ret;
}


static int __process_fw_loading(struct ice_pnetwork *pnetwork,
		u64 fw_image, u64 fw_binmap, u32 fw_binmap_size, u8 *md5)
{
	int ret = CVE_DEFAULT_ERROR_CODE;
	struct cve_device_group *dg = cve_dg_get();
	struct cve_fw_loaded_sections *out_fw_sec = NULL;
	int load_new_fw = 0;

	load_new_fw = ice_dg_find_matching_fw(pnetwork, md5, &out_fw_sec);

	/* check if we stored a copy of IVP lib, if not, store it */
	if (load_new_fw) {
		/* check if free node available in cached list
		 * if not, release oldest free node from loaded
		 * firmwares
		 */
		ice_dg_return_cached_mem(pnetwork);
		/* allocate and load a copy of the firmware */
		ret = ice_dev_fw_load(fw_image, fw_binmap,
				fw_binmap_size, &out_fw_sec);
		if (ret < 0) {
			cve_os_log_default(CVE_LOGLEVEL_ERROR,
					"PNTW:0x%llx cve_dev_fw_load failed %d\n",
					pnetwork->pntw_id, ret);
			goto out;
		}

		__assign_fw_ownership(dg, pnetwork, out_fw_sec, md5);
	}

	/* add this network to user list of the f/w,
	 * will be removed during destroy network
	 */
	__add_pntw_to_fw_user(pnetwork, out_fw_sec);

	cve_os_log(CVE_LOGLEVEL_DEBUG,
				"PNTW:0x%llx Mapping f/w 0x%p md5:%s load_new_fw:%d #FwCaching\n",
				pnetwork->pntw_id, out_fw_sec,
				out_fw_sec->md5_str, load_new_fw);
	ret = ice_dev_fw_map(pnetwork->dev_hctx_list, out_fw_sec,
			out_fw_sec->fw_type);
	if (ret < 0) {
		cve_os_log_default(CVE_LOGLEVEL_ERROR,
				"PNTW:0x%llx fw_map(0x%p) MD5:%s failed:%d\n",
				pnetwork->pntw_id, out_fw_sec,
				out_fw_sec->md5_str, ret);
		goto err_fw_map;
	}


	return ret;
err_fw_map:
	if (load_new_fw)
		__cleanup_fw_loading(pnetwork, out_fw_sec, load_new_fw);
out:
	return ret;
}


static int __alloc_and_copy(void *base_address,
	size_t sz,
	void **kernel_copy)
{
	int ret = 0;

	if (sz == 0) {
		ret = -EINVAL;
		goto out;
	}

	ret = OS_ALLOC_ZERO(sz, (void **)kernel_copy);
	if (ret < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"Allocation failed:%d SZ:%lu\n", ret, sz);
		goto out;
	}

	ret = cve_os_read_user_memory(base_address,
		sz, *kernel_copy);
	if (ret != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"os_read_user_memory failed %d\n",
			ret);
		goto error_copy;
	}

	return ret;

error_copy:
	OS_FREE(*kernel_copy, sz);
out:
	return ret;
}

static int __reset_infer_event(struct cve_completion_event *event)
{
	int ret = 0;

	event->infer_id = 0;
	event->ntw_id = 0;
	event->jobs_group_status = CVE_JOBSGROUPSTATUS_PENDING;
	event->user_data = 0;
	event->icedc_err_status = 0;
	event->ice_err_status = 0;
	event->shared_read_err_status = 0;
	ret = ice_memset_s(event->total_time,
			sizeof(event->total_time[0]) * MAX_CVE_DEVICES_NR,
			0, sizeof(event->total_time[0]) * MAX_CVE_DEVICES_NR);
	if (ret < 0)
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"Safelib memset failed %d\n", ret);
	return ret;
}

static int __move_completion_events_to_main_list(
		cve_context_process_id_t context_pid,
		struct ice_infer *inf) {
	struct cve_context_process *context_process = NULL;
	int retval = 0;

	/* get the process based on the id */
	retval = cve_context_process_get(context_pid, &context_process);
	if (retval != 0)
		goto out;

	while (inf->infer_events) {
		struct cve_completion_event *event = inf->infer_events;

		 __reset_infer_event(event);
		cve_dle_remove_from_list(inf->infer_events,
			infer_list, event);
		cve_dle_remove_from_list(context_process->alloc_events,
			sub_list, event);
		cve_dle_add_to_list_before(context_process->events,
			main_list, event);
	}
out:
	return retval;
}

#if 0
TODO: Even thoush we set dirty_dram, no action is taken by Driver.
	Enable full flow.
static void set_dirty_dram_cve_output_buff(struct cve_ntw_buffer *buf_list,
	struct cve_allocation_descriptor *jobs_allocs,
	u32 jobs_allocs_nr,
	struct cve_device *cve_dev)
{
	struct cve_ntw_buffer *buffer = NULL;
	u32 i;

	for (i = 0; i < jobs_allocs_nr; i++) {

		if (jobs_allocs[i].direction & CVE_SURFACE_DIRECTION_OUT) {
			buffer = cve_dle_lookup(
					buf_list,
					list,
					buffer_id,
					jobs_allocs[i].bufferid);
			if (!buffer) {
				cve_os_log(CVE_LOGLEVEL_ERROR,
					"Cannot find surface ID %llu!\n",
					jobs_allocs[i].bufferid);
				return;
			}

			cve_mm_set_dirty_dram(buffer,
				cve_dev);
		}
	}
}
#endif

/* returns a system-wide unique buffer id */
static inline cve_bufferid_t get_new_buffer_id(void)
{
	static atomic64_t bufferid;
	u64 n = cve_os_atomic_increment_64(&bufferid);

	return (cve_bufferid_t)n;
}

static void copy_event_data_and_remove(cve_context_process_id_t context_pid,
		struct cve_context_process *process,
		cve_context_id_t contextid,
		struct ice_infer *inf,
		struct cve_get_event *data) {
	struct ice_network *ntw;
	struct ds_context __maybe_unused *ctx;
	struct cve_completion_event *event;
	u64 *total_time = (uint64_t *)data->total_time;
	u64 *icedc_err_status = (uint64_t *)&data->icedc_err_status;
	u64 *ice_err_status = (uint64_t *)&data->ice_err_status;
	u32 *ice_error_status = (uint32_t *)&data->ice_error_status;
	u32 *ice_vir_phy_map = (uint32_t *)&data->ice_vir_phy_map;
	u32 *shared_read_err_status = &data->shared_read_err_status;
	int i;
	union icedc_intr_status_t reg;
	u64 ice_err;

	if (!data->infer_id)
		event = process->alloc_events;
	else
		event = inf->infer_events;

	data->infer_id = event->infer_id;
	data->jobs_group_status = event->jobs_group_status;
	data->user_data = event->user_data;
	data->err_severity = event->err_severity;
	*icedc_err_status = 0;
	*ice_err_status = 0;
	*shared_read_err_status = event->shared_read_err_status;
	reg.val = event->icedc_err_status;
	if (reg.field.illegal_access)
		*icedc_err_status |= (u64)ILLEGAL_ACCESS;
	if (reg.field.ice_read_err)
		*icedc_err_status |= (u64)ICE_READ_ERR;
	if (reg.field.ice_write_err)
		*icedc_err_status |= (u64)ICE_WRITE_ERR;
	if (reg.field.asf_ice1_err)
		*icedc_err_status |= (u64)ASF_ICE1_ERR;
	if (reg.field.asf_ice0_err)
		*icedc_err_status |= (u64)ASF_ICE0_ERR;
	if (reg.field.cntr_err)
		*icedc_err_status |= (u64)CNTR_ERR;
	if (reg.field.sem_err)
		*icedc_err_status |= (u64)SEM_ERR;
	if (reg.field.attn_err)
		*icedc_err_status |= (u64)ATTN_ERR;
	if (reg.field.cntr_oflow_err)
		*icedc_err_status |= (u64)CNTR_OFLOW_ERR;

	for (i = 0; i < MAX_CVE_DEVICES_NR; i++) {
		union mmio_hub_mem_interrupt_mask_t ice_status;

		total_time[i] = event->total_time[i];

		ice_vir_phy_map[i] = event->ice_vir_phy_map[i];

		ice_status.val = event->ice_error_status[i];

		ice_error_status[i] = 0;
		if (ice_status.field.TLC_ERROR)
			ice_error_status[i] |= (u64)TLC_ERR;
		if (ice_status.field.MMU_ERROR)
			ice_error_status[i] |= (u64)MMU_ERR;
		if (ice_status.field.TLC_PANIC)
			ice_error_status[i] |= (u64)TLC_PANIC;
		if (ice_status.field.MMU_PAGE_NO_WRITE_PERMISSION)
			ice_error_status[i] |= (u64)MMU_PAGE_NO_WRITE_PERM;
		if (ice_status.field.MMU_PAGE_NO_READ_PERMISSION)
			ice_error_status[i] |= (u64)MMU_PAGE_NO_READ_PERM;
		if (ice_status.field.MMU_PAGE_NO_EXECUTE_PERMISSION)
			ice_error_status[i] |= (u64)MMU_PAGE_NO_EXE_PERM;
		if (ice_status.field.MMU_PAGE_NONE_PERMISSION)
			ice_error_status[i] |= (u64)MMU_PAGE_NONE_PERM;
		if (ice_status.field.ASIP2HOST_INT)
			ice_error_status[i] |= (u64)ASIP2HOST_INTR;
		if (ice_status.field.IVP2HOST_INT)
			ice_error_status[i] |= (u64)IVP2HOST_INTR;
		if (ice_status.field.MMU_SOC_BUS_ERROR)
			ice_error_status[i] |= (u64)BUS_ERR;
		if (ice_status.field.INTERNAL_CVE_WATCHDOG_INTERRUPT)
			ice_error_status[i] |= (u64)INTERNAL_WD;
		if (ice_status.field.BTRS_CVE_WATCHDOG_INTERRUPT)
			ice_error_status[i] |= (u64)BTRS_WD;
		if (ice_status.field.INTERNAL_CVE_SECONDARY_WATCHDOG_INTERRUPT)
			ice_error_status[i] |= (u64)INTERNAL_SECONDARY_WD;
		if (ice_status.field.INTERNAL_CVE_CNC_WATCHDOG_INTERRUPT)
			ice_error_status[i] |= (u64)INTERNAL_CNC_WD;
		if (ice_status.field.DSRAM_SINGLE_ERR_INTERRUPT)
			ice_error_status[i] |= (u64)DSRAM_SINGLE_ERR;
		if (ice_status.field.DSRAM_DOUBLE_ERR_INTERRUPT)
			ice_error_status[i] |= (u64)DSRAM_DOUBLE_ERR;
		if (ice_status.field.SRAM_PARITY_ERR_INTERRUPT)
			ice_error_status[i] |= (u64)SRAM_PARITY_ERR;
		if (ice_status.field.DSRAM_UNMAPPED_ADDR_INTERRUPT)
			ice_error_status[i] |= (u64)DSRAM_UNMAPPED_ADDR;
		/* ICE_RDY ??? */
	}

	cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Received completion event for InferID=%llx\n",
			event->infer_id);
	ice_err = event->ice_err_status;

	if (is_tlc_error(ice_err))
		*ice_err_status |= (u64)TLC_ERR;
	if (is_mmu_error(ice_err))
		*ice_err_status |= (u64)MMU_ERR;
	if (is_bus_error(ice_err))
		*ice_err_status |= (u64)BUS_ERR;
	if (is_butress_error(ice_err))
		*ice_err_status |= (u64)BTRS_WD;
	if (is_wd_error(ice_err))
		*ice_err_status |= (u64)INTERNAL_WD;
	if (is_tlc_panic(ice_err))
		*ice_err_status |= (u64)TLC_PANIC;
	if (is_dsram_single_err(ice_err))
		*ice_err_status |= (u64)DSRAM_SINGLE_ERR;
	if (is_dsram_double_err(ice_err))
		*ice_err_status |= (u64)DSRAM_DOUBLE_ERR;
	if (is_sram_parity_err(ice_err))
		*ice_err_status |= (u64)SRAM_PARITY_ERR;
	if (is_dsram_unmapped_addr(ice_err))
		*ice_err_status |= (u64)DSRAM_UNMAPPED_ADDR;
	if (ice_err & ICE_READY_BIT_ERR)
		*ice_err_status |= (u64)ICE_READY_BIT_ERR;

	ntw = (struct ice_network *)event->ntw_id;
	ctx = ntw->pntw->wq->context;

	inf = cve_dle_lookup(ntw->inf_list, ntw_list,
				infer_id, event->infer_id);
	if (!inf) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"ERROR cve dle is NULL");
		goto out;
	}

	/* remove it from the sub/infer list and add it to main list */
	cve_dle_remove_from_list
		(process->alloc_events, sub_list, event);
	cve_dle_remove_from_list
		(inf->infer_events, infer_list, event);
	cve_dle_add_to_list_before(process->events, main_list, event);

	ice_swc_counter_add(ntw->hswc,
			ICEDRV_SWC_SUB_NETWORK_NETBUSYTIME,
			nsec_to_usec(trace_clock_global()
				- inf->busy_start_time));
	DO_TRACE(trace_icedrvEventGeneration(SPH_TRACE_OP_STATE_COMPLETE,
					ctx->swc_node.sw_id,
					ntw->swc_node.parent_sw_id,
					ntw->swc_node.sw_id,
					ntw->network_id,
					inf->swc_node.sw_id,
					SPH_TRACE_OP_STATUS_PASS, 0));
out:
	return;
}

/* returns a system-wide unique buffer id */
static inline u64 __get_ntw_id(void)
{
	static atomic64_t ntw_id;
	u64 n = cve_os_atomic_increment_64(&ntw_id);

	return n;
}


/* returns a system-wide unique job id */
static inline u64 get_new_wq_id(void)
{
	static atomic64_t wq_id;
	u64 n;

	n = cve_os_atomic_increment_64(&wq_id);

	return (u64)n;
}

/* returns a system-wide unique buffer id */
static inline cve_context_id_t get_contex_id(void)
{
	static atomic64_t contextid;
	u64 n = cve_os_atomic_increment_64(&contextid);

	return (cve_context_id_t)n;
}

static struct ds_context *get_context_from_process(
		struct cve_context_process *process,
		cve_context_id_t context_id)
{
	struct ds_context *ctx = NULL;

	ctx = cve_dle_lookup(
			process->list_contexts,
			list, context_id,
			context_id);
	return ctx;
}

static struct cve_workqueue *cve_workqueue_get(
		struct ds_context *context,
		u64 workqueueid)
{
	struct cve_workqueue *workqueue = NULL;

	workqueue = cve_dle_lookup(
			context->wq_list,
			list_context_wqs, wq_id,
			workqueueid);
	return workqueue;
}


/* returns a system-wide unique job id */
static inline u64 get_new_jobgroup_id(void)
{
	static atomic64_t jobgroupid;
	u64 n;

	n = cve_os_atomic_increment_64(&jobgroupid);

	return n;
}

static int __release_wq_resources(struct cve_workqueue *workqueue)
{
	int ret = 0;
	struct cve_workqueue *tmp;
	struct ds_dev_data *ds_dev_data = workqueue->dg->ds_data;

	cve_os_log(CVE_LOGLEVEL_DEBUG,
			"WQ:%p release network resources\n", workqueue);

	/* do network cleanup if required */
	ret = __do_pnetwork_cleanup(workqueue);
	if (ret < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"ERROR:%d WQ:%p parent network cleanup failed\n",
			ret, workqueue);
	}

	tmp = cve_dle_lookup(
			ds_dev_data->dispatch_workqueues,
			list, wq_id,
			workqueue->wq_id);
	/* remove the workqueue from the device group scheduler */
	if (tmp) {
		cve_dle_remove_from_list(ds_dev_data->dispatch_workqueues,
				list,
				workqueue);
	} else {
		cve_dle_remove_from_list(ds_dev_data->idle_workqueues,
				list,
				workqueue);
	}

	/* remove the workqueue from the context list */
	cve_dle_remove_from_list(
			workqueue->context->wq_list,
			list_context_wqs,
			workqueue);

	/* free the workqueue */
	OS_FREE(workqueue, sizeof(*workqueue));

	cve_os_log(CVE_LOGLEVEL_DEBUG,
			"WQ:%p reelased from context list\n", workqueue);

	return ret;

}

static void cleanup_context(struct ds_context *context)
{
	struct cve_workqueue *wq;

	if (context) {
		wq = cve_workqueue_get(context, 1);
		if (wq)
			__release_wq_resources(wq);

		if (context->pool_id != INVALID_POOL_ID) {
			cve_di_unset_pool_registers(context->pool_id);
			cve_ds_unmap_pool_context(context);
		}
	}
}


static void do_warm_reset(struct cve_device *cve_dev,
		cve_dev_context_handle_t dev_handle,
		os_domain_handle hdom,
		enum reset_type_flag reset_type)
{
	u32 page_dir_base_addr;

	ASSERT(dev_handle);

	ice_di_mmu_block_entrance(cve_dev);

	if (reset_type == RESET_TYPE_HARD) {
		/* restore FW sections */
		cve_dev_restore_ivp_fw(cve_dev, dev_handle);
	}

	/* get the page table from the mm module */
	cve_mm_get_page_directory_base_addr(hdom, &page_dir_base_addr);

	/* set the page table to the device */
	cve_di_set_page_directory_base_addr(cve_dev, page_dir_base_addr);

	ice_di_mmu_unblock_entrance(cve_dev);
}


static int md5_assign(u8 *src_md5, u8 *dest_md5)
{
	int ret = 0;

	ret = ice_memcpy_s(dest_md5,
		ICEDRV_MD5_MAX_SIZE * sizeof(src_md5[0]),
		src_md5,
		ICEDRV_MD5_MAX_SIZE * sizeof(src_md5[0]));
	if (ret < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
		"Safelib memcpy Failed %d\n", ret);
		return ret;
	}

	return 0;
}

/* return 0 on success
 * return 1 if mismatch detected
 */
static int md5_match(u8 *src_md5, u8 *dest_md5)
{
	int i = 0;

	for (; i < ICEDRV_MD5_MAX_SIZE; i++) {
		if (src_md5[i] != dest_md5[i])
			return 1;
	}
/* TODO: Returning 1 always to disable md5_match logic
 * revert to return 0 when needed
*/
	return 1;
}

/*
 * reset the CVE device..
 * return :
 */
static void do_reset(struct cve_device *cve_dev,
		cve_dev_context_handle_t dev_handle,
		os_domain_handle hdom,
		struct job_descriptor *job,
		enum reset_type_flag reset_type)
{
	u32 page_dir_base_addr;
	u32 *page_sz_list;

	ASSERT(dev_handle);

	ice_di_mmu_block_entrance(cve_dev);

	/* restore page sizes MMU configuration */
	ice_mm_get_page_sz_list(hdom, &page_sz_list);
	ice_di_update_page_sz(cve_dev, page_sz_list);

	if (reset_type == RESET_TYPE_HARD) {
		/* restore FW sections */
		cve_dev_restore_fws(cve_dev, dev_handle);
	}

	/* get the page table from the mm module */
	cve_mm_get_page_directory_base_addr(
				hdom,
				&page_dir_base_addr);

	/* set the page table to the device */
	cve_di_set_page_directory_base_addr(cve_dev, page_dir_base_addr);

	/* set the MMU addressing mode */
	ice_di_set_mmu_address_mode(cve_dev);

	/* Config mmu if regs set is different */
	if (md5_match(job->md5, cve_dev->prev_reg_config.mmu_config_md5) != 0) {

		ice_di_config_mmu_regs(cve_dev, job->mmu_cfg_list,
			job->num_mmu_cfg_regs);
		md5_assign(job->md5, cve_dev->prev_reg_config.mmu_config_md5);
	}

	/* reset the page table flags state */
	cve_mm_reset_page_table_flags(hdom);

	/* Commented cve_di_set_hw_counters as it is setting the activate
	 * performance counters bit in MMU CONFIG ,which is now being done
	 * through PMON configuration. Enabled if requested explictly via knob
	 */
	/* Enable/Disable HW counters */
	if (cve_dev->dg->dump_ice_mmu_pmon)
		cve_di_set_hw_counters(cve_dev);


	/* If (block_mmu) => Unblock it just before the Doorbell
	 * Else => Unblock here, in reset flow
	 */
	if (!block_mmu)
		ice_di_mmu_unblock_entrance(cve_dev);

	if (cve_dev->di_cve_needs_reset & ~CVE_DI_RESET_DUE_PNTW_SWITCH)
		/* complete the reset flow and run the device cores */
		cve_di_start_running(cve_dev);
		/* Set fifo size and address*/

	cve_dev->di_cve_needs_reset = 0;
}

static void __destroy_ice_dump_buffer(struct ice_network *ntw)
{
	u32 sz;
	struct di_cve_dump_buffer *ice_dump_buf_list =
					ntw->ice_dump->ice_dump_buf;
	struct ice_dump_desc *dump_desc = ntw->ice_dump;

	sz = (sizeof(*ice_dump_buf_list) * ntw->ice_dump->total_dump_buf);
	OS_FREE(ice_dump_buf_list, sz);

	OS_FREE(dump_desc, sizeof(*dump_desc));

	ntw->ice_dump = NULL;
}

static int  __create_ice_dump_buffer(struct ice_network *ntw)
{
	struct ice_dump_desc *dump_desc;
	struct di_cve_dump_buffer *ice_dump_buf_list, *cur_buf;
	struct cve_ntw_buffer *buffer = &ntw->buf_list[ntw->num_buf - 1];
	cve_virtual_address_t ice_vaddr = 0;
	u32 i, ice_dump_size = ntw->buf_desc_list[ntw->num_buf - 1].size_bytes;
	int ret = 0;
	size_t sz;
	u32 core_blob_sz =
		ALIGN(ice_di_get_core_blob_sz(), PLAFTORM_CACHELINE_SZ);

	ret = OS_ALLOC_ZERO(sizeof(*dump_desc), (void **)&dump_desc);
	if (ret < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
		"ERROR:%d  Allocation for ICE_DUMP Buffer List failed\n",
		ret);
		goto out;
	}
	ntw->ice_dump = dump_desc;
	dump_desc->dump_buf = buffer;
	dump_desc->total_dump_buf = ice_dump_size / core_blob_sz;
	if (!dump_desc->total_dump_buf)
		goto error_alloc;
	dump_desc->allocated_buf_cnt = 0;

	sz = (sizeof(*ice_dump_buf_list) * dump_desc->total_dump_buf);
	ret = OS_ALLOC_ZERO(sz, (void **)&ice_dump_buf_list);
	if (ret < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
		"ERROR:%d Allocation for ICE_DUMP Buffer List failed\n", ret);
		goto error_alloc;
	}

	dump_desc->ice_dump_buf = ice_dump_buf_list;
	ice_vaddr = ice_mm_get_iova(buffer);

	for (i = 0; i < dump_desc->total_dump_buf ; i++) {
		cur_buf = &ice_dump_buf_list[i];
		cur_buf->is_allowed_tlc_dump = 1;
		cur_buf->cve_dump_buffer = (void *)(uintptr_t)buffer->buffer_id;
		cur_buf->ice_vaddr = ALIGN((ice_vaddr +
		(i * ice_di_get_core_blob_sz())), PLAFTORM_CACHELINE_SZ);
	}

	/* success */
	return 0;
error_alloc:
	OS_FREE(dump_desc, sizeof(*dump_desc));
	ntw->ice_dump = NULL;
out:
	return ret;
}

enum pool_status cve_ds_map_pool_context(struct ds_context *context)
{
	int i;
	enum pool_status pstatus;
	u64 context_id = context->context_id;
	struct cve_device_group *dg = cve_dg_get();
	u64 *pool_context_map = dg->pool_context_map;

	if (context->pool_id != INVALID_POOL_ID) {

		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Pool %u exist for Context=%llu\n",
			context->pool_id, context_id);

		pstatus = POOL_EXIST;
		goto end;

	} else if (dg->num_avl_pool == 0) {

		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Insufficient Pool for Context=%llu\n",
			context_id);

		pstatus = POOL_EXHAUSTED;
		goto end;
	}

	for (i = 0; i < NUM_POOL_REG; i++) {
		if (pool_context_map[i] == INVALID_CONTEXT_ID) {
			pool_context_map[i] = context_id;
			context->pool_id = i;

			cve_os_log(CVE_LOGLEVEL_DEBUG,
				"Reserved Pool=%u for CtxID=%llu\n",
				i, context_id);

			pstatus = POOL_ALLOCATED;
			dg->num_avl_pool--;
			goto end;
		}
	}

	pstatus = POOL_EXHAUSTED;
	ASSERT(false);

end:
	return pstatus;
}

void cve_ds_unmap_pool_context(struct ds_context *context)
{
	int8_t pool_id = context->pool_id;
	struct cve_device_group *dg = cve_dg_get();
	u64 *pool_context_map = dg->pool_context_map;

	pool_context_map[pool_id] = INVALID_CONTEXT_ID;
	context->pool_id = INVALID_POOL_ID;
	dg->num_avl_pool++;

	cve_os_log(CVE_LOGLEVEL_INFO,
		"Released pool %u from Context=%llx\n",
		pool_id, context->context_id);
}

static int alloc_and_map_network_fifo(struct ice_network *network)
{

	int retval, i;
	cve_dev_context_handle_t dev_handle = NULL;
	struct ds_context *context = network->pntw->wq->context;
	struct ice_pnetwork *pntw = network->pntw;

	for (i = 0; i < pntw->num_ice; i++) {
		dev_handle = pntw->dev_ctx[i];
		cve_os_log(CVE_LOGLEVEL_DEBUG,
				COLOR_YELLOW(
					"Creating CBDT buffer for CBDT_Entries=%u\n"
					),
				network->max_cbdt_entries + 1);

		retval = cve_dev_alloc_and_map_cbdt(dev_handle,
				&network->fifo_desc[i],
				network->max_cbdt_entries);
		if (retval != 0) {
			cve_os_log_default(CVE_LOGLEVEL_ERROR,
					"cve_dev_alloc_and_map_cbdt failed %d\n",
					retval);
			cve_os_log_default(CVE_LOGLEVEL_ERROR,
					"ContextId:%llu, NtwID:0x%llx, CBDT Entries: %u\n",
					context->context_id,
					network->network_id,
					network->max_cbdt_entries);
			goto out;
		}
	}

	return 0;
out:
	/*TODO: check the logic of failure case */
	for (; i >= 0; i--) {
		dev_handle = pntw->dev_ctx[i];

		cve_os_log(CVE_LOGLEVEL_DEBUG,
				COLOR_YELLOW(
					"Destroying CBDT buffer for CBDT_Entries=%u\n"
					),
				network->max_cbdt_entries + 1);

		cve_dev_dealloc_and_unmap_cbdt(dev_handle,
				&network->fifo_desc[i]);

	}

	return retval;
}

static int dealloc_and_unmap_network_fifo(struct ice_network *network)
{
	cve_dev_context_handle_t dev_handle = NULL;
	struct ice_pnetwork *pntw = network->pntw;
	int i;

	for (i = 0; i < pntw->num_ice; i++) {
		dev_handle = pntw->dev_ctx[i];

		cve_os_log(CVE_LOGLEVEL_DEBUG,
				COLOR_YELLOW(
					"Destroying CBDT buffer CBDT_Entries=%u\n"
					),
				network->max_cbdt_entries + 1);

		cve_dev_dealloc_and_unmap_cbdt(dev_handle,
				&network->fifo_desc[i]);

	}

	return 0;
}

static void __send_ice_poweron_sync_message_to_cnc(struct cve_device *dev,
						u64 timestamp, u64 ctxId,
						u64 netId, u64 inferId)
{
	/* Send start marker message to CnC
	 */
	cve_os_write_mmio_32(dev,
	(cfg_default.ice_dbg_cbbid_base + cfg_default.ice_dbg_cbbid_cfg_offset +
	(1 * 4)), 0xCAFE1CE0 + dev->dev_index);

	/* Send lower 32 bits of timestamp to CnC
	*/
	cve_os_write_mmio_32(dev,
	(cfg_default.ice_dbg_cbbid_base + cfg_default.ice_dbg_cbbid_cfg_offset +
	(1 * 4)), timestamp & 0xFFFFFFFF);

	/* Send higher 32 bits of timestamp to CnC
	*/
	cve_os_write_mmio_32(dev,
	(cfg_default.ice_dbg_cbbid_base + cfg_default.ice_dbg_cbbid_cfg_offset +
	(1 * 4)), (timestamp >> 32) & 0xFFFFFFFF);

	/* Send lower 32 bits of context ID to CnC
	*/
	cve_os_write_mmio_32(dev,
	(cfg_default.ice_dbg_cbbid_base + cfg_default.ice_dbg_cbbid_cfg_offset +
	(1 * 4)), ctxId & 0xFFFFFFFF);

	/* Send higher 32 bits of context ID to CnC
	*/
	cve_os_write_mmio_32(dev,
	(cfg_default.ice_dbg_cbbid_base + cfg_default.ice_dbg_cbbid_cfg_offset +
	(1 * 4)), (ctxId >> 32) & 0xFFFFFFFF);

	/* Send lower 32 bits of network ID to CnC
	*/
	cve_os_write_mmio_32(dev,
	(cfg_default.ice_dbg_cbbid_base + cfg_default.ice_dbg_cbbid_cfg_offset +
	(1 * 4)), netId & 0xFFFFFFFF);

	/* Send higher 32 bits of network ID to CnC
	*/
	cve_os_write_mmio_32(dev,
	(cfg_default.ice_dbg_cbbid_base + cfg_default.ice_dbg_cbbid_cfg_offset +
	(1 * 4)), (netId >> 32) & 0xFFFFFFFF);

	/* Send lower 32 bits of inference ID to CnC
	*/
	cve_os_write_mmio_32(dev,
	(cfg_default.ice_dbg_cbbid_base + cfg_default.ice_dbg_cbbid_cfg_offset +
	(1 * 4)), inferId & 0xFFFFFFFF);

	/* Send higher 32 bits of inference ID to CnC
	*/
	cve_os_write_mmio_32(dev,
	(cfg_default.ice_dbg_cbbid_base + cfg_default.ice_dbg_cbbid_cfg_offset +
	(1 * 4)), (inferId >> 32) & 0xFFFFFFFF);

	/* Send stop marker message to CnC
	*/
	cve_os_write_mmio_32(dev,
	(cfg_default.ice_dbg_cbbid_base + cfg_default.ice_dbg_cbbid_cfg_offset +
	(1 * 4)), 0xDEAD1CE0 + dev->dev_index);
}

static int __dispatch_single_job(
		struct cve_device *cve_dev,
		struct jobgroup_descriptor *jobgroup)
{
	cve_di_subjob_handle_t *embedded_cbs_subjobs = NULL;
	struct ds_context __maybe_unused *next_ctx =
			jobgroup->wq->context;
	cve_dev_context_handle_t dev_next_ctx = NULL;
	os_domain_handle hdom = NULL;
	struct ice_network *ntw = jobgroup->network;
	struct ice_infer *inf = ntw->curr_exe;
	struct job_descriptor *job = jobgroup->next_dispatch;
	struct ice_pnetwork *pntw = ntw->pntw;
	cve_di_subjob_handle_t *warm_dev_ecb = NULL;
	int ret = 0, len = 0;
	struct cve_device_group *dg = cve_dg_get();
	u64 __maybe_unused po_ts;
	char sync_marker[12];
	bool throttling;
	u16 job_cdyn_val;

	DO_TRACE(trace_icedrvScheduleJob(
		SPH_TRACE_OP_STATE_QUEUED,
		cve_dev->dev_index,
		next_ctx->swc_node.sw_id,
		ntw->pntw->swc_node.sw_id,
		ntw->swc_node.sw_id,
		ntw->network_id,
		ntw->curr_exe->swc_node.sw_id,
		job, SPH_TRACE_OP_STATUS_CDYN_VAL,
		cve_di_get_cdyn_val(job->di_hjob)));

	if (ntw->ice_dump &&
	(ntw->ice_dump->allocated_buf_cnt < ntw->ice_dump->total_dump_buf)) {
		cve_dev->cve_dump_buf =
		&ntw->ice_dump->ice_dump_buf[ntw->ice_dump->allocated_buf_cnt];
		ntw->ice_dump->allocated_buf_cnt++;
		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"ICE:%d is_allowed_tlc_dump:%d iceDumpVaddr:0x%x\n",
			cve_dev->dev_index,
			cve_dev->cve_dump_buf->is_allowed_tlc_dump,
			cve_dev->cve_dump_buf->ice_vaddr);
	}

	hdom = inf->inf_hdom[job->id];

	if (!hdom) {
		ret = -EFAULT;
		goto out;
	}
	/* Mark the device as busy */
	cve_dev->state = CVE_DEVICE_BUSY;
	/* get a unique dev ctx for this job*/
	dev_next_ctx = pntw->dev_ctx[job->id];

	/* do reset if needed */
	if (cve_di_get_device_reset_flag(cve_dev)) {
		cve_os_dev_log(CVE_LOGLEVEL_DEBUG,
				cve_dev->dev_index,
				"Pntw:0x%llx Ntw:0x%llx Inf:0x%llx Job:%u GraphId:%u DummyId:%u Performing Hard Reset\n",
				ntw->pntw->pntw_id,
				ntw->network_id,
				inf->swc_node.sw_id,
				job->id, job->graph_ice_id,
				job->dummy_ice_id);


		ice_di_set_cold_run(job->di_hjob);

		/* if driver has respected the request then set the shared
		 * read mmio else disable it
		 */
		if (ntw->pntw->shared_read)
			ice_di_set_shared_read_reg(cve_dev, ntw, 1);
		else
			ice_di_set_shared_read_reg(cve_dev, ntw, 0);

		do_reset(cve_dev, dev_next_ctx, hdom, job, RESET_TYPE_HARD);

		po_ts = trace_clock_global();

		len = ice_snprintf_s_u(sync_marker, sizeof(sync_marker),
				"0xDEAD1CE%x\n", cve_dev->dev_index);
		if (len < 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
				"Safelib snprintf failed %d\n", len);
			return len;
		}

		DO_TRACE(trace_icedrvPowerOn(
			SPH_TRACE_OP_STATE_PO,
			cve_dev->dev_index,
			next_ctx->swc_node.sw_id,
			ntw->swc_node.parent_sw_id,
			ntw->swc_node.sw_id,
			ntw->network_id,
			ntw->curr_exe->swc_node.sw_id,
			po_ts, SPH_TRACE_OP_STATUS_POWERED_ON,
			sync_marker));

		/* Send ICE Power ON sync message to CnC
		*/
		__send_ice_poweron_sync_message_to_cnc(
				cve_dev, po_ts,
				next_ctx->swc_node.sw_id,
				ntw->swc_node.parent_sw_id,
				ntw->curr_exe->swc_node.sw_id);

		/* Configure ICE dump Registers with
		 * Buffer VA and Trigger=Dump On Error
		 * Configuration is done post enabling of cores to capture the
		 * register writes in CNC logs also
		 */
		cve_di_reset_cve_dump(cve_dev, cfg_default.ice_dump_on_error,
				cve_dev->cve_dump_buf);

		cve_dev_get_emb_cb_list(
			dev_next_ctx,
			&embedded_cbs_subjobs);

		job_cdyn_val = cve_di_get_cdyn_val(job->di_hjob);
		if (job_cdyn_val && cve_dev->cdyn_val != job_cdyn_val) {
			/* For A step Throttling is disabled */
			throttling = false;
			if (ice_get_iccp_throttling_flag())
				throttling = true;
			ret = ice_iccp_license_request(cve_dev, throttling,
								job_cdyn_val);
			cve_os_dev_log(CVE_LOGLEVEL_DEBUG,
					cve_dev->dev_index,
					" Sending iccp license request Curr:%u Requested:%u",
					cve_dev->cdyn_val,
					job_cdyn_val);
			if (ret) {
				cve_os_dev_log(CVE_LOGLEVEL_ERROR,
					cve_dev->dev_index,
					" failed in iccp license request (%d)\n",
					ret);
			}
			cve_dev->cdyn_val = job_cdyn_val;
		}

	} else {
		cve_os_dev_log(CVE_LOGLEVEL_DEBUG,
				cve_dev->dev_index,
				"No Reset\n");
		if (cve_dev->daemon.restore_needed_from_suspend)
			ice_trace_restore_daemon_config(cve_dev, true);

		if (ntw->pntw->ntw_count > 1)
			do_warm_reset(cve_dev, dev_next_ctx,
					hdom, RESET_TYPE_HARD);

		/* invalidate the page table if needed */
		cve_mm_invalidate_tlb(hdom, cve_dev);

		cve_dev_get_emb_cb_list(dev_next_ctx, &warm_dev_ecb);
	}

	/* Device FIFO pointer will now point to Network's ICE specific FIFO */
	cve_dev->fifo_desc = &jobgroup->network->fifo_desc[job->id];

	if (dg->dump_conf.pt_dump)
		print_cur_page_table(hdom);


	cve_os_dev_log(CVE_LOGLEVEL_DEBUG,
			cve_dev->dev_index,
			"Ctx-ID:0x%llx, NtwID:0x%llx Job:%p\n",
			next_ctx->context_id,
			jobgroup->id,
			job);

	/* dispatch the current job */
	cve_di_dispatch_job(cve_dev, job->di_hjob,
			embedded_cbs_subjobs, warm_dev_ecb);

	/* increment the next dispatch pointer */
	jobgroup->next_dispatch =
			cve_dle_next(jobgroup->next_dispatch,
					list);
out:
	return ret;
}

int config_ds_trace_node_sysfs(struct cve_device *dev, struct ice_network *ntw,
		struct job_descriptor *job, int job_id)
{
	u32 index, count;
	bool job_id_match = false;
	struct cve_device_group *dg = cve_dg_get();
	struct trace_node_sysfs *node = dg->node_group_sysfs;

	u64 ctx_id = ntw->pntw->wq->context->swc_node.sw_id;
	u64 ntw_id = ntw->swc_node.sw_id;
	u64 infer_num = ntw->curr_exe->infer_id;
	int retval = 0;

	/*TODO: Optimize loop*/
	for (index = 0; index < dg->trace_node_cnt; index++)
		for (count = 0; count < node[index].job_count; count++)
			if (((job->graph_ice_id ==
					node[index].job_list[count]) ||
				((job->graph_ice_id == INVALID_ICE_ID) &&
				 job_id == node[index].job_list[count]))
					&& (node[index].ctx_id == ctx_id ||
					node[index].ctx_id == DEFAULT_ID) &&
					(node[index].ntw_id == ntw_id ||
					 node[index].ntw_id == DEFAULT_ID) &&
					(node[index].infer_num == infer_num ||
					 node[index].infer_num == DEFAULT_ID)) {

				dev->logical_dso = true;
				retval = ice_memcpy_s(&dev->dso,
					sizeof(struct ice_dso_regs_data),
					&node[index].job.dso,
					sizeof(struct ice_dso_regs_data));
				if (retval < 0) {
					cve_os_log(CVE_LOGLEVEL_ERROR,
					"Safelib memcpy failed %d\n", retval);
					return retval;
				}

				retval = ice_memcpy_s(&dev->perf_counter,
					sizeof(struct ice_perf_counter_config),
					&node[index].job.perf_counter,
					sizeof(struct ice_perf_counter_config));
				if (retval < 0) {
					cve_os_log(CVE_LOGLEVEL_ERROR,
					"Safelib memcpy failed %d\n", retval);
					return retval;
				}
				retval = ice_memcpy_s(&dev->daemon,
					sizeof(struct ice_read_daemon_config),
					&node[index].job.daemon,
					sizeof(struct ice_read_daemon_config));
				if (retval < 0) {
					cve_os_log(CVE_LOGLEVEL_ERROR,
					"Safelib memcpy Failed %d\n", retval);
					return retval;
				}

				cve_os_log(CVE_LOGLEVEL_DEBUG,
				     "job_graph_iceid %d, user jobid with %d\n",
					job->graph_ice_id,
					node[index].job_list[count]);
				job_id_match = true;

			}

	if (dev->dso.dso_config_status != TRACE_STATUS_DEFAULT &&
			(!job_id_match)) {

		dev->dso.dso_config_status =
			TRACE_STATUS_DEFAULT_CONFIG_WRITE_PENDING;
		dev->dso.is_default_config = true;
		ice_trace_set_default_dso(dev);
	}
	return retval;
}

static void __trigger_work_on_ice(struct ice_network *ntw)
{
	u8 i = 0;
	struct cve_device *dev;
	u64 busy_start_time = trace_clock_global();
	unsigned long db_jiffy = ice_os_get_current_jiffy();
	struct job_descriptor *job;

	while (i < ntw->jg_list->submitted_jobs_nr) {
		job = &ntw->jg_list->job_list[i];

		/* At this point it is guaranteed that device will be found */
		dev = cve_device_get(job->hw_ice_id);
#if ENABLE_GPR_WAIT
		if (dev->cdyn_requested)
			ice_iccp_license_ack(dev);
#endif
		cve_di_set_counters(dev, busy_start_time, db_jiffy);
		cve_di_do_job_db(dev, dev->hjob);
		i++;
	};
}

int ice_ds_dispatch_jg(struct jobgroup_descriptor *jobgroup)
{
	u32 i, ice_mask = 0, clos_mask;
	struct cve_device *dev;
	int retval = 0;
	struct cve_device_group *dg = cve_dg_get();
	struct ice_network *ntw = jobgroup->network;
	struct job_descriptor *job;

	if (!ice_sch_preemption())
		os_disable_preemption();

	if (ntw->pntw->resource_mapped == 0) {
		retval = __map_resources_and_context(ntw->pntw);
		if (retval < 0)
			goto exit;

	}

	__map_dev_to_jobs(ntw->pntw);

	DO_TRACE(trace__icedrvScheduleInfer(
		SPH_TRACE_OP_STATE_QUEUED,
		ntw->pntw->wq->context->swc_node.sw_id,
		ntw->swc_node.parent_sw_id,
		ntw->swc_node.sw_id, ntw->network_id,
		ntw->curr_exe->swc_node.sw_id,
		SPH_TRACE_OP_STATUS_ICE, ntw->ntw_icemask));

	ice_swc_counter_inc(ntw->hswc,
			ICEDRV_SWC_SUB_NETWORK_COUNTER_INF_SCHEDULED);

	/* Patch InferBuffer */
	retval = ice_mm_patch_inf_pp_arr(ntw->curr_exe);
	if (retval < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"ice_mm_patch_inf_pp_arr failed %d\n", retval);
		goto exit;
	}

	dg->num_running_ntw++;
	clos_mask = (ntw->pntw->clos[ICE_CLOS_1] << 16) |
		ntw->pntw->clos[ICE_CLOS_2];
	ntw->pntw->wq->num_ntw_running++;

	if ((dg->num_running_ntw == 1)
		&& (dg->clos_signature != clos_mask)) {
		/* If this is the only Ntw running then respect the
		 * CLOS requirement
		 */
		cve_os_log(CVE_LOGLEVEL_INFO,
			"Allocate CLOS for NtwId=0x%lx\n", (uintptr_t)ntw);
		__ntw_reserve_clos(ntw->pntw);
		ice_os_set_clos((void *)&dg->dg_clos_manager);
		dg->clos_signature = clos_mask;
	} else if ((dg->num_running_ntw == 2)
		&& (dg->clos_signature != CLOS_SIGNATURE_DEFAULT)) {

		clos_mask = CLOS_SIGNATURE_DEFAULT;
		cve_os_log(CVE_LOGLEVEL_INFO,
			"Reset CLOS\n");
		/* Reset CLOS MSR registers */
		ice_os_reset_clos((void *)&dg->dg_clos_manager);
		dg->clos_signature = clos_mask;
	}

	retval = set_idc_registers(ntw, true);
	if (retval < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"ERROR:%d NtwID=0x%lx ICE configuration failed\n",
			retval, (uintptr_t)ntw);

		if (retval == -ICEDRV_KERROR_ICE_DOWN)
			ntw->ice_err_status |= (u64)ICE_READY_BIT_ERR;

		goto exit;
	}

	/* Reset all ICEs together */
	cve_di_reset_device(ntw);

	for (i = 0; i < jobgroup->submitted_jobs_nr; i++) {

		job = jobgroup->next_dispatch;

		/* If next Job is persistent then scheduler should pick
		 * the ICE with proper graph_ice_id
		 */
		dev = cve_device_get(job->hw_ice_id);
		/* At this point it is guaranteed that device will be found */

		if (!dev) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
				"ERROR cve dev is NULL");
			ASSERT(false);
		}
		if (dg->trace_node_cnt > 0) {
			retval = config_ds_trace_node_sysfs(dev, ntw, job, i);
			if (retval < 0)
				goto exit;
		}

		if (job->graph_ice_id < NUM_ICE_UNIT) {
			ntw->ice_vir_phy_map[job->graph_ice_id] =
				job->hw_ice_id;
		} else {
			ntw->ice_vir_phy_map[i] = job->hw_ice_id;
		}

		ice_mask |= (1 << dev->dev_index);
		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"JobID=0x%lx will be executed on ICE-%u\n",
			(uintptr_t)job, dev->dev_index);

		if (ntw->patch_cntr && job->job_cntr_pp_list) {

			cve_os_log(CVE_LOGLEVEL_DEBUG,
				COLOR_YELLOW(
					"Patching CounterPP. JobID=%lx\n"
				),
				(uintptr_t)job);


			/* Patch Counters */
			retval = ice_mm_patch_cntrs(ntw->buf_list,
				job, dev);
			if (retval < 0) {
				cve_os_log(CVE_LOGLEVEL_ERROR,
				"ERROR: %d, ice_mm_patch_cntrs() failed\n",
				retval);
				goto exit;
			}

		}

		/*TODO: This call should never fail because of resource */
		retval = __dispatch_single_job(dev, jobgroup);
		if (retval)
			goto exit;
	}
	__trigger_work_on_ice(ntw);
exit:
	DO_TRACE(trace__icedrvScheduleInfer(
		SPH_TRACE_OP_STATE_START,
		ntw->pntw->wq->context->swc_node.sw_id,
		ntw->swc_node.parent_sw_id,
		ntw->swc_node.sw_id, ntw->network_id,
		ntw->curr_exe->swc_node.sw_id,
		SPH_TRACE_OP_STATUS_ICE, ice_mask));

	if (!ice_sch_preemption())
		os_enable_preemption();

	return retval;
}

static int cve_destroy_workqueue(
		struct cve_workqueue *workqueue)
{
	int retval = CVE_DEFAULT_ERROR_CODE;
	struct cve_workqueue *tmp;
	struct ds_dev_data *ds_dev_data =
			workqueue->dg->ds_data;

	cve_os_log(CVE_LOGLEVEL_DEBUG,
				"START Destroy WQ\n");

	/* refuse to close active workqueues */
	if (is_workqueue_contain_network(workqueue)) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"Cannot destroy WQ. Network Exists!!!\n");
		retval = -ICEDRV_KERROR_CTX_BUSY;
		goto out;
	}

	tmp = cve_dle_lookup(
			ds_dev_data->dispatch_workqueues,
			list, wq_id,
			workqueue->wq_id);
	/* remove the workqueue from the device group scheduler */
	if (tmp) {
		cve_dle_remove_from_list(ds_dev_data->dispatch_workqueues,
				list,
				workqueue);
	} else {
		cve_dle_remove_from_list(ds_dev_data->idle_workqueues,
				list,
				workqueue);
	}

	/* remove the workqueue from the context list */
	cve_dle_remove_from_list(
			workqueue->context->wq_list,
			list_context_wqs,
			workqueue);

	/* free the workqueue */
	OS_FREE(workqueue, sizeof(*workqueue));

	cve_os_log(CVE_LOGLEVEL_DEBUG,
				"END Destroy WQ\n");

	/* success */
	retval = 0;

out:
	return retval;
}

static int cve_create_workqueue(
		struct ds_context *context,
		struct cve_device_group *dg,
		struct cve_workqueue **out_wq)
{
	int retval = CVE_DEFAULT_ERROR_CODE;
	struct cve_workqueue *new_workqueue = NULL;
	struct ds_dev_data *ds_dev_data = dg->ds_data;

	/* create a new context entry */
	retval = OS_ALLOC_ZERO(sizeof(*new_workqueue),
			(void **)&new_workqueue);
	if (retval != 0)
		goto out;

	new_workqueue->context = context;
	new_workqueue->state = WQ_STATE_ACTIVE;
	new_workqueue->dg = dg;
	new_workqueue->wq_id = 1;
	new_workqueue->num_ntw_using_pool = 0;
	new_workqueue->num_ntw_reserving_pool = 0;
	new_workqueue->num_ntw_running = 0;

	/* add the new workqueue to context list */
	cve_dle_add_to_list_after(context->wq_list,
			list_context_wqs,
			new_workqueue);

	/* add the new workqueue to the scheduler list */
	cve_dle_add_to_list_after(ds_dev_data->idle_workqueues,
			list,
			new_workqueue);

	cve_dg_print(dg);

	*out_wq = new_workqueue;

	/* success */
	retval = 0;
out:
	if (retval != 0)
		if (new_workqueue)
			OS_FREE(new_workqueue, sizeof(*new_workqueue));

	return retval;
}

/* INTERFACE FUNCTIONS */

static void __reset_network_state(struct ice_network *ntw)
{
	if (ntw->ice_dump)
		ntw->ice_dump->allocated_buf_cnt = 0;

	/* Cntr patching will be done only when new counters are used */
	ntw->patch_cntr = false;

	ntw->jg_list->ended_jobs_nr = 0;
	ntw->jg_list->aborted_jobs_nr = 0;
}

int ice_ds_raise_event(struct ice_network *ntw,
	enum cve_jobs_group_status status,
	bool reschedule)
{
	u32 abort;
	struct cve_workqueue *wq;
	struct ds_context *context;
	struct ice_infer *inf = ntw->curr_exe;
	struct cve_completion_event event, *event_ptr;
	u64 max_ice_cycle = 0;
	struct cve_device_group *dg = cve_dg_get();
	int ret = 0;

	declare_u8_var(trace_status);

	wq = ntw->pntw->wq;
	context = wq->context;

	/*Calculate average ice cycles */
	__calc_ice_max_cycle(max_ice_cycle, ntw->ntw_exec_time);

	if (status != CVE_JOBSGROUPSTATUS_COMPLETED) {
		abort = status;
		max_ice_cycle = abort;
		trace_status = SPH_TRACE_OP_STATUS_FAIL;
	} else {
		abort = CVE_JOBSGROUPSTATUS_COMPLETED;
		trace_status = SPH_TRACE_OP_STATUS_MAX;
	}

	DO_TRACE(trace_icedrvExecuteNetwork(
				SPH_TRACE_OP_STATE_COMPLETE,
				ntw->pntw->wq->context->swc_node.sw_id,
				ntw->pntw->swc_node.sw_id,
				ntw->swc_node.sw_id, ntw->network_id,
				inf->swc_node.sw_id,
				trace_status, max_ice_cycle));


	/* Can we do this before DB? This will reduce duplicacy.
	 * Currently we do same thing during Ntw create and then post
	 * Ntw completion
	 */
	__reset_network_state(ntw);

	ice_swc_counter_inc(ntw->hswc,
			ICEDRV_SWC_SUB_NETWORK_COUNTER_INF_COMPLETED);
	ice_swc_counter_set(inf->hswc,
			ICEDRV_SWC_INFER_STATE,
			ICEDRV_SWC_INFER_STATE_COMPLETED);

	/* create event object if needed */
	if (ntw->produce_completion) {
		event.infer_id = inf->infer_id;
		event.ntw_id = ntw->network_id;
		event.user_data = inf->user_data;
		event.jobs_group_status = abort;
		event.icedc_err_status = ntw->icedc_err_status;
		event.ice_err_status = ntw->ice_err_status;
		event.shared_read_err_status = ntw->shared_read_err_status;
		ret = ice_memcpy_s(event.total_time,
			MAX_CVE_DEVICES_NR * sizeof(event.total_time[0]),
			ntw->ntw_exec_time,
			MAX_CVE_DEVICES_NR * sizeof(event.total_time[0]));
		if (ret < 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
			"Safelib memcpy Failed %d\n", ret);
			return ret;
		}
		ret = ice_memcpy_s(event.ice_error_status,
			MAX_CVE_DEVICES_NR * sizeof(event.ice_error_status[0]),
			ntw->ice_error_status,
			MAX_CVE_DEVICES_NR * sizeof(event.ice_error_status[0]));
		if (ret < 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
			"Safelib memcpy Failed %d\n", ret);
			return ret;
		}

		ret = ice_memcpy_s(event.ice_vir_phy_map,
			MAX_CVE_DEVICES_NR * sizeof(event.ice_vir_phy_map[0]),
			ntw->ice_vir_phy_map,
			MAX_CVE_DEVICES_NR * sizeof(event.ice_vir_phy_map[0]));
		if (ret < 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
			"Safelib memcpy Failed %d\n", ret);
			return ret;
		}

		event.max_ice_cycle = max_ice_cycle;

		if (dg->icedc_state == ICEDC_STATE_CARD_RESET_REQUIRED) {
			event.err_severity = ERROR_SEVERITY_CARD_RESET;
			cve_os_log_default(CVE_LOGLEVEL_INFO,
				"ERROR_SEVERITY_CARD_RESET raised\n");
		} else if (ntw->reset_ntw) {
			event.err_severity = ERROR_SEVERITY_ICE_RESET;
			cve_os_log_default(CVE_LOGLEVEL_INFO,
				"ERROR_SEVERITY_ICE_RESET raised\n");
		} else {
			event.err_severity = ERROR_SEVERITY_NONE;
		}
	}

	/* reset execution time before scheduling another inference */
	ret = ice_memset_s(ntw->ntw_exec_time,
			MAX_CVE_DEVICES_NR * sizeof(ntw->ntw_exec_time[0]), 0,
			MAX_CVE_DEVICES_NR * sizeof(ntw->ntw_exec_time[0]));
	if (ret < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"Safelib memset failed %d\n", ret);
		return ret;
	}

	/* reset execution time before scheduling another inference */
	ret = ice_memset_s(ntw->ice_vir_phy_map,
		MAX_CVE_DEVICES_NR * sizeof(ntw->ice_vir_phy_map[0]), -1,
		MAX_CVE_DEVICES_NR * sizeof(ntw->ice_vir_phy_map[0]));
	if (ret < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"Safelib memset failed %d\n", ret);
		return ret;
	}

	/* reset error state */
	ntw->icedc_err_status = 0;
	ntw->pntw->icedc_err_status = 0;

	/* Reset error state, logging Safelib error, but not returning. */
	ret = ice_memset_s(ntw->ice_error_status, MAX_CVE_DEVICES_NR *
			sizeof(ntw->ice_error_status[0]), 0,
			MAX_CVE_DEVICES_NR * sizeof(ntw->ice_error_status[0]));
	if (ret < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"Safelib memset failed %d\n", ret);
		return ret;
	}

	/* Reset error state, logging Safelib error, but not returning. */
	ret = ice_memset_s(ntw->pntw->ice_error_status, MAX_CVE_DEVICES_NR *
			sizeof(ntw->pntw->ice_error_status[0]), 0,
			MAX_CVE_DEVICES_NR *
			sizeof(ntw->pntw->ice_error_status[0]));
	if (ret < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"Safelib memset failed %d\n", ret);
		return ret;
	}

	/* Reset counters before scheduling */
	__ntw_reset_cntr(ntw->pntw);

	if (reschedule)
		ice_sch_engine(ntw->pntw, true);

	if (ntw->produce_completion) {


		if (context->process->events) {
			event_ptr = context->process->events;
			cve_dle_remove_from_list(context->process->events,
				main_list, event_ptr);
		} else
			ret = OS_ALLOC_ZERO(sizeof(struct cve_completion_event),
				(void **)&event_ptr);
		if (ret < 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
				"Failed to assign memory to event_ptr %d\n",
				ret);
			ASSERT(false);
		}

		*event_ptr = event;


		/* add to the end of events list */
		cve_dle_add_to_list_before(context->process->alloc_events,
				sub_list, event_ptr);
		cve_dle_add_to_list_before(inf->infer_events,
				infer_list, event_ptr);

		cve_os_log(CVE_LOGLEVEL_INFO,
			"Generating completion event(%p) for NtwID:0x%llx InferID:0x%llx. Status:%s\n",
			event_ptr,
			ntw->network_id, inf->infer_id,
			get_cve_jobs_group_status_str(abort));

		/* wake up anyone who waits for completion event */
		cve_os_wakeup(&wq->context->process->events_wait_queue);
		cve_os_wakeup(&inf->events_wait_queue);

		DO_TRACE(trace_icedrvEventGeneration(SPH_TRACE_OP_STATE_ADD,
					ntw->pntw->wq->context->swc_node.sw_id,
					ntw->swc_node.parent_sw_id,
					ntw->swc_node.sw_id, ntw->network_id,
					inf->swc_node.sw_id,
					SPH_TRACE_OP_STATUS_MAX,
					event.max_ice_cycle));
	}
	return ret;
}

static struct ice_pnetwork *__get_pnetwork_from_id(
		cve_context_process_id_t context_pid,
		cve_context_id_t context_id,
		ice_pnetwork_id_t parent_ntw_id)
{
	int retval = CVE_DEFAULT_ERROR_CODE;
	struct cve_workqueue *wq = NULL;
	struct ice_pnetwork *pntw = NULL;

	retval = __get_wq_from_contex_pid(context_pid, context_id, &wq);
	if (!wq || (retval != 0)) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"ERROR:%d CtxPid:%llu CtxId:%llu get_wq_from_contex_pid() failed\n",
				retval, context_pid, context_id);
		goto out;
	}

	pntw = cve_dle_lookup(wq->pntw_list, list, pntw_id, parent_ntw_id);
	if (!pntw) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"ERROR:%d CtxPid:%llu CtxId:%llu parent network lookup failed\n",
				retval, context_pid, context_id);
		goto out;
	}

out:
	return pntw;
}


static struct ice_network *__get_network_from_id(
		cve_context_process_id_t context_pid,
		cve_context_id_t context_id,
		u64 ntw_id)
{
	int retval = CVE_DEFAULT_ERROR_CODE;
	struct cve_workqueue *wq = NULL;
	struct ice_network *ntw = NULL;
	struct ice_pnetwork *curr_pntw;

	retval = __get_wq_from_contex_pid(context_pid, context_id, &wq);
	if (!wq || (retval != 0)) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"ERROR:%d CtxPid:%llu CtxId:%llu get_wq_from_contex_pid() failed\n",
				retval, context_pid, context_id);
		goto out;
	}

	if (!wq->pntw_list) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"ERROR:%d CtxPid:%llu CtxId:%llu parent network lookup failed\n",
				retval, context_pid, context_id);
		goto out;
	}

	curr_pntw = wq->pntw_list;
	do {
		ntw = cve_dle_lookup(curr_pntw->ntw_list, list,
				network_id, ntw_id);
		if (ntw)
			break;

		curr_pntw = cve_dle_next(curr_pntw, list);
	} while (curr_pntw != wq->pntw_list);
out:
	return ntw;
}

static int __get_wq_from_contex_pid(cve_context_process_id_t context_pid,
		cve_context_id_t context_id,
		struct cve_workqueue **p_wq)
{
	int retval = CVE_DEFAULT_ERROR_CODE;
	struct ds_context *context = NULL;
	struct cve_context_process *context_process = NULL;

	/* get the process based on the id */
	retval = cve_context_process_get(context_pid, &context_process);
	if (retval != 0)
		goto out;

	/* Get the context from the process */
	context = get_context_from_process(
		context_process,
		context_id);
	if (!context) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"ERROR: CTXPID:0x%llx CTXID:0x%llx get_context_from_process failed\n",
			context_pid, context_id);
		retval = -ICEDRV_KERROR_CTX_INVAL_ID;
		goto out;
	}

	/* this call will never fail as there is only 1 WQ per context */
	*p_wq = cve_workqueue_get(context, 1);

out:
	return retval;
}

static int __pntw_check_resources(struct cve_workqueue *workqueue,
		struct ice_pnetwork *pntw)
{
	int retval = 0;
	u32 num_ice = 0, llc_size = 0, i;

	num_ice = pntw->num_ice;
	/* TODO: Check if this makes sense */
	if (num_ice > workqueue->dg->dev_info.active_device_nr) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"failed since requested ice %d is larger than max ice %d\n",
			num_ice, workqueue->dg->dev_info.active_device_nr);
		retval = -ICEDRV_KERROR_NTW_INVAL_RESOURCE_REQ;
		goto out;
	}

	for (i = 0; i < ICE_CLOS_MAX; i++)
		llc_size += pntw->clos[i];

	/* TODO: Check if this makes sense */
	if (llc_size > workqueue->dg->dg_clos_manager.size) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"failed since requested llc_size %d is larger than max llc sz:%d\n",
			llc_size, workqueue->dg->dg_clos_manager.size);
		retval = -ICEDRV_KERROR_NTW_INVAL_RESOURCE_REQ;
		goto out;
	}

out:
	return retval;
}

static int __check_resources(struct ice_network *network)
{
	int retval = 0;
	u32 num_ice = 0;

	num_ice = network->num_ice;
	if (num_ice > network->pntw->num_ice) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"failed since requested ice %d is larger than max ice %d\n",
			num_ice, network->pntw->num_ice);
		retval = -ICEDRV_KERROR_NTW_INVAL_RESOURCE_REQ;
		goto out;
	}

	if (network->jg_list->num_of_idc_cntr > NUM_COUNTER_REG) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
		"failed since requested counter %d is larger than max:%d\n",
		network->jg_list->num_of_idc_cntr, NUM_COUNTER_REG);
		retval = -ICEDRV_KERROR_NTW_INVAL_RESOURCE_REQ;
		goto out;
	}

out:
	return retval;
}

static int __prepare_cb_desc_for_sub_jobs(struct ice_network *ntw,
	struct cve_job *job_desc,
	struct cve_command_buffer_descriptor **p_cb_desc)
{
	int ret = 0;
	struct cve_surface_descriptor *cur_buf_desc;
	struct cve_command_buffer_descriptor *cb_desc = NULL;
	u32 i = 0, cb_idx = 01, *cb_desc_index_arr;
	size_t sz = 0;

	*p_cb_desc = NULL;

	/* TODO HACK: allocate memory for CB(legacy)*/
	sz = (sizeof(*cb_desc) * (job_desc->cb_nr));
	ret = OS_ALLOC_ZERO(sz, (void **)&cb_desc);
	if (ret < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"Allocation failed(%d) for CB descriptor SZ:%lu\n",
			ret, sz);
		goto out;
	}

	cb_desc_index_arr = (u32 *)job_desc->cb_buf_desc_list;
	for (i = 0; i < job_desc->cb_nr; i++) {
		cb_idx = cb_desc_index_arr[i];
		cur_buf_desc = &ntw->buf_desc_list[cb_idx];

		if (cur_buf_desc->surface_type) {
#define CMD_SZ_BYTE 32
			cb_desc[i].bufferid = cur_buf_desc->bufferid;
			cb_desc[i].commands_nr =
				(cur_buf_desc->actual_size_bytes) / CMD_SZ_BYTE;
			if (cur_buf_desc->surface_type ==
					ICE_SURF_TYPE_CB_RELOAD)
				cb_desc[i].is_reloadable = 1;
			else
				cb_desc[i].is_reloadable = 0;
		} else {
			ret = -ICEDRV_KERROR_CB_INVAL_BUFFER_ID;
			cve_os_log_default(CVE_LOGLEVEL_ERROR,
				"ERROR:%d NtwID:0x%llx Invalid Buffer Descriptor, should be a Command Buffer\n",
				ret, ntw->network_id);
			goto err_invalid_surface;
		}
	}

	*p_cb_desc = cb_desc;
	return ret;

err_invalid_surface:
	OS_FREE(cb_desc, sz);
out:
	return ret;
}

/*
 * Successful call returns number of CBs in the given Job
*/
static int __process_job(struct cve_job *job_desc,
	struct job_descriptor *cur_job)
{
	int ret = 0;
	size_t sz = 0;
	u32 *k_cb_desc_index_list, *u_cb_desc_index_list;
	struct ice_network *ntw;
	struct jobgroup_descriptor *jg;
	struct ds_context *context = NULL;
	struct cve_workqueue *wq = NULL;
	struct cve_command_buffer_descriptor *cb_desc = NULL;
	struct cve_patch_point_descriptor *k_pp_desc_list, *u_pp_desc_list;

	jg = cur_job->jobgroup;
	ntw = jg->network;
	wq = ntw->pntw->wq;
	context = wq->context;

	cur_job->num_mmu_cfg_regs = 0;
	if (job_desc->num_mmu_cfg_regs) {

		ASSERT(job_desc->num_mmu_cfg_regs > 0);

		cur_job->num_mmu_cfg_regs = job_desc->num_mmu_cfg_regs;
		ret = __alloc_and_copy((void *)job_desc->mmu_cfg_list,
			sizeof(*cur_job->mmu_cfg_list) * 2 *
			cur_job->num_mmu_cfg_regs,
			(void **)&cur_job->mmu_cfg_list);

		if (ret < 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
				"ERROR:%d __alloc_and_copy() failed for MMU Config reg array\n",
				ret);
			goto out;
		}

		ret = ice_di_check_mmu_regs(cur_job->mmu_cfg_list,
				cur_job->num_mmu_cfg_regs);
		if (ret < 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
				"ERROR:%d Invalid MMU Config reg offset\n",
				ret);
			goto err_mmu_cfg;
		}

		ret = ice_memcpy_s(cur_job->md5,
			sizeof(job_desc->md5[0]) * ICEDRV_MD5_MAX_SIZE,
			job_desc->md5,
			sizeof(job_desc->md5[0]) * ICEDRV_MD5_MAX_SIZE);
		if (ret < 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
				"Safelib memcpy Failed %d\n", ret);
			goto out;
		}
	}

	/* Allocate memory and copy cb list
	* reffered as an array of indexes from buffer descriptor array
	*/
	u_cb_desc_index_list = (u32 *)job_desc->cb_buf_desc_list;
	sz = (sizeof(*k_cb_desc_index_list) * job_desc->cb_nr);
	ret = __alloc_and_copy(u_cb_desc_index_list, sz,
			(void **)&k_cb_desc_index_list);
	if (ret < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"ERROR:%d __alloc_and_copy() failed for CB descriptor index array\n",
			ret);
		goto err_mmu_cfg;
	}

	/* override the cb array list with kernel space array*/
	job_desc->cb_buf_desc_list = (u64)k_cb_desc_index_list;
	ret = __prepare_cb_desc_for_sub_jobs(ntw, job_desc, &cb_desc);
	if (ret < 0 || cb_desc == NULL) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"ERROR:%d __prepare_cb_desc_for_sub_jobs failed\n",
			ret);
		goto err_prepare_sub_job;
	}

	/* copy the user provided CB to the device interface */
	ret = cve_di_handle_submit_job(context->buf_list, cur_job,
				job_desc, cb_desc, &cur_job->di_hjob);
	if (ret != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"ERROR:%d handle_submit_job failed\n", ret);
		goto err_handle_sub_job;
	}

	if (job_desc->patch_points_nr > 0) {
		/* Allocate memory and copy patch point list */
		u_pp_desc_list =
			(struct cve_patch_point_descriptor *)
			job_desc->patch_points;
		sz = (sizeof(*k_pp_desc_list) * job_desc->patch_points_nr);
		ret = __alloc_and_copy(u_pp_desc_list, sz,
				(void **)&k_pp_desc_list);
		if (ret < 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
					"ERROR:%d __alloc_and_copy() failed for PP descriptor array\n",
					ret);
			goto err_pp_copy;
		}

		/* pass the current job to which patch point belongs */
		ret = ice_mm_process_patch_point(ntw->buf_list, k_pp_desc_list,
				job_desc->patch_points_nr, cur_job);
		if (ret < 0) {
			cve_os_log_default(CVE_LOGLEVEL_ERROR,
					"ERROR:%d NtwID:0x%llx JG:0x%p Job:%p ice_mm_process_patch_point() failed\n",
					ret, ntw->network_id, jg, cur_job);
			goto err_patching;
		}

		cve_os_log(CVE_LOGLEVEL_DEBUG,
				"Processed %d patch points\n",
				job_desc->patch_points_nr);

		sz = (sizeof(*k_pp_desc_list) * job_desc->patch_points_nr);
		OS_FREE(k_pp_desc_list, sz);
	}

	sz = (sizeof(*k_cb_desc_index_list) * job_desc->cb_nr);
	OS_FREE(k_cb_desc_index_list, sz);

	OS_FREE(cb_desc, (sizeof(*cb_desc) * (job_desc->cb_nr)));

	ret = job_desc->cb_nr;
	goto out;

err_patching:
	sz = (sizeof(*k_pp_desc_list) * job_desc->patch_points_nr);
	OS_FREE(k_pp_desc_list, sz);
err_pp_copy:
	remove_di_job(cur_job->di_hjob);
err_handle_sub_job:
	OS_FREE(cb_desc, (sizeof(*cb_desc) * (job_desc->cb_nr)));
err_prepare_sub_job:
	sz = (sizeof(*k_cb_desc_index_list) * job_desc->cb_nr);
	OS_FREE(k_cb_desc_index_list, sz);
err_mmu_cfg:
	if (!job_desc->num_mmu_cfg_regs) {
		sz = sizeof(*cur_job->mmu_cfg_list) * 2 *
				cur_job->num_mmu_cfg_regs;
		OS_FREE(cur_job->mmu_cfg_list, sz);
	}
out:
	return ret;
}

static void __destroy_pp_mirror_image(struct ice_pp_copy **pp_list)
{
	while (*pp_list) {
		struct ice_pp_copy *cur_pp = *pp_list;

		cve_dle_remove_from_list(*pp_list, list, cur_pp);
		OS_FREE(cur_pp, sizeof(*cur_pp));
	}

	cve_os_log(CVE_LOGLEVEL_DEBUG, "PP Destroyed\n");
}

static void __destroy_job_list(struct jobgroup_descriptor *jg,
	u32 max_jobs)
{
	u32 i = 0, sz = 0;
	struct job_descriptor *cur_job, *job_list;

	job_list = jg->job_list;
	for (i = 0; i < max_jobs; i++) {
		cur_job = &job_list[i];

		/* release the memory allocated for counter patching for
		 * this job during create inference
		 */
		__destroy_pp_mirror_image(&cur_job->job_cntr_pp_list);

		/* remove di job*/
		remove_di_job(cur_job->di_hjob);
		cve_dle_remove_from_list(jg->jobs, list, cur_job);

		if (cur_job->num_mmu_cfg_regs) {
			OS_FREE(cur_job->mmu_cfg_list,
				sizeof(*cur_job->mmu_cfg_list) * 2 *
				cur_job->num_mmu_cfg_regs);
		}

		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"SUCCESS> JG:%p Index:%d CurJob:%p Destroy Sub Jobs\n",
			jg, i, cur_job);
	}

	/* allocate structure for the job list*/
	sz = (sizeof(*job_list) * jg->total_jobs);
	OS_FREE(job_list, sz);

	cve_os_log(CVE_LOGLEVEL_DEBUG,
			"SUCCESS> JG:%p JobsDestroyed:%d TotalJobs:%d Destroy JobList:%p\n",
			jg, max_jobs, jg->total_jobs, jg->job_list);

	jg->job_list = NULL;
	jg->total_jobs = 0;
}

/*
 * Successful call returns maximum number of CBs present
 * in any Job within given Jobgroup
*/
static int __process_job_list(struct cve_job_group *jg_desc,
		struct jobgroup_descriptor *jg)
{
	u32 i = 0;
	size_t sz = 0;
	int ret = 0, max_cb = 0;
	struct cve_job *k_job_desc_list, *cur_job_desc;
	struct cve_job *u_jobs_desc_list = (struct cve_job *)(jg_desc->jobs);
	struct job_descriptor *job_list, *cur_job;
	struct ice_network *ntw = jg->network;
	struct pntw_ice_map *global_ice_map = ntw->pntw->global_ice_map;

	/* Allocate memory and copy job descriptor list
	* from user space
	*/
	sz = (sizeof(*k_job_desc_list) * jg_desc->jobs_nr);
	ret = __alloc_and_copy(u_jobs_desc_list, sz, (void **)&k_job_desc_list);
	if (ret < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"__alloc_and_copy() %d\n",
			ret);
		goto out;
	}

	/* allocate structure for the job list*/
	sz = (sizeof(*job_list) * jg_desc->jobs_nr);
	ret = OS_ALLOC_ZERO(sz, (void **)&job_list);
	if (ret < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"Allocation for Job List failed %d\n", ret);
		goto err_alloc_job_list;
	}
	jg->job_list = job_list;
	jg->total_jobs = jg_desc->jobs_nr;

	for (i = 0; i < jg_desc->jobs_nr; i++) {

		cur_job_desc = &k_job_desc_list[i];
		cur_job = &job_list[i];

		cur_job->job_cntr_pp_list = NULL;
		cur_job->jobgroup = jg;
		cur_job->hw_ice_id = INVALID_ICE_ID;
		cur_job->paired_job = NULL;
		cur_job->id = i;

		if (cur_job_desc->graph_ice_id < 0)
			cur_job->graph_ice_id = INVALID_ICE_ID;
		else {
			cur_job->graph_ice_id = (u8)cur_job_desc->graph_ice_id;

			/* If here then this is a Persistent Job.
			 * So Job count for given ICE should be increased
			 */
			ntw->pntw->global_graph_id_mask |=
				(1 << cur_job->graph_ice_id);
			ntw->pjob_list[cur_job->graph_ice_id] = cur_job;
			if (global_ice_map[cur_job->graph_ice_id].policy !=
					PNTW_ICE_ALLOC_POLICY_BO) {
				global_ice_map[cur_job->graph_ice_id].policy =
					PNTW_ICE_ALLOC_POLICY_DONT_CARE;
			}
		}

		cve_os_log(CVE_LOGLEVEL_DEBUG,
			COLOR_GREEN(
				"Processing Job-%d. NtwID:0x%llx, JG_ID:0x%lx, JobID:0x%lx\n"
				),
			i, ntw->network_id, (uintptr_t)jg, (uintptr_t)cur_job);
		ret = __process_job(cur_job_desc, cur_job);
		if (ret < 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
				"ERROR:%d __process_job failed\n", ret);
			__destroy_job_list(jg, i);
			goto err_alloc_job_list;
		}

		max_cb = (ret > max_cb) ? ret : max_cb;

		/* add the job to the jobgroup list */
		cve_dle_add_to_list_before(jg->jobs, list, cur_job);
		cve_os_log(CVE_LOGLEVEL_DEBUG,
			COLOR_GREEN(
				"Job-%d processing completed\n"
				),
			i);
	}

	ret = max_cb;

err_alloc_job_list:
	sz = (sizeof(*k_job_desc_list) * jg_desc->jobs_nr);
	OS_FREE(k_job_desc_list, sz);
out:
	return ret;
}

static void __destroy_jg(struct ice_network *ntw,
	struct jobgroup_descriptor *jg)
{
	__destroy_job_list(jg, jg->total_jobs);
}


/*
 * Successful call returns maximum number of CBs present
 * in any Job within given Jobgroup
*/
static int __process_jg(struct ice_network *ntw,
		struct cve_job_group *jg_desc,
		struct jobgroup_descriptor *jg)
{
	int ret = 0, max_cb;
	struct cve_device_group *dg = cve_dg_get();

	if (jg_desc->num_of_cves > dg->dev_info.active_device_nr) {
		ret = -ICEDRV_KERROR_NTW_ICE_MAX;
		cve_os_log_default(CVE_LOGLEVEL_ERROR,
			"ERROR(%d) Requested ICE(%d) is more than available(%d)\n",
			ret, jg_desc->num_of_cves,
			dg->dev_info.active_device_nr);
		goto out;
	}

	/* initialize the jobgroup */
	/* TODO HACK: assign netwrok ID to enable event generate network ID
	 * on completion
	 */
	jg->id = ntw->network_id;
	jg->wq = ntw->pntw->wq;
	jg->network = ntw;
	jg->submitted_jobs_nr = jg_desc->jobs_nr;
	jg->total_jobs = jg_desc->jobs_nr;
	/* to be populated during schedule */
	jg->next_dispatch = NULL;
	jg->llc_size = jg_desc->LLC_size;
	jg->num_of_idc_cntr = jg_desc->num_of_idc_cntr;
	jg->produce_completion = jg_desc->produce_completion;
	jg->cntr_bitmap = 0;
	jg->aborted_jobs_nr = 0;

	ret = __process_job_list(jg_desc, jg);
	if (ret < 0) {
		cve_os_log_default(CVE_LOGLEVEL_ERROR,
			"__process_job_list failed %d\n",
			ret);
		goto out;
	}

	max_cb = ret;
	jg->network = ntw;

	cve_os_log(CVE_LOGLEVEL_DEBUG,
			"JG processing completed. JG_ID=0x%lx, JobCount=%d\n",
			(uintptr_t)jg, jg->total_jobs);

	ret = max_cb;

out:
	return ret;
}

static void __destroy_jg_list(struct ice_network *ntw)
{
	struct jobgroup_descriptor *cur_jg;

	cur_jg = ntw->jg_list;
	if (cur_jg)
		__destroy_jg(ntw, cur_jg);

	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"SUCCESS: NtwID:0x%llx JG:%p destroy_jg done\n",
		ntw->network_id, cur_jg);

	/* free the job group list*/
	OS_FREE(ntw->jg_list, sizeof(*cur_jg));

	ntw->jg_list = NULL;
}

/*
 * Successful call returns maximum number of CBs present
 * in any Job within given Jobgroup List
*/
static int __process_jg_list(struct ice_network *ntw,
		struct cve_job_group *jg_desc_list)
{
	struct jobgroup_descriptor *jg_list;
	u32 i = 0;
	int ret = 0;
	struct pntw_ice_map *global_ice_map = ntw->pntw->global_ice_map;

	ASSERT(ntw->num_jg == 1);

	/* allocate structure for the job group list*/
	ret = OS_ALLOC_ZERO(sizeof(*jg_list), (void **)&jg_list);
	if (ret < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"Allocation for JG List failed %d\n", ret);
		goto out;
	}
	ntw->jg_list = jg_list;

	cve_os_log(CVE_LOGLEVEL_DEBUG,
		COLOR_GREEN(
			"Processing JG. NtwID:0x%llx, JG_ID=0x%lx\n"
			),
		ntw->network_id, (uintptr_t)jg_list);
	ret = __process_jg(ntw, jg_desc_list, jg_list);
	if (ret < 0)
		goto error_process_jg;

	ntw->cntr_bitmap = jg_list->cntr_bitmap;
	ntw->pntw->cntr_bitmap |= ntw->cntr_bitmap;
	/* Update cnounter map in parent network */

	if (ntw->pntw->org_icebo_req != ICEBO_DEFAULT) {

		struct job_descriptor **pjob_list = ntw->pjob_list;

		for (i = 0; i < MAX_NUM_ICEBO; i++) {

			if (pjob_list[2 * i] && pjob_list[2 * i + 1]) {

				ntw->org_pbo_req++;

				pjob_list[2 * i]->paired_job =
					pjob_list[2 * i + 1];
				pjob_list[2 * i + 1]->paired_job =
					pjob_list[2 * i];
				global_ice_map[2 * i].policy =
					PNTW_ICE_ALLOC_POLICY_BO;
				global_ice_map[(2 * i) + 1].policy =
					PNTW_ICE_ALLOC_POLICY_BO;

			}
		}

		ntw->org_dice_req = ntw->num_ice - (2 * ntw->org_pbo_req);

	} else {

		ntw->org_pbo_req = 0;
		ntw->org_dice_req = ntw->num_ice;
	}

	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"ICE requirement: picebo=%d dicebo=%d\n",
		ntw->org_pbo_req, ntw->org_dice_req);

	goto out;

error_process_jg:
	OS_FREE(jg_list, sizeof(*jg_list));
	ntw->jg_list = NULL;
out:
	return ret;
}

static int __destroy_buf(struct ice_network *ntw,
	struct cve_ntw_buffer *buf)
{
	struct ds_context *context = NULL;
	struct cve_workqueue *wq = NULL;
	cve_context_id_t dummy_context_id = 0;

	wq = ntw->pntw->wq;
	context = wq->context;

	cve_mm_unmap_kva(buf->ntw_buf_alloc);

	cve_mm_destroy_buffer(dummy_context_id, buf->ntw_buf_alloc);

	/* remove the buffer from the list in the context */
	cve_dle_remove_from_list(context->buf_list, list, buf);

	cve_os_log(CVE_LOGLEVEL_DEBUG, "Buffer destroyed bufferid =>%lld\n",
		buf->buffer_id);

	return 0;
}

/*
 * Found, assign the same mapped handle and retrun true
 * not found, return false
 */
static int __lookup_buf_fd(struct ice_network *ntw,
		struct cve_surface_descriptor *buf_desc,
		struct cve_ntw_buffer *buf)
{
	struct ice_pnetwork *pntw = ntw->pntw;
	struct ice_network *head = pntw->ntw_list;
	struct ice_network *curr_ntw = head;
	int ret = 0;
	u64 idx = 0;

	/* if head is NULL means, this is first network,
	 * so no lookup required
	 */
	if (!head)
		goto exit;

	do {
		struct cve_ntw_buffer *cur_buf;
		u64 size_bytes, fd;
		u32 page_sz;
		u8 pid;

		for (idx = 0; idx < curr_ntw->num_buf; idx++) {
			cur_buf = &curr_ntw->buf_list[idx];
			ice_mm_get_buf_info(cur_buf->ntw_buf_alloc,
					&size_bytes, &page_sz, &pid, &fd);
			if (buf_desc->fd != 0 && fd == buf_desc->fd) {
				/* found a matching fd, assign the alloc
				 * handle to this new buffer also
				 */
				ice_mm_inc_user(cur_buf->ntw_buf_alloc);
				buf->ntw_buf_alloc = cur_buf->ntw_buf_alloc;
				ret = 1;
				break;
			}

		}
		curr_ntw = cve_dle_next(curr_ntw, list);
	} while (curr_ntw != head && ret != 1);
exit:
	return ret;
}

static int __process_buf_desc(struct ice_network *ntw,
	struct cve_surface_descriptor *buf_desc,
	struct cve_ntw_buffer *buf)
{
	int ret = 0;
	struct ds_context *context = NULL;
	struct cve_workqueue *wq = NULL;
	os_domain_handle cve_os_hdomain[MAX_CVE_DEVICES_NR];

	wq = ntw->pntw->wq;
	context = wq->context;

	if (buf_desc->alloc_higher_va &&
			buf_desc->low_pp_cnt != buf_desc->high_pp_cnt) {
		ret = -ICEDRV_KERROR_PP_COUNT_EINVAL;
		cve_os_log_default(CVE_LOGLEVEL_ERROR,
				"ERROR:%d NtwID:0x%llx buffer_id:%lld Invalid patch points(Low:%d High:%d)\n",
				ret, ntw->network_id, buf->buffer_id,
				buf_desc->low_pp_cnt,
				buf_desc->high_pp_cnt);
		goto out;
	}

	cve_dev_get_os_domain_arr(ntw->pntw->dev_hctx_list,
			ntw->pntw->num_ice, cve_os_hdomain);

	/* initialize the buffer's object attributes */
	buf->buffer_id = (uintptr_t)buf;
	buf->surface_type = buf_desc->surface_type;
	buf->is_shared_surf = false;

	cve_os_log(CVE_LOGLEVEL_DEBUG,
		COLOR_GREEN(
			"Start Mapping Buffer. NtwID:0x%llx, BufferID:0x%llx\n"
			),
		ntw->network_id, buf->buffer_id);

	if (ice_enable_llc_config_via_axi_reg() &&
			buf_desc->alloc_higher_va == 1)
		buf_desc->llc_policy = ICE_LLC_ATTR_CONFIG_VIA_AXI_REG;

	/* Hard Code LLC config to uncached for HSLE */
	__override_llc_config(buf_desc->llc_policy);

	ret =  __lookup_buf_fd(ntw, buf_desc, buf);
	if (ret == 0) {
		ret = cve_mm_create_buffer(cve_os_hdomain,
				ntw->pntw->num_ice,
				buf_desc, &buf->ntw_buf_alloc);
		if (ret < 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
					"cve_mm_create_buffer Sz:%llu PageSz:0x%x failed %d\n",
					buf_desc->size_bytes,
					buf_desc->page_sz, ret);
			goto out;
		}
	}
	cve_os_log(CVE_LOGLEVEL_DEBUG,
		COLOR_GREEN(
			"Stop Mapping Buffer. BufferID:0x%llx\n"
			),
		buf->buffer_id);

	/* add it to the buffer list in the context */
	cve_dle_add_to_list_after(context->buf_list, list, buf);

	/* Set the buffer as cache dirty */
	cve_mm_set_dirty_cache(buf->ntw_buf_alloc);

	/* Update buffer ID to descriptor as a place holder
	 * for CB processing
	 */
	buf_desc->bufferid = buf->buffer_id;

	return ret;

out:
	return ret;
}

static int __destroy_buf_list(struct ice_network *ntw,
	struct cve_ntw_buffer *buf_list, u32 buf_count)
{
	struct cve_ntw_buffer *cur_buf;
	u64 *infer_idx_list = ntw->infer_idx_list;
	u32 sz = 0, idx = 0;

	if (buf_list)
		for (; idx < buf_count; idx++) {
			cur_buf = &buf_list[idx];
			__destroy_buf(ntw, cur_buf);
		}

	if (infer_idx_list) {
		sz = (sizeof(*infer_idx_list) * ntw->infer_buf_count);
		OS_FREE(infer_idx_list, sz);
	}

	sz = (sizeof(*buf_list) * buf_count);
	OS_FREE(buf_list, sz);

	return 0;
}

static int __process_buf_desc_list(struct ice_network *ntw,
	struct cve_surface_descriptor *buf_desc_list)
{
	struct cve_ntw_buffer *buf_list = NULL, *cur_buf = NULL;
	struct cve_surface_descriptor *cur_buf_desc = NULL;
	u64 *infer_idx_list = NULL;
	u32 idx = 0, inf_itr = 0;
	size_t sz = 0;
	int ret = 0;

	if (ntw->infer_buf_count > MAX_BUFFER_COUNT) {
		ret = -ICEDRV_KERROR_BUFFER_COUNT_MISMATCH;
		cve_os_log_default(CVE_LOGLEVEL_ERROR,
				"InferBufCount mismatch. Received=%d, Max_allowable=%d\n",
				ntw->infer_buf_count, MAX_BUFFER_COUNT);
		goto out;
	}

	sz = (sizeof(*buf_list) * ntw->num_buf);
	ret = OS_ALLOC_ZERO(sz, (void **)&buf_list);
	if (ret < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"ERROR:%d Allocation for Buffer List failed\n", ret);
		goto out;
	}
	ntw->buf_list = buf_list;

	if (ntw->infer_buf_count) {
		ret = OS_ALLOC_ZERO(
				sizeof(*infer_idx_list) * ntw->infer_buf_count,
				(void **)&infer_idx_list);
		if (ret < 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
					"ERROR:%d Allocation for Infer index list failed\n",
					ret);
			goto out;
		}
		ntw->infer_idx_list = infer_idx_list;
	}

	for (; idx < ntw->num_buf; idx++) {
		cur_buf_desc = &buf_desc_list[idx];
		cur_buf = &buf_list[idx];

		ret = __process_buf_desc(ntw, cur_buf_desc, cur_buf);
		if (ret < 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
					"ERROR:%d Allocation for Buffer List failed\n",
					ret);
			goto error_buf_desc;
		}
		if (!cur_buf_desc->fd && !cur_buf_desc->base_address) {

			if (inf_itr >= ntw->infer_buf_count) {
				ret = -ICEDRV_KERROR_BUFFER_COUNT_MISMATCH;
				cve_os_log(CVE_LOGLEVEL_ERROR,
					"More than expected Infer buffer (Max=%u)\n",
					ntw->infer_buf_count);

				goto error_buf_desc;
			}

			infer_idx_list[inf_itr] = idx;
			cve_os_log(CVE_LOGLEVEL_DEBUG,
			"NtwID:0x%lx infer_buf_count:%d infer_index:%d updated in the array\n",
			(uintptr_t)ntw, ntw->infer_buf_count, idx);

			cur_buf->index_in_inf = inf_itr;

			inf_itr++;
		} else {
			/* Not an InferBuffer so no entry in Infer list */
			cur_buf->index_in_inf = INVALID_INDEX;
		}
	}

	if (inf_itr != ntw->infer_buf_count) {
		ret = -ICEDRV_KERROR_BUFFER_COUNT_MISMATCH;
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"Unexpected Infer buffer. Present=%u, Expecting=%u\n",
			inf_itr, ntw->infer_buf_count);

		goto error_buf_desc;
	}

	ntw->num_inf_buf = inf_itr;

	return ret;

error_buf_desc:
	__destroy_buf_list(ntw, buf_list, idx);
out:
	return ret;
}

static int __infer_idx_lookup(u64 *arr, u32 sz, u64 key)
{
	u32 i;

	for (i = 0; i < sz; i++)
		if (arr[i] == key)
			return i;

	return -1;
}


static int __lookup_infer_list(struct ice_network *ntw,
		struct cve_inf_buffer *inf_buf)
{
	struct ice_infer *head = ntw->inf_list;
	struct ice_infer *curr_inf = head;
	struct cve_inf_buffer *curr_buf;
	int ret = 0;
	u64 __maybe_unused user_count = 0;
	u32 idx;

	if (head == NULL)
		goto exit;

	do {
		cve_os_log(CVE_LOGLEVEL_DEBUG,
				"NtwID:0x%lx Infer:0x%lx lookup infer buf list\n",
				(uintptr_t)ntw, (uintptr_t)curr_inf);
		for (idx = 0; idx < curr_inf->num_buf; idx++) {
			curr_buf = &curr_inf->buf_list[idx];
			if (curr_buf->fd != 0 && curr_buf->fd == inf_buf->fd) {
				inf_buf->inf_buf_alloc =
					curr_buf->inf_buf_alloc;
				ice_mm_inc_user(curr_buf->inf_buf_alloc);
				ret = 1;
				ice_mm_get_user(curr_buf->inf_buf_alloc,
						&user_count);
				cve_os_log(CVE_LOGLEVEL_INFO,
					"PNTW:0x%llx NtwID:0x%lx Infer:0x%lx found matching FD:%llu AllocHdl:0x%lx UserCount:%llu\n",
					ntw->pntw->pntw_id,
					(uintptr_t)ntw, (uintptr_t)curr_inf,
					curr_buf->fd,
					(uintptr_t)curr_buf->inf_buf_alloc,
					user_count);
				break;
			}
		}

		curr_inf = cve_dle_next(curr_inf, ntw_list);
	} while (curr_inf != head && ret != 1);

exit:
	return ret;
}

/*
 * Found, assign the same mapped handle and retrun true
 * not found, return false
 */
static int __lookup_infer_buf_fd(struct ice_infer *inf,
		struct cve_inf_buffer *curr_inf_buf)
{
	struct ice_network *ntw = inf->ntw;
	struct ice_pnetwork *pntw = ntw->pntw;
	struct ice_network *head = pntw->ntw_list;
	struct ice_network *curr_ntw = head;
	int ret = 0;

	/* if head is NULL means, this is first network,
	 * so no lookup required
	 */
	if (!head)
		goto exit;

	do {
		ret = __lookup_infer_list(curr_ntw, curr_inf_buf);
		if (ret == 1) {
			/* Found a matching FD, assigned same handle to
			 * requested infer buffer.
			 */
			break;
		}
		curr_ntw = cve_dle_next(curr_ntw, list);
	} while (curr_ntw != head && ret != 1);
exit:
	return ret;
}


static int __process_inf_buf_desc_list(struct ice_infer *inf,
	struct cve_infer_surface_descriptor *buf_desc_list)
{
	int retval = 0;
	u32 idx, i;
	size_t sz = 0;
	struct ice_network *ntw;
	struct cve_inf_buffer *buf_list, *cur_buf;
	struct cve_infer_surface_descriptor *cur_buf_desc;

	sz = (sizeof(*buf_list) * inf->num_buf);
	retval = OS_ALLOC_ZERO(sz, (void **)&buf_list);
	if (retval < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"ERROR:%d Allocation for Buffer List failed\n", retval);
		goto out;
	}
	inf->buf_list = buf_list;

	ntw = inf->ntw;

	for (idx = 0; idx < inf->num_buf; idx++) {
		cur_buf_desc = &buf_desc_list[idx];
		cur_buf = &buf_list[idx];

		retval = __infer_idx_lookup(ntw->infer_idx_list,
				ntw->infer_buf_count, cur_buf_desc->index);
		if (retval < 0) {
			retval = -ICEDRV_KERROR_INF_INDEX_INVAL_ID;
			cve_os_log_default(CVE_LOGLEVEL_ERROR,
			"ERROR:%d Index:%llx of infer buffer:%p is invalid\n",
			retval, cur_buf_desc->index, &buf_desc_list[idx]);
			goto invalid_index;
		}
		/* reset return value as it holds index value at this point */
		retval = 0;

		cur_buf->index_in_ntw = cur_buf_desc->index;
		cur_buf->base_address = cur_buf_desc->base_address;
		cur_buf->fd = cur_buf_desc->fd;

		if (ntw->buf_list[cur_buf->index_in_ntw].is_shared_surf)
			continue;

		retval = __lookup_infer_buf_fd(inf, cur_buf);
		if (retval == 0) {
			/*no duplicate entry found*/
			retval = cve_mm_create_infer_buffer(inf->infer_id,
					inf->inf_hdom, ntw->pntw->num_ice,
					ntw->buf_list[cur_buf->index_in_ntw].
					ntw_buf_alloc,
					cur_buf);
			if (retval < 0) {
				cve_os_log_default(CVE_LOGLEVEL_ERROR,
						"cve_mm_create_infer_buffer failed %d\n",
						retval);
				goto undo_loop;
			}

			cve_mm_set_dirty_cache(cur_buf->inf_buf_alloc);
		}
		retval = 0;
	}

	goto out;

invalid_index:
	if (idx)
		idx--;
undo_loop:

	for (i = 0; i < idx; i++) {
		cve_mm_destroy_infer_buffer(inf->infer_id,
			&inf->buf_list[i]);
	}

	sz = (sizeof(*buf_list) * inf->num_buf);
	OS_FREE(buf_list, sz);
out:
	return retval;
}

static void __destroy_infer(struct ice_infer *inf)
{
	/*
	 * Before entring this function it is expected that execution
	 * request of this Inference is already removed from scheduler.
	 */
	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"Delete Infer. PNTW:0x%llx NtwID=0x%llx, InfID=%lx\n",
		inf->ntw->pntw->pntw_id,
		inf->ntw->network_id, (uintptr_t)inf);


	__move_completion_events_to_main_list(inf->process_pid, inf);

	__destroy_infer_desc(inf);

	ice_swc_destroy_infer_node(inf);

	cve_dle_remove_from_list(inf->ntw->inf_list, ntw_list, inf);
}

static int __destroy_all_inferences(struct ice_network *ntw)
{
	struct ice_infer *head = ntw->inf_list;
	struct ice_infer *curr = NULL;
	struct ice_infer *next = NULL;
	u32 is_last = 0;

	if (head == NULL)
		goto exit;

	curr = head;
	do {
		next = cve_dle_next(curr, ntw_list);

		if (next == curr)
			is_last = 1;

		cve_os_log(CVE_LOGLEVEL_INFO,
				"Pntw:0x%llx NtwID:0x%lx Infer:0x%lx Forced Cleanup\n",
				ntw->pntw->pntw_id, (uintptr_t)ntw,
				(uintptr_t)curr);

		__destroy_infer(curr);
		OS_FREE(curr, sizeof(*curr));

		curr = next;

	} while (!is_last);

exit:
	return 0;
}

static int __destroy_network(struct ice_network *ntw)
{
	struct ice_network *head;

	head = ntw;

	do {
		cve_os_log(CVE_LOGLEVEL_INFO, "Destroying NtwID=0x%lx\n",
			(uintptr_t)ntw);

		__destroy_all_inferences(ntw);

		dealloc_and_unmap_network_fifo(ntw);

		__destroy_buf_list(ntw, ntw->buf_list, ntw->num_buf);
		ntw->buf_list = NULL;

		if (ntw->ice_dump != NULL)
			__destroy_ice_dump_buffer(ntw);

		__destroy_jg_list(ntw);
		__destroy_pp_mirror_image(&ntw->ntw_surf_pp_list);
		ice_swc_destroy_ntw_node(ntw);

		ntw = cve_dle_next(ntw, del_list);
	} while (ntw != head);

	return 0;
}

static void __update_ntw_sw_id(
		struct ice_network_descriptor *network_desc,
		struct ice_network *ntw)
{
	struct ice_swc_node *swc_node = &ntw->swc_node;

	swc_node->parent_sw_id = ntw->pntw->swc_node.sw_id;

	if (network_desc->obj_id < 0)
		swc_node->sw_id = ntw->network_id;
	else
		swc_node->sw_id = network_desc->obj_id;
}


static int __process_network_desc(
		struct ice_network_descriptor *network_desc,
		struct ice_network *network)
{
	struct ice_network *ntw = network;
	struct cve_job_group *jg_desc_list;
	struct cve_surface_descriptor *k_buf_desc_list;
	size_t sz;
	u32 i;
	int retval = 0;

	if (network_desc->num_ice > ntw->pntw->num_ice) {
		retval = -ICEDRV_KERROR_NTW_ICE_MAX;
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"Error(%d) Invalid ICE Request Available:%d Requested:%d\n",
				retval,
				ntw->pntw->num_ice,
				network_desc->num_ice);
		goto out;
	}

	ntw->produce_completion = ntw->pntw->produce_completion;
	ntw->num_ice = network_desc->num_ice;
	ntw->network_id = (u64)ntw;
	ntw->infer_buf_count = network_desc->infer_buf_count;
	ntw->ntw_surf_pp_count = 0;
	ntw->icedc_err_status = 0;
	for (i = 0; i < MAX_CVE_DEVICES_NR; i++) {
		ntw->ntw_exec_time[i] = 0;
		ntw->ice_error_status[i] = 0;
		ntw->ice_vir_phy_map[i] = -1;
	}

	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"Creating new Network. CtxID:%llu, PNtw:0x%llx NtwID:0x%llx\n",
		ntw->pntw->wq->context->context_id,
		ntw->pntw->pntw_id, ntw->network_id);

	/* Allocate memory and copy buffer descriptor list
	* from user space
	*/
	if (network_desc->num_buf_desc > MAX_BUFFER_COUNT) {
		retval = -ICEDRV_KERROR_BUFFER_COUNT_MISMATCH;
		cve_os_log_default(CVE_LOGLEVEL_ERROR,
				"NumBuf mismatch. Received=%d, Max=%d\n",
				network_desc->num_buf_desc, MAX_BUFFER_COUNT);
		goto out;
	}

	sz = (sizeof(*k_buf_desc_list) * network_desc->num_buf_desc);
	retval = __alloc_and_copy(network_desc->buf_desc_list,
		sz, (void **)&k_buf_desc_list);
	if (retval < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"__alloc_and_copy() %d\n",
			retval);
		goto out;
	}

	ntw->num_buf = network_desc->num_buf_desc;
	ntw->buf_desc_list = k_buf_desc_list;
	retval = ice_memcpy_s(ntw->infer_buf_page_config,
			ICEDRV_PAGE_ALIGNMENT_MAX *
			sizeof(ntw->infer_buf_page_config[0]),
			network_desc->infer_buf_page_config,
			ICEDRV_PAGE_ALIGNMENT_MAX *
			sizeof(ntw->infer_buf_page_config[0]));
	if (retval < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"Safelib memcpy Failed %d\n", retval);
		return retval;
	}

	retval = __process_buf_desc_list(ntw, k_buf_desc_list);
	if (retval < 0) {
		cve_os_log_default(CVE_LOGLEVEL_ERROR,
			"__process_buf_desc_list() %d\n",
			retval);
		goto error_buf_desc_process;
	}

	if (network_desc->is_ice_dump_enabled) {
		retval = __create_ice_dump_buffer(ntw);
		if (retval < 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
			"__process_buf_desc_list() %d\n",
			retval);
			goto error_ice_dump_buf_process;
		}
		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"NtwID:0x%llx ice_dump is enabled with total_dump_buf=%x\n",
			ntw->network_id, ntw->ice_dump->total_dump_buf);
	} else
		ntw->ice_dump = NULL;

	/* Allocate memory and copy job group descriptor list
	 * from user space
	*/

	if (network_desc->num_jg_desc > MAX_NUM_JG_DESC) {
		retval = -ICEDRV_KERROR_INVALID_JG_COUNT;
		cve_os_log_default(CVE_LOGLEVEL_ERROR,
				"NumJG more than 1. Received=%d\n",
				network_desc->num_jg_desc);
		goto error_jg_desc_copy;
	}

	sz = (sizeof(*jg_desc_list) * network_desc->num_jg_desc);
	retval = __alloc_and_copy(network_desc->jg_desc_list,
		sz, (void **)&jg_desc_list);
	if (retval < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"__alloc_and_copy() %d\n",
			retval);
		goto error_jg_desc_copy;
	}

	ntw->num_jg = network_desc->num_jg_desc;

	for (i = 0; i < NUM_ICE_UNIT; i++)
		ntw->pjob_list[i] = NULL;

	retval = __process_jg_list(ntw, jg_desc_list);
	if (retval < 0) {
		cve_os_log_default(CVE_LOGLEVEL_ERROR,
			"__process_jg_list() %d\n",
			retval);
		goto error_jg_desc_process;
	}
/* post patch dump enable through sysfs */

	ntw->max_cbdt_entries = retval;
	retval = alloc_and_map_network_fifo(ntw);
	if (retval < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"ERROR:%d alloc_and_map_network_fifo failed\n",
				retval);
		goto err_fifo_alloc;
	}

	sz = (sizeof(*jg_desc_list) * network_desc->num_jg_desc);
	OS_FREE(jg_desc_list, sz);

	sz = (sizeof(*k_buf_desc_list) * network_desc->num_buf_desc);
	OS_FREE(k_buf_desc_list, sz);

	__update_ntw_sw_id(network_desc, ntw);
	cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Network processing completed. NtwID:0x%llx, BufferCount:%d, JG_Count:%d\n",
			ntw->network_id, ntw->num_buf, ntw->num_jg);

	goto out;

err_fifo_alloc:
	__destroy_jg_list(ntw);
error_jg_desc_process:

	__destroy_pp_mirror_image(&ntw->ntw_surf_pp_list);

	sz = (sizeof(*jg_desc_list) * network_desc->num_jg_desc);
	OS_FREE(jg_desc_list, network_desc->num_jg_desc);
error_jg_desc_copy:
	if (ntw->ice_dump != NULL)
		__destroy_ice_dump_buffer(ntw);
error_ice_dump_buf_process:
	__destroy_buf_list(ntw, ntw->buf_list, ntw->num_buf);
	ntw->buf_list = NULL;
error_buf_desc_process:
	sz = (sizeof(*k_buf_desc_list) * network_desc->num_buf_desc);
	OS_FREE(k_buf_desc_list, sz);
out:
	return retval;
}

static void __destroy_infer_desc(struct ice_infer *inf)
{
	u32 idx;
	 struct ice_pp_value *pp_arr = inf->inf_pp_arr;

	for (idx = 0; idx < inf->num_buf; idx++) {
		cve_mm_destroy_infer_buffer(inf->infer_id,
			&inf->buf_list[idx]);
	}

	if (inf->buf_list)
		OS_FREE(inf->buf_list,
			(inf->num_buf * sizeof(struct cve_inf_buffer)));

	if (pp_arr)
		OS_FREE(pp_arr,
			sizeof(*pp_arr) * inf->ntw->ntw_surf_pp_count);
}

static int __process_infer_desc(
		struct ice_infer_descriptor *inf_desc,
		struct ice_infer *inf)
{
	struct cve_infer_surface_descriptor *k_buf_desc_list;
	size_t sz;
	int retval = 0;
	struct ice_pp_value *pp_arr = NULL;

	if (inf_desc->num_buf_desc != inf->ntw->num_inf_buf) {
		retval = -ICEDRV_KERROR_BUFFER_COUNT_MISMATCH;
		cve_os_log_default(CVE_LOGLEVEL_ERROR,
			"NumBuf mismatch. Expected=%d, Received=%d\n",
			inf->ntw->num_inf_buf, inf_desc->num_buf_desc);
		goto out;
	}

	if (inf->ntw->num_inf_buf != 0) {
		sz = (sizeof(*k_buf_desc_list) * inf_desc->num_buf_desc);
		retval = __alloc_and_copy(inf_desc->buf_desc_list,
				sz, (void **)&k_buf_desc_list);
		if (retval < 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
					"__alloc_and_copy(). Ret=%d\n",
					retval);
			goto out;
		}
	}

	cve_dev_get_os_domain_arr(inf->ntw->pntw->dev_hctx_list,
		inf->ntw->pntw->num_ice, inf->inf_hdom);

	inf->user_data = inf_desc->user_data;

	if (inf->ntw->num_inf_buf != 0) {
		/* Configure number of infer buffer only if we process it */
		inf->num_buf = inf_desc->num_buf_desc;

		if (inf->ntw->ntw_surf_pp_count != 0) {
			retval = OS_ALLOC_ZERO(
					sizeof(*pp_arr) *
					inf->ntw->ntw_surf_pp_count,
					(void **)&pp_arr);
			if (retval < 0) {
				cve_os_log(CVE_LOGLEVEL_ERROR,
						"os_alloc_zero failed %d\n",
						retval);
				goto free_mem_1;
			}

		}
		inf->inf_pp_arr = pp_arr;

		retval = __process_inf_buf_desc_list(inf, k_buf_desc_list);
		if (retval < 0) {
			cve_os_log_default(CVE_LOGLEVEL_ERROR,
					"__process_inf_buf_desc_list failed %d\n",
					retval);
			goto free_mem_2;
		}

		if (inf->ntw->ntw_surf_pp_count != 0) {
			retval = ice_mm_process_inf_pp_arr(inf);
			if (retval < 0) {
				cve_os_log_default(CVE_LOGLEVEL_ERROR,
						"ice_mm_process_inf_pp_arr failed %d\n",
						retval);
				goto destroy_infer;
			}
		}
		/* Flush the inference surfaces */
		__flush_inf_buffers(inf);
	}

	cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Inference processing completed. InfID=%llx, BufferCount=%d\n",
			inf->infer_id, inf->num_buf);

	if (inf->ntw->num_inf_buf != 0) {
		sz = (sizeof(*k_buf_desc_list) * inf_desc->num_buf_desc);
		OS_FREE(k_buf_desc_list, sz);
	}
	goto out;

destroy_infer:
	__destroy_infer_desc(inf);
	goto free_mem_1;
free_mem_2:
	OS_FREE(pp_arr, sizeof(*pp_arr) * inf->ntw->ntw_surf_pp_count);
free_mem_1:
	sz = (sizeof(*k_buf_desc_list) * inf_desc->num_buf_desc);
	OS_FREE(k_buf_desc_list, sz);
out:
	return retval;
}

int cve_ds_handle_create_network(
		cve_context_process_id_t context_pid,
		cve_context_id_t context_id,
		ice_pnetwork_id_t pntw_id,
		struct ice_network_descriptor *network_desc,
		u64 *network_id)
{
	int retval = CVE_DEFAULT_ERROR_CODE;
	struct ice_network *network;
	struct ice_pnetwork *pntw = NULL;
	struct cve_device_group *dg = cve_dg_get();
	struct cve_device *dev = ice_get_first_dev();
	u32 ntw_resources[6];

	ntw_resources[0] = 0;
	ntw_resources[1] = 0;
	ntw_resources[2] = 0;
	ntw_resources[3] = 0;
	ntw_resources[4] = network_desc->num_ice;
	ntw_resources[5] = 0;

	retval = cve_os_lock(&g_cve_driver_biglock, CVE_INTERRUPTIBLE);
	if (retval != 0) {
		retval = -ERESTARTSYS;
		goto out;
	}

	pntw = __get_pnetwork_from_id(context_pid, context_id, pntw_id);
	if (!pntw) {
		retval = -ICEDRV_KERROR_INVALID_PNTW_HANDLE;
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"get_pnetwork_from_id() failed %d\n", retval);
		goto out;
	}

	ntw_resources[0] = pntw->clos[ICE_CLOS_0];
	ntw_resources[1] = pntw->clos[ICE_CLOS_1];
	ntw_resources[2] = pntw->clos[ICE_CLOS_2];
	ntw_resources[3] = pntw->clos[ICE_CLOS_3];

	DO_TRACE(trace_icedrvCreateNetwork(
		SPH_TRACE_OP_STATE_START, pntw->wq->context->swc_node.sw_id,
		pntw->swc_node.sw_id, network_desc->obj_id, 0,
		ntw_resources, SPH_TRACE_OP_STATUS_LOCATION, __LINE__));

	if (dev == NULL) {
		retval = -ICEDRV_KERROR_CTX_NODEV;
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"Error:%d dev cannot be NULL\n", retval);
		goto out;
	}

	if (dg->icedc_state == ICEDC_STATE_CARD_RESET_REQUIRED) {
		retval = -ICEDRV_KERROR_CARD_RESET_NEEDED;
		cve_os_log(CVE_LOGLEVEL_ERROR,
		"ERROR:%d Due to IceDC error, card reset is required\n",
		retval);
		goto out;
	}

	if (pntw->last_done) {
		retval = -ICEDRV_KERROR_INVALID_API_CALL;
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"Error:%d PNtw:0x%llx Last network creation already done\n",
				retval, pntw->pntw_id);
		goto out;
	}

	/* allocate structure for the network*/
	retval = OS_ALLOC_ZERO(sizeof(*network), (void **)&network);
	if (retval < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"Allocation failed %d\n", retval);
		goto out;
	}

	network->unique_id = __get_ntw_id();
	network->pntw = pntw;
	network->ntw_running = false;
	network->reset_ntw = false;
	cve_dle_init(&network->del_list, (void *)network);

	retval = __process_network_desc(network_desc, network);
	if (retval < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"__process_network_desc() failed:%d\n", retval);
		goto error_process_ntw;
	}

	retval = __check_resources(network);
	if (retval < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"ERROR:%d __check_resources() failed\n",
				retval);
		goto error_resources;
	}

	/* Flush the network surfaces */
	__flush_ntw_buffers(network);

	/* add to the parent list */
	cve_dle_add_to_list_before(pntw->ntw_list, list, network);
	pntw->ntw_count++;
	/* return the job id to the user */
	*network_id = network->network_id;
	__pntw_update_ice_alloc_policy(network, network_desc->is_last);

	ice_swc_create_ntw_node(network);
	/* referencing JG list directly assuming that we have
	 * one job group always with multiple jobs <= max ice
	*/
	ice_swc_counter_set(network->hswc,
			ICEDRV_SWC_SUB_NETWORK_TOTAL_JOBS,
			network->jg_list->total_jobs);


	__local_builtin_popcount(network->cntr_bitmap, ntw_resources[5]);

	DO_TRACE(trace_icedrvCreateNetwork(
		SPH_TRACE_OP_STATE_COMPLETE,
		pntw->wq->context->swc_node.sw_id,
		pntw->swc_node.sw_id,
		network->swc_node.sw_id, network->network_id, ntw_resources,
		SPH_TRACE_OP_STATUS_PASS, retval));

	cve_os_unlock(&g_cve_driver_biglock);

	return retval;

error_resources:
	__destroy_network(network);
error_process_ntw:
	OS_FREE(network, sizeof(*network));
out:
	cve_os_unlock(&g_cve_driver_biglock);

	DO_TRACE(trace_icedrvCreateNetwork(
			SPH_TRACE_OP_STATE_ABORT,
			context_id, pntw_id,
			network_desc->obj_id, 0, ntw_resources,
			SPH_TRACE_OP_STATUS_FAIL, retval));
	return retval;
}

static void __update_infer_sw_id(
		struct ice_infer_descriptor *inf_desc,
		struct ice_infer *infer)
{
	struct ice_swc_node *swc_node = &infer->swc_node;

	if (inf_desc->obj_id < 0)
		swc_node->sw_id = infer->infer_id;
	else
		swc_node->sw_id = inf_desc->obj_id;
}

int cve_ds_handle_create_infer(
		cve_context_process_id_t context_pid,
		cve_context_id_t context_id,
		cve_network_id_t ntw_id,
		struct ice_infer_descriptor *inf_desc,
		u64 *inf_id)
{
	int retval = CVE_DEFAULT_ERROR_CODE;
	struct cve_device_group *dg = cve_dg_get();
	struct ice_network *ntw;
	struct ice_infer *inf;
	__maybe_unused u64 ctx_sw_id = 0, ntw_sw_id = 0, parent_ntw_sw_id = 0;

	/* Invalid ID */
	*inf_id = 0;
	retval = cve_os_lock(&g_cve_driver_biglock, CVE_INTERRUPTIBLE);
	if (retval != 0) {
		retval = -ERESTARTSYS;
		/* Bug. Trying to unlock and exit. */
		goto out;
	}

	if (dg->icedc_state == ICEDC_STATE_CARD_RESET_REQUIRED) {
		retval = ICEDRV_KERROR_CARD_RESET_NEEDED;
		cve_os_log(CVE_LOGLEVEL_ERROR,
		"ERROR:%d Due to IceDC error, card reset is required\n",
		retval);
		goto out;
	}

	ntw = __get_network_from_id(context_pid, context_id, ntw_id);
	if (ntw == NULL) {
		ctx_sw_id = context_id;
		ntw_sw_id = ntw_id;

		retval = -ICEDRV_KERROR_NTW_INVAL_ID;
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"ERROR:%d Given NtwID:0x%llx is not present in this context\n",
				retval, ntw_id);
		goto out;
	}

	if (!ntw->pntw->last_done) {
		retval = -ICEDRV_KERROR_INVALID_API_CALL;
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"Error:%d PNtw:0x%llx Last network not yet declared\n",
				retval, ntw->pntw->pntw_id);
		goto out;
	}

	ctx_sw_id = ntw->pntw->wq->context->swc_node.sw_id;
	ntw_sw_id = ntw->swc_node.sw_id;
	parent_ntw_sw_id = ntw->swc_node.parent_sw_id;
	DO_TRACE(trace__icedrvCreateInfer(
				SPH_TRACE_OP_STATE_START,
				ctx_sw_id, parent_ntw_sw_id, ntw_sw_id,
				ntw->network_id,
				inf_desc->obj_id,
				SPH_TRACE_OP_STATUS_LOCATION, __LINE__));

	retval = OS_ALLOC_ZERO(sizeof(*inf), (void **)&inf);
	if (retval < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"Allocation failed %d\n", retval);
		goto out;
	}

	inf->ntw = ntw;
	inf->infer_id = (u64)inf;
	inf->inf_running = false;
	inf->inf_sch_node.inf = inf;
	inf->inf_sch_node.ntw = ntw;
	inf->inf_sch_node.pntw = ntw->pntw;
	inf->inf_sch_node.ntype = NODE_TYPE_INFERENCE;
	inf->inf_sch_node.is_queued = false;
	cve_dle_init(&inf->ntw_list, (void *)inf);
	__update_infer_sw_id(inf_desc, inf);

	retval = cve_os_init_wait_que(&inf->events_wait_queue);
#ifdef RING3_VALIDATION
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"events_wait_queue init failed  %d\n", retval);
		goto free_mem;
	}
#endif

	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"Processing CreateInfer. NtwID=0x%llx, InfID=%lx, numPP=%d, numBuf=%d\n",
		ntw->network_id, (uintptr_t)inf,
		ntw->ntw_surf_pp_count, inf_desc->num_buf_desc);

	retval = __process_infer_desc(inf_desc, inf);
	if (retval < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"CreateInfer Failed. NtwId=0x%lx, Ret=%d\n",
			(uintptr_t)ntw, retval);
		goto free_mem;
	}

	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"Completed CreateInfer. PNTW:0x%llx NtwID=0x%llx, InfID=%lx\n",
		ntw->pntw->pntw_id,
		ntw->network_id, (uintptr_t)inf);

	cve_dle_add_to_list_before(ntw->inf_list, ntw_list, inf);
	inf->process_pid = context_pid;
	ice_swc_create_infer_node(inf);

	*inf_id = inf->infer_id;

	cve_os_unlock(&g_cve_driver_biglock);

	DO_TRACE(trace__icedrvCreateInfer(
				SPH_TRACE_OP_STATE_COMPLETE,
				ctx_sw_id, parent_ntw_sw_id, ntw_sw_id,
				ntw->network_id,
				inf->swc_node.sw_id,
				SPH_TRACE_OP_STATUS_PASS, retval));

	return retval;

free_mem:
	OS_FREE(inf, sizeof(*inf));
out:
	cve_os_unlock(&g_cve_driver_biglock);

	DO_TRACE(trace__icedrvCreateInfer(
				SPH_TRACE_OP_STATE_ABORT,
				ctx_sw_id, parent_ntw_sw_id, ntw_sw_id,
				0,
				inf_desc->obj_id,
				SPH_TRACE_OP_STATUS_FAIL,
				retval));

	return retval;
}

static int __validate_shared_surfaces(struct ice_ntw_ss_descriptor *ss_desc,
	struct ice_network *ntw)
{
	int retval = 0;
	u32 i, ntw_buf_idx;
	struct cve_ntw_buffer *ntw_buf;

	for (i = 0; i < ss_desc->num_index; i++) {

		ntw_buf_idx = ss_desc->index_list[i];

		if (ntw_buf_idx >= ntw->num_buf) {
			retval = -ICEDRV_KERROR_INVALID_BUFFER_IDX;
			cve_os_log(CVE_LOGLEVEL_ERROR,
				"Invalid Ntw buffer index. Max=%d, Given=%d\n",
				ntw->num_buf - 1, ntw_buf_idx);
			goto out;
		}

		ntw_buf = &ntw->buf_list[ntw_buf_idx];

		if (ntw_buf->index_in_inf == INVALID_INDEX) {
			retval = -ICEDRV_KERROR_INVALID_BUFFER;
			cve_os_log(CVE_LOGLEVEL_ERROR,
				"Given Ntw buffer does not correspond to Inf buffer. Given=%d, PointingTo=%d\n",
				ntw_buf_idx, ntw_buf->index_in_inf);
			goto out;
		}
	}

out:
	return retval;
}

static int __check_infer_created_per_ntw(struct ice_pnetwork *pntw)
{
	int retval = 0;
	struct ice_network *head = pntw->ntw_list;
	struct ice_network *curr = head;
	u32 num_inf = 0;

	if (!head) {
		retval = -ICEDRV_KERROR_NTW_INVAL_ID;
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"ERROR:%d NO active network within the parent:0x%llx\n",
				retval, pntw->pntw_id);
		goto out;

	}

	do {
		num_inf = 0;
		/* There must be exactly one CreateInfer call at this point */
		if (curr->inf_list) {
			struct ice_infer *inf = curr->inf_list;

			do {
				num_inf++;
				inf = cve_dle_next(inf, ntw_list);
			} while (inf != curr->inf_list);
		}

		if (num_inf != 1) {
			retval = -ICEDRV_KERROR_INVALID_API_CALL;
			cve_os_log(CVE_LOGLEVEL_ERROR,
					"ERROR:%d Exactly one CreateInfer must be called before this API. Numinf=%d\n",
					retval, num_inf);
			goto out;
		}

		curr = cve_dle_next(curr, list);
	} while (curr != head);
out:
	return retval;
}

static int __process_ntw_shared_surfaces(
		struct ice_ntw_ss_descriptor *ss_desc,
		struct ice_network *ntw)
{
	u8 pid;
	int retval;
	u32 i, page_sz;
	struct cve_inf_buffer *inf_buf;
	struct cve_ntw_buffer *ntw_buf;
	u64 size_bytes, sz, ntw_buf_idx;
	struct ice_pnetwork *pntw = ntw->pntw;
	u64 *page_config = pntw->infer_buf_page_config;

	retval = __validate_shared_surfaces(ss_desc, ntw);
	if (retval < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"__validate_shared_surfaces failed. Error=%d\n",
			retval);
		goto out;
	}

	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"Old Infer size requirement (Low, 32K, 16M, 32M) = (0x%llx, 0x%llx, 0x%llx, 0x%llx)\n",
		page_config[IOVA_PAGE_ALIGNMENT_LOW_32K],
		page_config[IOVA_PAGE_ALIGNMENT_32K],
		page_config[IOVA_PAGE_ALIGNMENT_16M],
		page_config[IOVA_PAGE_ALIGNMENT_32M]);

	/* Calculate the partition size of extended ICEVA */
	for (i = 0; i < ss_desc->num_index; i++) {

		ntw_buf_idx = ss_desc->index_list[i];

		ntw_buf = &ntw->buf_list[ntw_buf_idx];
		inf_buf = &ntw->inf_list->buf_list[ntw_buf->index_in_inf];

		ice_mm_get_buf_info(ntw_buf->ntw_buf_alloc,
			&size_bytes, &page_sz, &pid, NULL);

		ntw_buf->is_shared_surf = true;

		/* This will prevent DestroyInfer from destroying SSurfaces */
		ice_mm_transfer_shared_surface(ntw_buf, inf_buf);

		ice_mm_get_buf_info(ntw_buf->ntw_buf_alloc,
			&size_bytes, &page_sz, &pid, NULL);

		sz = round_up_cve_pagesize(size_bytes, page_sz);

		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"SharedSurface NtwBufIdx:%llu InfBufIdx:%u Size=0x%llx, PageSz=%x, RoundedSize=0x%llx, PID=%d\n",
			ntw_buf_idx, ntw_buf->index_in_inf,
			size_bytes, page_sz, sz, pid);

		if (pid == MEM_PARTITION_LOW_32KB) {
			ASSERT(page_config[IOVA_PAGE_ALIGNMENT_LOW_32K] >= sz);
			page_config[IOVA_PAGE_ALIGNMENT_LOW_32K] -= sz;

		} else if (pid == MEM_PARTITION_HIGH_32KB) {
			ASSERT(page_config[IOVA_PAGE_ALIGNMENT_32K] >= sz);
			page_config[IOVA_PAGE_ALIGNMENT_32K] -= sz;

		} else if (pid == MEM_PARTITION_HIGH_16MB) {
			ASSERT(page_config[IOVA_PAGE_ALIGNMENT_16M] >= sz);
			page_config[IOVA_PAGE_ALIGNMENT_16M] -= sz;

		} else if (pid == MEM_PARTITION_HIGH_32MB) {
			ASSERT(page_config[IOVA_PAGE_ALIGNMENT_32M] >= sz);
			page_config[IOVA_PAGE_ALIGNMENT_32M] -= sz;
		} else
			ASSERT(false);
	}

	/* Map all non Shared Infer buffers to use extended VA Map */
	for (i = 0; i < ntw->num_buf; i++) {
		ntw_buf = &ntw->buf_list[i];

		if ((ntw_buf->index_in_inf != INVALID_INDEX) &&
				(!ntw_buf->is_shared_surf))
			ice_mm_use_extended_iceva(ntw_buf);
	}

	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"New Infer size requirement (Low, 32K, 16M, 32M) = (0x%llx, 0x%llx, 0x%llx, 0x%llx)\n",
		page_config[IOVA_PAGE_ALIGNMENT_LOW_32K],
		page_config[IOVA_PAGE_ALIGNMENT_32K],
		page_config[IOVA_PAGE_ALIGNMENT_16M],
		page_config[IOVA_PAGE_ALIGNMENT_32M]);


out:
	return retval;
}

static int __process_shared_surfaces(struct ice_pnetwork *pntw,
		struct ice_report_ss *ss_desc)
{
	int retval = 0;
	u32 i = 0, j = 0;
	struct ice_network *head = pntw->ntw_list;
	struct ice_network *ntw = head;
	u64 sz;
	struct ice_ntw_ss_descriptor *ntw_ss_desc_list, *curr_ntw_ss_desc;
	struct ice_ntw_ss_descriptor temp_ntw_ss_desc;
	struct cve_device *next;

	ASSERT(head);
	sz = (ss_desc->num_ntw * sizeof(*ntw_ss_desc_list));
	retval = __alloc_and_copy(ss_desc->ntw_ss_desc, sz,
			(void **)&ntw_ss_desc_list);
	if (retval < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"__alloc_and_copy() %d\n",
				retval);
		goto out;
	}

	for (; i < ss_desc->num_ntw; i++) {
		curr_ntw_ss_desc = &ntw_ss_desc_list[i];

		if (curr_ntw_ss_desc->num_index > MAX_BUFFER_COUNT) {
			retval = -ICEDRV_KERROR_BUFFER_COUNT_MISMATCH;
			cve_os_log_default(CVE_LOGLEVEL_ERROR,
					"NumIndex mismatch. Received=%d, Max_allowable=%d\n",
					curr_ntw_ss_desc->num_index,
					MAX_BUFFER_COUNT);
			goto free_mem;
		}
		ntw = cve_dle_lookup(pntw->ntw_list, list,
				network_id, curr_ntw_ss_desc->network_id);
		if (!ntw) {
			retval = -ICEDRV_KERROR_NTW_INVAL_ID;
			cve_os_log(CVE_LOGLEVEL_ERROR,
					"Error:%d PNtw:0x%llx Network:0x%llx not found\n",
					retval, pntw->pntw_id,
					curr_ntw_ss_desc->network_id);
			goto free_mem;
		}

		temp_ntw_ss_desc.num_index = curr_ntw_ss_desc->num_index;
		sz = (curr_ntw_ss_desc->num_index *
				sizeof(*curr_ntw_ss_desc->index_list));
		retval = __alloc_and_copy(curr_ntw_ss_desc->index_list, sz,
				(void **)&temp_ntw_ss_desc.index_list);
		if (retval < 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
					"__alloc_and_copy() %d\n",
					retval);
			goto free_mem;
		}
		retval = __process_ntw_shared_surfaces(&temp_ntw_ss_desc, ntw);
		if (retval < 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
					"Error:%d PNTW:%llx NTW:%llx process_ntw_shared_surfaces failed\n",
					retval, pntw->pntw_id, ntw->network_id);
			OS_FREE(temp_ntw_ss_desc.index_list, sz);
			goto free_mem;
		}
		curr_ntw_ss_desc->index_list = temp_ntw_ss_desc.index_list;

	}

	/* Next execution must be Cold run */
	if (!pntw->ice_list)
		goto free_mem;

	next = pntw->ice_list;
	do {
		cve_di_set_device_reset_flag(next, CVE_DI_RESET_DUE_CVE_ERROR);

		next = cve_dle_next(next, owner_list);
	} while (next != pntw->ice_list);


free_mem:
	for (j = 0; j < i; j++) {
		curr_ntw_ss_desc = &ntw_ss_desc_list[j];
		sz = (curr_ntw_ss_desc->num_index *
				sizeof(*curr_ntw_ss_desc->index_list));
		OS_FREE(curr_ntw_ss_desc->index_list, sz);
	}
	sz = (ss_desc->num_ntw * sizeof(*ntw_ss_desc_list));
	OS_FREE(ntw_ss_desc_list, sz);
out:
	return retval;
}


int cve_ds_handle_shared_surfaces(
		cve_context_process_id_t context_pid,
		cve_context_id_t context_id,
		ice_pnetwork_id_t pntw_id,
		struct ice_report_ss *ss_desc)
{
	int retval = CVE_DEFAULT_ERROR_CODE;
	struct cve_device_group *dg = cve_dg_get();
	struct ice_pnetwork *pntw;

	retval = cve_os_lock(&g_cve_driver_biglock, CVE_INTERRUPTIBLE);
	if (retval != 0)
		return -ERESTARTSYS;

	if (dg->icedc_state == ICEDC_STATE_CARD_RESET_REQUIRED) {
		retval = ICEDRV_KERROR_CARD_RESET_NEEDED;
		cve_os_log(CVE_LOGLEVEL_ERROR,
		"ERROR:%d Due to IceDC error, card reset is required\n",
		retval);
		goto out;
	}

	pntw = __get_pnetwork_from_id(context_pid, context_id, pntw_id);
	if (pntw == NULL) {
		retval = -ICEDRV_KERROR_INVALID_PNTW_HANDLE;
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"ERROR:%d Given PNtwID:0x%llx is not present in this context\n",
				retval, pntw_id);
		goto out;
	}

	retval = __check_infer_created_per_ntw(pntw);
	if (retval < 0)
		goto out;

	if (pntw->ntw_count < ss_desc->num_ntw) {
		retval = -ICEDRV_KERROR_INVALID_API_CALL;
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"ERROR:%d Given PNtwID:0x%llx Request network count:%d cannot be greater than exsisitng %u networks\n",
				retval, pntw_id, ss_desc->num_ntw,
				pntw->ntw_count);
		goto out;
	}

	retval = __process_shared_surfaces(pntw, ss_desc);
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"__process_shared_surfaces failed %d\n", retval);
		goto free_mem;
	}

	retval = ice_extend_sw_dev_contexts(pntw);
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"ice_extend_sw_dev_contexts failed %d\n", retval);
		goto free_mem;
	}

	/* Next run must be Cold */

free_mem:
out:
	cve_os_unlock(&g_cve_driver_biglock);

	return retval;
}

int cve_ds_handle_destroy_infer(cve_context_process_id_t context_pid,
		cve_context_id_t context_id,
		cve_network_id_t ntw_id,
		cve_infer_id_t inf_id)
{
	int retval = CVE_DEFAULT_ERROR_CODE;
	struct ice_network *ntw;
	struct ice_infer *inf;

	retval = cve_os_lock(&g_cve_driver_biglock, CVE_INTERRUPTIBLE);
	if (retval != 0) {
		retval = -ERESTARTSYS;
		goto out;
	}

	ntw = __get_network_from_id(context_pid, context_id, ntw_id);
	if (ntw == NULL) {
		retval = -ICEDRV_KERROR_NTW_INVAL_ID;
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"ERROR:%d Given NtwID:0x%llx is not present in this context\n",
				retval, ntw_id);
		goto out;
	}

	inf = cve_dle_lookup(ntw->inf_list, ntw_list, infer_id, inf_id);
	if (inf == NULL) {
		retval = -ICEDRV_KERROR_INF_INVAL_ID;
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"Given InfID:0x%llx is not present in NtwID:0x%llx. Error:%d\n",
				inf_id, ntw_id, retval);
		goto out;
	}

	if (!ice_lsch_del_inf_from_queue(inf, true)) {

		retval = -ICEDRV_KERROR_INF_EALREADY;
		goto out;
	}

	__destroy_infer(inf);
	OS_FREE(inf, sizeof(*inf));

out:
	cve_os_unlock(&g_cve_driver_biglock);

	return retval;
}

static int __get_resource_availability(struct resource_info *res)
{
	u32 i;
	struct cve_device_group *dg = cve_dg_get();
	u64 *pool_context_map = dg->pool_context_map;
	int retval = 0;

	retval = ice_memset_s(res, sizeof(struct resource_info),
			0, sizeof(struct resource_info));
	if (retval < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"Safelib memset failed %d\n", retval);
		return retval;
	}

	res->num_ice = (2 * dg->total_pbo) + dg->total_dice;

	res->num_cntr = dg->num_avl_cntr;

	for (i = 0; i < MAX_IDC_POOL_NR; i++)
		if (pool_context_map[i] == INVALID_CONTEXT_ID)
			res->num_pool++;

	for (i = 0; i < ICE_CLOS_MAX; i++)
		res->clos[i] = dg->dg_clos_manager.clos_size[i];

	return retval;
}

int cve_ds_handle_manage_resource(
		cve_context_process_id_t context_pid,
		cve_context_id_t context_id,
		ice_pnetwork_id_t pntw_id,
		struct ice_resource_request *rreq) {

	struct ice_pnetwork *pntw;
	struct resource_info res;
	bool is_success;
	int status;
	int retval = cve_os_lock(&g_cve_driver_biglock, CVE_INTERRUPTIBLE);
	int ret = 0;

	if (retval != 0) {
		retval = -ERESTARTSYS;
		goto out;
	}

	pntw = __get_pnetwork_from_id(context_pid, context_id, pntw_id);
	if (pntw == NULL) {
		retval = -ICEDRV_KERROR_INVALID_PNTW_HANDLE;
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"ERROR:%d Given NtwID:0x%llx is not present in this context\n",
				retval, pntw_id);
		goto unlock_out;
	}

	/* Place this request in queue and then wait for given timeout */
	if (rreq->is_reserve) {

		if (pntw->last_request_type == NODE_TYPE_RESERVE) {

			retval = -ICEDRV_KERROR_DUPLICATE_REQUEST;
			goto unlock_out;
		}

		ice_lsch_add_rr_to_queue(&pntw->pntw_res_node);

		pntw->last_request_type = NODE_TYPE_RESERVE;
	} else {

		if (pntw->last_request_type == NODE_TYPE_RELEASE) {

			retval = -ICEDRV_KERROR_DUPLICATE_REQUEST;
			goto unlock_out;
		}

		ice_lsch_add_rr_to_queue(&pntw->pntw_rel_node);

		pntw->last_request_type = NODE_TYPE_RELEASE;
	}

	if (rreq->is_reserve) {

		cve_os_unlock(&g_cve_driver_biglock);

		if (rreq->timeout < 0) {
			/* TODO: Wait for ptr and read status from there */
			status = cve_os_block_interruptible_infinite(
				&pntw->rr_wait_queue, pntw->rr_node);
		} else {
			status = cve_os_block_interruptible_timeout(
				&pntw->rr_wait_queue, pntw->rr_node,
				rreq->timeout);
		}

		if (status == -ERESTARTSYS) {

			retval = -ERESTARTSYS;
			goto out;

		}

		retval = cve_os_lock(&g_cve_driver_biglock, CVE_INTERRUPTIBLE);
		if (retval != 0) {
			retval = -ERESTARTSYS;
			goto out;
		}

		/* status=0 when timeout occurs before reservation node is
		 * picked by the scheduler.
		 * For infinite wait, status = 0 means condition is
		 * evaluated true, so its picked by the scheduler or network
		 * deletion is requested.
		 */
		if (!pntw->rr_node)
			is_success = !ice_lsch_del_rr_from_queue(
				&pntw->pntw_res_node, true);
		else
			is_success = pntw->rr_node->is_success;

		/*TODO*/
		pntw->rr_node = NULL;

		if (!is_success) {

			/* TODO: Add Ntw resource info [ICE-18719] */

			pntw->last_request_type = NODE_TYPE_RELEASE;

			retval = -ICEDRV_KERROR_RESERVATION_FAIL;
			ret = __get_resource_availability(&res);
			/*
			 * This failure case should return retval which is
			 * '-ICEDRV_KERROR_RESERVATION_FAIL',
			 * So not overwriting the any other error
			 */
			if (ret < 0)
				cve_os_log(CVE_LOGLEVEL_ERROR,
					"resource availability failed %d\n",
					ret);

			rreq->num_ice = res.num_ice;
			rreq->num_cntr = res.num_cntr;
			rreq->num_pool = res.num_pool;

			/*
			 * This failure case should return retval which is
			 * '-ICEDRV_KERROR_RESERVATION_FAIL',
			 * So not overwriting the any other error
			 */
			ret = ice_memcpy_s(rreq->clos,
				ICE_CLOS_MAX * sizeof(res.clos[0]), res.clos,
				ICE_CLOS_MAX * sizeof(res.clos[0]));
			if (ret < 0)
				cve_os_log(CVE_LOGLEVEL_ERROR,
					"Safelib failed memcpy %d\n", ret);

			cve_os_log(CVE_LOGLEVEL_DEBUG,
				"Ntw numICE: %d\n", rreq->num_ice);
			cve_os_log(CVE_LOGLEVEL_DEBUG,
				"Ntw numCounter: %d\n", rreq->num_cntr);
			cve_os_log(CVE_LOGLEVEL_DEBUG,
				"Ntw numPool: 0x%x\n", rreq->num_pool);
			cve_os_log(CVE_LOGLEVEL_DEBUG,
				"Ntw clos: %d, %d, %d, %d\n",
				rreq->clos[0], rreq->clos[1],
				rreq->clos[2], rreq->clos[3]);
		}
	}

unlock_out:
	cve_os_unlock(&g_cve_driver_biglock);
out:
	return retval;
}

int cve_ds_handle_execute_infer(cve_context_process_id_t context_pid,
		cve_context_id_t context_id,
		cve_network_id_t ntw_id,
		cve_infer_id_t inf_id,
		struct ice_execute_infer_data *data) {

	int retval = CVE_DEFAULT_ERROR_CODE;
	struct ice_infer *inf;
	struct ice_network *ntw;
	struct cve_device_group *dg = cve_dg_get();

	DO_TRACE(trace_icedrvExecuteNetwork(
				SPH_TRACE_OP_STATE_REQ,
				context_id, 0, 0, ntw_id, inf_id,
				SPH_TRACE_OP_STATUS_LOCATION, __LINE__));

	retval = cve_os_lock(&g_cve_driver_biglock, CVE_INTERRUPTIBLE);
	if (retval != 0) {
		retval = -ERESTARTSYS;
		DO_TRACE(trace_icedrvExecuteNetwork(
				SPH_TRACE_OP_STATE_START,
				context_id, 0, 0, ntw_id, inf_id,
				SPH_TRACE_OP_STATUS_FAIL, retval));

		goto err_lock;
	}


	if (dg->icedc_state == ICEDC_STATE_CARD_RESET_REQUIRED) {
		retval = -ICEDRV_KERROR_CARD_RESET_NEEDED;
		cve_os_log(CVE_LOGLEVEL_ERROR,
		"ERROR:%d Due to IceDC error, card reset is required\n",
		retval);
		goto err_sanity;
	}

	ntw = __get_network_from_id(context_pid, context_id, ntw_id);
	if (ntw == NULL) {
		retval = -ICEDRV_KERROR_NTW_INVAL_ID;
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"ERROR:%d Given NtwID:0x%llx is not present in this context\n",
				retval, ntw_id);
		goto err_sanity;
	}

	inf = cve_dle_lookup(ntw->inf_list, ntw_list, infer_id, inf_id);
	if (inf == NULL) {
		retval = -ICEDRV_KERROR_INF_INVAL_ID;
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"Given InfID:0x%llx is not present in NtwID:0x%llx. Error=%d\n",
				inf_id, ntw_id, retval);
		goto err_sanity;
	}

	if (!ntw->pntw->exIR_performed)
		ntw->pntw->exIR_performed = 1;

	DO_TRACE(trace_icedrvExecuteNetwork(
				SPH_TRACE_OP_STATE_QUEUED,
				ntw->pntw->wq->context->swc_node.sw_id,
				ntw->pntw->swc_node.sw_id,
				ntw->swc_node.sw_id, ntw->network_id,
				inf->swc_node.sw_id,
				SPH_TRACE_OP_STATUS_PRIORITY,
				data->priority));

	if (!ice_lsch_add_inf_to_queue(inf, data->priority, data->enable_bp)) {

		retval = -ICEDRV_KERROR_INF_EALREADY;
		goto out;
	}

	cve_os_unlock(&g_cve_driver_biglock);

	return retval;

err_sanity:
	DO_TRACE(trace_icedrvExecuteNetwork(
				SPH_TRACE_OP_STATE_START,
				context_id, 0, 0, ntw_id, inf_id,
				SPH_TRACE_OP_STATUS_FAIL, retval));

out:
	cve_os_unlock(&g_cve_driver_biglock);


err_lock:
	DO_TRACE(trace_icedrvExecuteNetwork(
		SPH_TRACE_OP_STATE_ABORT, context_id, 0, 0,
		ntw_id, inf_id,
		SPH_TRACE_OP_STATUS_FAIL,
		retval));

	return retval;

}

int ice_ds_destroy_pnetwork(cve_context_process_id_t context_pid,
		cve_context_id_t context_id,
		ice_pnetwork_id_t pntw_id) {
	int retval = CVE_DEFAULT_ERROR_CODE;
	struct ice_pnetwork *pntw;
	uint64_t __maybe_unused sw_ctx_id = 0, sw_ntw_id = 0,
		 sw_sub_ntw_id = 0;

	retval = cve_os_lock(&g_cve_driver_biglock, CVE_INTERRUPTIBLE);
	if (retval != 0) {
		retval = -ERESTARTSYS;
		goto out;
	}

	pntw = __get_pnetwork_from_id(context_pid, context_id, pntw_id);
	if (pntw == NULL) {
		retval = -ICEDRV_KERROR_INVALID_PNTW_HANDLE;
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"ERROR:%d Given PNtwID:0x%llx is not present in this context\n",
				retval, pntw_id);
		goto out;
	}

	sw_ctx_id = pntw->wq->context->swc_node.sw_id;
	sw_ntw_id = pntw->swc_node.sw_id;

	DO_TRACE(trace_icedrvDestroyNetwork(
		SPH_TRACE_OP_STATE_START, sw_ctx_id, sw_ntw_id, sw_sub_ntw_id,
		pntw_id, SPH_TRACE_OP_STATUS_LOCATION, __LINE__));

	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"Deleting PNtwID:0x%llx\n", pntw->pntw_id);

	retval = __destroy_pntw(pntw);

	/* Since ICE have been released, check if any network can be scheduled
	 * from the queue.
	 */
	ice_sch_engine(NULL, false);

out:
	cve_os_unlock(&g_cve_driver_biglock);

#ifndef RING3_VALIDATION
	if (retval)
		DO_TRACE(trace_icedrvDestroyNetwork(
				SPH_TRACE_OP_STATE_ABORT,
				context_id, sw_ntw_id, sw_sub_ntw_id, pntw_id,
				SPH_TRACE_OP_STATUS_FAIL, retval));
	else
		DO_TRACE(trace_icedrvDestroyNetwork(
					SPH_TRACE_OP_STATE_COMPLETE,
					sw_ctx_id, sw_ntw_id, sw_sub_ntw_id,
					pntw_id, SPH_TRACE_OP_STATUS_PASS, 0));
#endif

	return retval;
}

static int __do_network_cleanup(struct ice_pnetwork *pntw)
{
	struct ice_network *head = pntw->ntw_list;
	struct ice_network *curr, *next, *ntw_list = NULL;
	int ret = 0, is_last = 0;

	/* try to destroy all networks within this parent */
	if (head == NULL)
		goto exit;

	curr = head;
	do {
		cve_dle_add_to_list_before(ntw_list, del_list, curr)

		curr = cve_dle_next(curr, list);
	} while (curr != head);

	ice_lsch_destroy_pnetwork(pntw);
	__destroy_network(ntw_list);

	curr = pntw->ntw_list;
	do {
		next = cve_dle_next(curr, list);

		if (next == curr)
			is_last = 1;

		cve_dle_remove_from_list(pntw->ntw_list, list, curr);
		pntw->ntw_count--;
		OS_FREE(curr, sizeof(*curr));
		curr = next;
	} while (!is_last);

exit:
	return ret;
}

void ice_ds_handle_ice_error(struct cve_device *dev,
		u64 ice_err_status)
{
	struct ice_network *ntw;

	ntw = (struct ice_network *)dev->dev_ntw_id;
	ntw->ice_err_status |= ice_err_status;
}

void cve_ds_handle_job_completion(struct cve_device *dev,
	cve_ds_job_handle_t ds_job_handle,
	enum cve_job_status job_status, u64 exec_time)
{
	u32 err;
	struct jobgroup_descriptor *jobgroup;
	struct job_descriptor *job;
	struct ice_network *ntw;
	struct ice_infer *inf;
	struct cve_device_group *dg = cve_dg_get();
	enum cve_job_status jg_status;

	job = (struct job_descriptor *)ds_job_handle;
	jobgroup = job->jobgroup;
	ntw = jobgroup->network;
	inf = ntw->curr_exe;

	ntw->ntw_exec_time[dev->dev_index] = exec_time;

	/* Mark the device as idle */
	dev->state = CVE_DEVICE_IDLE;
	/* Perform pmon reset to avoid huge cnc traces in DTF */
	if (dev->daemon.daemon_config_status != TRACE_STATUS_DEFAULT)
		perform_daemon_suspend(dev);

	if (inf->hswc)
		ice_swc_counter_inc(inf->hswc,
			ICEDRV_SWC_INFER_COUNTER_REQUEST_COMPLETED);

	DO_TRACE(trace_icedrvScheduleJob(
				SPH_TRACE_OP_STATE_COMPLETE,
				dev->dev_index,
				ntw->pntw->wq->context->swc_node.sw_id,
				ntw->pntw->swc_node.sw_id,
				ntw->swc_node.sw_id,
				ntw->network_id, inf->swc_node.sw_id, job,
				SPH_TRACE_OP_STATUS_PERF, exec_time));

	if (ntw->pntw->shared_read) {

		err = ice_di_is_shared_read_error(dev);

		if (err) {
			cve_os_dev_log_default(CVE_LOGLEVEL_ERROR,
				dev->dev_index,
				"Error: NtwID:0x%llx, shared_read_status value:%x\n",
				ntw->network_id, err);

			ntw->shared_read_err_status = 1;
			ntw->pntw->shared_read_err_status = 1;
			ice_di_set_shared_read_reg(dev, ntw, 1);
		}
	}

	/* remove the job from the jobgroup list */
	jobgroup->ended_jobs_nr++;

	/* keep track the aborted jobs */
	if (job_status == CVE_JOBSTATUS_ABORTED) {
		/*explictly set job as cold run in case previous run caused an
		 * ice error for this job
		 */
		ice_di_set_cold_run(job->di_hjob);
		jobgroup->aborted_jobs_nr++;
	}

	cve_os_dev_log(CVE_LOGLEVEL_INFO,
			dev->dev_index,
			"JobCompleted Status:0x%x PNtwId:0x%llx NtwID:0x%llx JobID=%u GraphId:%u DummyId:%u TotalJobs:%d DoneJobs:%d\n",
			job_status,
			ntw->pntw->pntw_id,
			ntw->network_id,
			job->id, job->graph_ice_id, job->dummy_ice_id,
			jobgroup->submitted_jobs_nr,
			jobgroup->ended_jobs_nr);

	if (jobgroup->submitted_jobs_nr ==
			jobgroup->ended_jobs_nr) {
		cve_os_dev_log(CVE_LOGLEVEL_INFO,
				dev->dev_index,
				"AllJobCompleted Status:0x%x NtwID:0x%llx JobID=%u GraphId:%u DummyId:%u TotalJobs:%d DoneJobs:%d\n",
				job_status,
				ntw->network_id,
				job->id, job->graph_ice_id, job->dummy_ice_id,
				jobgroup->submitted_jobs_nr,
				jobgroup->ended_jobs_nr);

		DO_TRACE(trace__icedrvScheduleInfer(
					SPH_TRACE_OP_STATE_COMPLETE,
					ntw->pntw->wq->context->swc_node.sw_id,
					ntw->swc_node.parent_sw_id,
					ntw->swc_node.sw_id,
					ntw->network_id,
					ntw->curr_exe->swc_node.sw_id,
					SPH_TRACE_OP_STATUS_ICE,
					ntw->ntw_icemask));

		dg->num_running_ntw--;
		ntw->pntw->wq->num_ntw_running--;

		if (jobgroup->aborted_jobs_nr)
			jg_status = CVE_JOBSGROUPSTATUS_ABORTED;
		else
			jg_status = CVE_JOBSGROUPSTATUS_COMPLETED;

		ice_ds_raise_event(ntw, jg_status, true);
	}
}

int cve_ds_handle_fw_loading(
		cve_context_process_id_t context_pid,
		cve_context_id_t context_id,
		ice_pnetwork_id_t pnetwork_id,
		u64 fw_image,
		u64 fw_binmap,
		u32 fw_binmap_size_bytes,
		u8 *md5)
{
	int retval = CVE_DEFAULT_ERROR_CODE;
	struct cve_device_group *dg = cve_dg_get();
	struct ice_pnetwork *pnetwork = NULL;

	retval = cve_os_lock(&g_cve_driver_biglock, CVE_INTERRUPTIBLE);
	if (retval != 0) {
		retval = -ERESTARTSYS;
		goto out;
	}

	if (dg->icedc_state == ICEDC_STATE_CARD_RESET_REQUIRED) {
		retval = ICEDRV_KERROR_CARD_RESET_NEEDED;
		cve_os_log(CVE_LOGLEVEL_ERROR,
		"ERROR:%d Due to IceDC error, card reset is required\n",
		retval);
		goto out;
	}

	pnetwork = __get_pnetwork_from_id(context_pid, context_id, pnetwork_id);
	if (pnetwork == NULL) {
		retval = -ICEDRV_KERROR_NTW_INVAL_ID;
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"ERROR:%d Given PNtwID:0x%llx is not present in this context\n",
				retval, pnetwork_id);
		goto out;
	}

	if (pnetwork->exIR_performed) {
		retval = -ICEDRV_KERROR_FW_FROZEN;
		goto out;
	}

	/*
	 * TODO: This flow can be optimized. This function
	 * load the image and then map it to cve device.
	 * loading operation can be performed only once,
	 * map operation should be performed multiple times
	 * according to number of CVEs in the system
	 */

	if (fw_binmap_size_bytes > MAX_FW_SIZE_BYTES) {
		retval = -ICEDRV_KERROR_FW_PERM;
		cve_os_log_default(CVE_LOGLEVEL_ERROR,
				"FW_BINMAP_SIZE is more than allowable. Received=%d, Max_allowable=%d\n",
				fw_binmap_size_bytes, MAX_FW_SIZE_BYTES);
		goto out;
	}

	retval = __process_fw_loading(pnetwork, fw_image, fw_binmap,
			fw_binmap_size_bytes, md5);
	if (retval < 0) {
		cve_os_log_default(CVE_LOGLEVEL_ERROR,
				"cve_dev_fw_load_and_map failed %d\n",
				retval);
		goto out;
	}

	/* success */
	retval = 0;

out:
	cve_os_unlock(&g_cve_driver_biglock);
	return retval;
}

int cve_ds_open_context(cve_context_process_id_t context_pid,
		int64_t obj_id, u64 *out_contextid)
{
	struct cve_context_process *context_process = NULL;
	struct ds_context *new_context = NULL;
	struct cve_workqueue *new_workqueue = NULL;
	struct cve_device_group *dg = NULL;
	uint16_t i;
	struct ice_swc_node *swc_node;

	int retval = cve_os_lock(&g_cve_driver_biglock, CVE_INTERRUPTIBLE);

	DO_TRACE(trace_icedrvCreateContext(
		SPH_TRACE_OP_STATE_START, obj_id, 0,
		SPH_TRACE_OP_STATUS_LOCATION, __LINE__));
	if (retval != 0) {
		retval = -ERESTARTSYS;
		goto out;
	}

	/* get the process based on the id */
	retval = cve_context_process_get(context_pid, &context_process);
	if (retval != 0)
		goto out;
	/* create a new context entry */
	retval = OS_ALLOC_ZERO(sizeof(*new_context),
			(void **)&new_context);
	if (retval != 0)
		goto out;

	/* set pool id as invalid to avoid pool cleanup in error handling*/
	new_context->pool_id = INVALID_POOL_ID;

	/* get the ICE device list */
	dg = cve_dg_get();
	if (dg == NULL) {
		retval = -EINVAL;
		goto out;
	}


	retval = cve_os_init_wait_que(&new_context->destroy_wqs_que);
#ifdef RING3_VALIDATION
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"os_init_wait_que failed %d\n", retval);
		goto out;
	}
#endif

	/* get context id */
	new_context->context_id = get_contex_id();


	/* add the new context to the list */
	cve_dle_add_to_list_after(context_process->list_contexts,
			list,
			new_context);

	/* add the new context to the device group list */
	cve_dle_add_to_list_after(dg->list_contexts,
			dg_list,
			new_context);


	new_context->process = context_process;

	cve_create_workqueue(new_context, dg, &new_workqueue);

	cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Context Created. CtxID=%lld\n",
			new_context->context_id);


	for (i = 0; i < NUM_ICE_UNIT; i++) {
		struct cve_completion_event *event;

		retval = OS_ALLOC_ZERO(sizeof(*event), (void **)&event);
		if (retval != 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
			"cve_completion_event alloc failed %d\n", retval);
			goto out;
		}
		cve_dle_add_to_list_before(context_process->events,
			main_list, event);
	}

	*out_contextid = new_context->context_id;

	swc_node = &new_context->swc_node;
	if (obj_id >= 0)
		swc_node->sw_id = obj_id;
	else
		swc_node->sw_id = new_context->context_id;

	ice_swc_create_context_node(new_context);

	/* success */
	retval = 0;
out:
	if (retval != 0) {
		cleanup_context(new_context);
		OS_FREE(new_context, sizeof(*new_context));

		DO_TRACE(trace_icedrvCreateContext(
					SPH_TRACE_OP_STATE_ABORT,
					obj_id, 0, SPH_TRACE_OP_STATUS_FAIL,
					retval));
	} else {
		DO_TRACE(trace_icedrvCreateContext(
					SPH_TRACE_OP_STATE_COMPLETE,
					new_context->swc_node.sw_id,
					new_context->context_id,
					SPH_TRACE_OP_STATUS_PASS, 0));
	}

	cve_os_unlock(&g_cve_driver_biglock);

	return retval;
}

void cve_destroy_context(
		struct cve_context_process *context_process,
		struct ds_context *context)
{
	struct cve_device_group *dg = cve_dg_get();

	while (context_process->events) {
		struct cve_completion_event *event = context_process->events;

		cve_dle_remove_from_list(context_process->events,
			main_list, event);
		OS_FREE(event, sizeof(*event));
	}
	context_process->events = NULL;
	context_process->alloc_events = NULL;

	/* remove the context from the process list */
	cve_dle_remove_from_list(
			context_process->list_contexts,
			list,
			context);

	/* remove the context from the device group list */
	cve_dle_remove_from_list(
			dg->list_contexts,
			dg_list,
			context);

	/* destroy the context */
	cleanup_context(context);

	ice_swc_destroy_context_node(context);

	OS_FREE(context, sizeof(*context));
}

int cve_ds_close_context(
		cve_context_process_id_t context_pid,
		cve_context_id_t context_id)
{
	struct ds_context *context = NULL;
	struct cve_context_process *context_process = NULL;
	struct cve_workqueue *workqueue = NULL;
	u64 __maybe_unused ctx_sw_id = context_id;
	int retval;

	DO_TRACE(trace_icedrvDestroyContext(
		SPH_TRACE_OP_STATE_REQ, 0, context_id,
		SPH_TRACE_OP_STATUS_LOCATION, __LINE__));

	retval = cve_os_lock(&g_cve_driver_biglock, CVE_INTERRUPTIBLE);
	if (retval != 0) {
		retval = -ERESTARTSYS;
		goto out;
	}

	cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Destroy context_id %lld START\n",
			context_id);

	/* get the process based on the id */
	retval = cve_context_process_get(context_pid, &context_process);
	if (retval != 0)
		goto out;

	/* Get the context from the process */
	context = get_context_from_process(
			context_process,
			context_id);
	if (!context) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"get_context_from_process failed\n");
		retval = -EINVAL;
		goto out;
	}

	ctx_sw_id = context->swc_node.sw_id;
	DO_TRACE(trace_icedrvDestroyContext(
		SPH_TRACE_OP_STATE_START, ctx_sw_id, context_id,
		SPH_TRACE_OP_STATUS_LOCATION, __LINE__));

	workqueue = cve_workqueue_get(context, 1);
	if (!workqueue) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"cve_workqueue_get failed %d\n", retval);
		retval = -EINVAL;
		goto out;
	}

	retval = cve_destroy_workqueue(workqueue);
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"cve_destroy_workqueue failed retval=%d\n",
			retval);
		goto out;
	}

	cve_destroy_context(context_process, context);

	cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Destroy context_id %lld\n",
			context_id);

	/* success */
	retval = 0;
out:
	cve_os_unlock(&g_cve_driver_biglock);

#ifndef RING3_VALIDATION
	if (retval)
		DO_TRACE(trace_icedrvDestroyContext(
				SPH_TRACE_OP_STATE_ABORT, ctx_sw_id,
				context_id,
				SPH_TRACE_OP_STATUS_FAIL, retval));
	else
		DO_TRACE(trace_icedrvDestroyContext(
				SPH_TRACE_OP_STATE_COMPLETE,
				ctx_sw_id, context_id,
				SPH_TRACE_OP_STATUS_PASS, 0));
#endif

	return retval;
}

static void __dump_ntw_job_ice_mapping(struct ds_context *context,
		struct ice_network *ntw)
{
	struct ice_pnetwork *pntw = NULL;
	struct jobgroup_descriptor *jg = NULL;
	u32 idx = 0;
	struct job_descriptor *job;

	if (!ntw || !context)
		goto exit;

	pntw = ntw->pntw;
	jg = ntw->jg_list;

	for (; idx < jg->submitted_jobs_nr; idx++) {
		job = &jg->job_list[idx];
		cve_os_log_default(CVE_LOGLEVEL_ERROR,
				"CTX:%llu PNTW:0x%llx NTW:0x%llx JobId:%d HwIceId:%d GraphId:%u DummyId:%u\n",
				context->context_id, pntw->pntw_id,
				ntw->network_id, job->id,
				job->hw_ice_id, job->graph_ice_id,
				job->dummy_ice_id);
	}
exit:
	return;
}

static void __dump_ctx_pntw_data(struct ds_context *context)
{
	struct ice_pnetwork *head = context->wq_list->pntw_list;
	struct ice_pnetwork *curr_pntw = head;
	struct ice_network *curr_ntw;
	struct ice_infer *curr_infer;

	if (!context)
		return;

	head = context->wq_list->pntw_list;

	if (head == NULL) {
		cve_os_log_default(CVE_LOGLEVEL_ERROR,
				"UMD Timeout, No active parent networks under the context:%llu\n",
				context->context_id);
		goto exit;
	}

	curr_pntw = head;
	do {
		curr_ntw = curr_pntw->curr_ntw;
		if (curr_ntw && curr_ntw->curr_exe) {
			curr_infer = curr_ntw->curr_exe;
			cve_os_log_default(CVE_LOGLEVEL_ERROR,
					"CTX:%llu PNTW:0x%llx NTW:0x%llx Infer:0x%llx is active, TotalJobs:%u CompletedJobs:%u\n",
					context->context_id,
					curr_pntw->pntw_id,
					curr_ntw->network_id,
					curr_infer->infer_id,
					curr_ntw->jg_list->submitted_jobs_nr,
					curr_ntw->jg_list->ended_jobs_nr);
			__dump_ntw_job_ice_mapping(context, curr_ntw);

		} else {
			cve_os_log_default(CVE_LOGLEVEL_ERROR,
				"UMD Timeout, No active networks under the context:%llu PNTW:0x%llx\n",
				context->context_id, curr_pntw->pntw_id);
		}

		curr_pntw = cve_dle_next(curr_pntw, list);
	} while (curr_pntw != head);
exit:
	return;
}

static void __dump_pntw_with_resources(struct cve_device_group *dg,
		struct ds_context *context)
{
	struct ice_pnetwork *curr_pntw;
	u32 idx = 0;

	if (!dg) {
		cve_os_log_default(CVE_LOGLEVEL_ERROR,
				"UMD TIMEOUT: DG can never be NULL\n");
		goto exit;
	}

	if (!dg->pntw_with_resources) {
		cve_os_log_default(CVE_LOGLEVEL_ERROR,
				"UMD Timeout: Context:%llu No parent networks with resources\n",
				context->context_id);
		goto exit;
	}

	curr_pntw = dg->pntw_with_resources;
	do {
		for (idx = 0; idx < curr_pntw->num_ice; idx++) {
			cve_os_log_default(CVE_LOGLEVEL_ERROR,
					"CTX:%llu PNTW:0x%llx ICE:%d\n",
					context->context_id,
					curr_pntw->pntw_id,
					curr_pntw->cur_ice_map[idx]);
		}
		curr_pntw = cve_dle_next(curr_pntw, list);
	} while (curr_pntw != dg->pntw_with_resources);

exit:
	return;
}

static void __dump_resources_data(struct cve_device_group *dg,
		struct ds_context *context)
{
	struct cve_device *dev, *dev_head;
	u32 i;

	for (i = 0; i < MAX_NUM_ICEBO; i++) {
		dev_head = dg->dev_info.icebo_list[i].dev_list;
		dev = dev_head;
		if (!dev)
			continue;
		do {
			cve_os_log_default(CVE_LOGLEVEL_ERROR,
					"CurCtx:%lld ICE%d CTX:%llu PNTW:0x%llx NTW:0x%llx State:%u\n",
					context->context_id, dev->dev_index,
					dev->dev_ctx_id, dev->dev_pntw_id,
					dev->dev_ntw_id, dev->state);

			dev = cve_dle_next(dev, bo_list);
		} while (dev != dev_head);
	}
}

static int __handle_infer_completion_via_ctx(
		cve_context_process_id_t context_pid,
		struct cve_context_process *context_process,
		struct ds_context *context,
		struct cve_get_event *event)
{
	u8 continue_wait = 0;
	enum cve_wait_event_status *wait_status = &event->wait_status;
	u32 timeout_msec = event->timeout_msec;
	int retval = 0, lock_ret = 0;

	do {
		retval = cve_os_block_interruptible_timeout(
				&context_process->events_wait_queue,
				context_process->alloc_events, timeout_msec);
		if (retval > 0) {
			lock_ret = cve_os_lock(&g_cve_driver_biglock,
					CVE_INTERRUPTIBLE);
			if (lock_ret != 0) {
				retval = -ERESTARTSYS;
				goto out;
			}

			continue_wait = 0;
			if (context_process->alloc_events)
				copy_event_data_and_remove(context_pid,
						context_process,
						event->contextid, NULL,
						event);
			else
				continue_wait = 1;

			cve_os_unlock(&g_cve_driver_biglock);
		}
	} while (continue_wait);

	if (retval == 0) {
		cve_os_log_default(CVE_LOGLEVEL_ERROR, "Timeout\n");
		*wait_status = CVE_WAIT_EVENT_TIMEOUT;

		/* Raise CARD_RESET if there was atleast one Infer scheduled
		 * against this Context.
		 */
		if (context->wq_list->num_ntw_running) {

			struct cve_device_group *dg = cve_dg_get();

			cve_os_log(CVE_LOGLEVEL_ERROR,
				"Raising CARD_RESET. UMD timed out while Inf is running\n");

			__dump_ctx_pntw_data(context);
			__dump_pntw_with_resources(dg, context);
			__dump_resources_data(dg, context);
			dg->icedc_state = ICEDC_STATE_CARD_RESET_REQUIRED;
			event->err_severity = ERROR_SEVERITY_CARD_RESET;
		}
	} else if (retval == -ERESTARTSYS) {
		*wait_status = CVE_WAIT_EVENT_ERROR;
	} else {
		*wait_status = CVE_WAIT_EVENT_COMPLETE;
		retval = 0;
	}

out:
	if (retval < 0)
		DO_TRACE(trace_icedrvEventGeneration(
					SPH_TRACE_OP_STATE_COMPLETE,
					event->contextid, 0, 0,
					event->networkid,
					event->infer_id,
					SPH_TRACE_OP_STATUS_FAIL, retval));
	return retval;
}

static int __handle_infer_completion_via_infer(
		cve_context_process_id_t context_pid,
		struct cve_context_process *context_process,
		struct cve_get_event *event,
		 struct ice_infer *inf)
{
	enum cve_wait_event_status *wait_status = &event->wait_status;
	u32 timeout_msec = event->timeout_msec;
	int retval = 0;

	retval = cve_os_block_interruptible_timeout(
			&inf->events_wait_queue,
			inf->infer_events, timeout_msec);
	if (retval > 0) {
		int ret = 0;

		ret = cve_os_lock(&g_cve_driver_biglock,
				CVE_INTERRUPTIBLE);
		if (ret != 0) {
			retval = -ERESTARTSYS;
			goto out;
		}

		copy_event_data_and_remove(context_pid, context_process,
				event->contextid, inf, event);

		cve_os_unlock(&g_cve_driver_biglock);
	}

	if (retval == 0) {
		cve_os_log_default(CVE_LOGLEVEL_ERROR, "Timeout\n");
		*wait_status = CVE_WAIT_EVENT_TIMEOUT;
	} else if (retval == -ERESTARTSYS) {
		*wait_status = CVE_WAIT_EVENT_ERROR;
	} else {
		*wait_status = CVE_WAIT_EVENT_COMPLETE;
		retval = 0;
	}

out:
	if (retval < 0)
		DO_TRACE(trace_icedrvEventGeneration(
					SPH_TRACE_OP_STATE_COMPLETE,
					event->contextid, 0, 0,
					event->networkid,
					event->infer_id,
					SPH_TRACE_OP_STATUS_FAIL, retval));
	return retval;
}


int cve_ds_wait_for_event(cve_context_process_id_t context_pid,
		struct cve_get_event *event)
{
	struct cve_context_process *context_process = NULL;
	struct ds_context *context = NULL;
	struct ice_infer *inf = NULL;
	struct ice_network *ntw = NULL;
	u64 __maybe_unused ctx_sw_id = 0xFFFFFF;

	int retval = cve_os_lock(&g_cve_driver_biglock, CVE_INTERRUPTIBLE);

	if (retval != 0) {
		retval = -ERESTARTSYS;
		goto out;
	}

	/* get the process based on the id */
	retval = cve_context_process_get(context_pid, &context_process);
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "Invalid Context process\n");
		goto unlock;
	}

	/* Get the context from the process */
	context = get_context_from_process(context_process, event->contextid);
	if (!context) {
		retval = -ICEDRV_KERROR_CTX_INVAL_ID;
		cve_os_log(CVE_LOGLEVEL_ERROR, "Invalid Context\n");
		goto unlock;
	}

	ctx_sw_id = context->swc_node.sw_id;

	if (!event->infer_id) {
		DO_TRACE(trace_icedrvEventGeneration(SPH_TRACE_OP_STATE_START,
					ctx_sw_id, 0, 0, event->networkid, 0,
					SPH_TRACE_OP_STATUS_LOCATION,
					__LINE__));

		cve_os_unlock(&g_cve_driver_biglock);

		retval = __handle_infer_completion_via_ctx(context_pid,
				context_process, context, event);
		goto out;

	} else {
		/* get the ice_network based on the network id */
		ntw = __get_network_from_id(context_pid, event->contextid,
				event->networkid);
		if (ntw == NULL) {
			retval = -ICEDRV_KERROR_NTW_INVAL_ID;
			cve_os_log_default(CVE_LOGLEVEL_ERROR,
			"ERROR:%d Given NETWORK_ID:%lld is not present in this context\n",
			retval, event->networkid);
			goto unlock;
		}

		/* get the ice_infer based on the infer id */
		inf = cve_dle_lookup(ntw->inf_list, ntw_list,
				infer_id, event->infer_id);
		if (inf == NULL) {
			retval = -ICEDRV_KERROR_INF_INVAL_ID;
			cve_os_log_default(CVE_LOGLEVEL_ERROR,
			"Given InfID=0x%llx is not present in NtwId=0x%llx. Error=%d\n",
			event->infer_id, event->networkid, retval);
			goto unlock;
		}

		DO_TRACE(trace_icedrvEventGeneration(SPH_TRACE_OP_STATE_START,
					ntw->pntw->wq->context->swc_node.sw_id,
					ntw->swc_node.parent_sw_id,
					ntw->swc_node.sw_id,
					ntw->network_id,
					inf->swc_node.sw_id,
					SPH_TRACE_OP_STATUS_LOCATION,
					__LINE__));

		cve_os_unlock(&g_cve_driver_biglock);
		retval = __handle_infer_completion_via_infer(context_pid,
				context_process, event, inf);
		goto out;
	}
unlock:
	if (retval < 0)
		DO_TRACE(trace_icedrvEventGeneration(
					SPH_TRACE_OP_STATE_COMPLETE,
					event->contextid, 0, 0,
					event->networkid,
					event->infer_id,
					SPH_TRACE_OP_STATUS_FAIL, retval));

	cve_os_unlock(&g_cve_driver_biglock);
out:
	return retval;

}

int cve_ds_get_version(cve_context_process_id_t context_pid,
		cve_context_id_t context_id,
		ice_pnetwork_id_t pntw_id,
		struct cve_components_version *out_versions)
{
	struct cve_components_version versions;
	struct cve_device_group *dg = cve_dg_get();
	struct ice_pnetwork *pnetwork = NULL;

	int retval = cve_os_lock(&g_cve_driver_biglock, CVE_INTERRUPTIBLE);

	if (retval != 0) {
		retval = -ERESTARTSYS;
		goto out;
	}

	if (dg->icedc_state == ICEDC_STATE_CARD_RESET_REQUIRED) {
		retval = ICEDRV_KERROR_CARD_RESET_NEEDED;
		cve_os_log(CVE_LOGLEVEL_ERROR,
		"ERROR:%d Due to IceDC error, card reset is required\n",
		retval);
		goto unlock;
	}

	pnetwork = __get_pnetwork_from_id(context_pid, context_id, pntw_id);
	if (pnetwork == NULL) {
		retval = -ICEDRV_KERROR_INVALID_PNTW_HANDLE;
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"ERROR:%d Given PNtwID:0x%llx is not present in this context\n",
				retval, pntw_id);
		goto unlock;
	}

	versions.kmd_version = binary_version;
	/* fill the base package FWs versions */
	versions.tlc_version = tlc_version;
	versions.ivp_mfw_version = ivp_version;
	versions.asip_mfw_version = asip_version;
	/* fill the custom kernel versions per context.
	 * the first dev_context is taken since all
	 * dev_context has the same loaded FWs.
	 */
	/* BUG: What if they are from Base pkg??? */
	cve_dev_get_custom_fw_version_per_context(
			pnetwork->loaded_cust_fw_sections,
			CVE_FW_IVP_BANK0_TYPE,
			&versions.ivp_bank0_version);
	cve_dev_get_custom_fw_version_per_context(
			pnetwork->loaded_cust_fw_sections,
			CVE_FW_IVP_BANK1_TYPE,
			&versions.ivp_bank1_version);
	cve_dev_get_custom_fw_version_per_context(
			pnetwork->loaded_cust_fw_sections,
			CVE_FW_ASIP_BANK0_TYPE,
			&versions.asip_bank0_version);
	cve_dev_get_custom_fw_version_per_context(
			pnetwork->loaded_cust_fw_sections,
			CVE_FW_ASIP_BANK1_TYPE,
			&versions.asip_bank1_version);

	*out_versions = versions;

	cve_utils_print_version_struct("kmd",
			&versions.kmd_version);
	cve_utils_print_version_struct("tlc",
			&versions.tlc_version);
	cve_utils_print_version_struct("ivp",
			&versions.ivp_mfw_version);
	cve_utils_print_version_struct("asip",
			&versions.asip_mfw_version);
	cve_utils_print_version_struct("ivp bank0",
			&versions.ivp_bank0_version);
	cve_utils_print_version_struct("ivp bank1",
			&versions.ivp_bank1_version);
	cve_utils_print_version_struct("asip bank0",
			&versions.asip_bank0_version);
	cve_utils_print_version_struct("asip bank1",
			&versions.asip_bank1_version);

unlock:
	cve_os_unlock(&g_cve_driver_biglock);
out:
	return retval;
}

int cve_ds_get_metadata(struct cve_get_metadata_params *metadata)
{
	int retval = cve_os_lock(&g_cve_driver_biglock, CVE_INTERRUPTIBLE);
	struct cve_get_metadata_params data;

	if (retval != 0) {
		retval = -ERESTARTSYS;
		goto out;
	}

	data.icemask = g_icemask;
	data.ice_dump_buf_size = ice_di_get_core_blob_sz();

	*metadata = data;

	cve_os_unlock(&g_cve_driver_biglock);
out:
	return retval;
}

static void __link_ices_and_pool(struct ice_pnetwork *pntw)
{
	int8_t pool_id;
	struct cve_device *head = pntw->ice_list;
	struct cve_device *next = pntw->ice_list;

	ASSERT(next);

	pool_id = pntw->wq->context->pool_id;

	do {
		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Linking ICE-%d to Pool=%d\n",
			next->dev_index, pool_id);
		cve_di_set_pool_registers(next, pool_id);

		next = cve_dle_next(next, owner_list);
	} while (next != head);
}

static void __delink_ices_and_pool(struct ice_pnetwork *pntw)
{

	struct cve_device *head = pntw->ice_list;
	struct cve_device *next = pntw->ice_list;

	ASSERT(next);

	do {
		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Delinking ICE-%d from Pool\n",
			next->dev_index);
		/* TODO: As of now there is no function that selectively
		 *  removes ICE from Pool. Whenever ICE is allocated to
		 * a pool, cve_di_set_pool_registers ensures that it also
		 * removes that ICE from any other pool
		 */

		next = cve_dle_next(next, owner_list);
	} while (next != head);
}

static void __link_counters_and_pool(struct ice_pnetwork *pntw)
{
	int8_t pool_id;
	struct cve_device *dev = get_first_device();
	struct cve_os_device *os_dev = to_cve_os_device(dev);
	struct cve_hw_cntr_descriptor *head = pntw->cntr_list;
	struct cve_hw_cntr_descriptor *next = pntw->cntr_list;

	if (!next)
		return;

	pool_id = pntw->wq->context->pool_id;

	do {
		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Linking CntrHwID=%d to Pool=%d\n",
			next->hw_cntr_id, pool_id);
		cve_set_hw_sync_regs(&os_dev->idc_dev,
			next->hw_cntr_id, pool_id);

		next = cve_dle_next(next, list);
	} while (next != head);
}

static void __delink_counters_and_pool(struct ice_pnetwork *pntw)
{
	struct cve_device *dev = get_first_device();
	struct cve_os_device *os_dev = to_cve_os_device(dev);
	struct cve_hw_cntr_descriptor *head = pntw->cntr_list;
	struct cve_hw_cntr_descriptor *next = pntw->cntr_list;

	if (!next)
		return;

	do {
		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Delinking CntrHwID=%d from Pool\n",
			next->hw_cntr_id);
		cve_reset_hw_sync_regs(&os_dev->idc_dev,
			next->hw_cntr_id);

		next = cve_dle_next(next, list);
	} while (next != head);
}

static void __link_resource_and_pool(struct ice_pnetwork *pntw)
{
	/* ICEs */
	__link_ices_and_pool(pntw);

	/* Counters */
	__link_counters_and_pool(pntw);
}

static void __delink_resource_and_pool(struct ice_pnetwork *pntw)
{
	/* Counters */
	__delink_counters_and_pool(pntw);

	/* ICEs */
	__delink_ices_and_pool(pntw);
}

/* Move this function to DG */
static void __lazy_capture_ices(struct ice_pnetwork *pntw)
{
	u32 i;
	struct cve_device *dev;

	for (i = 0; i < pntw->num_ice; i++) {
		ASSERT(pntw->cur_ice_map[i] >= 0);

		dev = cve_device_get(pntw->cur_ice_map[i]);
		if (!dev) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
				"cve device is NULL\n");
			ASSERT(false);
		}
		ice_dg_borrow_this_ice(pntw, dev, true);
	}
}


static void __map_pntw_pbo_ntw_jobs(struct ice_pnetwork *pntw)
{
	struct ice_network *head = pntw->ntw_list;
	struct ice_network *curr = head;
	u8 i = 0, id = 0;

	ASSERT(head != NULL);

	do {
		struct job_descriptor *job;

		curr->ntw_icemask = 0;
		for (i = 0; i < curr->jg_list->submitted_jobs_nr; i++) {
			job = &curr->jg_list->job_list[i];

			if (job->graph_ice_id < NUM_ICE_UNIT)
				id = job->graph_ice_id;
			else
				id = job->dummy_ice_id;

			job->hw_ice_id = pntw->global_ice_map[id].hw_ice_id;
			curr->ntw_icemask |= (1 << job->hw_ice_id);
		}
		curr = cve_dle_next(curr, list);
	} while (curr != head);
}


/*
 * Remove ICE from DG and allocate it to Network list
*/
static int __ntw_reserve_ice(struct ice_pnetwork *pntw)
{
	int ret = 0;
	u32 i, ice_count = 0;
	struct cve_device_group *dg = cve_dg_get();
	struct ice_network *head = pntw->ntw_list;
	struct ice_network *curr = NULL;
	struct cve_device *ice0, *ice1;
	struct job_descriptor *job;

	/* At this point ice requirement must be satisfied */

	ret = cve_os_lock(&dg->poweroff_dev_list_lock, CVE_INTERRUPTIBLE);
	if (ret != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "cve_os_lock error\n");
		return -1;
	}

	if (ice_dg_can_lazy_capture_ice(pntw)) {

		cve_os_log(CVE_LOGLEVEL_INFO,
				"PNTW:0x%llx Lazy Capture activated\n",
				pntw->pntw_id);

		__lazy_capture_ices(pntw);

		goto out;

	} else {
		if (head != NULL) {
			/* Loop on all network under the parent
			 * and unlink all jobs
			 */
			curr = head;
			do {
				/* Removing Job2ICE linkage and
				 * setting Ntw for Cold run
				 */
				for (i = 0;
					i < curr->jg_list->submitted_jobs_nr;
					i++) {
					job = &curr->jg_list->job_list[i];
					job->hw_ice_id = INVALID_ICE_ID;
					ice_di_set_cold_run(job->di_hjob);
				}
				curr->ntw_icemask = 0;
				curr = cve_dle_next(curr, list);
			} while (curr != head);
		}

		pntw->resource_mapped = 0;
		/* Unset PNTW ICE Map */
		for (i = 0; i < MAX_CVE_DEVICES_NR; i++)
			pntw->cur_ice_map[i] = -1;

		/* Unset PNTW ICE Map */
		for (i = 0; i < MAX_CVE_DEVICES_NR; i++)
			pntw->global_ice_map[i].hw_ice_id = INVALID_ICE_ID;

		cve_os_log(CVE_LOGLEVEL_INFO,
				"PNTW:0x%llx Lazy Capture Failed\n",
				pntw->pntw_id);
	}

	pntw->given_pbo_req = pntw->temp_pbo_req;
	pntw->given_dice_req = pntw->temp_dice_req;
	pntw->given_icebo_req = pntw->temp_icebo_req;
	pntw->shared_read = (pntw->temp_icebo_req == ICEBO_MANDATORY);

	for (i = 0; i < MAX_CVE_DEVICES_NR; i = i+2) {
		if (pntw->global_ice_map[i].policy ==
				PNTW_ICE_ALLOC_POLICY_BO) {
			if (pntw->given_icebo_req == ICEBO_MANDATORY) {
				ice_dg_borrow_next_pbo(pntw, &ice0, &ice1);
			} else {
				ice_dg_borrow_next_dice(pntw, &ice0);
				ice_dg_borrow_next_dice(pntw, &ice1);
			}
			pntw->global_ice_map[i].hw_ice_id = ice0->dev_index;
			pntw->cur_ice_map[ice_count++] = ice0->dev_index;
			pntw->global_ice_map[i + 1].hw_ice_id = ice1->dev_index;
			pntw->cur_ice_map[ice_count++] = ice1->dev_index;
		}
	}

	for (i = 0; i < MAX_CVE_DEVICES_NR; i++) {
		if ((pntw->global_ice_map[i].policy ==
					PNTW_ICE_ALLOC_POLICY_DONT_CARE) ||
				(pntw->global_ice_map[i].policy ==
				 PNTW_ICE_ALLOC_POLICY_ANYTHING)) {
			ice_dg_borrow_next_dice(pntw, &ice0);
			pntw->global_ice_map[i].hw_ice_id = ice0->dev_index;
			pntw->cur_ice_map[ice_count++] = ice0->dev_index;
		}
	}

	ASSERT(ice_count == pntw->num_ice);
	__map_pntw_pbo_ntw_jobs(pntw);
out:
	cve_os_unlock(&dg->poweroff_dev_list_lock);

	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"PNtwID=0x%lx, Reserved pICEBO=%d dICEBO=%d\n",
		(uintptr_t)pntw, pntw->given_pbo_req,
		pntw->given_dice_req);

	return ret;
}

static void __ntw_release_ice(struct ice_pnetwork *pntw)
{
	struct cve_device *head;

	while (pntw->ice_list) {
		head = pntw->ice_list;

		ice_dg_return_this_ice(pntw, head);
	}

	cve_os_log(CVE_LOGLEVEL_INFO,
		"Released %d ICE from PNtwID:0x%llx\n",
			pntw->num_ice, pntw->pntw_id);
}

static void __lazy_capture_counters(struct ice_pnetwork *pntw)
{
	int i;
	int8_t cntr_id;
	u32 mask, cntr_bitmap;
	struct cve_hw_cntr_descriptor *hw_cntr;
	struct cve_device_group *dg = g_cve_dev_group_list;

	cntr_bitmap = pntw->cntr_bitmap;
	while (cntr_bitmap) {

		/* #Trailing zero indicates counter_id */
		i = __builtin_ctz(cntr_bitmap);
		mask = (1 << i);

		cntr_bitmap &= ~(mask);

		cntr_id = pntw->cntr_id_map[i];
		ASSERT(cntr_id != INVALID_CTR_ID);

		hw_cntr = &dg->base_addr_hw_cntr[cntr_id];
		cve_dle_move(pntw->cntr_list, dg->hw_cntr_list, list, hw_cntr);

		hw_cntr->in_free_pool = false;
		hw_cntr->cntr_pntw_id = pntw->pntw_id;
		dg->num_avl_cntr--;

		cve_os_log(CVE_LOGLEVEL_INFO,
			"PNtwID:0x%llx Map Counter[%u]->%u\n",
			pntw->pntw_id, i, hw_cntr->hw_cntr_id);
	}

}

static int __ntw_reserve_cntr(struct ice_pnetwork *pntw)
{
	int i, ret = 0;
	int8_t cntr_id;
	bool lazy_capture = pntw->cntr_bitmap;
	bool patch_cntr = false;
	u32 mask, cntr_bitmap;
	struct cve_device_group *dg = g_cve_dev_group_list;
	struct cve_hw_cntr_descriptor *hw_cntr;
	struct ice_network *head = pntw->ntw_list;
	struct ice_network *curr = NULL;
	u32 count = 0;

	__local_builtin_popcount(pntw->cntr_bitmap, count);

	/* Check if previous Counters are still available */
	cntr_bitmap = pntw->cntr_bitmap;
	while (cntr_bitmap) {

		/* #Trailing zero indicates counter_id */
		i = __builtin_ctz(cntr_bitmap);
		mask = (1 << i);

		cntr_bitmap &= ~(mask);

		cntr_id = pntw->cntr_id_map[i];
		if (cntr_id == INVALID_CTR_ID) {
			lazy_capture = false;
			break;
		}

		hw_cntr = &dg->base_addr_hw_cntr[cntr_id];
		if (!hw_cntr->in_free_pool) {
			lazy_capture = false;
			break;
		}
	}

	if (lazy_capture) {

		cve_os_log(CVE_LOGLEVEL_DEBUG, "Lazy Capture activated\n");

		__lazy_capture_counters(pntw);

		patch_cntr = false;

		if (ice_is_soc() && ice_get_a_step_enable_flag())
			patch_cntr = true;

		/* ntw->patch_cntr is already false */

		goto out;

	} else {
		for (i = 0; i < MAX_HW_COUNTER_NR; i++)
			pntw->cntr_id_map[i] = INVALID_CTR_ID;

		patch_cntr = true;
	}

	/* Update counter patching status */
	if (head != NULL) {
		curr = head;
		do {
			curr->patch_cntr = patch_cntr;
			curr = cve_dle_next(curr, list);
		} while (curr != head);
	}

	cntr_bitmap = pntw->cntr_bitmap;
	while (cntr_bitmap) {

		/* #Trailing zero indicates counter_id */
		i = __builtin_ctz(cntr_bitmap);
		mask = (1 << i);

		cntr_bitmap &= ~(mask);

		/* Allocate new Counter and map */
		hw_cntr = dg->hw_cntr_list;

		/* Should make sure that enough Counters are available */
		ASSERT(hw_cntr != NULL);

		cve_dle_move(pntw->cntr_list, dg->hw_cntr_list, list, hw_cntr);

		hw_cntr->in_free_pool = false;
		dg->num_avl_cntr--;

		hw_cntr->cntr_pntw_id = pntw->pntw_id;

		pntw->cntr_id_map[i] = hw_cntr->hw_cntr_id;

		cve_os_log(CVE_LOGLEVEL_INFO,
			"PNtwID:0x%llx Map Counter[%u]->%u\n",
			pntw->pntw_id, i, hw_cntr->hw_cntr_id);
	}

out:
	cve_os_log(CVE_LOGLEVEL_INFO,
		"Reserved %d Counter for NtwID:0x%llx\n",
			count, pntw->pntw_id);

	return ret;
}

static void __ntw_release_cntr(struct ice_pnetwork *pntw)
{
	int i;
	u32 mask, cntr_bitmap;
	struct cve_hw_cntr_descriptor *head;
	struct cve_device_group *dg = g_cve_dev_group_list;
	u32 count = 0;

	__local_builtin_popcount(pntw->cntr_bitmap, count);

	cntr_bitmap = pntw->cntr_bitmap;
	while (cntr_bitmap) {

		/* #Trailing zero indicates counter_id */
		i = __builtin_ctz(cntr_bitmap);
		mask = (1 << i);

		cntr_bitmap &= ~(mask);
		if (!pntw->cntr_list)
			goto out;
		head = pntw->cntr_list;
		cve_dle_move(dg->hw_cntr_list, pntw->cntr_list, list, head);

		head->in_free_pool = true;
		head->cntr_pntw_id = INVALID_NETWORK_ID;
		dg->num_avl_cntr++;

		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"PNTW:0x%llxUndo Map Counter [%u] = %u\n",
			pntw->pntw_id,
			i, head->hw_cntr_id);
	}
out:
	cve_os_log(CVE_LOGLEVEL_INFO,
		"Released %d Counter from PNtwID:0x%llx\n",
				count, pntw->pntw_id);
}

static void __ntw_reset_cntr(struct ice_pnetwork *pntw)
{
	u32 mask, cntr_bitmap;
	int i;

	cntr_bitmap = pntw->cntr_bitmap;
	while (cntr_bitmap) {
		i = __builtin_ctz(cntr_bitmap);
		mask = (1 << i);
		cntr_bitmap &= ~(mask);
		ice_di_reset_counter(pntw->cntr_id_map[i]);
	}
}

static int __ntw_reserve_clos(struct ice_pnetwork *pntw)
{
	int ret = 0;
	struct cve_device_group *dg = cve_dg_get();
	struct clos_manager *mclos = &dg->dg_clos_manager;

	cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Reserving LLC for PNTW:=0x%llx Required(%u, %u, %u, %u)\n",
			pntw->pntw_id,
			pntw->clos[0], pntw->clos[1],
			pntw->clos[2], pntw->clos[3]);

	mclos->clos_size[ICE_CLOS_1] = pntw->clos[ICE_CLOS_1];
	mclos->clos_size[ICE_CLOS_2] = pntw->clos[ICE_CLOS_2];
	mclos->clos_size[ICE_CLOS_0] = (MAX_CLOS_SIZE_MB -
					(pntw->clos[ICE_CLOS_1] +
					pntw->clos[ICE_CLOS_2]));

	ASSERT(mclos->clos_size[ICE_CLOS_0] >= 3);

	return ret;
}

static int __is_pool_required(struct ice_pnetwork *pntw)
{
	return pntw->cntr_bitmap ? 1 : 0;
}

enum resource_status ice_ds_ntw_reserve_resource(struct ice_pnetwork *pntw)
{
	enum resource_status status = RESOURCE_OK;
	struct cve_device_group *dg = cve_dg_get();
	struct cve_device *dev;

	if (pntw->res_resource) {

		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Resources already reserved. PNtwID=0x%lx\n",
			(uintptr_t)pntw);
		status = RESOURCE_OK;
		goto out;
	}

	/* If !has_resource => Borrow */
	if (!pntw->has_resource) {

		status = ice_ds_ntw_borrow_resource(pntw);
		if (status != RESOURCE_OK)
			goto out;
	}

	/* Update Reservation flags */
	pntw->res_resource = true;

	/* Loop over Ntw ICEs and reserve them */
	dev = pntw->ice_list;
	do {
		ice_dg_reserve_this_ice(dev);

		dev = cve_dle_next(dev, owner_list);
	} while (dev != pntw->ice_list);

	/* Counter */
	dg->num_nonres_cntr -= __builtin_popcount(pntw->cntr_bitmap);

	/* Pool */
	if (__is_pool_required(pntw)) {

		pntw->wq->num_ntw_reserving_pool++;

		if (pntw->wq->num_ntw_reserving_pool == 1)
			dg->num_nonres_pool--;
	}

	cve_os_log(CVE_LOGLEVEL_INFO,
		"Resources reserved. PNtwID=0x%lx\n",
		(uintptr_t)pntw);

out:
	return status;
}

static int __map_resources_and_context(struct ice_pnetwork *pntw)
{
	u32 i, j;
	struct cve_device *dev;
	int retval = 0;
	struct job_descriptor *job;
	struct ice_network *ntw = NULL;

	/* No active network, landed here due to resource reservation */
	if (pntw->curr_ntw == NULL) {
		pntw->resource_mapped = 0;
		return 0;
	}

	ntw = pntw->curr_ntw;

	for (i = 0; i < ntw->jg_list->total_jobs; i++) {
		cve_dev_context_handle_t dev_ctx = NULL;

		job = &ntw->jg_list->job_list[i];
		dev_ctx = pntw->dev_ctx[job->id];

		/* At this point it is guaranteed that device will be found */
		dev = cve_device_get(job->hw_ice_id);
		if (!dev) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
					"dev is NULL\n");
			ASSERT(false);
		}
		/* assign this ICE to dev ctx */
		ice_map_dev_and_context(dev_ctx, dev);
		dev->dev_ntw_id = ntw->network_id;
		dev->hswc_infer = ntw->dev_hswc[i];
		ice_swc_counter_set(dev->hswc_infer,
				ICEDRV_SWC_INFER_DEVICE_COUNTER_ID,
				dev->dev_index);

		if (((cve_di_get_device_reset_flag(dev) &
			CVE_DI_RESET_DUE_PNTW_SWITCH) != 0) &&
				pntw->pntw_cntrmask) {
			/* Unmap old mapping and add Map BAR1 Space */
			ice_unmap_bar1(dev_ctx);
			retval = ice_map_bar1(dev, dev_ctx);
			if (retval < 0) {
				cve_os_log(CVE_LOGLEVEL_ERROR,
						"ICE%d NTW:0x%llx Job:%u BAR1 mapping failed(%d)\n",
						dev->dev_index,
						ntw->network_id, job->id,
						retval);
				ice_unmap_dev_and_context(dev_ctx);
				goto exit;
			}
		}
	}

	pntw->resource_mapped = 1;

	return retval;

exit:
	j = i;
	for (i = 0; i < j; i++) {
		cve_dev_context_handle_t dev_ctx = NULL;

		job = &ntw->jg_list->job_list[i];
		dev_ctx = pntw->dev_ctx[job->id];

		/* At this point it is guaranteed that device will be found */
		dev = cve_device_get(job->hw_ice_id);

		/* Unmap BAR1 Space */
		ice_unmap_bar1(dev_ctx);

		ice_unmap_dev_and_context(dev_ctx);
	}

	return retval;
}

enum resource_status ice_ds_ntw_borrow_resource(struct ice_pnetwork *pntw)
{
	int err;
	enum resource_status status = RESOURCE_OK;
	enum pool_status pstatus = POOL_EXIST;
	struct cve_device *head, *next;
	struct cve_hw_cntr_descriptor *head_cntr, *next_cntr;
	struct cve_device_group *dg = cve_dg_get();
	u64 pntwIceMask = 0;
	u64 pntwCntrMask = 0;

	if (pntw->has_resource) {
		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Resources already borrowed. PNtwID=0x%lx\n",
			(uintptr_t)pntw);
		goto end;
	}

	DO_TRACE(trace_icedrvNetworkResource(
				SPH_TRACE_OP_STATE_START,
				pntw->wq->context->swc_node.sw_id,
				pntw->swc_node.sw_id,
				0, pntw->pntw_id,
				pntw->num_ice, pntw->cntr_bitmap, pntw->clos));

	if (__is_pool_required(pntw)) {

		pstatus = cve_ds_map_pool_context(pntw->wq->context);
		if (pstatus == POOL_EXHAUSTED) {

			if (dg->num_nonres_pool == 0)
				status = RESOURCE_INSUFFICIENT;
			else if (dg->num_avl_pool == 0)
				status = RESOURCE_BUSY;

			cve_os_log(CVE_LOGLEVEL_INFO,
				"Pool not available. PNtwID=0x%lx, Status=%d\n",
				(uintptr_t)pntw, status);

			goto end;
		}

		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Pool allocated. PNtwID=0x%lx\n",
			(uintptr_t)pntw);
	} else {
		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Pool not required. PNtwID=0x%lx\n",
			(uintptr_t)pntw);
	}

	/* WARNING: This value may change in Lazy Capture */
	pntw->temp_pbo_req = pntw->org_pbo_req;
	pntw->temp_dice_req = pntw->org_dice_req;
	pntw->temp_icebo_req = pntw->org_icebo_req;

	/* Update ICE requirement before checking for ICE availability*/
	if (pntw->temp_icebo_req == ICEBO_PREFERRED) {

		status = ice_dg_check_resource_availability(pntw);
		if (status != RESOURCE_OK) {
			pntw->temp_dice_req += (2 * pntw->temp_pbo_req);
			pntw->temp_pbo_req = 0;
			pntw->temp_icebo_req = ICEBO_DEFAULT;
		} else
			pntw->temp_icebo_req = ICEBO_MANDATORY;
	}

	status = ice_dg_check_resource_availability(pntw);
	if (status != RESOURCE_OK) {

		cve_os_log(CVE_LOGLEVEL_INFO,
			"Resources not available. PNtwID=0x%lx, Status=%d\n",
			(uintptr_t)pntw, status);

		if (pstatus == POOL_ALLOCATED)
			cve_ds_unmap_pool_context(pntw->wq->context);
		goto end;
	}

	ASSERT(__ntw_reserve_ice(pntw) == 0);

	ASSERT(__ntw_reserve_cntr(pntw) == 0);

	cve_dle_add_to_list_before(dg->pntw_with_resources,
		resource_list, pntw);

	if (__is_pool_required(pntw)) {

		__link_resource_and_pool(pntw);
		pntw->wq->num_ntw_using_pool++;
	}

	pntw->has_resource = 1;

	cve_os_log(CVE_LOGLEVEL_INFO,
		"Resources borrowed. PNtwID=0x%lx\n",
		(uintptr_t)pntw);

	head = pntw->ice_list;
	next = head;
	do {
		pntwIceMask |= (1ULL << next->dev_index);
		next = cve_dle_next(next, owner_list);
	} while (head != next);

	head_cntr = pntw->cntr_list;
	if (head_cntr != NULL) {
		next_cntr = head_cntr;
		do {
			pntwCntrMask |= (1ULL << next_cntr->hw_cntr_id);
			next_cntr = cve_dle_next(next_cntr, list);
		} while (head_cntr != next_cntr);
	}

	pntw->pntw_icemask = pntwIceMask;
	pntw->pntw_cntrmask = pntwCntrMask;
	err = __map_resources_and_context(pntw);
	if (err) {
		status = RESOURCE_INSUFFICIENT;
		ice_ds_ntw_return_resource(pntw);
		goto end;
	}

	DO_TRACE(trace_icedrvNetworkResource(
				SPH_TRACE_OP_STATE_COMPLETE,
				pntw->wq->context->swc_node.sw_id,
				pntw->swc_node.sw_id,
				0, pntw->pntw_id,
				pntwIceMask, pntwCntrMask, pntw->clos));

	return RESOURCE_OK;

end:
	DO_TRACE(trace_icedrvNetworkResource(
			SPH_TRACE_OP_STATE_ABORT,
			pntw->wq->context->swc_node.sw_id,
			pntw->swc_node.sw_id,
			0, pntw->pntw_id,
			pntw->num_ice, pntw->cntr_bitmap,
			pntw->clos));

	return status;
}

static void __power_off_ntw_devices(struct ice_pnetwork *pntw)
{
	int retval;
	struct cve_device *head = pntw->ice_list;
	struct cve_device *next = head;
	unsigned long cur_jiffy;
	struct cve_device_group *dg = g_cve_dev_group_list;
	bool wakeup_po_thread = false;

	retval = cve_os_lock(&dg->poweroff_dev_list_lock, CVE_INTERRUPTIBLE);
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "cve_os_lock error\n");
		return;
	}

	cur_jiffy = ice_os_get_current_jiffy();

	/*
	 * When PowerOff thread has nothing to do, it wakes up every 60 sec.
	 * This is the only function that assigns work to PO thread.
	 * Wake up this thread if currently its queue is empty, else, anyways
	 * it will wake-up in sometime to turn off the already queued ices.
	 */
	wakeup_po_thread = (dg->poweroff_dev_list == NULL);

	do {
		if (next->power_state == ICE_POWER_ON) {

			/* Write current timestamp to Device */
			next->poff_jiffy = cur_jiffy;

			ice_dev_set_power_state(next, ICE_POWER_OFF_INITIATED);
			ice_swc_counter_set(next->hswc,
				ICEDRV_SWC_DEVICE_COUNTER_POWER_STATE,
				ice_dev_get_power_state(next));
			cve_os_log(CVE_LOGLEVEL_INFO,
					"PNtwID:0x%lx Adding ICE%d to LPM Task\n",
					(uintptr_t)pntw, next->dev_index);
			cve_dle_add_to_list_before(dg->poweroff_dev_list,
				poweroff_list, next);
		}

		next = cve_dle_next(next, owner_list);
	} while (next != head);

	if (wakeup_po_thread) {
		dg->start_poweroff_thread = 1;
		cve_os_wakeup(&dg->power_off_wait_queue);
	}

	cve_os_unlock(&dg->poweroff_dev_list_lock);
}

void ice_ds_ntw_release_resource(struct ice_pnetwork *pntw)
{
	struct cve_device_group *dg = cve_dg_get();
	struct cve_device *dev;

	if (!pntw->res_resource) {

		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Resources already released. PNtwID=0x%lx\n",
			(uintptr_t)pntw);
		goto out;
	}

	if (pntw->reset_ntw) {
		cve_os_log(CVE_LOGLEVEL_INFO,
			"Ntw in error state. Cannot release resource. NtwID=0x%lx\n",
			(uintptr_t)pntw);
		goto out;
	}

	/* Update Reservation flags */
	pntw->res_resource = false;

	/* Loop over Ntw ICEs and release them */
	dev = pntw->ice_list;
	do {
		ice_dg_release_this_ice(dev);

		dev = cve_dle_next(dev, owner_list);
	} while (dev != pntw->ice_list);

	/* Counter */
	dg->num_nonres_cntr += __builtin_popcount(pntw->cntr_bitmap);

	/* Pool */
	if (__is_pool_required(pntw)) {

		pntw->wq->num_ntw_reserving_pool--;

		if (pntw->wq->num_ntw_reserving_pool == 0)
			dg->num_nonres_pool++;
	}

	cve_os_log(CVE_LOGLEVEL_INFO,
		"Resources released. PNtwID=0x%lx\n",
		(uintptr_t)pntw);

	ice_ds_ntw_return_resource(pntw);

out:
	return;
}

void ice_ds_ntw_return_resource(struct ice_pnetwork *pntw)
{
	struct cve_device_group *dg = cve_dg_get();

	if (!pntw->has_resource) {

		ASSERT(!pntw->res_resource);
		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"No resource to return. PNtwID=0x%lx\n",
			(uintptr_t)pntw);
		goto end;

	} else if (pntw->reset_ntw) {

		ASSERT(pntw->res_resource);
		cve_os_log(CVE_LOGLEVEL_INFO,
			"Ntw in error state. Cannot return resource. PNtwID=0x%lx\n",
			(uintptr_t)pntw);
		goto end;

	} else if (pntw->res_resource) {

		cve_os_log(CVE_LOGLEVEL_INFO,
			"Resources reserved. Cannot return. PNtwID:0x%lx\n",
			(uintptr_t)pntw);
		goto end;
	}

	/* Once workload is over, placing ICEs in Power-off queue */
	__power_off_ntw_devices(pntw);

	/* If reservation not required then release all resources*/
	if (__is_pool_required(pntw)) {
		__delink_resource_and_pool(pntw);

		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Pool returned. PNtwID=0x%lx\n", (uintptr_t)pntw);
	}

	DO_TRACE(trace__icedrvResourceRelease(
			SPH_TRACE_OP_STATE_START,
			pntw->wq->context->swc_node.sw_id,
			pntw->swc_node.sw_id, 0, pntw->pntw_id,
			pntw->res_resource, pntw->pntw_icemask,
			pntw->pntw_cntrmask, pntw->clos));

	__ntw_release_ice(pntw);
	pntw->pntw_icemask = 0;

	__ntw_release_cntr(pntw);
	pntw->pntw_cntrmask = 0;

	if (__is_pool_required(pntw)) {

		pntw->wq->num_ntw_using_pool--;

		if (!pntw->wq->num_ntw_using_pool) {

			cve_di_unset_pool_registers(pntw->wq->context->pool_id);
			cve_ds_unmap_pool_context(pntw->wq->context);
		}
	}

	cve_dle_remove_from_list(dg->pntw_with_resources, resource_list, pntw);

	pntw->has_resource = 0;

	cve_os_log(CVE_LOGLEVEL_INFO,
		"Resources returned. PNtwID:0x%lx\n", (uintptr_t)pntw);

	DO_TRACE(trace__icedrvResourceRelease(
			SPH_TRACE_OP_STATE_COMPLETE,
			pntw->wq->context->swc_node.sw_id,
			pntw->swc_node.sw_id,
			0, pntw->pntw_id,
			pntw->res_resource, pntw->pntw_icemask,
			pntw->pntw_cntrmask, pntw->clos));
	return;

end:
	DO_TRACE(trace__icedrvResourceRelease(
			SPH_TRACE_OP_STATE_ABORT,
			pntw->wq->context->swc_node.sw_id,
			pntw->swc_node.sw_id,
			0, pntw->pntw_id,
			pntw->res_resource, pntw->pntw_icemask,
			pntw->pntw_cntrmask, pntw->clos));
}

static void __flush_ntw_buffers(struct ice_network *ntw)
{
	u32 idx = 0;
	struct cve_ntw_buffer *buf_list, *cur_buf;
	struct cve_device *dev = ice_get_first_dev();

	buf_list = ntw->buf_list;

	for (; idx < ntw->num_buf; idx++) {
		cur_buf = &buf_list[idx];
		cve_mm_sync_mem_to_dev(cur_buf->ntw_buf_alloc, dev);
		cve_os_log(CVE_LOGLEVEL_DEBUG,
				"Flushing the buffers. NtwID:0x%llx, Buffer[%d]:0x%lx\n",
				ntw->network_id, idx, (uintptr_t)cur_buf);
	}
}

static void __flush_inf_buffers(struct ice_infer *inf)
{
	u32 idx;
	struct cve_inf_buffer *cur_buf;
	struct cve_device *dev = ice_get_first_dev();

	for (idx = 0; idx < inf->num_buf; idx++) {
		cur_buf = &inf->buf_list[idx];

		/* Will be NULL if this is a SSurface */
		if (!cur_buf->inf_buf_alloc)
			continue;

		cve_mm_sync_mem_to_dev(cur_buf->inf_buf_alloc, dev);
		cve_os_log(CVE_LOGLEVEL_DEBUG,
				"Flushing the buffers. InfID:0x%lx, Buffer[%d]:0x%lx\n",
				(uintptr_t)inf, idx, (uintptr_t)cur_buf);
	}
}

#if 0
/* Flushes the CBs that were patched with InferBuffers */
static void __flush_inf_cbs(struct ice_infer *inf)
{
	u32 idx;
	struct ice_pp_value *pp_value;
	struct cve_ntw_buffer *cur_buf;
	struct cve_device *dev = ice_get_first_dev();

	for (idx = 0; idx < inf->ntw->ntw_surf_pp_count; idx++) {
		pp_value = &inf->inf_pp_arr[idx];
		cur_buf = pp_value->ntw_buf;
		cve_mm_sync_mem_to_dev(cur_buf->ntw_buf_alloc, dev);
		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Flushing the patched buffers. NtwID=0x%lx, Buffer=0x%lx\n",
			(uintptr_t)inf->ntw, (uintptr_t)cur_buf);
	}
}
#endif

u64 __get_sw_id_from_context_pid(cve_context_process_id_t context_pid,
			cve_context_id_t context_id)
{

	u64 context_sw_id = 0;
	int retval = 0;
	struct ds_context *context = NULL;
	struct cve_context_process *context_process = NULL;

	/* get the process based on the id */
	retval = cve_context_process_get(context_pid, &context_process);
	if (retval != 0)
		goto out;

	/* Get the context from the process */
	context = get_context_from_process(
		context_process,
		context_id);
	if (!context) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"ERROR: CTXPID:0x%llx CTXID:0x%llx get_context_from_process failed\n",
			context_pid, context_id);
		goto out;
	}

	context_sw_id = context->swc_node.sw_id;
out:
	return context_sw_id;
}

int ice_ds_reset_network(cve_context_process_id_t context_pid,
		cve_context_id_t context_id,
		ice_pnetwork_id_t pntw_id)
{
	int retval = CVE_DEFAULT_ERROR_CODE;
	u32 i;
	struct cve_device_group *dg = cve_dg_get();
	struct ice_pnetwork *pntw;
	struct ice_network *head, *curr;

	retval = cve_os_lock(&g_cve_driver_biglock, CVE_INTERRUPTIBLE);
	if (retval != 0) {
		retval = -ERESTARTSYS;
		goto out;
	}

	if (dg->icedc_state == ICEDC_STATE_CARD_RESET_REQUIRED) {
		retval = ICEDRV_KERROR_CARD_RESET_NEEDED;
		cve_os_log(CVE_LOGLEVEL_ERROR,
		"ERROR:%d Due to IceDC error, card reset is required\n",
		retval);
		goto unlock_out;
	}

	pntw = __get_pnetwork_from_id(context_pid, context_id, pntw_id);
	if (pntw == NULL) {
		retval = -ICEDRV_KERROR_INVALID_PNTW_HANDLE;
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"ERROR:%d Given PNtwID:0x%llx is not present in this context\n",
				retval, pntw_id);
		goto unlock_out;
	}

	if (!pntw->reset_ntw) {
		/* Network Reset not required */
		retval = -ICEDRV_KERROR_NTW_RESET_NA;
		goto unlock_out;
	}

	head = pntw->ntw_list;
	curr = head;
	pntw->reset_ntw = false;
	ASSERT(head);
	do {
		curr->reset_ntw = false;
		curr = cve_dle_next(curr, list);
	} while (curr != head);

	cve_os_log(CVE_LOGLEVEL_INFO,
		"Performing PNtw Reset. PNtwID=0x%lx\n", (uintptr_t)pntw);

	for (i = 0; i < pntw->num_ice; i++) {

		struct cve_device *dev;

		ASSERT(pntw->cur_ice_map[i] >= 0);

		dev = cve_device_get(pntw->cur_ice_map[i]);
		if (!dev) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
				"Performing Ntw reset. PNtwID=0x%lx\n",
				(uintptr_t)pntw);
			retval = -ENODEV;
			goto unlock_out;
		}

		cve_di_set_device_reset_flag(dev, CVE_DI_RESET_DUE_CVE_ERROR);
	}

	if (pntw->reserved_on_error)
		ice_ds_ntw_release_resource(pntw);

unlock_out:
	cve_os_unlock(&g_cve_driver_biglock);
out:
	return retval;
}

void ice_ds_block_network(struct ice_pnetwork *pntw,
	cve_ds_job_handle_t ds_jobh, u32 status,
	bool is_ice_err)
{
	struct ice_network *ntw = NULL;

	if (pntw)
		ntw = pntw->curr_ntw;

	if (is_ice_err) {

		struct cve_device *dev;
		struct job_descriptor *job;

		job = (struct job_descriptor *)ds_jobh;
		/* Ntw info is not passed in case of ice_error */
		ntw = job->jobgroup->network;
		pntw = ntw->pntw;
		/* Disables WDT */
		dev = cve_device_get(job->hw_ice_id);
		project_hook_interrupt_handler_exit(dev);

		if (job->graph_ice_id < NUM_ICE_UNIT) {
			ntw->ice_error_status[job->graph_ice_id] |= status;
			pntw->ice_error_status[job->graph_ice_id] |=
				status;

		} else {
			ntw->ice_error_status[job->dummy_ice_id] |= status;
			pntw->ice_error_status[job->dummy_ice_id] |=
				status;
		}
	} else {

		ASSERT(ntw);
		ntw->icedc_err_status |= (u64)status;
		pntw->icedc_err_status |= (u64)status;
	}

	if (!ntw->reset_ntw) {

		ntw->reset_ntw = true;
		pntw->reset_ntw = true;

		if (pntw->res_resource)
			pntw->reserved_on_error = false;
		else {
			pntw->reserved_on_error = true;
			ASSERT(ice_ds_ntw_reserve_resource(pntw) ==
					RESOURCE_OK);
		}
	}
}

static void __update_pntw_sw_id(struct ice_pnetwork *pntw, int obj_id)
{
	struct ice_swc_node *swc_node = &pntw->swc_node;

	swc_node->parent_sw_id = pntw->swc_node.sw_id;

	if (obj_id < 0)
		swc_node->sw_id = pntw->pntw_id;
	else
		swc_node->sw_id = obj_id;
}

static int __create_pntw(struct ice_pnetwork_descriptor *pntw_desc,
		struct cve_workqueue *wq,
		u64 *pntw)
{
	struct ice_pnetwork *parent;
	int ret = 0, i = 0;

	ret = OS_ALLOC_ZERO(sizeof(*parent), (void **)&parent);
	if (ret < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"Allocation failed %d\n", ret);
		goto exit;
	}

	parent->pntw_id = (u64)parent;
	parent->wq = wq;
	parent->num_ice = pntw_desc->num_ice;
	parent->shared_read = pntw_desc->shared_read;
	parent->produce_completion = pntw_desc->produce_completion;

	/* if user has not provided max shared distance then store
	 * the default value
	 */
	parent->max_shared_distance = (pntw_desc->max_shared_distance != 0) ?
		pntw_desc->max_shared_distance : DEFAULT_MAX_SHARED_DISTANCE;

	parent->last_done = 0;
	parent->exIR_performed = 0;
	parent->sch_queue[EXE_INF_PRIORITY_0] = NULL;
	parent->sch_queue[EXE_INF_PRIORITY_1] = NULL;
	parent->last_request_type = NODE_TYPE_RELEASE;
	parent->pntw_res_node.pntw = parent;
	parent->pntw_res_node.ntype = NODE_TYPE_RESERVE;
	parent->pntw_rel_node.pntw = parent;
	parent->pntw_rel_node.ntype = NODE_TYPE_RELEASE;
	parent->rr_node = NULL;
	parent->res_resource = false;
	parent->has_resource = 0;
	parent->global_graph_id_mask = 0;
	parent->org_icebo_req = pntw_desc->icebo_req;
	parent->org_pbo_req = 0;
	parent->org_dice_req = 0;
	parent->pntw_running = false;
	parent->ntw_count = 0;

	ret = cve_os_init_wait_que(&parent->rr_wait_queue);

	for (i = CVE_FW_TYPE_START; i < CVE_FW_END_TYPES; i++) {
		parent->self_info[i].user = (void *)parent;
		parent->self_info[i].owner_fw = (void *)NULL;
	}

	for (i = 0; i < NUM_COUNTER_REG; i++)
		parent->cntr_id_map[i] = INVALID_CTR_ID;

	for (i = 0; i < MAX_CVE_DEVICES_NR; i++)
		parent->cur_ice_map[i] = -1;

	/* Unset PNTW ICE Map */
	for (i = 0; i < MAX_CVE_DEVICES_NR; i++) {
		parent->global_ice_map[i].policy = PNTW_ICE_ALLOC_POLICY_UNUSED;
		parent->global_ice_map[i].hw_ice_id = INVALID_ICE_ID;
	}

	for (i = 0; i < ICE_CLOS_MAX; i++)
		parent->clos[i] = pntw_desc->llc_size[i];

	ret = ice_memcpy_s(parent->infer_buf_page_config,
			ICEDRV_PAGE_ALIGNMENT_MAX *
			sizeof(parent->infer_buf_page_config[0]),
			pntw_desc->infer_buf_page_config,
			ICEDRV_PAGE_ALIGNMENT_MAX *
			sizeof(parent->infer_buf_page_config[0]));
	if (ret < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"Safelib memcpy Failed %d\n", ret);
		goto error_free_mem;
	}

	ret = ice_memcpy_s(parent->ntw_buf_page_config,
			ICEDRV_PAGE_ALIGNMENT_MAX *
			sizeof(parent->ntw_buf_page_config[0]),
			pntw_desc->va_partition_config,
			ICEDRV_PAGE_ALIGNMENT_MAX *
			sizeof(parent->ntw_buf_page_config[0]));
	if (ret < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"Safelib memcpy Failed %d\n", ret);
		return ret;
	}

	ret = __pntw_check_resources(wq, parent);
	if (ret < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"pntw_check_resources() Failed %d\n", ret);
		goto error_free_mem;
	}

	ret = ice_init_sw_dev_contexts(parent->num_ice,
			(uint64_t *)pntw_desc->va_partition_config,
			(uint64_t *)parent->infer_buf_page_config,
			parent);
	if (ret != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"ice_init_sw_dev_contexts failed %d\n", ret);
		goto error_free_mem;
	}

	for (i = 0; i < ICEDRV_PAGE_ALIGNMENT_MAX; i++) {
		cve_os_log(CVE_LOGLEVEL_DEBUG,
				"PNTW:0x%llx PageAlignment:%u NtwBufConfigSz:%llu InfBufConfig:%llu\n",
				parent->pntw_id, i,
				pntw_desc->va_partition_config[i],
				parent->infer_buf_page_config[i]);
	}

	__update_pntw_sw_id(parent, pntw_desc->obj_id);
	ice_swc_create_pntw_node(parent);
	ice_swc_counter_inc(g_sph_swc_global,
			ICEDRV_SWC_GLOBAL_COUNTER_PNTW_TOT);

	cve_os_log(CVE_LOGLEVEL_DEBUG,
			"New PNTW:0x%llx Created NumIce:%d CLOS0:%d CLOS1:%d CLOS2:%d CLOS3:%d\n",
			parent->pntw_id, parent->num_ice,
			parent->clos[0], parent->clos[1],
			parent->clos[2], parent->clos[3]);

	/* add to the WQ parent list */
	cve_dle_add_to_list_before(wq->pntw_list, list, parent);
	*pntw = (u64)parent;

	return ret;

error_free_mem:
	OS_FREE(parent, sizeof(*parent));
exit:
	return ret;

}


int ice_ds_create_pnetwork(
		cve_context_process_id_t context_pid,
		cve_context_id_t context_id,
		struct ice_pnetwork_descriptor *pnetwork_desc,
		u64 *pnetwork_id)
{
	int retval = CVE_DEFAULT_ERROR_CODE;
	struct cve_workqueue *workqueue = NULL;
	struct cve_device_group *dg = cve_dg_get();
	struct cve_device *dev = ice_get_first_dev();

	retval = cve_os_lock(&g_cve_driver_biglock, CVE_INTERRUPTIBLE);
	if (retval != 0) {
		retval = -ERESTARTSYS;
		goto out;
	}

	retval = __get_wq_from_contex_pid(context_pid, context_id, &workqueue);
	if (!workqueue) {
		retval = -ICEDRV_KERROR_INVALID_PNTW_HANDLE;
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"get_wq_from_contex_pid() failed %d\n", retval);
		goto out;
	}

	if (dev == NULL) {
		retval = -ICEDRV_KERROR_CTX_NODEV;
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"Error:%d dev cannot be NULL\n", retval);
		goto out;
	}

	if (dg->icedc_state == ICEDC_STATE_CARD_RESET_REQUIRED) {
		retval = ICEDRV_KERROR_CARD_RESET_NEEDED;
		cve_os_log(CVE_LOGLEVEL_ERROR,
		"ERROR:%d Due to IceDC error, card reset is required\n",
		retval);
		goto out;
	}

	retval = __create_pntw(pnetwork_desc, workqueue, pnetwork_id);
	if (retval < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"create_pntw() failed:%d\n", retval);
		goto out;
	}

	cve_os_unlock(&g_cve_driver_biglock);

	return retval;

out:
	cve_os_unlock(&g_cve_driver_biglock);
	return retval;
}

static int __destroy_pntw(struct ice_pnetwork *pntw)
{

	if (!pntw)
		return -ICEDRV_KERROR_INVALID_PNTW_HANDLE;

	__do_network_cleanup(pntw);
	ASSERT(!pntw->has_resource);

	__remove_pntw_from_fw_user(pntw);
	/*Do other cleanup related to HW resource*/
	ice_fini_sw_dev_contexts(pntw->dev_hctx_list,
				pntw->loaded_cust_fw_sections);
	ice_swc_destroy_pntw_node(pntw);
	cve_dle_remove_from_list(pntw->wq->pntw_list, list, pntw);
	OS_FREE(pntw, sizeof(*pntw));

	return 0;
}

static int __do_pnetwork_cleanup(struct cve_workqueue *wq)
{
	struct ice_pnetwork *head = wq->pntw_list;
	struct ice_pnetwork *curr = NULL;
	int ret = 0;

	/* try to destroy all networks within this workqueue */
	if (head == NULL)
		goto exit;

	curr = head;
	do {
		__do_network_cleanup(curr);
		__remove_pntw_from_fw_user(curr);
		/*Do other cleanup related to HW resource*/
		ice_fini_sw_dev_contexts(curr->dev_hctx_list,
				curr->loaded_cust_fw_sections);
		ice_swc_destroy_pntw_node(curr);

		cve_dle_remove_from_list(wq->pntw_list, list, curr);
		OS_FREE(curr, sizeof(*curr));

		if (wq->pntw_list)
			curr = cve_dle_next(wq->pntw_list, list);

	} while (wq->pntw_list);

exit:
	return ret;
}

static void __pntw_update_ice_alloc_policy(struct ice_network *ntw,
		u8 is_last)
{
	struct ice_pnetwork *pntw = ntw->pntw;
	u8 i, j = 0, used = 0, pbo_req = 0;
	struct ice_network *head = pntw->ntw_list;
	struct ice_network *curr = head;
	struct job_descriptor *job;

	pntw->org_pbo_req = 0;
	pntw->org_dice_req = 0;

	if (!is_last)
		goto exit;

	pntw->last_done = 1;
	__local_builtin_popcount(pntw->global_graph_id_mask, used);

	if (used == pntw->num_ice)
		goto map_jobs;

	/* If atleast one job is still not mapped with an sw ICE ID
	 * then update the resource policy
	 */
	for (i = 0; i < MAX_CVE_DEVICES_NR; i++) {
		if (pntw->global_graph_id_mask & (1 << i))
			continue;

		pntw->global_ice_map[i].policy = PNTW_ICE_ALLOC_POLICY_ANYTHING;
		j++;
		if ((used + j) == pntw->num_ice)
			break;

	}

map_jobs:
	for (i = 0; i < MAX_CVE_DEVICES_NR; i++) {
		if (pntw->global_ice_map[i].policy == PNTW_ICE_ALLOC_POLICY_BO)
			pbo_req++;
	}

	pntw->org_pbo_req = (pbo_req / 2);
	pntw->org_dice_req = (pntw->num_ice - pbo_req);

	do {
		j = 0;
		for (i = 0; i < curr->jg_list->submitted_jobs_nr; i++) {
			job = &curr->jg_list->job_list[i];

			if (job->graph_ice_id < NUM_ICE_UNIT)
				continue;

			for (; j < MAX_CVE_DEVICES_NR;)  {
				if ((pntw->global_ice_map[j].policy ==
					PNTW_ICE_ALLOC_POLICY_BO) ||
					(pntw->global_ice_map[j].policy ==
					 PNTW_ICE_ALLOC_POLICY_DONT_CARE)) {
					j++;
					continue;
				}
				job->dummy_ice_id = j;
				pntw->global_ice_map[j].policy =
						PNTW_ICE_ALLOC_POLICY_ANYTHING;
				j++;
				break;
			}
		}

		cve_os_log(CVE_LOGLEVEL_DEBUG,
				"PNTW:0x%llx NTW:0x%llx Jobs:%d Mapped\n",
				pntw->pntw_id, curr->network_id,
				curr->jg_list->submitted_jobs_nr);

		curr = cve_dle_next(curr, list);
	} while (curr != head);

exit:
	return;

}

static int __map_dev_to_jobs(struct ice_pnetwork *pntw)
{
	u32 i;
	struct cve_device *dev;
	int retval = 0;
	struct job_descriptor *job;
	struct ice_network *ntw = NULL;

	ntw = pntw->curr_ntw;
	ASSERT(ntw);

	for (i = 0; i < ntw->jg_list->total_jobs; i++) {
		job = &ntw->jg_list->job_list[i];
		/* At this point it is guaranteed that device will be found */
		dev = cve_device_get(job->hw_ice_id);
		if (!dev) {
			cve_os_log(CVE_LOGLEVEL_ERROR, "dev is NULL\n");
			ASSERT(false);
		}
		dev->dev_ntw_id = ntw->network_id;
		dev->hswc_infer = ntw->dev_hswc[i];
		ice_swc_counter_set(dev->hswc_infer,
				ICEDRV_SWC_INFER_DEVICE_COUNTER_ID,
				dev->dev_index);
	}

	return retval;
}
