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

#ifdef RING3_VALIDATION
#include <string.h>
#include <icedrv_sw_trace_stub.h>
#else
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/completion.h>
#include <linux/preempt.h>
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


/* max number of Shared_Read requests from the leader, that */
/* were not yet matched by the follower. */
#define MAX_SHARED_DISTANCE 0x40

#define __local_builtin_popcount(y, ctr) \
do { \
	u32 pos = 0, x = y; \
	ctr = 0; \
	while (x) {\
		pos = __builtin_ctz(x); \
		x = (x >> (pos + 1)); \
		ctr++; \
	}; \
} while (0)

/*Calculate average ice cycles */
#define __calc_ice_average_cycle(average_ice_cycles, total_time) \
do { \
	uint8_t idx = 0, ice_cnt = 0; \
	u64 sum = 0; \
	\
	average_ice_cycles = 0; \
	for (; idx < MAX_CVE_DEVICES_NR; idx++) { \
		if (total_time[idx]) { \
			sum += total_time[idx]; \
			ice_cnt++; \
		} \
		if (ice_cnt) \
			average_ice_cycles = (sum/ice_cnt); \
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
	u32 sz,
	void **kernel_copy);

static int __do_network_cleanup(struct cve_workqueue *wq);
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
static int __ntw_reserve_ice(struct ice_network *ntw);
static void __ntw_release_ice(struct ice_network *ntw);
static int __ntw_reserve_cntr(struct ice_network *ntw);
static void __ntw_release_cntr(struct ice_network *ntw);
static void __ntw_reset_cntr(struct ice_network *ntw);
static int __ntw_reserve_clos(struct ice_network *ntw);
static void __flush_ntw_buffers(struct ice_network *ntw);
static void __flush_inf_buffers(struct ice_infer *inf);
static void __destroy_infer_desc(struct ice_infer *inf);

#if 0
/*Not required as soc arch ensures cache coherency*/
static void __flush_inf_cbs(struct ice_infer *inf);
#endif

static int __alloc_and_copy(void *base_address,
	u32 sz,
	void **kernel_copy)
{
	int ret = 0;

	if (sz == 0)
		goto out;

	ret = OS_ALLOC_ZERO(sz, (void **)kernel_copy);
	if (ret < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"Allocation failed:%d SZ:%d\n", ret, sz);
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

static void __reset_infer_event(struct cve_completion_event *event)
{
	event->infer_id = 0;
	event->ntw_id = 0;
	event->jobs_group_status = CVE_JOBSGROUPSTATUS_PENDING;
	event->user_data = 0;
	event->icedc_err_status = 0;
	event->ice_err_status = 0;
	event->shared_read_err_status = 0;
	memset(event->total_time, 0,
			sizeof(event->total_time[0]) * MAX_CVE_DEVICES_NR);
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
	*icedc_err_status = 0;
	*ice_err_status = 0;
	*shared_read_err_status = event->shared_read_err_status;
	reg.val = event->icedc_err_status;
	if (reg.field.illegal_access)
		*icedc_err_status |= ILLEGAL_ACCESS;
	if (reg.field.ice_read_err)
		*icedc_err_status |= ICE_READ_ERR;
	if (reg.field.ice_write_err)
		*icedc_err_status |= ICE_WRITE_ERR;
	if (reg.field.asf_ice1_err)
		*icedc_err_status |= ASF_ICE1_ERR;
	if (reg.field.asf_ice0_err)
		*icedc_err_status |= ASF_ICE0_ERR;
	if (reg.field.cntr_err)
		*icedc_err_status |= CNTR_ERR;
	if (reg.field.sem_err)
		*icedc_err_status |= SEM_ERR;
	if (reg.field.attn_err)
		*icedc_err_status |= ATTN_ERR;
	if (reg.field.cntr_oflow_err)
		*icedc_err_status |= CNTR_OFLOW_ERR;

	for (i = 0; i < MAX_CVE_DEVICES_NR; i++)
		total_time[i] = event->total_time[i];

	cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Received completion event for InferID=%llx\n",
			event->infer_id);
	ice_err = event->ice_err_status;

	if (is_tlc_error(ice_err))
		*ice_err_status |= TLC_ERR;
	if (is_mmu_error(ice_err))
		*ice_err_status |= MMU_ERR;
	if (is_page_fault_error(ice_err))
		*ice_err_status |= PAGE_FAULT;
	if (is_bus_error(ice_err))
		*ice_err_status |= BUS_ERR;
	if (is_butress_error(ice_err))
		*ice_err_status |= BTRS_WD;
	if (is_wd_error(ice_err))
		*ice_err_status |= INTERNAL_WD;
	if (is_tlc_panic(ice_err))
		*ice_err_status |= TLC_PANIC;
	if (is_dsram_single_err(ice_err))
		*ice_err_status |= DSRAM_SINGLE_ERR;
	if (is_dsram_double_err(ice_err))
		*ice_err_status |= DSRAM_DOUBLE_ERR;
	if (is_sram_parity_err(ice_err))
		*ice_err_status |= SRAM_PARITY_ERR;
	if (is_dsram_unmapped_addr(ice_err))
		*ice_err_status |= DSRAM_UNMAPPED_ADDR;
	if (ice_err & ICE_READY_BIT_ERR)
		*ice_err_status |= ICE_READY_BIT_ERR;

	ntw = (struct ice_network *)event->ntw_id;
	ctx = ntw->wq->context;

	inf = cve_dle_lookup(ntw->inf_list, ntw_list,
				infer_id, event->infer_id);

	/* remove it from the sub/infer list and add it to main list */
	cve_dle_remove_from_list
		(process->alloc_events, sub_list, event);
	cve_dle_remove_from_list
		(inf->infer_events, infer_list, event);
	cve_dle_add_to_list_before(process->events, main_list, event);

	DO_TRACE(trace_icedrvEventGeneration(SPH_TRACE_OP_STATE_COMPLETE,
					ctx->swc_node.sw_id,
					ntw->swc_node.parent_sw_id,
					ntw->swc_node.sw_id,
					ntw->network_id,
					inf->swc_node.sw_id,
					SPH_TRACE_OP_STATUS_PASS, 0));

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
	ret = __do_network_cleanup(workqueue);
	if (ret < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"ERROR:%d WQ:%p network cleanup failed\n",
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

/*
 * reset the CVE device..
 * return :
 */
static void do_reset(struct cve_device *cve_dev,
		os_domain_handle hdom,
		struct ice_network *ntw,
		enum reset_type_flag reset_type)
{
	cve_dev_context_handle_t dev_handle = NULL;
	u32 page_dir_base_addr;
	u32 *page_sz_list;

	cve_dev_context_get_by_cve_idx(
		ntw->dev_hctx_list,
		cve_dev->dev_index,
		&dev_handle);

	ASSERT(dev_handle);

	ice_di_mmu_block_entrance(cve_dev);

	/* do device reset */
	cve_di_reset_device(cve_dev);

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

	/* configure CBB to ATU mapping to ensure all use a dedicated ATU
	 * Done only if network requests shared read else default address
	 * based ATU mapping is used
	 */
	if (ntw->shared_read)
		ice_di_configure_atu_cbb_mapping(cve_dev);

	/* reset the page table flags state */
	cve_mm_reset_page_table_flags(hdom);

	/* Commented cve_di_set_hw_counters as it is setting the activate
	 * performance counters bit in MMU CONFIG ,which is now being done
	 * through PMON configuration .
	 */
	/* Enable/Disable HW counters */
	/*cve_di_set_hw_counters(cve_dev);*/

	/* reset dump register */
	cve_di_reset_cve_dump(cve_dev, cfg_default.ice_dump_on_error,
					cve_dev->cve_dump_buf);

	/* If (block_mmu) => Unblock it just before the Doorbell
	 * Else => Unblock here, in reset flow
	 */
	if (!block_mmu)
		ice_di_mmu_unblock_entrance(cve_dev);

	/* complete the reset flow and run the device cores */
	cve_di_start_running(cve_dev);
	/* Set fifo size and address*/
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
	u32 sz, core_blob_sz =
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
	struct cve_device *dev, *dev_head, *dev_tail;
	cve_dev_context_handle_t dev_handle = NULL;
	struct ds_context *context = network->wq->context;
	struct cve_device_group *cve_dg = g_cve_dev_group_list;

	/* Only 1 DG exist in new Driver. So not looping on it. */
	for (i = 0; i < MAX_NUM_ICEBO; i++) {
		dev_head = cve_dg->dev_info.icebo_list[i].dev_list;
		dev = dev_head;
		if (!dev_head)
			continue;
		do {
			cve_dev_context_get_by_cve_idx(
			network->dev_hctx_list, dev->dev_index, &dev_handle);

			cve_os_log(CVE_LOGLEVEL_DEBUG,
				COLOR_YELLOW(
					"Creating CBDT buffer for ICE-%d. CBDT_Entries=%u\n"
					),
				dev->dev_index, network->max_cbdt_entries + 1);

			retval = cve_dev_alloc_and_map_cbdt(dev_handle,
				&network->fifo_desc[dev->dev_index],
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

			dev = cve_dle_next(dev, bo_list);
		} while (dev != dev_head);
	}

	return 0;
out:
	/*TODO: check the logic of failure case */
	dev_tail = dev;
	for (; i >= 0; i--) {
		dev_head = cve_dg->dev_info.icebo_list[i].dev_list;
		dev = dev_head;
		while ((dev != dev_tail) && (dev != dev_head)) {

			cve_dev_context_get_by_cve_idx(
				network->dev_hctx_list,
				dev->dev_index, &dev_handle);

			cve_os_log(CVE_LOGLEVEL_DEBUG,
				COLOR_YELLOW(
					"Destroying CBDT buffer for ICE-%d. CBDT_Entries=%u\n"
					),
				dev->dev_index, network->max_cbdt_entries + 1);

			cve_dev_dealloc_and_unmap_cbdt(dev_handle,
				&network->fifo_desc[dev->dev_index]);

			dev = cve_dle_next(dev, bo_list);
		}
	}

	return retval;
}

static int dealloc_and_unmap_network_fifo(struct ice_network *network)
{
	struct cve_device *dev, *dev_head;
	cve_dev_context_handle_t dev_handle = NULL;
	struct cve_device_group *cve_dg = g_cve_dev_group_list;
	int i;

	/* Only 1 DG exist in new Driver. So not looping on it. */
	for (i = 0; i < MAX_NUM_ICEBO; i++) {
		dev_head = cve_dg->dev_info.icebo_list[i].dev_list;
		dev = dev_head;
		if (!dev_head)
			continue;
		do {
			cve_dev_context_get_by_cve_idx(
				network->dev_hctx_list,
				dev->dev_index,
				&dev_handle);

			cve_os_log(CVE_LOGLEVEL_DEBUG,
				COLOR_YELLOW(
					"Destroying CBDT buffer for ICE-%d. CBDT_Entries=%u\n"
					),
				dev->dev_index, network->max_cbdt_entries + 1);

			cve_dev_dealloc_and_unmap_cbdt(dev_handle,
				&network->fifo_desc[dev->dev_index]);

			dev = cve_dle_next(dev, bo_list);
		} while (dev != dev_head);
	}

	return 0;
}

static struct cve_device *
find_idle_device_for_next_job(
		struct cve_device_group *dg,
		struct jobgroup_descriptor *jobgroup)
{
	struct ice_network *ntw;
	struct job_descriptor *job;
	struct cve_device *cve_dev = NULL;
	struct cve_device *head, *next;
	int is_complete_bo_required = 0, bo_id = 0;
	int  temp, ice_id = NUM_ICE_UNIT;

	ntw = jobgroup->network;
	job = jobgroup->next_dispatch;

	if (job->hw_ice_id < NUM_ICE_UNIT) {

		cve_dev = cve_device_get(job->hw_ice_id);
		goto out;
	}

	/* If persistent Job and mapping exist then
	 * pick that particular ICE else select new
	 */
	if ((job->graph_ice_id < NUM_ICE_UNIT) &&
		(ntw->pjob_info.ice_id_map[job->graph_ice_id] < NUM_ICE_UNIT)) {

		cve_dev = cve_device_get(
				ntw->pjob_info.ice_id_map[job->graph_ice_id]);

		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"ICE_SwID:%u already Mapped to ICE_HwID:%u. NtwID:0x%llx\n",
			job->graph_ice_id, cve_dev->dev_index, ntw->network_id);

		/* If this device is busy => do not schedule */
		if (cve_dev->state == CVE_DEVICE_BUSY) {
			/* PJob = Persistent Job */
			cve_os_log(CVE_LOGLEVEL_DEBUG,
				"but Device is Busy.\n");
			cve_dev = NULL;
		}

		goto out;
	}
	if (job->graph_ice_id < NUM_ICE_UNIT)
		bo_id = job->graph_ice_id / 2;
	if ((job->graph_ice_id < NUM_ICE_UNIT) &&
		(ntw->icebo_req == ICEBO_MANDATORY) &&
		ntw->pjob_info.num_pjob[2 * bo_id] &&
		ntw->pjob_info.num_pjob[2 * bo_id + 1]) {
		/* If here then complete ICEBOn is required based on current
		 * jobs graph_ice_id hence if any one of the graph_ice_id is
		 * already mapped to driver_ice_id then pick from same ICEBO
		 */
		is_complete_bo_required = 1;
		if (ntw->pjob_info.ice_id_map[2 * bo_id] < NUM_ICE_UNIT) {
			temp = ntw->pjob_info.ice_id_map[2 * bo_id];
			ice_id = (temp % 2 == 1) ? (temp - 1) : (temp + 1);
			cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Picking ICE_HwID:%u for ICE_SwID:%u because ICE_SwID:%u already Mapped to ICE_HwID:%u. NtwID:0x%llx\n",
			ice_id, job->graph_ice_id, 2 * bo_id, temp,
			ntw->network_id);
		} else if (ntw->pjob_info.ice_id_map[2 * bo_id + 1] <
			NUM_ICE_UNIT) {
			temp = ntw->pjob_info.ice_id_map[2 * bo_id + 1];
			ice_id = (temp % 2 == 1) ? (temp - 1) : (temp + 1);
			cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Picking ICE_HwID:%u for ICE_SwID:%u because ICE_SwID:%u already Mapped to ICE_HwID:%u. NtwID:0x%llx\n",
			ice_id, job->graph_ice_id, 2 * bo_id + 1, temp,
			ntw->network_id);
		}
		if (ice_id < NUM_ICE_UNIT) {
			cve_dev = cve_device_get(ice_id);
			if (cve_dev->state == CVE_DEVICE_BUSY) {
				cve_os_log(CVE_LOGLEVEL_DEBUG,
					"but Device is Busy.\n");
				cve_dev = NULL;
			}
			goto out;
		}
	}


	head = ntw->ice_list;
	next = head;
	do {
		if (next->state == CVE_DEVICE_IDLE) {
			if ((ntw->icebo_req == ICEBO_MANDATORY) &&
			(is_complete_bo_required == 1) &&
		(ntw->pjob_info.picebo[next->dev_index / 2] == 1)) {
				cve_dev = next;
				goto out;
			} else if ((ntw->icebo_req == ICEBO_MANDATORY)
			&& (is_complete_bo_required == 0) &&
			ntw->pjob_info.sicebo[next->dev_index / 2] ==
			next->dev_index) {
				cve_dev = next;
				goto out;
			} else if (ntw->icebo_req != ICEBO_MANDATORY) {
				cve_dev = next;
				goto out;
			}
		}
		next = cve_dle_next(next, owner_list);
	} while (head != next);

out:

	ASSERT(cve_dev);
	job->hw_ice_id = cve_dev->dev_index;

	return cve_dev;
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
	int ret = 0;

	DO_TRACE(trace_icedrvScheduleJob(
		SPH_TRACE_OP_STATE_QUEUED,
		cve_dev->dev_index,
		next_ctx->swc_node.sw_id,
		ntw->swc_node.parent_sw_id,
		ntw->swc_node.sw_id,
		ntw->network_id,
		ntw->curr_exe->swc_node.sw_id,
		job, SPH_TRACE_OP_STATUS_CDYN_VAL,
		cve_di_get_cdyn_val(job->di_hjob)));

	ret = set_idc_registers(cve_dev, true);
	if (ret < 0) {
		cve_os_dev_log_default(CVE_LOGLEVEL_ERROR,
			cve_dev->dev_index,
			"ERROR:%d DEV:%p JG:%p ICE configuration failed\n",
			ret, cve_dev, jobgroup);

		if (ret == -ICEDRV_KERROR_ICE_DOWN)
			ntw->ice_err_status |= ICE_READY_BIT_ERR;

		return ret;
	}


	if (ntw->ice_dump &&
	(ntw->ice_dump->allocated_buf_cnt < ntw->ice_dump->total_dump_buf)) {
		cve_dev->cve_dump_buf =
		ntw->ice_dump->ice_dump_buf[ntw->ice_dump->allocated_buf_cnt];
		ntw->ice_dump->allocated_buf_cnt++;
	}

	ice_mm_get_domain_by_cve_idx(inf->inf_hdom,
		g_cve_dev_group_list->dev_info.active_device_nr,
		cve_dev,
		&hdom);

	/* Mark the device as busy */
	cve_dev->state = CVE_DEVICE_BUSY;

	/* do reset if needed */
	if (cve_di_get_device_reset_flag(cve_dev)) {
		cve_os_dev_log(CVE_LOGLEVEL_DEBUG,
				cve_dev->dev_index,
				"Performing Hard Reset\n");

		ice_di_set_cold_run(job->di_hjob);

		/* if driver has respected the request then set the shared
		 * read mmio else disable it
		 */
		if (ntw->icebo_req == ICEBO_MANDATORY)
			ice_di_set_shared_read_reg(cve_dev, ntw, 1);
		else
			ice_di_set_shared_read_reg(cve_dev, ntw, 0);

		do_reset(cve_dev, hdom, ntw, RESET_TYPE_HARD);

		cve_dev_context_get_by_cve_idx(
			ntw->dev_hctx_list, cve_dev->dev_index, &dev_next_ctx);

		cve_dev_get_emb_cb_list(
			dev_next_ctx,
			&embedded_cbs_subjobs);
	} else {
		cve_os_dev_log(CVE_LOGLEVEL_DEBUG,
				cve_dev->dev_index,
				"No Reset\n");
		if (cve_dev->daemon.restore_needed_from_suspend)
			ice_trace_restore_daemon_config(cve_dev, true);

		/* invalidate the page table if needed */
		cve_mm_invalidate_tlb(hdom, cve_dev);
	}

	/* Device FIFO pointer will now point to Network's ICE specific FIFO */
	cve_dev->fifo_desc = &jobgroup->network->fifo_desc[cve_dev->dev_index];

#ifdef _DEBUG
	print_cur_page_table(hdom);
#endif

	cve_os_dev_log(CVE_LOGLEVEL_DEBUG,
			cve_dev->dev_index,
			"Ctx-ID:0x%llx, NtwID:0x%llx Job:%p\n",
			next_ctx->context_id,
			jobgroup->id,
			job);

	/* dispatch the current job */
	cve_di_dispatch_job(cve_dev, job->di_hjob, embedded_cbs_subjobs);

	/* increment the next dispatch pointer */
	jobgroup->next_dispatch =
			cve_dle_next(jobgroup->next_dispatch,
					list);

	return ret;
}

int ice_ds_dispatch_jg(struct jobgroup_descriptor *jobgroup)
{
	u32 i, ice_mask = 0;
	struct cve_device *dev;
	int retval = 0;
	struct cve_device_group *dg = cve_dg_get();
	struct ice_network *ntw = jobgroup->network;
	struct job_descriptor *job;

	if (!ice_sch_preemption())
		os_disable_preemption();

	DO_TRACE(trace__icedrvScheduleInfer(
		SPH_TRACE_OP_STATE_QUEUED,
		ntw->wq->context->swc_node.sw_id,
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
	ntw->ntw_running = true;
	ntw->curr_exe->inf_running = true;

	if (dg->num_running_ntw == 1) {
		/* If this is the only Ntw running then respect the
		 * CLOS requirement
		 */

		cve_os_log(CVE_LOGLEVEL_INFO,
			"Allocate CLOS for NtwId=0x%lx\n", (uintptr_t)ntw);
		__ntw_reserve_clos(ntw);
		ice_os_set_clos((void *)&dg->dg_clos_manager);

	} else if (dg->num_running_ntw == 2) {

		cve_os_log(CVE_LOGLEVEL_INFO,
			"Reset CLOS\n");
		/* Reset CLOS MSR registers */
		ice_os_reset_clos((void *)&dg->dg_clos_manager);
	}

	for (i = 0; i < jobgroup->submitted_jobs_nr; i++) {

		job = jobgroup->next_dispatch;

		/* If next Job is persistent then scheduler should pick
		 * the ICE with proper graph_ice_id
		 */
		dev = find_idle_device_for_next_job(dg, jobgroup);
		/* At this point it is guaranteed that device will be found */

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

exit:
	DO_TRACE(trace__icedrvScheduleInfer(
		SPH_TRACE_OP_STATE_START,
		ntw->wq->context->swc_node.sw_id,
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
}

int ice_ds_raise_event(struct ice_network *ntw, bool reschedule)
{
	struct jobgroup_descriptor *cur_jg;
	u32 abort;
	struct cve_workqueue *wq;
	struct ds_context *context;
	struct ice_infer *inf = ntw->curr_exe;
	struct cve_completion_event event, *event_ptr;
	u64 average_ice_cycles;

	declare_u8_var(trace_status);

	wq = ntw->wq;
	context = wq->context;

	cur_jg = ntw->jg_list;

	/*Calculate average ice cycles */
	__calc_ice_average_cycle(average_ice_cycles, ntw->ntw_exec_time);

	if (cur_jg->aborted_jobs_nr > 0) {
		abort = CVE_JOBSGROUPSTATUS_ABORTED;
		trace_status = SPH_TRACE_OP_STATUS_FAIL;
		average_ice_cycles = abort;
	} else {
		abort = CVE_JOBSGROUPSTATUS_COMPLETED;
		trace_status = SPH_TRACE_OP_STATUS_AVG;
	}

	DO_TRACE(trace_icedrvExecuteNetwork(
				SPH_TRACE_OP_STATE_COMPLETE,
				ntw->wq->context->swc_node.sw_id,
				ntw->swc_node.parent_sw_id,
				ntw->swc_node.sw_id, ntw->network_id,
				inf->swc_node.sw_id,
				trace_status, average_ice_cycles));

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
		memcpy(event.total_time, ntw->ntw_exec_time,
			MAX_CVE_DEVICES_NR * sizeof(event.total_time[0]));
		event.average_ice_cycles = average_ice_cycles;
	}

	/* reset execution time before scheduling another inference */
	memset(ntw->ntw_exec_time, 0,
			MAX_CVE_DEVICES_NR * sizeof(ntw->ntw_exec_time[0]));

	/* Reset counters before scheduling */
	__ntw_reset_cntr(ntw);

	if (reschedule)
		ice_sch_engine(ntw);

	if (ntw->produce_completion) {


		if (context->process->events) {
			event_ptr = context->process->events;
			cve_dle_remove_from_list(context->process->events,
				main_list, event_ptr);
		} else
			OS_ALLOC_ZERO(sizeof(struct cve_completion_event),
				(void **)&event_ptr);

		*event_ptr = event;


		/* add to the end of events list */
		cve_dle_add_to_list_before(context->process->alloc_events,
				sub_list, event_ptr);
		cve_dle_add_to_list_before(inf->infer_events,
				infer_list, event_ptr);

		cve_os_log(CVE_LOGLEVEL_INFO,
			"Generating completion event(%p) for NtwID:0x%llx InferID:%llx. Status:%s\n",
			event_ptr,
			ntw->network_id, inf->infer_id,
			get_cve_jobs_group_status_str(abort));

		/* wake up anyone who waits for completion event */
		cve_os_wakeup(&wq->context->process->events_wait_queue);
		cve_os_wakeup(&inf->events_wait_queue);

		DO_TRACE(trace_icedrvEventGeneration(SPH_TRACE_OP_STATE_ADD,
					ntw->wq->context->swc_node.sw_id,
					ntw->swc_node.parent_sw_id,
					ntw->swc_node.sw_id, ntw->network_id,
					inf->swc_node.sw_id,
					SPH_TRACE_OP_STATUS_AVG,
					event.average_ice_cycles));
	}
	return 0;
}

static struct ice_network *__get_network_from_id(
		cve_context_process_id_t context_pid,
		cve_context_id_t context_id,
		u64 ntw_id)
{
	int retval = CVE_DEFAULT_ERROR_CODE;
	struct cve_workqueue *wq = NULL;
	struct ice_network *ntw = NULL;

	retval = __get_wq_from_contex_pid(context_pid, context_id, &wq);
	if (!wq || (retval != 0)) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"ERROR:%d CtxPid:%llu CtxId:%llu get_wq_from_contex_pid() failed\n",
				retval, context_pid, context_id);
		goto out;
	}

	ntw = cve_dle_lookup(wq->ntw_list, list, network_id, ntw_id);
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


static int __check_resources(struct cve_workqueue *workqueue,
		struct ice_network *network)
{
	int retval = 0;
	u32 num_ice = 0, llc_size = 0, i;

	/* TODO: Check if this makes sense */
	if (num_ice > workqueue->dg->dev_info.active_device_nr) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"failed since requested ice %d is larger than max ice %d\n",
			num_ice, workqueue->dg->dev_info.active_device_nr);
		retval = -ICEDRV_KERROR_NTW_INVAL_RESOURCE_REQ;
		goto out;
	}

	for (i = 0; i < ICE_CLOS_MAX; i++)
		llc_size += network->clos[i];

	/* TODO: Check if this makes sense */
	if (llc_size > workqueue->dg->dg_clos_manager.size) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"failed since requested llc_size %d is larger than max llc sz:%d\n",
			llc_size, workqueue->dg->dg_clos_manager.size);
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
	u32 i = 0, cb_idx = 0, sz = 0, *cb_desc_index_arr;

	*p_cb_desc = NULL;

	/* TODO HACK: allocate memory for CB(legacy)*/
	sz = (sizeof(*cb_desc) * (job_desc->cb_nr));
	ret = OS_ALLOC_ZERO(sz, (void **)&cb_desc);
	if (ret < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"Allocation failed(%d) for CB descriptor SZ:%d\n",
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
	u32 sz = 0;
	u32 *k_cb_desc_index_list, *u_cb_desc_index_list;
	struct ice_network *ntw;
	struct jobgroup_descriptor *jg;
	struct ds_context *context = NULL;
	struct cve_workqueue *wq = NULL;
	struct cve_command_buffer_descriptor *cb_desc = NULL;
	struct cve_patch_point_descriptor *k_pp_desc_list, *u_pp_desc_list;

	jg = cur_job->jobgroup;
	ntw = jg->network;
	wq = ntw->wq;
	context = wq->context;

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
		goto out;
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
	u32 i = 0, sz = 0;
	int ret = 0, max_cb = 0;
	struct cve_job *k_job_desc_list, *cur_job_desc;
	struct cve_job *u_jobs_desc_list = (struct cve_job *)(jg_desc->jobs);
	struct job_descriptor *job_list, *cur_job;
	struct ice_network *ntw = jg->network;

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

		if (cur_job_desc->graph_ice_id < 0)
			cur_job->graph_ice_id = INVALID_ICE_ID;
		else {
			cur_job->graph_ice_id = (u8)cur_job_desc->graph_ice_id;

			/* If here then this is a Persistent Job.
			 * So Job count for given ICE should be increased
			 */
			ntw->pjob_info.num_pjob[cur_job->graph_ice_id]++;
			cve_os_log(CVE_LOGLEVEL_DEBUG,
				"Inc PJob count (NtwID:0x%llx, GraphIceId:%d)\n",
				ntw->network_id, cur_job->graph_ice_id);
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
	jg->wq = ntw->wq;
	jg->network = ntw;
	jg->submitted_jobs_nr = jg_desc->jobs_nr;
	jg->total_jobs = jg_desc->jobs_nr;
	/* to be populated during schedule */
	jg->next_dispatch = NULL;
	jg->llc_size = jg_desc->LLC_size;
	jg->num_of_idc_cntr = jg_desc->num_of_idc_cntr;
	jg->produce_completion = jg_desc->produce_completion;
	jg->cntr_bitmap = 0;

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
	__destroy_jg(ntw, cur_jg);
	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"SUCCESS: NtwID:0x%llx JG:%p destroy_jg done\n",
		ntw->network_id, cur_jg);

	/* free the job group list*/
	OS_FREE(ntw->jg_list, sizeof(*cur_jg));
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

	/* If both the graph_ice_ids of an ICEBOn have atleast one job
	 * then increase num_picebo_req else increase num_sicebo_req
	 * TODO: check if increasing num_sicebo_req is valid
	 * i.e resource wastage is acceptable or not
	 */
	if (ntw->num_ice && (ntw->icebo_req != ICEBO_DEFAULT)) {
		for (i = 0; i < MAX_NUM_ICEBO; i++) {
			if ((ntw->pjob_info.num_pjob[2 * i]) &&
				(ntw->pjob_info.num_pjob[2 * i + 1]))
				ntw->num_picebo_req++;
			else if ((ntw->pjob_info.num_pjob[2 * i]) ||
				(ntw->pjob_info.num_pjob[2 * i + 1]))
				ntw->num_sicebo_req++;
		}
	} else if (ntw->num_ice && (ntw->icebo_req == ICEBO_DEFAULT)) {
		ntw->num_picebo_req = ntw->num_ice / 2;
		ntw->num_dicebo_req = ntw->num_ice % 2;
	}
	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"ICE requirement: picebo=%d sicebo=%d dicebo=%d\n",
		ntw->num_picebo_req, ntw->num_sicebo_req,
		ntw->num_dicebo_req);
	goto out;

error_process_jg:
	OS_FREE(jg_list, sizeof(*jg_list));
out:
	return ret;
}

static int __destroy_buf(struct ice_network *ntw,
	struct cve_ntw_buffer *buf)
{
	int ret = 0;
	struct ds_context *context = NULL;
	struct cve_workqueue *wq = NULL;
	cve_context_id_t dummy_context_id = 0;

	wq = ntw->wq;
	context = wq->context;

	ret = cve_mm_unmap_kva(buf->ntw_buf_alloc);
	if (ret < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"cve_mm_unmap_kva failed %d\n", ret);
	}

	cve_mm_destroy_buffer(dummy_context_id, buf->ntw_buf_alloc);

	/* remove the buffer from the list in the context */
	cve_dle_remove_from_list(context->buf_list, list, buf);

	cve_os_log(CVE_LOGLEVEL_DEBUG, "Buffer destroyed bufferid =>%lld\n",
		buf->buffer_id);

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

	wq = ntw->wq;
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

	cve_dev_get_os_domain_arr(ntw->dev_hctx_list,
		g_cve_dev_group_list->dev_info.active_device_nr,
		cve_os_hdomain);

	/* initialize the buffer's object attributes */
	buf->buffer_id = (uintptr_t)buf;
	buf->surface_type = buf_desc->surface_type;

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

	ret = cve_mm_create_buffer(cve_os_hdomain,
			g_cve_dev_group_list->dev_info.active_device_nr,
			buf_desc, &buf->ntw_buf_alloc);
	if (ret < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"cve_mm_create_buffer failed %d\n", ret);
		goto out;
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
	int ret = 0;

	for (; idx < buf_count; idx++) {
		cur_buf = &buf_list[idx];
		ret = __destroy_buf(ntw, cur_buf);
	}

	if (infer_idx_list) {
		sz = (sizeof(*infer_idx_list) * ntw->infer_buf_count);
		OS_FREE(infer_idx_list, sz);
	}

	sz = (sizeof(*buf_list) * buf_count);
	OS_FREE(buf_list, sz);

	return ret;
}

static int __process_buf_desc_list(struct ice_network *ntw,
	struct cve_surface_descriptor *buf_desc_list)
{
	struct cve_ntw_buffer *buf_list, *cur_buf;
	struct cve_surface_descriptor *cur_buf_desc;
	u64 *infer_idx_list;
	u32 sz = 0, idx = 0, inf_itr = 0;
	int ret = 0;

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

static int __process_inf_buf_desc_list(struct ice_infer *inf,
	struct cve_infer_surface_descriptor *buf_desc_list)
{
	int retval = 0;
	u32 sz = 0, idx, i;
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


		cur_buf->index_in_ntw = cur_buf_desc->index;
		cur_buf->base_address = cur_buf_desc->base_address;
		cur_buf->fd = cur_buf_desc->fd;

		retval = cve_mm_create_infer_buffer(inf->infer_id,
			inf->inf_hdom,
			g_cve_dev_group_list->dev_info.active_device_nr,
			ntw->buf_list[cur_buf->index_in_ntw].ntw_buf_alloc,
				cur_buf);
		if (retval < 0) {
			cve_os_log_default(CVE_LOGLEVEL_ERROR,
				"cve_mm_create_infer_buffer failed %d\n",
				retval);
			goto undo_loop;
		}

		cve_mm_set_dirty_cache(cur_buf->inf_buf_alloc);
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
	/* Remove this inference from Scheduler queue */
	if (inf->inf_sch_node.is_queued)
		ice_sch_del_inf_from_queue(inf);

	__move_completion_events_to_main_list(inf->process_pid, inf);

	__destroy_infer_desc(inf);

	ice_swc_destroy_infer_node(inf);

	cve_dle_remove_from_list(inf->ntw->inf_list, ntw_list, inf);
}

static int __destroy_pending_inference(struct ice_network *ntw)
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
				"NtwID:0x%llx Infer:0x%p Forced Cleanup\n",
				ntw->network_id, curr);

		__destroy_infer(curr);
		OS_FREE(curr, sizeof(*curr));

		curr = next;

	} while (!is_last);

exit:
	return 0;
}

static void __block_ice_if_on(struct ice_network *ntw)
{
	u32 i = 0; int ret = 0;
	struct cve_device *dev;
	struct job_descriptor *job;
	struct cve_device_group *dg = cve_dg_get();

	ret = cve_os_lock(&dg->poweroff_dev_list_lock, CVE_INTERRUPTIBLE);
	if (ret != 0) {
		cve_os_log_default(CVE_LOGLEVEL_ERROR,
				"Error:%d cve_os_lock error\n", ret);
		return;
	}

	/* Check if previous ICEs are still available */
	for (i = 0; i < ntw->jg_list->submitted_jobs_nr; i++) {
		job = &ntw->jg_list->job_list[i];

		/* ICE was never allocated to this network*/
		if (job->hw_ice_id == INVALID_ICE_ID)
			break;

		dev = cve_device_get(job->hw_ice_id);
		/* Block MMU if ICE is powered on and still not allocated to
		 * any other network
		 */
		if ((dev->dev_ntw_id == ntw->network_id) &&
			((dev->power_state == ICE_POWER_ON) ||
				(dev->power_state == ICE_POWER_OFF_INITIATED)))
			ice_di_mmu_block_entrance(dev);
	}

	cve_os_unlock(&dg->poweroff_dev_list_lock);

}

static int __destroy_network(struct ice_network *ntw)
{
	int ret = 0;

	ntw->ntw_running = false;
	cve_dle_remove_from_list(ntw->wq->ntw_list, list, ntw);

	__block_ice_if_on(ntw);
	__destroy_pending_inference(ntw);

	/* All resource must be released */
	if (ntw->res_resource)
		ice_ds_ntw_release_resource(ntw);
	else
		ice_ds_ntw_return_resource(ntw);

	dealloc_and_unmap_network_fifo(ntw);

	ret = __destroy_buf_list(ntw, ntw->buf_list, ntw->num_buf);
	if (ret < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"ERROR:%d NtwID:0x%llx destroy_buf_list() failed\n",
			ret, ntw->network_id);
		goto out;
	}

	if (ntw->ice_dump != NULL)
		__destroy_ice_dump_buffer(ntw);

	__destroy_jg_list(ntw);
	__destroy_pp_mirror_image(&ntw->ntw_surf_pp_list);
	cve_dev_close_all_contexts(ntw->dev_hctx_list);
	ice_swc_destroy_ntw_node(ntw);

out:
	return ret;
}

static void __update_ntw_sw_id(
		struct ice_network_descriptor *network_desc,
		struct ice_network *ntw)
{
	struct ice_swc_node *swc_node = &ntw->swc_node;

	if (network_desc->parent_obj_id < 0)
		swc_node->parent_sw_id = ntw->network_id;
	else
		swc_node->parent_sw_id = network_desc->parent_obj_id;

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
	u32 sz, i;
	int retval = 0;
	struct cve_device_group *dg = cve_dg_get();

	if (network_desc->num_ice > dg->dev_info.active_device_nr) {
		retval = -ICEDRV_KERROR_NTW_ICE_MAX;
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"Error(%d) Invalid ICE Request Available:%d Requested:%d\n",
				retval,
				dg->dev_info.active_device_nr,
				network_desc->num_ice);
		goto out;
	}
	if (network_desc->max_shared_distance > MAX_SHARED_DISTANCE) {
		retval = -ICEDRV_KERROR_INVAL_MAX_SHARED_DISTANCE;
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"Error(%d) Invalid Max shared distance Valid:%d Requested:%d\n",
			retval, MAX_SHARED_DISTANCE,
			network_desc->max_shared_distance);
		goto out;
	}

	ntw->produce_completion = network_desc->produce_completion;
	ntw->num_ice = network_desc->num_ice;
	ntw->has_resource = 0;
	ntw->cntr_bitmap = 0;
	ntw->ice_list = NULL;
	ntw->cntr_list = NULL;
	ntw->network_id = (u64)ntw;
	ntw->icebo_req = network_desc->icebo_req;
	ntw->num_picebo_req = 0;
	ntw->num_sicebo_req = 0;
	ntw->num_dicebo_req = 0;
	ntw->network_type = network_desc->network_type;
	ntw->shared_read = network_desc->shared_read;
	ntw->infer_buf_count = network_desc->infer_buf_count;
	ntw->ntw_surf_pp_count = 0;
	for (i = 0; i < MAX_CVE_DEVICES_NR; i++)
		ntw->ntw_exec_time[i] = 0;
	for (i = 0; i < ICE_CLOS_MAX; i++)
		ntw->clos[i] = network_desc->llc_size[i];

	/* if user has not provided max shared distance then store
	 * the default value
	 */
	ntw->max_shared_distance = (network_desc->max_shared_distance != 0) ?
		network_desc->max_shared_distance : DEFAULT_MAX_SHARED_DISTANCE;


	retval = cve_os_init_wait_que(&ntw->rr_wait_queue);
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"NtwID:0x%llx rr_wait_queue init failed  %d\n",
			ntw->network_id, retval);
		goto out;
	}

	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"Creating new Network. CtxID:%llu, NtwID:0x%llx\n",
		ntw->wq->context->context_id, ntw->network_id);

	/* Allocate memory and copy buffer descriptor list
	* from user space
	*/
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

	for (i = 0; i < NUM_ICE_UNIT; i++) {
		ntw->pjob_info.ice_id_map[i] = INVALID_ICE_ID;
		ntw->pjob_info.num_pjob[i] = 0;
	}
	for (i = 0; i < MAX_NUM_ICEBO; i++) {
		ntw->pjob_info.picebo[i] = INVALID_ENTRY;
		ntw->pjob_info.sicebo[i] = INVALID_ENTRY;
		ntw->pjob_info.dicebo[i] = INVALID_ENTRY;
	}
	for (i = 0; i < NUM_COUNTER_REG; i++)
		ntw->cntr_info.cntr_id_map[i] = INVALID_CTR_ID;

	retval = __process_jg_list(ntw, jg_desc_list);
	if (retval < 0) {
		cve_os_log_default(CVE_LOGLEVEL_ERROR,
			"__process_jg_list() %d\n",
			retval);
		goto error_jg_desc_process;
	}

	/* cache ICEBO params. Networks without reservation, release resource
	 * after no more inferences are queued. In case of preferred ICEBO
	 * policy, scheduler modifies the ICEBO requirement based on current
	 * free pool status. Cached values are used to restore the modified
	 * values for future inferences
	 */
	ntw->cached_num_picebo_req = ntw->num_picebo_req;
	ntw->cached_num_sicebo_req = ntw->num_sicebo_req;
	ntw->cached_num_dicebo_req = ntw->num_dicebo_req;
	ntw->cached_icebo_req = ntw->icebo_req;

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
	u32 sz;
	int retval = 0;
	struct ice_pp_value *pp_arr;

	if (inf->ntw->ntw_surf_pp_count != 0) {
		sz = (sizeof(*k_buf_desc_list) * inf_desc->num_buf_desc);
		retval = __alloc_and_copy(inf_desc->buf_desc_list,
				sz, (void **)&k_buf_desc_list);
		if (retval < 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
					"__alloc_and_copy() %d\n",
					retval);
			goto out;
		}
	}

	cve_dev_get_os_domain_arr(inf->ntw->dev_hctx_list,
		g_cve_dev_group_list->dev_info.active_device_nr,
		inf->inf_hdom);

	inf->user_data = inf_desc->user_data;

	/* If infer patch points are 0 , then bypass PT processing and
	 * patching
	 */
	if (inf->ntw->ntw_surf_pp_count != 0) {
		/* Configure number of infer buffer only if we process it */
		inf->num_buf = inf_desc->num_buf_desc;

		retval = OS_ALLOC_ZERO(
				sizeof(*pp_arr) * inf->ntw->ntw_surf_pp_count,
				(void **)&pp_arr);
		if (retval < 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
					"os_alloc_zero failed %d\n", retval);
			goto free_mem_1;
		}

		inf->inf_pp_arr = pp_arr;

		retval = __process_inf_buf_desc_list(inf, k_buf_desc_list);
		if (retval < 0) {
			cve_os_log_default(CVE_LOGLEVEL_ERROR,
					"__process_inf_buf_desc_list failed %d\n",
					retval);
			goto free_mem_2;
		}

		retval = ice_mm_process_inf_pp_arr(inf);
		if (retval < 0) {
			cve_os_log_default(CVE_LOGLEVEL_ERROR,
					"ice_mm_process_inf_pp_arr failed %d\n",
					retval);
			goto destroy_infer;
		}

		/* Flush the inference surfaces */
		__flush_inf_buffers(inf);
	}

	cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Inference processing completed. InfID=%llx, BufferCount=%d\n",
			inf->infer_id, inf->num_buf);

	if (inf->ntw->ntw_surf_pp_count != 0) {
		sz = (sizeof(*k_buf_desc_list) * inf_desc->num_buf_desc);
		OS_FREE(k_buf_desc_list, sz);
	}
	goto out;

destroy_infer:
	__destroy_infer_desc(inf);
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
		struct ice_network_descriptor *network_desc,
		u64 *network_id)
{
	int retval = CVE_DEFAULT_ERROR_CODE;
	struct ice_network *network;
	struct cve_workqueue *workqueue = NULL;
	struct cve_device_group *dg = cve_dg_get();
	struct cve_device *dev = ice_get_first_dev();
	u32 ntw_resources[6];

	ntw_resources[0] = network_desc->llc_size[ICE_CLOS_0];
	ntw_resources[1] = network_desc->llc_size[ICE_CLOS_1];
	ntw_resources[2] = network_desc->llc_size[ICE_CLOS_2];
	ntw_resources[3] = network_desc->llc_size[ICE_CLOS_3];
	ntw_resources[4] = network_desc->num_ice;
	ntw_resources[5] = 0;

	retval = cve_os_lock(&g_cve_driver_biglock, CVE_INTERRUPTIBLE);
	if (retval != 0) {
		retval = -ERESTARTSYS;
		goto out;
	}

	retval = __get_wq_from_contex_pid(context_pid, context_id, &workqueue);
	if (!workqueue) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"get_wq_from_contex_pid() failed %d\n", retval);
		goto out;
	}

	DO_TRACE(trace_icedrvCreateNetwork(
		SPH_TRACE_OP_STATE_START, workqueue->context->swc_node.sw_id,
		network_desc->parent_obj_id, network_desc->obj_id, 0,
		ntw_resources, SPH_TRACE_OP_STATUS_LOCATION, __LINE__));

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

	/* allocate structure for the network*/
	retval = OS_ALLOC_ZERO(sizeof(*network), (void **)&network);
	if (retval < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"Allocation failed %d\n", retval);
		goto out;
	}

	network->wq = workqueue;
	network->ntw_running = false;
	network->sch_queue[EXE_INF_PRIORITY_0] = NULL;
	network->sch_queue[EXE_INF_PRIORITY_1] = NULL;
	network->sch_queued_inf_count = 0;
	network->last_request_type = NODE_TYPE_RELEASE;
	network->ntw_res_node.ntw = network;
	network->ntw_res_node.ntype = NODE_TYPE_RESERVE;
	network->ntw_rel_node.ntw = network;
	network->ntw_rel_node.ntype = NODE_TYPE_RELEASE;
	network->rr_node = NULL;
	network->res_resource = false;

	retval = cve_dev_open_all_contexts(
			(u64 *)network_desc->va_partition_config,
			(u64 *)network_desc->infer_buf_page_config,
			&network->dev_hctx_list);
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"cve_dev_open_all_contexts failed %d\n", retval);
		goto error_domain_creation;
	}

	retval = __process_network_desc(network_desc, network);
	if (retval < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"__process_network_desc() failed:%d\n", retval);
		goto error_process_ntw;
	}


	retval = __check_resources(workqueue, network);
	if (retval < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"ERROR:%d __check_resources() failed\n",
				retval);
		goto error_resources;
	}

	/* Flush the network surfaces */
	__flush_ntw_buffers(network);

	/* add to the wq list */
	cve_dle_add_to_list_before(workqueue->ntw_list, list, network);
	/* return the job id to the user */
	*network_id = network->network_id;

	ice_swc_create_ntw_node(network);
	/* referencing JG list directly assuming that we have
	 * one job group always with multiple jobs <= max ice
	*/
	ice_swc_counter_set(network->hswc,
			ICEDRV_SWC_SUB_NETWORK_TOTAL_JOBS,
			network->jg_list->total_jobs);


	ntw_resources[0] = network->clos[ICE_CLOS_0];
	ntw_resources[1] = network->clos[ICE_CLOS_1];
	ntw_resources[2] = network->clos[ICE_CLOS_2];
	ntw_resources[3] = network->clos[ICE_CLOS_3];
	ntw_resources[4] = network->num_ice;
	__local_builtin_popcount(network->cntr_bitmap, ntw_resources[5]);

	DO_TRACE(trace_icedrvCreateNetwork(
		SPH_TRACE_OP_STATE_COMPLETE,
		workqueue->context->swc_node.sw_id,
		network->swc_node.parent_sw_id,
		network->swc_node.sw_id, network->network_id, ntw_resources,
		SPH_TRACE_OP_STATUS_PASS, retval));

	cve_os_unlock(&g_cve_driver_biglock);

	return retval;

error_resources:
	__destroy_network(network);
error_process_ntw:
	cve_dev_close_all_contexts(network->dev_hctx_list);
error_domain_creation:
	OS_FREE(network, sizeof(*network));
out:
	cve_os_unlock(&g_cve_driver_biglock);


	ntw_resources[0] = network_desc->llc_size[ICE_CLOS_0];
	ntw_resources[1] = network_desc->llc_size[ICE_CLOS_1];
	ntw_resources[2] = network_desc->llc_size[ICE_CLOS_2];
	ntw_resources[3] = network_desc->llc_size[ICE_CLOS_3];
	ntw_resources[4] = network_desc->num_ice;
	ntw_resources[5] = 0;

	DO_TRACE(trace_icedrvCreateNetwork(
			SPH_TRACE_OP_STATE_ABORT,
			context_id, network_desc->parent_obj_id,
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

	ctx_sw_id = ntw->wq->context->swc_node.sw_id;
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
	inf->inf_sch_node.ntype = NODE_TYPE_INFERENCE;
	inf->inf_sch_node.is_queued = false;
	__update_infer_sw_id(inf_desc, inf);

	retval = cve_os_init_wait_que(&inf->events_wait_queue);
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"events_wait_queue init failed  %d\n", retval);
		goto free_mem;
	}

	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"Processing CreateInfer. NtwID:0x%llx, InfID:%lx\n",
		ntw->network_id, (uintptr_t)inf);
	retval = __process_infer_desc(inf_desc, inf);
	if (retval < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"CreateInfer Failed:%d\n", retval);
		goto free_mem;
	}
	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"Completed CreateInfer. NtwID:0x%llx, InfID=%lx\n",
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

	if (inf->inf_running) {

		retval = -ICEDRV_KERROR_INF_EALREADY;
		goto out;
	}

	__destroy_infer(inf);
	OS_FREE(inf, sizeof(*inf));

out:
	cve_os_unlock(&g_cve_driver_biglock);

	return retval;
}

static void __get_resource_availability(struct resource_info *res)
{
	u32 i;
	struct cve_device_group *dg = cve_dg_get();
	u64 *pool_context_map = dg->pool_context_map;

	memset(res, 0, sizeof(struct resource_info));

	res->num_ice = (2 * dg->dev_info.num_avl_picebo) +
				dg->dev_info.num_avl_dicebo;

	res->num_cntr = dg->num_avl_cntr;

	for (i = 0; i < MAX_IDC_POOL_NR; i++)
		if (pool_context_map[i] == INVALID_CONTEXT_ID)
			res->num_pool++;

	for (i = 0; i < ICE_CLOS_MAX; i++)
		res->clos[i] = dg->dg_clos_manager.clos_size[i];
}

int cve_ds_handle_manage_resource(
		cve_context_process_id_t context_pid,
		cve_context_id_t context_id,
		cve_network_id_t ntw_id,
		struct ice_resource_request *rreq) {

	struct ice_network *ntw;
	struct resource_info res;
	bool is_success;
	int status;
	int retval = cve_os_lock(&g_cve_driver_biglock, CVE_INTERRUPTIBLE);

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
		goto unlock_out;
	}


	/* Place this request in queue and then wait for given timeout */
	if (rreq->is_reserve) {

		if (ntw->last_request_type == NODE_TYPE_RESERVE) {

			retval = -ICEDRV_KERROR_DUPLICATE_REQUEST;
			goto unlock_out;
		}

		ice_sch_add_rr_to_queue(&ntw->ntw_res_node);

		ntw->last_request_type = NODE_TYPE_RESERVE;
	} else {

		if (ntw->last_request_type == NODE_TYPE_RELEASE) {

			retval = -ICEDRV_KERROR_DUPLICATE_REQUEST;
			goto unlock_out;
		}

		ice_sch_add_rr_to_queue(&ntw->ntw_rel_node);

		ntw->last_request_type = NODE_TYPE_RELEASE;
	}

	if (rreq->is_reserve) {

		cve_os_unlock(&g_cve_driver_biglock);

		if (rreq->timeout < 0) {
			/* TODO: Wait for ptr and read status from there */
			status = cve_os_block_interruptible_infinite(
				&ntw->rr_wait_queue, ntw->rr_node);
		} else {
			status = cve_os_block_interruptible_timeout(
				&ntw->rr_wait_queue, ntw->rr_node,
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
		if (!ntw->rr_node)
			is_success = false;
		else
			is_success = ntw->rr_node->is_success;

		/*TODO*/
		ntw->rr_node = NULL;

		if (!is_success) {

			/* TODO: Add Ntw resource info [ICE-18719] */

			ntw->last_request_type = NODE_TYPE_RELEASE;

			retval = -ICEDRV_KERROR_RESERVATION_FAIL;
			__get_resource_availability(&res);

			rreq->num_ice = res.num_ice;
			rreq->num_cntr = res.num_cntr;
			rreq->num_pool = res.num_pool;
			memcpy(rreq->clos, res.clos,
				ICE_CLOS_MAX * sizeof(res.clos[0]));

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

	if (inf->inf_sch_node.is_queued || inf->inf_running) {
		retval = -ICEDRV_KERROR_INF_EALREADY;
		goto out;
	}

	/* Assigning order to ExecuteInfer. Lesser this value,
	 * higher is execution priority.
	 */
#ifdef _DEBUG
	inf->inf_exe_order = dg->dg_exe_order++;
#endif
	inf->inf_pr = data->priority;
	ntw->ntw_enable_bp = data->enable_bp;

	DO_TRACE(trace_icedrvExecuteNetwork(
				SPH_TRACE_OP_STATE_QUEUED,
				ntw->wq->context->swc_node.sw_id,
				ntw->swc_node.parent_sw_id,
				ntw->swc_node.sw_id, ntw->network_id,
				inf->swc_node.sw_id,
				SPH_TRACE_OP_STATUS_PRIORITY, inf->inf_pr));

	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"Processing ExecuteInfer. NtwID:0x%lx, InfID=0x%lx\n",
		(uintptr_t)ntw, (uintptr_t)inf);
	ice_sch_add_inf_to_queue(inf);

	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"Completed ExecuteInfer. NtwID:0x%lx, InfID=0x%lx\n",
		(uintptr_t)ntw, (uintptr_t)inf);

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

int cve_ds_handle_destroy_network(cve_context_process_id_t context_pid,
		cve_context_id_t context_id,
		cve_context_id_t ntw_id) {
	int retval = CVE_DEFAULT_ERROR_CODE;
	struct ice_network *ntw;
	uint64_t __maybe_unused sw_ctx_id = 0, sw_ntw_id = 0,
		 sw_sub_ntw_id = 0;

	DO_TRACE(trace_icedrvDestroyNetwork(
		SPH_TRACE_OP_STATE_REQ, context_id,
		0, 0, ntw_id,
		SPH_TRACE_OP_STATUS_LOCATION, __LINE__));

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

	sw_ctx_id = ntw->wq->context->swc_node.sw_id;
	sw_ntw_id = ntw->swc_node.parent_sw_id;
	sw_sub_ntw_id = ntw->swc_node.sw_id;

	DO_TRACE(trace_icedrvDestroyNetwork(
		SPH_TRACE_OP_STATE_START, sw_ctx_id, sw_ntw_id, sw_sub_ntw_id,
		ntw_id, SPH_TRACE_OP_STATUS_LOCATION, __LINE__));

	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"Deleting NtwID:0x%llx\n", ntw->network_id);

	retval = __destroy_network(ntw);
	if (retval < 0) {
		cve_os_log_default(CVE_LOGLEVEL_ERROR,
			"__destroy_network failed %d\n", retval);
		goto out;
	}

	OS_FREE(ntw, sizeof(*ntw));

	/* Since ICE have been released, check if any network can be scheduled
	 * from the queue.
	 */
	ice_sch_engine(NULL);

out:
	cve_os_unlock(&g_cve_driver_biglock);

#ifndef RING3_VALIDATION
	if (retval)
		DO_TRACE(trace_icedrvDestroyNetwork(
				SPH_TRACE_OP_STATE_ABORT,
				context_id, sw_ntw_id, sw_sub_ntw_id, ntw_id,
				SPH_TRACE_OP_STATUS_FAIL, retval));
	else
		DO_TRACE(trace_icedrvDestroyNetwork(
					SPH_TRACE_OP_STATE_COMPLETE,
					sw_ctx_id, sw_ntw_id, sw_sub_ntw_id,
					ntw_id, SPH_TRACE_OP_STATUS_PASS, 0));
#endif

	return retval;
}

static int __do_network_cleanup(struct cve_workqueue *wq)
{
	struct ice_network *head = wq->ntw_list;
	struct ice_network *curr = NULL;
	struct ice_network *next = NULL;
	int ret = 0;
	u32 is_last = 0;

	/* try to destroy all networks within this workqueue */
	if (head == NULL)
		goto exit;

	curr = head;
	do {
		next = cve_dle_next(curr, list);

		if (next == curr)
			is_last = 1;

		cve_os_log(CVE_LOGLEVEL_DEBUG,
				"WQ:%p Remove NtwID:0x%llx\n",
				wq, curr->network_id);

		/* destroy the network */
		__destroy_network(curr);
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
	struct jobgroup_descriptor *jobgroup;
	struct job_descriptor *job;
	struct ice_network *ntw;
	struct ice_infer *inf;
	struct cve_device_group *dg = cve_dg_get();

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
				ntw->wq->context->swc_node.sw_id,
				ntw->swc_node.parent_sw_id,
				ntw->swc_node.sw_id,
				ntw->network_id, inf->swc_node.sw_id, job,
				SPH_TRACE_OP_STATUS_PERF, exec_time));

	if (ntw->shared_read)
		is_shared_read_error(ntw, dev, dev->dev_index / 2);

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

	if (jobgroup->submitted_jobs_nr ==
			jobgroup->ended_jobs_nr) {

		cve_os_log(CVE_LOGLEVEL_DEBUG,
				"NtwID:0x%llx JG_ID=0x%lx Completed. Total_JG:%d\n",
				ntw->network_id,
				(uintptr_t)jobgroup,
				ntw->num_jg);

		DO_TRACE(trace__icedrvScheduleInfer(
					SPH_TRACE_OP_STATE_COMPLETE,
					ntw->wq->context->swc_node.sw_id,
					ntw->swc_node.parent_sw_id,
					ntw->swc_node.sw_id,
					ntw->network_id,
					ntw->curr_exe->swc_node.sw_id,
					SPH_TRACE_OP_STATUS_ICE,
					ntw->ntw_icemask));

		dg->num_running_ntw--;
		ntw->ntw_running = false;
		ntw->curr_exe->inf_running = false;

		ice_ds_raise_event(ntw, true);
	}
	cve_os_log(CVE_LOGLEVEL_INFO,
			"EXIT: NtwID:0x%llx JG_ID=0x%lx Completed. Total_JG:%d\n",
			ntw->network_id,
			(uintptr_t)jobgroup,
			ntw->num_jg);
}

int cve_ds_handle_fw_loading(
		cve_context_process_id_t context_pid,
		cve_context_id_t context_id,
		cve_network_id_t network_id,
		u64 fw_image,
		u64 fw_binmap,
		u32 fw_binmap_size_bytes)
{
	int retval = CVE_DEFAULT_ERROR_CODE;
	struct cve_device_group *dg = cve_dg_get();
	struct ice_network *network = NULL;

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

	network = __get_network_from_id(context_pid, context_id, network_id);
	if (network == NULL) {
		retval = -ICEDRV_KERROR_NTW_INVAL_ID;
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"ERROR:%d Given NtwID:0x%llx is not present in this context\n",
				retval, network_id);
		goto out;
	}

	/*
	 * TODO: This flow can be optimized. This function
	 * load the image and then map it to cve device.
	 * loading operation can be performed only once,
	 * map operation should be performed multiple times
	 * according to number of CVEs in the system
	 */
	retval = cve_dev_fw_load_and_map(network->dev_hctx_list,
			fw_image,
			fw_binmap,
			fw_binmap_size_bytes);

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
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"os_init_wait_que failed %d\n", retval);
		goto out;
	}

	/* get context id */
	new_context->context_id = get_contex_id();


	/* add the new context to the list */
	cve_dle_add_to_list_after(context_process->list_contexts,
			list,
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
	/* remove the context from the process list */
	cve_dle_remove_from_list(
			context_process->list_contexts,
			list,
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

	while (context_process->events) {
		struct cve_completion_event *event = context_process->events;

		cve_dle_remove_from_list(context_process->events,
			main_list, event);
		OS_FREE(event, sizeof(*event));
	}
	context_process->events = NULL;
	context_process->alloc_events = NULL;

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

static int __handle_infer_completion_via_ctx(
		cve_context_process_id_t context_pid,
		struct cve_context_process *context_process,
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
		goto out;
	} else if (retval == -ERESTARTSYS) {
		*wait_status = CVE_WAIT_EVENT_ERROR;
		goto out;
	} else {
		*wait_status = CVE_WAIT_EVENT_COMPLETE;
		retval = 0;
	}

	if (retval < 0)
		DO_TRACE(trace_icedrvEventGeneration(
					SPH_TRACE_OP_STATE_COMPLETE,
					event->contextid, 0, 0,
					event->networkid,
					event->infer_id,
					SPH_TRACE_OP_STATUS_FAIL, retval));

out:
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
	u32 __maybe_unused timeout_msec = event->timeout_msec;
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
	if (retval != 0)
		goto unlock;

	/* Get the context from the process */
	context = get_context_from_process(context_process, event->contextid);
	if (context)
		ctx_sw_id = context->swc_node.sw_id;

	/*in case debug enabled don't timeout (~1000hours)*/
	if (unlikely(cve_debug_get(DEBUG_TENS_EN)))
		timeout_msec = 0xFFFFFFFF;

	if (!event->infer_id) {
		DO_TRACE(trace_icedrvEventGeneration(SPH_TRACE_OP_STATE_START,
					ctx_sw_id, 0, 0, event->networkid, 0,
					SPH_TRACE_OP_STATUS_LOCATION,
					__LINE__));

		cve_os_unlock(&g_cve_driver_biglock);

		retval = __handle_infer_completion_via_ctx(context_pid,
				context_process, event);
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
					ntw->wq->context->swc_node.sw_id,
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
		cve_network_id_t ntw_id,
		struct cve_components_version *out_versions)
{
	struct cve_components_version versions;
	struct ice_network *network = NULL;
	struct cve_device_group *dg = cve_dg_get();

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

	network = __get_network_from_id(context_pid, context_id, ntw_id);
	if (network == NULL) {
		retval = -ICEDRV_KERROR_NTW_INVAL_ID;
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"ERROR:%d Given NtwID:0x%llx is not present in this context\n",
				retval, ntw_id);
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
	cve_dev_get_custom_fw_version_per_context(network->dev_hctx_list,
			CVE_FW_IVP_BANK0_TYPE,
			&versions.ivp_bank0_version);
	cve_dev_get_custom_fw_version_per_context(network->dev_hctx_list,
			CVE_FW_IVP_BANK1_TYPE,
			&versions.ivp_bank1_version);
	cve_dev_get_custom_fw_version_per_context(network->dev_hctx_list,
			CVE_FW_ASIP_BANK0_TYPE,
			&versions.asip_bank0_version);
	cve_dev_get_custom_fw_version_per_context(network->dev_hctx_list,
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

int cve_ds_get_metadata(u32 *icemask)
{
	int retval = cve_os_lock(&g_cve_driver_biglock, CVE_INTERRUPTIBLE);

	if (retval != 0) {
		retval = -ERESTARTSYS;
		goto out;
	}

	*icemask = g_icemask;

	cve_os_unlock(&g_cve_driver_biglock);
out:
	return retval;
}

static void __link_ices_and_pool(struct ice_network *ntw)
{
	int8_t pool_id;
	struct cve_device *head = ntw->ice_list;
	struct cve_device *next = ntw->ice_list;

	ASSERT(next);

	pool_id = ntw->wq->context->pool_id;

	do {
		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Linking ICE-%d to Pool=%d\n",
			next->dev_index, pool_id);
		cve_di_set_pool_registers(next, pool_id);

		next = cve_dle_next(next, owner_list);
	} while (next != head);
}

static void __delink_ices_and_pool(struct ice_network *ntw)
{

	struct cve_device *head = ntw->ice_list;
	struct cve_device *next = ntw->ice_list;

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

static void __link_counters_and_pool(struct ice_network *ntw)
{
	int8_t pool_id;
	struct cve_device *dev = get_first_device();
	struct cve_os_device *os_dev = to_cve_os_device(dev);
	struct cve_hw_cntr_descriptor *head = ntw->cntr_list;
	struct cve_hw_cntr_descriptor *next = ntw->cntr_list;

	if (!next)
		return;

	pool_id = ntw->wq->context->pool_id;

	do {
		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Linking CntrHwID=%d to Pool=%d\n",
			next->hw_cntr_id, pool_id);
		cve_set_hw_sync_regs(&os_dev->idc_dev,
			next->hw_cntr_id, pool_id);

		next = cve_dle_next(next, list);
	} while (next != head);
}

static void __delink_counters_and_pool(struct ice_network *ntw)
{
	struct cve_device *dev = get_first_device();
	struct cve_os_device *os_dev = to_cve_os_device(dev);
	struct cve_hw_cntr_descriptor *head = ntw->cntr_list;
	struct cve_hw_cntr_descriptor *next = ntw->cntr_list;

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

static void __link_resource_and_pool(struct ice_network *ntw)
{
	/* ICEs */
	__link_ices_and_pool(ntw);

	/* Counters */
	__link_counters_and_pool(ntw);
}

static void __delink_resource_and_pool(struct ice_network *ntw)
{
	/* Counters */
	__delink_counters_and_pool(ntw);

	/* ICEs */
	__delink_ices_and_pool(ntw);
}

static inline void __add_ice_to_ntw_list(struct ice_network *ntw,
		struct cve_device *dev, bool lazy)
{
	struct cve_device_group *dg = cve_dg_get();

	dev->dev_ntw_id = ntw->network_id;
	cve_os_log(CVE_LOGLEVEL_INFO,
			"NtwID:0x%llx Reserved ICE%d power_status:%d\n",
			ntw->network_id, dev->dev_index,
			ice_dev_get_power_state(dev));

	if (!lazy)
		cve_di_set_device_reset_flag(dev, CVE_DI_RESET_DUE_NTW_SWITCH);

	cve_dle_add_to_list_before(ntw->ice_list, owner_list, dev);
	dev->in_free_pool = false;

	if (dev->power_state == ICE_POWER_OFF_INITIATED) {

		ice_dev_set_power_state(dev, ICE_POWER_ON);

		cve_dle_remove_from_list(dg->poweroff_dev_list,
			poweroff_list, dev);

		ice_swc_counter_set(dev->hswc,
			ICEDRV_SWC_DEVICE_COUNTER_POWER_STATE,
			ice_dev_get_power_state(dev));
	}

	dev->hswc_infer = ntw->dev_hswc[ntw->used_hswc_count++];
	ice_swc_counter_set(dev->hswc_infer,
				ICEDRV_SWC_INFER_DEVICE_COUNTER_ID,
				dev->dev_index);

}

static void __lazy_capture_ices(struct ice_network *ntw)
{
	int i;
	struct icebo_desc *bo;
	struct cve_device_group *dg = cve_dg_get();
	struct cve_device *dev;

	for (i = 0; i < MAX_NUM_ICEBO; i++) {

		bo = &dg->dev_info.icebo_list[i];

		if (ntw->pjob_info.picebo[i] != INVALID_ENTRY) {

			dev = bo->dev_list;
			__add_ice_to_ntw_list(ntw, dev, true);

			dev = cve_dle_next(dev, bo_list);
			__add_ice_to_ntw_list(ntw, dev, true);

			cve_dle_remove_from_list(dg->dev_info.picebo_list,
				owner_list, bo);
			dg->dev_info.num_avl_picebo--;
			bo->bo_curr_state = NO_ICE;

		} else if (ntw->pjob_info.sicebo[i] != INVALID_ENTRY) {

			dev = cve_device_get(ntw->pjob_info.sicebo[i]);
			__add_ice_to_ntw_list(ntw, dev, true);

			cve_dle_move(dg->dev_info.sicebo_list,
				dg->dev_info.picebo_list, owner_list, bo);
			dg->dev_info.num_avl_picebo--;
			dg->dev_info.num_avl_sicebo++;
			bo->bo_curr_state = ONE_ICE;

		} else if (ntw->pjob_info.dicebo[i] != INVALID_ENTRY) {

			dev = cve_device_get(ntw->pjob_info.dicebo[i]);
			__add_ice_to_ntw_list(ntw, dev, true);

			if (bo->bo_curr_state == TWO_ICE) {

				cve_dle_move(dg->dev_info.dicebo_list,
					dg->dev_info.picebo_list,
					owner_list, bo);
				dg->dev_info.num_avl_dicebo++;
				dg->dev_info.num_avl_picebo--;
				bo->bo_curr_state = ONE_ICE;

			} else if (bo->bo_curr_state == ONE_ICE) {

				cve_dle_remove_from_list(
					dg->dev_info.dicebo_list,
					owner_list, bo);
				dg->dev_info.num_avl_dicebo--;
				bo->bo_curr_state = NO_ICE;

			} else
				ASSERT(false);
		}
	}
}

/*
 * Remove ICE from DG and allocate it to Network list
*/
static int __ntw_reserve_ice(struct ice_network *ntw)
{
	int ret = 0;
	u32 i;
	bool lazy_capture = true;
	struct cve_device *dev;
	struct icebo_desc *bo;
	struct cve_device_group *dg = cve_dg_get();
	struct job_descriptor *job;

	/* At this point ice requirement must be satisfied */
	ASSERT((ntw->num_picebo_req + ntw->num_sicebo_req) <=
			dg->dev_info.num_avl_picebo);
	ASSERT(ntw->num_dicebo_req <= ((dg->dev_info.num_avl_picebo -
			ntw->num_picebo_req - ntw->num_sicebo_req) * 2
			+ dg->dev_info.num_avl_dicebo));

	ret = cve_os_lock(&dg->poweroff_dev_list_lock, CVE_INTERRUPTIBLE);
	if (ret != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "cve_os_lock error\n");
		return -1;
	}

	/* Check if previous ICEs are still available */
	for (i = 0; i < ntw->jg_list->submitted_jobs_nr; i++) {
		job = &ntw->jg_list->job_list[i];

		if (job->hw_ice_id == INVALID_ICE_ID) {
			lazy_capture = false;
			break;
		}

		dev = cve_device_get(job->hw_ice_id);

		/* ICE must be
		 *	1. Powered on
		 *	2. In free list
		 *	3. Last executing Ntw must be same as this
		 */
		if ((dev->power_state == ICE_POWER_OFF) ||
			(dev->dev_ntw_id != ntw->network_id) ||
			!dev->in_free_pool) {

			lazy_capture = false;
			break;
		}
	}

	if (lazy_capture) {

		cve_os_log(CVE_LOGLEVEL_DEBUG, "Lazy Capture activated\n");

		__lazy_capture_ices(ntw);

		goto out;

	} else {

		/* memset the ICE id map with invalid ICE ID i.e. 255 */
		memset(&ntw->pjob_info.ice_id_map[0], 0xFF,
				(sizeof(u8) * MAX_CVE_DEVICES_NR));
		memset(&ntw->pjob_info.picebo[0], 0xFF,
				(sizeof(u8) * MAX_NUM_ICEBO));
		memset(&ntw->pjob_info.sicebo[0], 0xFF,
				(sizeof(u8) * MAX_NUM_ICEBO));
		memset(&ntw->pjob_info.dicebo[0], 0xFF,
				(sizeof(u8) * MAX_NUM_ICEBO));

		/* Removing Job2ICE linkage and setting Ntw for Cold run */
		for (i = 0; i < ntw->jg_list->submitted_jobs_nr; i++) {
			job = &ntw->jg_list->job_list[i];
			job->hw_ice_id = INVALID_ICE_ID;
			ice_di_set_cold_run(job->di_hjob);
		}
	}

	for (i = 0; i < ntw->num_picebo_req; i++) {
		bo = dg->dev_info.picebo_list;

		/* add first device of BOn to ntw ice list */
		dev = bo->dev_list;
		__add_ice_to_ntw_list(ntw, dev, false);

		/* add second device of BOn to ntw ice list */
		dev = cve_dle_next(dev, bo_list);
		__add_ice_to_ntw_list(ntw, dev, false);

		/* Update BO list */
		cve_dle_remove_from_list(dg->dev_info.picebo_list, owner_list,
			bo);
		dg->dev_info.num_avl_picebo--;
		bo->bo_curr_state = NO_ICE;
		ntw->pjob_info.picebo[bo->bo_id] = 1;
	}
	for (i = 0; i < ntw->num_sicebo_req; i++) {
		bo = dg->dev_info.picebo_list;

		/* add first device of BOn to ntw ice list */
		dev = bo->dev_list;
		__add_ice_to_ntw_list(ntw, dev, false);

		/* Update BO list */
		cve_dle_move(dg->dev_info.sicebo_list, dg->dev_info.picebo_list,
			owner_list, bo);
		dg->dev_info.num_avl_picebo--;
		dg->dev_info.num_avl_sicebo++;
		bo->bo_curr_state = ONE_ICE;
		ntw->pjob_info.sicebo[bo->bo_id] = dev->dev_index;
	}
	for (i = 0; i < ntw->num_dicebo_req; i++) {
		if (dg->dev_info.dicebo_list) {
			bo = dg->dev_info.dicebo_list;
			dev = bo->dev_list;

			if (!dev->in_free_pool)
				dev = cve_dle_next(dev, bo_list);

			cve_dle_remove_from_list(dg->dev_info.dicebo_list,
				owner_list, bo);
			dg->dev_info.num_avl_dicebo--;
			bo->bo_curr_state = NO_ICE;
		} else {
			bo = dg->dev_info.picebo_list;
			dev = bo->dev_list;
			cve_dle_move(dg->dev_info.dicebo_list,
				dg->dev_info.picebo_list, owner_list, bo);
			dg->dev_info.num_avl_dicebo++;
			dg->dev_info.num_avl_picebo--;
			bo->bo_curr_state = ONE_ICE;
		}

		__add_ice_to_ntw_list(ntw, dev, false);

		ntw->pjob_info.dicebo[bo->bo_id] = dev->dev_index;
	}

out:
	cve_os_unlock(&dg->poweroff_dev_list_lock);

	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"NtwID=0x%lx, Reserved pICEBO=%d sICEBO=%d dICEBO=%d\n",
		(uintptr_t)ntw, ntw->num_picebo_req,
		ntw->num_sicebo_req, ntw->num_dicebo_req);

	for (i = 0; i < MAX_NUM_ICEBO; i++) {
		if ((ntw->pjob_info.picebo[i] != INVALID_ENTRY) ||
			(ntw->pjob_info.sicebo[i] != INVALID_ENTRY) ||
			(ntw->pjob_info.dicebo[i] != INVALID_ENTRY))
			cve_os_log(CVE_LOGLEVEL_DEBUG,
			"NtwID:0x%llx, pICEBO[%d]=%d sICEBO[%d]=%d dICEBO[%d]=%d\n",
			ntw->network_id, i, ntw->pjob_info.picebo[i], i,
			ntw->pjob_info.sicebo[i], i, ntw->pjob_info.dicebo[i]);
	}

	return ret;
}

static void __ntw_release_ice(struct ice_network *ntw)
{
	struct cve_device *head;
	struct cve_device_group *dg = g_cve_dev_group_list;
	int bo_id;
	struct icebo_desc *bo;

	while (ntw->ice_list) {
		head = ntw->ice_list;
		bo_id = head->dev_index / 2;
		bo = &dg->dev_info.icebo_list[bo_id];

		/* Forced release will ensure correct state */
		head->state = CVE_DEVICE_IDLE;

		cve_dle_remove_from_list(ntw->ice_list, owner_list, head);

		/*Invalidate the ICE ID */
		ice_swc_counter_set(head->hswc_infer,
				ICEDRV_SWC_INFER_DEVICE_COUNTER_ID,
				0xFFFF);
		head->hswc_infer = NULL;
		ntw->used_hswc_count--;
		cve_os_log(CVE_LOGLEVEL_INFO,
				"NtwID:0x%llx ICEBO:%d released ICE%d\n",
				ntw->network_id, bo_id, head->dev_index);

		head->in_free_pool = true;
		if (bo->bo_curr_state == NO_ICE) {
			cve_dle_add_to_list_before(dg->dev_info.dicebo_list,
				owner_list, bo);
			dg->dev_info.num_avl_dicebo++;
			bo->bo_curr_state = ONE_ICE;
		} else if (bo->bo_curr_state == ONE_ICE) {
			if (ntw->pjob_info.sicebo[bo_id] == head->dev_index) {
				cve_dle_move(dg->dev_info.picebo_list,
					dg->dev_info.sicebo_list,
					owner_list, bo);
				dg->dev_info.num_avl_picebo++;
				dg->dev_info.num_avl_sicebo--;
			} else {
				cve_dle_move(dg->dev_info.picebo_list,
					dg->dev_info.dicebo_list,
					owner_list, bo);
				dg->dev_info.num_avl_picebo++;
				dg->dev_info.num_avl_dicebo--;
			}
			bo->bo_curr_state = TWO_ICE;
		} else
			ASSERT(false);
	}

	cve_os_log(CVE_LOGLEVEL_INFO,
		"Released %d ICE from NtwID:0x%llx\n",
			ntw->num_ice, ntw->network_id);
}

static void __lazy_capture_counters(struct ice_network *ntw)
{
	int i;
	int8_t cntr_id;
	u32 mask, cntr_bitmap;
	struct cve_hw_cntr_descriptor *hw_cntr;
	struct cve_device_group *dg = g_cve_dev_group_list;

	cntr_bitmap = ntw->cntr_bitmap;
	while (cntr_bitmap) {

		/* #Trailing zero indicates counter_id */
		i = __builtin_ctz(cntr_bitmap);
		mask = (1 << i);

		cntr_bitmap &= ~(mask);

		cntr_id = ntw->cntr_info.cntr_id_map[i];
		ASSERT(cntr_id != INVALID_CTR_ID);

		hw_cntr = &dg->base_addr_hw_cntr[cntr_id];
		cve_dle_move(ntw->cntr_list, dg->hw_cntr_list, list, hw_cntr);

		hw_cntr->in_free_pool = false;
		dg->num_avl_cntr--;

		cve_os_log(CVE_LOGLEVEL_INFO,
			"NtwID:0x%llx Map Counter[%u]->%u\n",
			ntw->network_id, i, hw_cntr->hw_cntr_id);
	}

}

static int __ntw_reserve_cntr(struct ice_network *ntw)
{
	int i, ret = 0;
	int8_t cntr_id;
	bool lazy_capture = ntw->cntr_bitmap;
	u32 mask, cntr_bitmap;
	struct cve_device_group *dg = g_cve_dev_group_list;
	struct cve_hw_cntr_descriptor *hw_cntr;
	u32 count = 0;

	__local_builtin_popcount(ntw->cntr_bitmap, count);

	/* Check if previous Counters are still available */
	cntr_bitmap = ntw->cntr_bitmap;
	while (cntr_bitmap) {

		/* #Trailing zero indicates counter_id */
		i = __builtin_ctz(cntr_bitmap);
		mask = (1 << i);

		cntr_bitmap &= ~(mask);

		cntr_id = ntw->cntr_info.cntr_id_map[i];
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

		__lazy_capture_counters(ntw);

		/* ntw->patch_cntr is already false */

		goto out;

	} else {
		for (i = 0; i < MAX_HW_COUNTER_NR; i++)
			ntw->cntr_info.cntr_id_map[i] = INVALID_CTR_ID;

		ntw->patch_cntr = true;
	}

	cntr_bitmap = ntw->cntr_bitmap;
	while (cntr_bitmap) {

		/* #Trailing zero indicates counter_id */
		i = __builtin_ctz(cntr_bitmap);
		mask = (1 << i);

		cntr_bitmap &= ~(mask);

		/* Allocate new Counter and map */
		hw_cntr = dg->hw_cntr_list;

		/* Should make sure that enough Counters are available */
		ASSERT(hw_cntr != NULL);

		cve_dle_move(ntw->cntr_list, dg->hw_cntr_list, list, hw_cntr);

		hw_cntr->in_free_pool = false;
		dg->num_avl_cntr--;

		hw_cntr->cntr_ntw_id = ntw->network_id;

		ntw->cntr_info.cntr_id_map[i] = hw_cntr->hw_cntr_id;

		cve_os_log(CVE_LOGLEVEL_INFO,
			"NtwID:0x%llx Map Counter[%u]->%u\n",
			ntw->network_id, i, hw_cntr->hw_cntr_id);
	}

out:
	cve_os_log(CVE_LOGLEVEL_INFO,
		"Reserved %d Counter for NtwID:0x%llx\n",
			count, ntw->network_id);

	return ret;
}

static void __ntw_release_cntr(struct ice_network *ntw)
{
	int i;
	u32 mask, cntr_bitmap;
	struct cve_hw_cntr_descriptor *head;
	struct cve_device_group *dg = g_cve_dev_group_list;
	u32 count = 0;

	__local_builtin_popcount(ntw->cntr_bitmap, count);

	cntr_bitmap = ntw->cntr_bitmap;
	while (cntr_bitmap) {

		/* #Trailing zero indicates counter_id */
		i = __builtin_ctz(cntr_bitmap);
		mask = (1 << i);

		cntr_bitmap &= ~(mask);

		head = ntw->cntr_list;
		cve_dle_move(dg->hw_cntr_list, ntw->cntr_list, list, head);

		head->in_free_pool = true;
		dg->num_avl_cntr++;

		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Undo Map Counter [%u] = %u\n",
			i, head->hw_cntr_id);
	}
	cve_os_log(CVE_LOGLEVEL_INFO,
		"Released %d Counter from NtwID:0x%llx\n",
				count, ntw->network_id);
}

static void __ntw_reset_cntr(struct ice_network *ntw)
{
	u32 mask, cntr_bitmap;
	int i;

	cntr_bitmap = ntw->cntr_bitmap;
	while (cntr_bitmap) {
		i = __builtin_ctz(cntr_bitmap);
		mask = (1 << i);
		cntr_bitmap &= ~(mask);
		ice_di_reset_counter(ntw->cntr_info.cntr_id_map[i]);
	}
}

static int __ntw_reserve_clos(struct ice_network *ntw)
{
	int ret = 0;
	struct cve_device_group *dg = cve_dg_get();
	struct clos_manager *mclos = &dg->dg_clos_manager;

	cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Reserving LLC for NtwID=0x%llx: Required(%u, %u, %u, %u)\n",
			ntw->network_id,
			ntw->clos[0], ntw->clos[1], ntw->clos[2], ntw->clos[3]);

	mclos->clos_size[ICE_CLOS_1] = ntw->clos[ICE_CLOS_1];
	mclos->clos_size[ICE_CLOS_2] = ntw->clos[ICE_CLOS_2];
	mclos->clos_size[ICE_CLOS_0] = (MAX_CLOS_SIZE_MB -
					(ntw->clos[ICE_CLOS_1] +
					ntw->clos[ICE_CLOS_2]));

	ASSERT(mclos->clos_size[ICE_CLOS_0] >= 3);

	return ret;
}

static void __update_ice_req(struct ice_network *ntw,
				struct cve_device_group *dg)
{
	int temp;

	temp = ntw->num_picebo_req + ntw->num_sicebo_req;
	if (dg->dev_info.num_avl_picebo < temp) {
		/* if here then it means that requested resource is not met
		 * hence fall back to default case
		 */
		ntw->num_picebo_req = dg->dev_info.num_avl_picebo;
		ntw->num_sicebo_req = 0;
		temp = (2 * ntw->num_picebo_req) + ntw->num_sicebo_req;
		ntw->num_dicebo_req = ntw->num_ice - temp;
		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"NtwID:0x%llx ICE requirement updated now pICEBO:%d sICEBO:%d dICEBO:%d\n",
			ntw->network_id, ntw->num_picebo_req,
			ntw->num_sicebo_req,
			ntw->num_dicebo_req);

		/*ICEBO request could not be met, so disable shared read also*/
		ntw->shared_read = 0;
	} else {
		/* If here then it means that requested resource is met
		 * and ICEBO_PREFERRED can act like MANDATORY during scheduling
		 * hence changing icebo_req
		 */
		if (ntw->icebo_req) {
			ntw->icebo_req = ICEBO_MANDATORY;
			ntw->shared_read = 1;
		} else {
			ntw->shared_read = 0;
		}
		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"NtwID:0x%llx icebo_req:%d\n",
			ntw->network_id, ntw->icebo_req);

	}


}

static enum resource_status __check_resource_availability(
		struct ice_network *ntw)
{
	struct cve_device_group *dg = cve_dg_get();
	struct dg_dev_info *dinfo = &dg->dev_info;
	int num_avl_ice, num_nonres_ice, num_ntw_ice;
	u32 count = 0;
	enum resource_status ice_status, cntr_status, status;

	if (ntw->icebo_req == ICEBO_MANDATORY) {

		num_avl_ice = dinfo->num_avl_picebo;
		num_nonres_ice = dg->num_nonres_picebo;
		num_ntw_ice = (ntw->num_picebo_req + ntw->num_sicebo_req);

		ASSERT(ntw->num_dicebo_req == 0);
	} else {
		num_avl_ice = (2 * dg->dev_info.num_avl_picebo) +
				dg->dev_info.num_avl_dicebo;
		num_nonres_ice = (2 * dg->num_nonres_picebo) +
				dg->num_nonres_dicebo;
		num_ntw_ice = (2 * ntw->num_picebo_req) +
				ntw->num_dicebo_req;

		ASSERT(ntw->num_sicebo_req == 0);
	}

	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"Available ICE = %d, Non-Reserved ICE = %d, Ntw ICE = %d\n",
		num_avl_ice, num_nonres_ice, num_ntw_ice);

	if (num_ntw_ice <= num_avl_ice) {
		/* Ok */
		ice_status = RESOURCE_OK;
	} else if (num_ntw_ice <= num_nonres_ice) {
		/* Wait */
		ice_status = RESOURCE_BUSY;
	} else {
		/* Discard */
		status = RESOURCE_INSUFFICIENT;
		goto out;
	}

	__local_builtin_popcount(ntw->cntr_bitmap, count);
	if (count <= dg->num_avl_cntr) {
		/* Ok */
		cntr_status = RESOURCE_OK;
	} else if (count <= dg->num_nonres_cntr) {
		/* Wait */
		cntr_status = RESOURCE_BUSY;
	} else {
		/* Discard */
		status = RESOURCE_INSUFFICIENT;
		goto out;
	}

	if ((ice_status == RESOURCE_OK) && (cntr_status == RESOURCE_OK))
		status = RESOURCE_OK;
	else
		status = RESOURCE_BUSY;

out:
	return status;
}

static int __is_pool_required(struct ice_network *ntw)
{
	return ntw->cntr_bitmap ? 1 : 0;
}

enum resource_status ice_ds_ntw_reserve_resource(struct ice_network *ntw)
{
	u8 dev_id;
	int i;
	enum resource_status status = RESOURCE_OK;
	struct icebo_desc *bo;
	struct cve_device_group *dg = cve_dg_get();

	if (ntw->res_resource) {

		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Resources already reserved. NtwID=0x%lx\n",
			(uintptr_t)ntw);
		status = RESOURCE_OK;
		goto out;
	}

	/* If !has_resource => Borrow */
	if (!ntw->has_resource) {

		status = ice_ds_ntw_borrow_resource(ntw);
		if (status != RESOURCE_OK)
			goto out;
	}

	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"Reserving resources. NtwID=0x%lx\n",
		(uintptr_t)ntw);

	/* Update Reservation flags */
	ntw->res_resource = true;

	/* ICE */
	dg->num_nonres_picebo -= (ntw->num_picebo_req +
				ntw->num_sicebo_req);

	for (i = 0; i < MAX_NUM_ICEBO; i++) {

		dev_id = ntw->pjob_info.dicebo[i];
		if (dev_id == INVALID_ENTRY)
			continue;

		dg->dice_res_status[dev_id] = 1;

		bo = &dg->dev_info.icebo_list[dev_id >> 1];
		if ((bo->bo_init_state == TWO_ICE) &&
			(bo->bo_curr_state == ONE_ICE)) {

			ASSERT(dg->num_nonres_picebo);
			dg->num_nonres_picebo--;
			dg->num_nonres_dicebo++;

		} else if ((bo->bo_init_state == TWO_ICE) &&
			(bo->bo_curr_state == NO_ICE)) {

			ASSERT(dg->num_nonres_dicebo);
			dg->num_nonres_dicebo--;
		} else if ((bo->bo_init_state == ONE_ICE) &&
			(bo->bo_curr_state == NO_ICE)) {

			ASSERT(dg->num_nonres_dicebo);
			dg->num_nonres_dicebo--;
		} else
			ASSERT(false);

		break;
	}

	/* Counter */
	dg->num_nonres_cntr -= __builtin_popcount(ntw->cntr_bitmap);

	/* Pool */
	if (__is_pool_required(ntw)) {

		ntw->wq->num_ntw_reserving_pool++;

		if (ntw->wq->num_ntw_reserving_pool == 1)
			dg->num_nonres_pool--;
	}

	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"Resources reserved. NtwID=0x%lx\n",
		(uintptr_t)ntw);

out:
	return status;
}

enum resource_status ice_ds_ntw_borrow_resource(struct ice_network *ntw)
{
	enum resource_status status = RESOURCE_OK;
	enum pool_status pstatus = POOL_EXIST;
	struct cve_device *head, *next;
	struct cve_hw_cntr_descriptor *head_cntr, *next_cntr;
	struct cve_device_group *dg = cve_dg_get();
	u64 ntwIceMask = 0;
	u64 ntwCntrMask = 0;

	if (ntw->has_resource) {
		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Resources already borrowed. NtwID=0x%lx\n",
			(uintptr_t)ntw);
		goto end;
	}

	DO_TRACE(trace_icedrvNetworkResource(
				SPH_TRACE_OP_STATE_START,
				ntw->wq->context->swc_node.sw_id,
				ntw->swc_node.parent_sw_id,
				ntw->swc_node.sw_id, ntw->network_id,
				ntw->num_ice, ntw->cntr_bitmap, ntw->clos));

	if (__is_pool_required(ntw)) {

		pstatus = cve_ds_map_pool_context(ntw->wq->context);
		if (pstatus == POOL_EXHAUSTED) {

			if (dg->num_nonres_pool == 0)
				status = RESOURCE_INSUFFICIENT;
			else if (dg->num_avl_pool == 0)
				status = RESOURCE_BUSY;

			goto end;
		}

		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Pool allocated. NtwID=0x%lx\n",
			(uintptr_t)ntw);
	} else {
		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Pool not required. NtwID=0x%lx\n",
			(uintptr_t)ntw);
	}

	ntw->num_picebo_req = ntw->cached_num_picebo_req;
	ntw->num_sicebo_req = ntw->cached_num_sicebo_req;
	ntw->num_dicebo_req = ntw->cached_num_dicebo_req;
	ntw->icebo_req = ntw->cached_icebo_req;

	/* Update ICE requirement before checking for ICE availability*/
	if (ntw->icebo_req != ICEBO_MANDATORY)
		__update_ice_req(ntw, dg);

	status = __check_resource_availability(ntw);
	if (status != RESOURCE_OK) {

		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Resources not available. NtwID=0x%lx\n",
			(uintptr_t)ntw);

		if (pstatus == POOL_ALLOCATED)
			cve_ds_unmap_pool_context(ntw->wq->context);
		goto end;
	}

	ASSERT(__ntw_reserve_ice(ntw) == 0);

	ASSERT(__ntw_reserve_cntr(ntw) == 0);

	cve_dle_add_to_list_before(dg->ntw_with_resources,
		resource_list, ntw);

	if (__is_pool_required(ntw)) {

		__link_resource_and_pool(ntw);
		ntw->wq->num_ntw_using_pool++;
	}

	ntw->has_resource = 1;

	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"Resources borrowed. NtwID=0x%lx\n",
		(uintptr_t)ntw);

	if (ntw->has_resource) {
		head = ntw->ice_list;
		if (head != NULL) {
			next = head;
			do {
				ntwIceMask |= (1ULL << next->dev_index);
				next = cve_dle_next(next, owner_list);
			} while (head != next);
		}
		head_cntr = ntw->cntr_list;
		if (head_cntr != NULL) {
			next_cntr = head_cntr;
			do {
				ntwCntrMask |= (1ULL << next_cntr->hw_cntr_id);
				next_cntr = cve_dle_next(next_cntr, list);
			} while (head_cntr != next_cntr);
		}

		ntw->ntw_icemask = ntwIceMask;
		ntw->ntw_cntrmask = ntwCntrMask;

		DO_TRACE(trace_icedrvNetworkResource(
					SPH_TRACE_OP_STATE_COMPLETE,
					ntw->wq->context->swc_node.sw_id,
					ntw->swc_node.parent_sw_id,
					ntw->swc_node.sw_id, ntw->network_id,
					ntwIceMask, ntwCntrMask, ntw->clos));
	}

end:
	if (status != RESOURCE_OK)
		DO_TRACE(trace_icedrvNetworkResource(
					SPH_TRACE_OP_STATE_ABORT,
					ntw->wq->context->swc_node.sw_id,
					ntw->swc_node.parent_sw_id,
					ntw->swc_node.sw_id, ntw->network_id,
					ntw->num_ice, ntw->cntr_bitmap,
					ntw->clos));

	return status;
}

static void __power_off_ntw_devices(struct ice_network *ntw)
{
	int retval;
	struct cve_device *head = ntw->ice_list;
	struct cve_device *next = head;
	struct timespec curr_ts;
	struct cve_device_group *dg = g_cve_dev_group_list;
	bool wakeup_po_thread = false;

	getnstimeofday(&curr_ts);

	retval = cve_os_lock(&dg->poweroff_dev_list_lock, CVE_INTERRUPTIBLE);
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "cve_os_lock error\n");
		return;
	}

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
			next->poweroff_ts = curr_ts;

			ice_dev_set_power_state(next, ICE_POWER_OFF_INITIATED);
			ice_swc_counter_set(next->hswc,
				ICEDRV_SWC_DEVICE_COUNTER_POWER_STATE,
				ice_dev_get_power_state(next));
			cve_os_log(CVE_LOGLEVEL_INFO,
					"NtwID:0x%lx Adding ICE%d to LPM Task\n",
					(uintptr_t)ntw, next->dev_index);
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

void ice_ds_ntw_release_resource(struct ice_network *ntw)
{
	int i;
	u8 dev_id;
	struct icebo_desc *bo;
	struct cve_device_group *dg = cve_dg_get();

	if (!ntw->res_resource) {

		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Resources already released. NtwID=0x%lx\n",
			(uintptr_t)ntw);
		goto out;
	}

	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"Releasing resources. NtwID=0x%lx\n",
		(uintptr_t)ntw);

	ASSERT(ntw->has_resource);

	/* Update Reservation flags */
	ntw->res_resource = false;

	/* ICE */
	dg->num_nonres_picebo += (ntw->num_picebo_req +
				ntw->num_sicebo_req);

	for (i = 0; i < MAX_NUM_ICEBO; i++) {

		dev_id = ntw->pjob_info.dicebo[i];
		if (dev_id == INVALID_ENTRY)
			continue;

		dg->dice_res_status[dev_id] = 0;

		bo = &dg->dev_info.icebo_list[dev_id >> 1];
		if ((bo->bo_init_state == TWO_ICE) &&
			(bo->bo_curr_state == NO_ICE)) {

			dg->num_nonres_dicebo++;

		} else if ((bo->bo_init_state == TWO_ICE) &&
			(bo->bo_curr_state == ONE_ICE)) {

			dg->num_nonres_picebo++;
			dg->num_nonres_dicebo--;
		} else if ((bo->bo_init_state == ONE_ICE) &&
			(bo->bo_curr_state == NO_ICE)) {

			dg->num_nonres_dicebo++;
		} else
			ASSERT(false);

		break;
	}

	/* Counter */
	dg->num_nonres_cntr += __builtin_popcount(ntw->cntr_bitmap);

	/* Pool */
	if (__is_pool_required(ntw)) {

		ntw->wq->num_ntw_reserving_pool--;

		if (ntw->wq->num_ntw_reserving_pool == 0)
			dg->num_nonres_pool++;
	}

	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"Resources released. NtwID=0x%lx\n",
		(uintptr_t)ntw);

	/* Should return resources iff Network is not running.
	 * Else it will be released after last running Inference is over.
	 */
	if (!ntw->ntw_running)
		ice_ds_ntw_return_resource(ntw);

out:
	return;
}

void ice_ds_ntw_return_resource(struct ice_network *ntw)
{
	struct cve_device_group *dg = cve_dg_get();

	if (!ntw->has_resource) {
		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"No resource to return. NtwID=0x%lx\n",
			(uintptr_t)ntw);
		goto end;
	}

	/* Once workload is over, placing ICEs in Power-off queue */
	__power_off_ntw_devices(ntw);

	/* If reservation not required then release all resources*/
	if (!ntw->res_resource && __is_pool_required(ntw))
		__delink_resource_and_pool(ntw);

	if (!ntw->res_resource) {
		DO_TRACE(trace__icedrvResourceRelease(
				SPH_TRACE_OP_STATE_START,
				ntw->wq->context->swc_node.sw_id,
				ntw->swc_node.parent_sw_id,
				ntw->swc_node.sw_id, ntw->network_id,
				ntw->res_resource, ntw->ntw_icemask,
				ntw->ntw_cntrmask, ntw->clos));

		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Releasing resources. NtwID=0x%lx\n",
			(uintptr_t)ntw);

		__ntw_release_ice(ntw);
		ntw->ntw_icemask = 0;

		__ntw_release_cntr(ntw);
		ntw->ntw_cntrmask = 0;

		if (__is_pool_required(ntw)) {
			ntw->wq->num_ntw_using_pool--;

			if (!ntw->wq->num_ntw_using_pool) {

				cve_di_unset_pool_registers(
					ntw->wq->context->pool_id);
				cve_ds_unmap_pool_context(
					ntw->wq->context);
			}
		}

		cve_dle_remove_from_list(dg->ntw_with_resources,
			resource_list, ntw);

		ntw->has_resource = 0;

		cve_os_log(CVE_LOGLEVEL_INFO,
			"Resources released. NtwID:0x%lx\n",
			(uintptr_t)ntw);

		DO_TRACE(trace__icedrvResourceRelease(
				SPH_TRACE_OP_STATE_COMPLETE,
				ntw->wq->context->swc_node.sw_id,
				ntw->swc_node.parent_sw_id,
				ntw->swc_node.sw_id, ntw->network_id,
				ntw->res_resource, ntw->ntw_icemask,
				ntw->ntw_cntrmask, ntw->clos));
		return;
	}
	cve_os_log(CVE_LOGLEVEL_INFO,
		"Not releasing resources. NtwID:0x%lx\n",
		(uintptr_t)ntw);
end:
	DO_TRACE(trace__icedrvResourceRelease(
				SPH_TRACE_OP_STATE_ABORT,
				ntw->wq->context->swc_node.sw_id,
				ntw->swc_node.parent_sw_id,
				ntw->swc_node.sw_id, ntw->network_id,
				ntw->res_resource, ntw->ntw_icemask,
				ntw->ntw_cntrmask, ntw->clos));
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

static int __ice_dev_configure_dump(void *user_data)
{
	int retval = 0, status = 0, i;
	struct ice_debug_control_ice_dump *dump;
	struct cve_device *dev = NULL;
	u32  sz, index = 0, ice_bitmap;
	void **k_list, *cur_addr;
	uint64_t tmp_addr;
	u32 pe_mask, value;

	sz = sizeof(struct ice_debug_control_ice_dump);
	retval = __alloc_and_copy(user_data, sz, (void **)&dump);
	if (retval < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
		"debug control  param alloc failed :%d SZ:%d\n", retval, sz);
		goto exit;
	}

	sz = (sizeof(void *) * dump->num_of_ice_dump);
	retval = __alloc_and_copy((void *)dump->base_addr, sz,
				(void **)&k_list);
	if (retval < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
		"debug control param alloc failed :%d SZ:%d\n", retval, sz);
		goto err_alloc_dump;
	}

	ice_bitmap = dump->ice_mask;
	while (ice_bitmap) {
		retval = cve_os_lock(&g_cve_driver_biglock, CVE_INTERRUPTIBLE);
		if (retval != 0) {
			retval = -ERESTARTSYS;
			goto err_alloc_addr;
		}

		if (index > dump->num_of_ice_dump) {
			status |= ICE_DEBUG_ICE_DUMP_ERROR;
			retval = -1;
			cve_os_log(CVE_LOGLEVEL_ERROR,
			"[ERROR_LOG] ICE bit set but buffer not allocated\n");
			goto unlock;
		}

		i = __builtin_ctz(ice_bitmap);
		ice_bitmap &= ~(1 << i);
		dev = cve_device_get(i);
		pe_mask = 1 << (i + 4);
		value = cve_os_read_idc_mmio(dev,
				cfg_default.bar0_mem_icepe_offset);

		/* Check if Device is powered ON */
		if ((value & pe_mask) != pe_mask) {
			/* TODO: check whether to continue or error out */
			cve_os_log(CVE_LOGLEVEL_INFO,
				"ICE-%d is not powered on, skipping\n", i);
			cve_os_unlock(&g_cve_driver_biglock);
			continue;
		}

		cve_di_reset_cve_dump(dev, cfg_default.ice_dump_now,
					dev->debug_control_buf);
		dev->debug_control_buf.is_dump_now = 1;

		cve_os_unlock(&g_cve_driver_biglock);

		retval = cve_os_block_interruptible_timeout(
			&dev->debug_control_buf.dump_wqs_que,
			dev->debug_control_buf.is_cve_dump_on_error, 240000);
		if (retval == 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR, "ICE DUMP Timeout\n");
			status |= ICE_DEBUG_ICE_DUMP_TIMEOUT;
			retval = -1;
			goto err_alloc_addr;
		} else if (retval == -ERESTARTSYS) {
			cve_os_log(CVE_LOGLEVEL_ERROR, "ICE DUMP Error\n");
			status |= ICE_DEBUG_ICE_DUMP_ERROR;
			retval = -1;
			goto err_alloc_addr;
		} else {
			cve_os_log(CVE_LOGLEVEL_ERROR, "ICE DUMP Complete\n");
			status |= ICE_DEBUG_ICE_DUMP_COMPLETE;
			retval = 0;
		}

		retval = cve_os_lock(&g_cve_driver_biglock, CVE_INTERRUPTIBLE);
		if (retval != 0) {
			retval = -ERESTARTSYS;
			goto err_alloc_addr;
		}
		cur_addr = &k_list[index];

		tmp_addr = *((uint64_t *)cur_addr);
		retval = cve_os_write_user_memory((void *)tmp_addr,
		ice_di_get_core_blob_sz(),
		dev->debug_control_buf.cve_dump_buffer);
		index += 1;
		cve_os_unlock(&g_cve_driver_biglock);
	}

	dump->ice_dump_status = status;
	sz = sizeof(struct ice_debug_control_ice_dump);
	cve_os_write_user_memory(user_data, sz, dump);

err_alloc_addr:
	sz = (sizeof(uint64_t) * dump->num_of_ice_dump);
	OS_FREE(k_list, sz);
err_alloc_dump:
	sz = sizeof(struct ice_debug_control_ice_dump);
	OS_FREE(dump, sz);
exit:
	return retval;
unlock:
	sz = (sizeof(uint64_t) * dump->num_of_ice_dump);
	OS_FREE(k_list, sz);
	sz = sizeof(struct ice_debug_control_ice_dump);
	OS_FREE(dump, sz);
	cve_os_unlock(&g_cve_driver_biglock);
	return retval;
}

static int __set_powered_on_icemask(void *user_data)
{
	struct ice_debug_control_ice_mask *im;
	int retval = 0;
	struct cve_device *ice_dev = get_first_device();
	u32 sz;
	idc_regs_icepe_t reg;

	sz = sizeof(struct ice_debug_control_ice_mask);
	retval = __alloc_and_copy(user_data, sz, (void **)&im);
	if (retval < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
		"debug control  param alloc failed :%d SZ:%d\n", retval, sz);
		goto out;
	}

	retval = cve_os_lock(&g_cve_driver_biglock, CVE_INTERRUPTIBLE);
	if (retval != 0) {
		retval = -ERESTARTSYS;
		goto err_alloc_im;
	}

	reg.val = cve_os_read_idc_mmio(ice_dev,
				cfg_default.bar0_mem_icepe_offset);
	im->powered_on_ice_mask = reg.field.ICEPE;

	cve_os_write_user_memory(user_data, sz, im);

	cve_os_unlock(&g_cve_driver_biglock);

err_alloc_im:
	sz = sizeof(struct ice_debug_control_ice_mask);
	OS_FREE(im, sz);
out:
	return retval;
}

int ice_ds_debug_control(struct ice_debug_control_params *dc)
{
	int retval = 0;

	switch (dc->type) {
	case ICE_DEBUG_CONTROL_GET_POWERED_ON_ICEMASK:
		retval = __set_powered_on_icemask((void *)dc->user_data);
		break;
	case ICE_DEBUG_CONTROL_GET_ICE_DUMP:
		retval = __ice_dev_configure_dump((void *)dc->user_data);
		break;
	default:
		retval = CVE_DEFAULT_ERROR_CODE;
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"Invalid option\n");
		break;
	}

	return retval;
}

int ice_set_hw_config(struct ice_set_hw_config_params *set_hw_config)
{
	int retval = 0;

	retval = cve_os_lock(&g_cve_driver_biglock, CVE_INTERRUPTIBLE);
	if (retval != 0) {
		retval = -ERESTARTSYS;
		goto out;
	}

	switch (set_hw_config->config_type) {
	case ICE_FREQ:
		retval = set_ice_freq((void *)&set_hw_config->ice_freq_config);
		break;
	case LLC_FREQ:
		retval = set_llc_freq((void *)&set_hw_config->llc_freq_config);
		break;
	default:
		retval = CVE_DEFAULT_ERROR_CODE;
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"Invalid option\n");
		break;
	}
out:
	cve_os_unlock(&g_cve_driver_biglock);
	return retval;
}

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
