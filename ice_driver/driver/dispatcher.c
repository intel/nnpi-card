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
#else
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/completion.h>
#include "ice_sw_counters.h"
#include "icedrv_sw_trace.h"
#endif

#include "cve_driver.h"
#include "cve_driver_internal.h"
#include "os_interface.h"
#include "dispatcher.h"
#include "memory_manager.h"
#include "device_interface.h"
#include "dev_context.h"
#include "project_device_interface.h"
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
#include <CVG_MMU_1_system_map_regs.h>
#include "icedrv_internal_sw_counter_funcs.h"
#include "TLC_command_formats_values_no_ifdef.h"


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

static struct jobgroup_descriptor *__get_non_dep_jg(struct ice_network *ntw);
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
static int __forced_hw_cleanup(struct ice_network *ntw);
static int __ntw_reserve_ice(struct ice_network *ntw);
static void __ntw_release_ice(struct ice_network *ntw);
static int __ntw_reserve_cntr(struct ice_network *ntw);
static void __ntw_release_cntr(struct ice_network *ntw);
static void __ntw_reset_cntr(struct ice_network *ntw);
static int __ntw_reserve_llc(struct ice_network *ntw);
static void __ntw_release_llc(struct ice_network *ntw);
static void __flush_ntw_buffers(struct cve_device *cve_dev,
		struct ice_network *ntw);
static void __flush_inf_buffers(struct ice_infer *inf);


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

static void set_dirty_dram_cve_output_buff(struct cve_user_buffer *buf_list,
	struct cve_allocation_descriptor *jobs_allocs,
	u32 jobs_allocs_nr,
	struct cve_device *cve_dev)
{
	struct cve_user_buffer *buffer = NULL;
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

/* returns a system-wide unique buffer id */
static inline cve_bufferid_t get_new_buffer_id(void)
{
	static atomic64_t bufferid;
	u64 n = cve_os_atomic_increment_64(&bufferid);

	return (cve_bufferid_t)n;
}

static void copy_event_data_and_remove(
		struct cve_context_process *process,
		struct cve_completion_event *event,
		struct cve_get_event *data) {
	u64 *total_time = (uint64_t *)data->total_time;
	u64 *icedc_err_status = (uint64_t *)&data->icedc_err_status;
	u64 *ice_err_status = (uint64_t *)&data->ice_err_status;
	u32 *shared_read_err_status = &data->shared_read_err_status;
	int i;
	union icedc_intr_status_t reg;
	u64 ice_err;

	data->jobs_group_id = event->jobs_group_id;
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
			"Received completion event for NtwID=%llx\n",
			event->jobs_group_id);
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

	/* remove it from the WQ list */
	cve_dle_remove_from_list
		(process->events, list, event);

	/* free the jobgroup */
	OS_FREE(event, sizeof(*event));

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

		/* close dev_context for each cve */
		cve_dev_close_all_contexts(context->dev_hctx_list);
	}
}

/*
 * reset the CVE device..
 * return :
 */
static void do_reset(struct cve_device *cve_dev,
		os_domain_handle hdom,
		struct ds_context *context,
		enum reset_type_flag reset_type)
{
	cve_dev_context_handle_t dev_handle = NULL;
	u32 page_dir_base_addr;
	u32 *page_sz_list;

	ASSERT(context);

	cve_dev_context_get_by_cve_idx(
		context->dev_hctx_list,
		cve_dev->dev_index,
		&dev_handle);

	ASSERT(dev_handle);

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

	/* reset the page table flags state */
	cve_mm_reset_page_table_flags(hdom);

	/* Commented cve_di_set_hw_counters as it is setting the activate
	 * performance counters bit in MMU CONFIG ,which is now being done
	 * through PMON configuration .
	 */
	/* Enable/Disable HW counters */
	/*cve_di_set_hw_counters(cve_dev);*/

	/* reset dump register */
	cve_di_reset_cve_dump(cve_dev, DUMP_CVE_ON_ERROR,
					cve_dev->cve_dump_buf);

	/* complete the reset flow and run the device cores */
	cve_di_start_running(cve_dev);
	/* Set fifo size and address*/
}

static int __destroy_ice_dump_buffer(struct ice_network *ntw)
{
	int ret = 0;
	u32 sz;
	struct di_cve_dump_buffer *ice_dump_buf_list =
					ntw->ice_dump->ice_dump_buf;
	struct ice_dump_desc *dump_desc = ntw->ice_dump;

	sz = (sizeof(*ice_dump_buf_list) * ntw->ice_dump->total_dump_buf);
	ret = OS_FREE(ice_dump_buf_list, sz);
	if (ret < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"ERROR:%d De-alloc failed for ice_dump_buf_list\n",
			ret);
	}

	ret = OS_FREE(dump_desc, sizeof(*dump_desc));
	if (ret < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"ERROR:%d De-alloc failed for dump_desc\n",
			ret);
	}

	ntw->ice_dump = NULL;

	return ret;
}

static int  __create_ice_dump_buffer(struct ice_network *ntw)
{
	struct ice_dump_desc *dump_desc;
	struct di_cve_dump_buffer *ice_dump_buf_list, *cur_buf;
	struct cve_user_buffer *buffer = &ntw->buf_list[ntw->num_buf - 1];
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

/* Returns bitmap of counters that it allocated */
u32 cve_ds_map_hw_cntr(struct jobgroup_descriptor *jobgroup)
{
	u8 hw_ctr_id;
	int i;
	u32 mask, cntr_bitmap;
	u32 mapped = 0;

	struct cve_hw_cntr_descriptor *hw_cntr;
	struct cve_hw_cntr_descriptor *hw_cntr_list =
				g_cve_dev_group_list->hw_cntr_list;
	struct ice_network *ntw = jobgroup->network;

	cntr_bitmap = jobgroup->cntr_bitmap;
	while (cntr_bitmap) {

		/* #Trailing zero indicates counter_id */
		i = __builtin_ctz(cntr_bitmap);
		mask = (1 << i);

		cntr_bitmap &= ~(mask);

		if (ntw->cntr_info.cntr_id_map[i] != INVALID_CTR_ID)
			continue;

		/* Else allocate new Counter and map */
		hw_cntr = cve_dle_lookup(hw_cntr_list,
				list, network_id, INVALID_NETWORK_ID);

		/* Should make sure that enough Counters are available */
		ASSERT(hw_cntr != NULL);

		mapped |= mask;

		hw_cntr->network_id = ntw->network_id;
		hw_ctr_id = hw_cntr->hw_cntr_id;

		ntw->cntr_info.cntr_id_map[i] = hw_ctr_id;

		g_cve_dev_group_list->counters_nr--;

		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Map Counter [%u] = %u\n",
			i, hw_ctr_id);
	}

	return mapped;
}

/* Undo the operations of last cve_ds_map_hw_cntr() */
void cve_ds_undo_map_hw_cntr(struct jobgroup_descriptor *jobgroup, u32 bitmap)
{
	int i;
	u32 mask;

	struct cve_hw_cntr_descriptor *hw_cntr;
	struct cve_hw_cntr_descriptor *hw_cntr_list =
				g_cve_dev_group_list->hw_cntr_list;
	struct ice_network *ntw = jobgroup->network;

	while (bitmap) {

		/* #Trailing zero indicates counter_id */
		i = __builtin_ctz(bitmap);
		mask = (1 << i);

		bitmap &= ~(mask);

		if (jobgroup->cntr_bitmap & mask) {

			hw_cntr = cve_dle_lookup(hw_cntr_list,
					list, hw_cntr_id,
					ntw->cntr_info.cntr_id_map[i]);

			/* Counters were just mapped, it has to exist */
			ASSERT(hw_cntr != NULL);

			hw_cntr->network_id = INVALID_NETWORK_ID;

			ntw->cntr_info.cntr_id_map[i] = INVALID_CTR_ID;

			g_cve_dev_group_list->counters_nr++;

			cve_os_log(CVE_LOGLEVEL_DEBUG,
				"Undo Map Counter [%u] = %u\n",
				i, hw_cntr->hw_cntr_id);
		}
	}

}

enum pool_status cve_ds_map_pool_context(struct ds_context *context)
{
	int i;
	enum pool_status pstatus;
	u64 context_id = context->context_id;
	u64 *pool_context_map = g_cve_dev_group_list->pool_context_map;

	if (context->pool_id != INVALID_POOL_ID) {

		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Pool %u exist for Context=%llu\n",
			context->pool_id, context_id);

		pstatus = POOL_EXIST;
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
			goto end;
		}
	}

	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"Insufficient Pool for Context=%llu\n",
		context_id);

	/* If here then Pool is not available */
	return POOL_EXHAUSTED;
end:

	return pstatus;
}

void cve_ds_unmap_pool_context(struct ds_context *context)
{
	int8_t pool_id = context->pool_id;
	u64 *pool_context_map = g_cve_dev_group_list->pool_context_map;

	pool_context_map[pool_id] = INVALID_CONTEXT_ID;
	context->pool_id = INVALID_POOL_ID;

	cve_os_log(CVE_LOGLEVEL_INFO,
		"Released pool %u from Context=%llx\n",
		pool_id, context->context_id);
}

int set_hw_sync_regs(struct cve_device *cve_dev,
				struct jobgroup_descriptor *jobgroup)
{
	u32 mask, cntr_bitmap;
	int i;
	struct cve_os_device *os_dev = to_cve_os_device(cve_dev);
	struct ice_network *ntw = jobgroup->network;

	cntr_bitmap = jobgroup->cntr_bitmap;
	while (cntr_bitmap) {

		/* #Trailing zero indicates counter_id */
		i = __builtin_ctz(cntr_bitmap);
		mask = (1 << i);

		cntr_bitmap &= ~(mask);

		ASSERT(ntw->cntr_info.cntr_id_map[i] != INVALID_CTR_ID);

		cve_set_hw_sync_regs(&os_dev->idc_dev,
		ntw->cntr_info.cntr_id_map[i],
		jobgroup->wq->context->pool_id);
	}

	return 0;
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
			context->dev_hctx_list,
			dev->dev_index,
			&dev_handle);

			cve_os_log(CVE_LOGLEVEL_DEBUG,
				COLOR_YELLOW(
					"Creating CBDT buffer for ICE-%d. CBDT_Entries=%u\n"
					),
				dev->dev_index, network->max_cbdt_entries + 1);

			retval = cve_dev_alloc_and_map_cbdt(dev_handle,
				&network->fifo_desc[dev->dev_index],
				network->max_cbdt_entries);
			if (retval != 0) {
				cve_os_log(CVE_LOGLEVEL_ERROR,
				"cve_dev_alloc_and_map_cbdt failed %d\n",
				retval);
				cve_os_log(CVE_LOGLEVEL_ERROR,
				"ContextId: %llu, Ntw: %p, CBDT Entries: %u\n",
				context->context_id,
				network,
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
				context->dev_hctx_list,
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
		}
	}

	return retval;
}

static int dealloc_and_unmap_network_fifo(struct ice_network *network)
{
	struct cve_device *dev, *dev_head;
	cve_dev_context_handle_t dev_handle = NULL;
	struct ds_context *context = network->wq->context;
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
				context->dev_hctx_list,
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

int cve_ds_dispatch_single_job(
		struct cve_device *cve_dev,
		struct jobgroup_descriptor *jobgroup)
{
	cve_di_subjob_handle_t *embedded_cbs_subjobs = NULL;
	struct ds_context *next_ctx =
			jobgroup->wq->context;
	cve_dev_context_handle_t dev_next_ctx = NULL;
	os_domain_handle hdom = NULL;
	u32 page_dir_base_addr;
	struct ice_network *ntw = jobgroup->network;
	struct ice_infer *inf = ntw->curr_exe;
	struct job_descriptor *job = jobgroup->next_dispatch;
	int ret = 0;

	ret = set_idc_registers(cve_dev, true);
	if (ret < 0) {
		cve_os_dev_log(CVE_LOGLEVEL_ERROR,
			cve_dev->dev_index,
			"ERROR:%d DEV:%p JG:%p ICE configuration failed\n",
			ret, cve_dev, jobgroup);

		if (ret == -ICEDRV_KERROR_ICE_DOWN)
			ntw->ice_err_status |= ICE_READY_BIT_ERR;

		return ret;
	}

	/* if shared read is requested and driver has respected the request
	 * then set the shared read mmio
	 * TODO: check if in all other cases shared read has to disabled or not
	 */
	if (ntw->shared_read && (ntw->icebo_req == ICEBO_MANDATORY))
		ice_di_set_shared_read_reg(cve_dev, ntw, 1);

	if (ntw->ice_dump &&
	(ntw->ice_dump->allocated_buf_cnt < ntw->ice_dump->total_dump_buf)) {
		cve_dev->cve_dump_buf =
		ntw->ice_dump->ice_dump_buf[ntw->ice_dump->allocated_buf_cnt];
		ntw->ice_dump->allocated_buf_cnt++;
	}


	cve_dev_context_get_by_cve_idx(
		next_ctx->dev_hctx_list,
		cve_dev->dev_index,
		&dev_next_ctx);

	ice_mm_get_domain_by_cve_idx(inf->inf_hdom,
		g_cve_dev_group_list->dev_info.active_device_nr,
		cve_dev,
		&hdom);

	/* Mark the device as busy */
	cve_dev->state = CVE_DEVICE_BUSY;

	if (ntw->scheduled == 0)
		ntw->scheduled = 1;

	ret = set_hw_sync_regs(cve_dev, jobgroup);
	if (ret == -1) {
		ret = -ICEDRV_KERROR_NTW_CNTR_NXIO;
		cve_os_dev_log(CVE_LOGLEVEL_ERROR,
			cve_dev->dev_index,
			"Could not set access control counter register\n");
		return ret;
	}

	/* Mark the device as busy */
	cve_dev->state = CVE_DEVICE_BUSY;
	ntw->num_ice_idle--;

	/* do reset if needed */
	if (cve_di_get_device_reset_flag(cve_dev)) {
		cve_os_dev_log(CVE_LOGLEVEL_DEBUG,
				cve_dev->dev_index,
				"Performing Hard Reset\n");
		do_reset(cve_dev, hdom, next_ctx, RESET_TYPE_HARD);
		if (!disable_embcb) {
			cve_dev_get_emb_cb_list(
				dev_next_ctx,
				&embedded_cbs_subjobs);
		}

	} else {
		cve_os_dev_log(CVE_LOGLEVEL_DEBUG,
				cve_dev->dev_index,
				"No Reset\n");

		/* get the page table from the mm module */
		cve_mm_get_page_directory_base_addr(
			hdom, &page_dir_base_addr);

		/* set the page table to the device */
		cve_di_set_page_directory_base_addr(cve_dev,
			page_dir_base_addr);

	}

	/* Update CBDT register of device */
	cve_dev_reset_fifo(cve_dev,
		&jobgroup->network->fifo_desc[cve_dev->dev_index]);

	/* TODO: Should be written only during Context Switch */
	cve_di_set_pool_registers(cve_dev, next_ctx->pool_id);

	/* invalidate the page table if needed */
	cve_mm_invalidate_tlb(hdom, cve_dev);

	cve_dev->last_network_id = ntw->network_id;

	/* keep the last context which executed on this device */
	cve_dev->last_context_id = next_ctx->context_id;

#ifdef _DEBUG
	print_cur_page_table(hdom);
#endif

	cve_os_dev_log(CVE_LOGLEVEL_DEBUG,
			cve_dev->dev_index,
			"Ctx-ID:0x%llx, NTW:0x%llx Job:%p\n",
			next_ctx->context_id,
			jobgroup->id,
			job);


	/* If persistent Job and mapping doesnot exist then map it and
	 *  since this ICE will be used first time, run SCB
	 * Else If persistent Job and mapping exist then skip SCB (if any)
	 *
	 * SCB (Special CB), if present, should be executed only when
	 * driver establishes graph_ice_id mapping with driver_ice_id
	 */
	if (job->graph_ice_id < NUM_ICE_UNIT) {

		if (ntw->pjob_info.ice_id_map[job->graph_ice_id] ==
				INVALID_ICE_ID) {

			if ((ntw->network_type == ICE_PRIORITY_DEEPSRAM_NETWORK)
			|| (ntw->network_type == ICE_DEEPSRAM_NETWORK)) {
				/*TODO: Remove it once Sanity in UMD is in place
				 */
				ASSERT(job->scb_state != SCB_STATE_ABSENT);

				job->scb_state = SCB_STATE_RUN;
			}
			cve_dev->pnetwork_id = ntw->network_id;
			ntw->pjob_info.ice_id_map[job->graph_ice_id] =
				cve_dev->dev_index;

			cve_os_log(CVE_LOGLEVEL_DEBUG,
				"(Ntw: %p) Mapping Device %u to ID %u\n",
				ntw, cve_dev->dev_index, job->graph_ice_id);
		} else if (job->scb_state == SCB_STATE_RUN)
			job->scb_state = SCB_STATE_SKIP;
	}

	/* dispatch the current job */
	cve_di_dispatch_job(cve_dev, job->di_hjob, embedded_cbs_subjobs,
			job->scb_state);

	/* increment the next dispatch pointer */
	jobgroup->next_dispatch =
			cve_dle_next(jobgroup->next_dispatch,
					list);
	jobgroup->dispatched_jobs_nr++;
	jobgroup->exe_num_of_cves++;

	/* this means that this was the last job
	 * to dispatch from the jobgroup, hence,
	 * we can move the jobgroup to the dispatched list.
	 */
	if (is_jobgroup_dispatch_completed(jobgroup))
		jobgroup->next_dispatch = NULL;

	return ret;
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
	u32 i;
	struct jobgroup_descriptor *cur_jg;

	ntw->num_jg_completed = 0;
	ntw->num_jg_scheduled = 0;
	ntw->scheduled = 0;
	for (i = 0; i < MAX_CVE_DEVICES_NR; i++)
		ntw->ntw_exec_time[i] = 0;

	if (ntw->ice_dump)
		ntw->ice_dump->allocated_buf_cnt = 0;

	for (i = 0; i < ntw->num_jg; i++) {
		cur_jg = &ntw->jg_list[i];
		/* default dep count */
		cur_jg->cur_dep_count = cur_jg->dependencies_nr;

		cur_jg->completed = 0;
		cur_jg->scheduled = 0;
		cur_jg->ended_jobs_nr = 0;
		cur_jg->dispatched_jobs_nr = 0;
	}

	memcpy(ntw->pjob_info.num_pjob_remaining,
		ntw->pjob_info.num_pjob,
		NUM_ICE_UNIT * sizeof(ntw->pjob_info.num_pjob[0]));

}

static int __add_network_completion_event(struct ice_network *ntw)
{
	struct jobgroup_descriptor *cur_jg;
	u32 abort = CVE_JOBSGROUPSTATUS_COMPLETED;
	struct cve_completion_event *event;
	struct cve_workqueue *wq;
	struct ds_context *context;
	struct ice_infer *inf = ntw->curr_exe;
	u32 i = 0;

	wq = ntw->wq;
	context = wq->context;

	for (; i < ntw->num_jg; i++) {
		cur_jg = &ntw->jg_list[i];

		if (cur_jg->aborted_jobs_nr > 0) {
			abort = CVE_JOBSGROUPSTATUS_ABORTED;
			break;
		}
	}

	/* create event object if needed */
	if (ntw->produce_completion) {
		OS_ALLOC_ZERO(sizeof(struct cve_completion_event),
				(void **)&event);
		event->jobs_group_id = inf->infer_id;
		event->user_data = inf->user_data;
		event->jobs_group_status = abort;
		event->icedc_err_status = ntw->icedc_err_status;
		event->ice_err_status = ntw->ice_err_status;
		event->shared_read_err_status = ntw->shared_read_err_status;

		for (i = 0; i < MAX_CVE_DEVICES_NR; i++) {
			event->total_time[i] = ntw->ntw_exec_time[i];

			if (ntw->ntw_exec_time[i] != 0) {
				cve_os_log(CVE_LOGLEVEL_INFO,
					"Execution time on ICE %d: %llu\n",
					i, ntw->ntw_exec_time[i]);
			}
		}

		/* add to the end of events list */
		cve_dle_add_to_list_before(context->process->events,
				list, event);

		cve_os_log(CVE_LOGLEVEL_INFO,
			"Generating completion event(%p) for NtwID=%llx. Status=%s\n",
			event,
			ntw->network_id,
			get_cve_jobs_group_status_str(abort));

		/* wake up anyone who waits for completion event */
		cve_os_wakeup(&wq->context->process->events_wait_queue);
	}

#ifndef RING3_VALIDATION
DO_TRACE(trace_icedrvExecuteNetwork(SPH_TRACE_DRV_EXECUTE_NETWORK,
	(abort == CVE_JOBSGROUPSTATUS_ABORTED) ? SPH_TRACE_OP_STATE_ABORT :
	SPH_TRACE_OP_STATE_COMPLETE,
	ntw->wq->context->context_id, ntw->network_id, inf->infer_id,
	(abort == CVE_JOBSGROUPSTATUS_ABORTED) ? SPH_TRACE_OP_STATUS_FAIL :
	SPH_TRACE_OP_STATUS_PASS, 0));
#endif
	__reset_network_state(ntw);

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

	/* Loop on each non dependent JG*/

	/* TODO: Check if this makes sense */
	if (num_ice > workqueue->dg->dev_info.active_device_nr) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"failed since requested ice %d is larger than max ice %d\n",
			num_ice, workqueue->dg->dev_info.active_device_nr);
		retval = -ICEDRV_KERROR_NTW_INVAL_RESOURCE_REQ;
		goto out;
	}

	/* TODO: Check if this makes sense */
	if (llc_size > workqueue->dg->llc_size) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"failed since requested llc_size %d is larger than max llc sz:%d\n",
			llc_size, workqueue->dg->llc_size);
		retval = -ICEDRV_KERROR_NTW_INVAL_RESOURCE_REQ;
		goto out;
	}

	for (i = 0; i < network->num_jg; i++) {
		if (network->jg_list[i].num_of_idc_cntr > NUM_COUNTER_REG) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
			"failed since requested counter %d is larger than max:%d\n",
			network->jg_list->num_of_idc_cntr, NUM_COUNTER_REG);
			retval = -ICEDRV_KERROR_NTW_INVAL_RESOURCE_REQ;
			goto out;
		}
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
			cve_os_log(CVE_LOGLEVEL_ERROR,
				"ERROR:%d NTW:%p Invalid Buffer Descriptor, should be a Command Buffer\n",
				ret, ntw);
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
	struct cve_surface_descriptor *buffer;

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

	/* Find out if this Job contains SCB (Special CB).
	 * Only first Command can be SCB.
	 */
	buffer = &ntw->buf_desc_list[k_cb_desc_index_list[0]];
	if (buffer->surface_type == ICE_BUFFER_TYPE_DEEP_SRAM_CB)
		cur_job->scb_state = SCB_STATE_RUN;
	else
		cur_job->scb_state = SCB_STATE_ABSENT;

	/* copy the user provided CB to the device interface */
	ret = cve_di_handle_submit_job(context->buf_list, cur_job,
				job_desc->cb_nr, cb_desc, &cur_job->di_hjob);
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
			cve_os_log(CVE_LOGLEVEL_ERROR,
					"ERROR:%d NTW:0x%p JG:0x%p Job:%p ice_mm_process_patch_point() failed\n",
					ret, ntw, jg, cur_job);
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

static int __destroy_jg_dep_list(struct jobgroup_descriptor *jg)
{
	struct jobgroup_descriptor **dep_jg_list;
	int sz = 0;
	int ret = 0;

	if (jg->dependencies_nr == 0)
		return 0;

	dep_jg_list = jg->dependencies;
	sz = (sizeof(*dep_jg_list) * jg->dependencies_nr);
	ret = OS_FREE(dep_jg_list, sz);
	if (ret < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"ERROR:%d De-Allocation failed for JG Dep Array\n",
			ret);
	}

	return ret;
}

static int __destroy_cntr_pp(struct job_descriptor *job,
	struct cve_cntr_pp *cntr_pp_list)
{
	int ret = 0;

	while (cntr_pp_list) {
		struct cve_cntr_pp *cur_cntr_pp =
			cntr_pp_list;

		cve_dle_remove_from_list(cntr_pp_list, list,
			cur_cntr_pp);
		ret = OS_FREE(cur_cntr_pp, sizeof(*cur_cntr_pp));
		if (ret < 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
			"ERROR:%d __destroy_cntr_pp failed\n", ret);
			goto out;
		}
	}

	cve_os_log(CVE_LOGLEVEL_DEBUG,
			"SUCCESS> Counters patch point destroyed:%d. JobID=%lx\n",
			job->cntr_patch_points_nr, (uintptr_t)job);

	job->counter_pp_desc_list = NULL;
	job->cntr_patch_points_nr = 0;

out:
	return ret;
}

static int __destroy_job_list(struct jobgroup_descriptor *jg,
	u32 max_jobs)
{
	u32 i = 0, sz = 0;
	int ret = 0;
	struct job_descriptor *cur_job, *job_list;

	job_list = jg->job_list;
	for (i = 0; i < max_jobs; i++) {
		cur_job = &job_list[i];

		/* release the memory allocated for counter patching for
		 * this job during create inference
		 */
		ret = __destroy_cntr_pp(cur_job,
				cur_job->counter_pp_desc_list);
		if (ret < 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
				"__destroy_cntr_pp failed %d\n", ret);
		}

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

	return ret;
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

		cur_job->cntr_patch_points_nr = 0;
		cur_job->jobgroup = jg;

		if (cur_job_desc->graph_ice_id < 0)
			cur_job->graph_ice_id = INVALID_ICE_ID;
		else {
			cur_job->graph_ice_id = (u8)cur_job_desc->graph_ice_id;

			/* If here then this is a Persistent Job.
			 * So Job count for given ICE should be increased
			 */
			ntw->pjob_info.num_pjob[cur_job->graph_ice_id]++;
			cve_os_log(CVE_LOGLEVEL_DEBUG,
				"Inc PJob count (NtwId=0x%llx, GraphIceId=%d)\n",
				ntw->network_id, cur_job->graph_ice_id);
		}

		cve_os_log(CVE_LOGLEVEL_DEBUG,
			COLOR_GREEN(
				"Processing Job-%d. NtwId=0x%llx, JG_ID=0x%lx, JobID=0x%lx\n"
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

static int __destroy_jg(struct ice_network *ntw,
	struct jobgroup_descriptor *jg)
{
	int ret = 0;

	ret = __destroy_job_list(jg, jg->total_jobs);
	if (ret < 0)
		cve_os_log(CVE_LOGLEVEL_ERROR, "__destroy_job_list failed %d\n",
			ret);

	ret = __destroy_jg_dep_list(jg);
	if (ret != 0)
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"__destroy_jg_dep_list failed %d\n", ret);

	return ret;
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
		cve_os_log(CVE_LOGLEVEL_ERROR,
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
	jg->dependencies_nr = jg_desc->dep_nr;
	/* default dep count */
	jg->cur_dep_count = jg_desc->dep_nr;
	jg->exe_num_of_cves = 0;
	jg->llc_size = jg_desc->LLC_size;
	jg->num_of_idc_cntr = jg_desc->num_of_idc_cntr;
	jg->produce_completion = jg_desc->produce_completion;
	jg->cntr_bitmap = 0;

	ret = __process_job_list(jg_desc, jg);
	if (ret < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"__process_job_list failed %d\n",
			ret);
		goto out;
	}

	max_cb = ret;
	jg->network = ntw;

	cve_os_log(CVE_LOGLEVEL_DEBUG,
			"JG processing completed. JG_ID=0x%lx, JobCount=%d, DepCount=%d\n",
			(uintptr_t)jg, jg->total_jobs, jg->dependencies_nr);

	ret = max_cb;

out:
	return ret;
}

static int __destroy_jg_list(struct ice_network *ntw, u32 jg_count)
{
	struct jobgroup_descriptor *cur_jg;
	u32 i = 0, sz = 0;
	int ret = 0;

	for (; i < jg_count; i++) {
		cur_jg = &(ntw->jg_list[i]);
		ret = __destroy_jg(ntw, cur_jg);
		if (ret < 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
					"ERROR:%d NTW:%p JG:%p __destroy_jg failed\n",
					ret, ntw, cur_jg);
		} else {
			cve_os_log(CVE_LOGLEVEL_DEBUG,
					"SUCCESS> NTW:%p JG:%p destroy_jg done\n",
					ntw, cur_jg);
		}
	}

	/* free the job group list*/
	sz = (sizeof(*cur_jg) * ntw->num_jg);
	OS_FREE(ntw->jg_list, sz);

	return ret;
}


/*
 * Successful call returns maximum number of CBs present
 * in any Job within given Jobgroup List
*/
static int __process_jg_list(struct ice_network *ntw,
		struct cve_job_group *jg_desc_list)
{
	struct cve_job_group *cur_jg_desc = NULL;
	struct jobgroup_descriptor *jg_list, *cur_jg;
	u32 i = 0, sz = 0;
	int ret = 0, max_cb = 0;

	/* allocate structure for the job group list*/
	sz = (sizeof(*jg_list) * ntw->num_jg);
	ret = OS_ALLOC_ZERO(sz, (void **)&jg_list);
	if (ret < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"Allocation for JG List failed %d\n", ret);
		goto out;
	}
	ntw->jg_list = jg_list;

	for (; i < ntw->num_jg; i++) {
		cur_jg_desc = &jg_desc_list[i];
		cur_jg = &jg_list[i];

		cve_os_log(CVE_LOGLEVEL_DEBUG,
			COLOR_GREEN(
				"Processing JG-%d. NtwId=0x%llx, JG_ID=0x%lx\n"
				),
			i, ntw->network_id, (uintptr_t)cur_jg);
		ret = __process_jg(ntw, cur_jg_desc, cur_jg);
		if (ret < 0)
			goto error_process_jg;

		max_cb = (ret > max_cb) ? ret : max_cb;
		ntw->cntr_bitmap |= cur_jg->cntr_bitmap;
	}
	ret = max_cb;
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
	__destroy_jg_list(ntw, i);
out:
	return ret;
}

static int __destroy_buf(struct ice_network *ntw,
	struct cve_user_buffer *buf)
{
	int ret = 0;
	struct ds_context *context = NULL;
	struct cve_workqueue *wq = NULL;
	cve_context_id_t dummy_context_id = 0;

	wq = ntw->wq;
	context = wq->context;

	ret = cve_mm_unmap_kva(buf->allocation);
	if (ret < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"cve_mm_unmap_kva failed %d\n", ret);
	}

	cve_mm_destroy_buffer(dummy_context_id, buf->allocation);

	/* remove the buffer from the list in the context */
	cve_dle_remove_from_list(context->buf_list, list, buf);

	cve_os_log(CVE_LOGLEVEL_DEBUG, "Buffer destroyed bufferid =>%lld\n",
		buf->buffer_id);

	return ret;
}

static int __process_buf_desc(struct ice_network *ntw,
	struct cve_surface_descriptor *buf_desc,
	struct cve_user_buffer *buf)
{
	int ret = 0;
	struct ds_context *context = NULL;
	struct cve_workqueue *wq = NULL;
	os_domain_handle cve_os_hdomain[MAX_CVE_DEVICES_NR];
	cve_context_id_t dummy_context_id = 0;

	wq = ntw->wq;
	context = wq->context;

	if (buf_desc->alloc_higher_va &&
			buf_desc->low_pp_cnt != buf_desc->high_pp_cnt) {
		ret = -ICEDRV_KERROR_PP_COUNT_EINVAL;
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"ERROR:%d NTW:%p buffer_id:%lld Invalid patch points(Low:%d High:%d)\n",
				ret, ntw, buf->buffer_id,
				buf_desc->low_pp_cnt,
				buf_desc->high_pp_cnt);
		goto out;
	}

	cve_dev_get_os_domain_arr(context->dev_hctx_list,
		g_cve_dev_group_list->dev_info.active_device_nr,
		cve_os_hdomain);

	/* initialize the buffer's object attributes */
	buf->buffer_id = (uintptr_t)buf;
	buf->surface_type = buf_desc->surface_type;

	cve_os_log(CVE_LOGLEVEL_DEBUG,
		COLOR_GREEN(
			"Start Mapping Buffer. NtwID=0x%llx, BufferID=0x%llx\n"
			),
		ntw->network_id, buf->buffer_id);

	if (ice_enable_llc_config_via_axi_reg() &&
			buf_desc->alloc_higher_va == 1)
		buf_desc->llc_policy = ICE_LLC_ATTR_CONFIG_VIA_AXI_REG;

	ret = cve_mm_create_buffer(cve_os_hdomain,
			g_cve_dev_group_list->dev_info.active_device_nr,
			buf_desc, &buf->allocation);
	if (ret < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"cve_mm_create_buffer failed %d\n", ret);
		goto out;
	}

	cve_os_log(CVE_LOGLEVEL_DEBUG,
		COLOR_GREEN(
			"Stop Mapping Buffer. BufferID=0x%llx\n"
			),
		buf->buffer_id);

	ret = cve_mm_map_kva(buf->allocation);
	if (ret < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"cve_mm_map_kva failed %d\n", ret);
		goto error_map_kva;
	}

	/* add it to the buffer list in the context */
	cve_dle_add_to_list_after(context->buf_list, list, buf);

	/* Set the buffer as cache dirty */
	cve_mm_set_dirty_cache(buf);

	/* Update buffer ID to descriptor as a place holder
	 * for CB processing
	 */
	buf_desc->bufferid = buf->buffer_id;

	return ret;

error_map_kva:
	cve_mm_destroy_buffer(dummy_context_id, buf->allocation);
out:
	return ret;
}

static int __destroy_buf_list(struct ice_network *ntw,
	struct cve_user_buffer *buf_list, u32 buf_count)
{
	struct cve_user_buffer *cur_buf;
	u32 sz = 0, idx = 0;
	int ret = 0;

	for (; idx < buf_count; idx++) {
		cur_buf = &buf_list[idx];
		ret = __destroy_buf(ntw, cur_buf);
	}

	sz = (sizeof(*buf_list) * buf_count);
	ret = OS_FREE(buf_list, sz);
	if (ret < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"ERROR:%d De-alloc failed for buf_list\n", ret);
	}

	return ret;
}

static int __process_buf_desc_list(struct ice_network *ntw,
	struct cve_surface_descriptor *buf_desc_list)
{
	struct cve_user_buffer *buf_list, *cur_buf;
	struct cve_surface_descriptor *cur_buf_desc;
	u32 sz = 0, idx = 0;
	int ret = 0;

	sz = (sizeof(*buf_list) * ntw->num_buf);
	ret = OS_ALLOC_ZERO(sz, (void **)&buf_list);
	if (ret < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"ERROR:%d Allocation for Buffer List failed\n", ret);
		goto out;
	}
	ntw->buf_list = buf_list;

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
	}

	return ret;

error_buf_desc:
	__destroy_buf_list(ntw, buf_list, idx);
out:
	return ret;
}

static int __process_inf_buf_desc_list(struct ice_infer *inf,
	struct cve_infer_surface_descriptor *buf_desc_list)
{
	int retval = 0;
	u32 sz = 0, idx, i;
	struct ice_network *ntw;
	struct cve_infer_buffer *buf_list, *cur_buf;
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

		cur_buf->index = cur_buf_desc->index;
		cur_buf->base_address = cur_buf_desc->base_address;
		cur_buf->fd = cur_buf_desc->fd;
		cur_buf->allocation = ntw->buf_list[cur_buf->index].allocation;

		retval = cve_mm_create_infer_buffer(inf->infer_id,
				inf->inf_hdom,
				g_cve_dev_group_list->dev_info.active_device_nr,
				cur_buf);
		if (retval < 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
				"cve_mm_create_infer_buffer failed %d\n",
				retval);
			goto undo_loop;
		}

		cve_mm_set_dirty_cache(&ntw->buf_list[cur_buf->index]);
	}

	goto out;

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

static int __destroy_network(struct ice_network *network)
{
	int ret = 0, i = 0;
	struct cve_device *ice_dev = NULL;

	/* All resource must be released */
	network->reserve_resource = 0x0;
	ice_ds_ntw_resource_release(network);

	dealloc_and_unmap_network_fifo(network);

	for (i = 0; i < NUM_ICE_UNIT; i++) {
		if (network->pjob_info.ice_id_map[i] < NUM_ICE_UNIT) {
			ice_dev = cve_device_get(
					network->pjob_info.ice_id_map[i]);
			ice_dev->pnetwork_id = INVALID_NETWORK_ID;
		}
	}

	ret = __destroy_buf_list(network, network->buf_list, network->num_buf);
	if (ret < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"ERROR:%d NTW:%p destroy_buf_list() failed\n",
			ret, network);
		goto out;
	}

	if (network->ice_dump != NULL) {
		ret =  __destroy_ice_dump_buffer(network);
		if (ret < 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
			"ERROR:%d NTW:%p destroy_ice_dump_buffer() failed\n",
			ret, network);
			goto out;
		}
	}

	ret = __destroy_jg_list(network, network->num_jg);
	if (ret < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"ERROR:%d NTW:%p destroy_jg_list() failed\n",
			ret, network);
		goto out;
	}

out:
	return ret;
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

	if ((network_desc->network_type == ICE_PRIORITY_NETWORK) ||
	  (network_desc->network_type == ICE_PRIORITY_DEEPSRAM_NETWORK)) {
		/* Priority Network */
		ntw->p_type = NTW_PRIORITY_0;
	} else {
		/* Normal Network */
		ntw->p_type = NTW_PRIORITY_1;
	}

	ntw->produce_completion = network_desc->produce_completion;
	ntw->num_ice = network_desc->num_ice;
	ntw->llc_size = network_desc->llc_size;
	/* To be incremented while adding ICEs */
	ntw->num_ice_idle = 0;
	ntw->has_resource = 0;
	ntw->cntr_bitmap = 0;
	ntw->ice_list = NULL;
	ntw->cntr_list = NULL;
	ntw->num_jg_completed = 0;
	ntw->num_jg_scheduled = 0;
	ntw->abort_ntw = 0;
	ntw->network_id = (u64)ntw;
	ntw->scheduled = 0;
	ntw->icebo_req = network_desc->icebo_req;
	ntw->num_picebo_req = 0;
	ntw->num_sicebo_req = 0;
	ntw->num_dicebo_req = 0;
	ntw->network_type = network_desc->network_type;
	ntw->shared_read = network_desc->shared_read;
	for (i = 0; i < MAX_CVE_DEVICES_NR; i++)
		ntw->ntw_exec_time[i] = 0;

	/* if user has not provided max shared distance then store
	 * the default value
	 */
	ntw->max_shared_distance = (network_desc->max_shared_distance != 0) ?
		network_desc->max_shared_distance : DEFAULT_MAX_SHARED_DISTANCE;

	retval = cve_os_init_wait_que(&ntw->abort_wq);
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"NTW:%p abort_wq init failed  %d\n", ntw, retval);
		goto out;
	}

	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"Creating new Network. CtxID=%llu, NtwID=0x%llx\n",
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
		cve_os_log(CVE_LOGLEVEL_ERROR,
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
			"NTW:%p ice_dump is enabled with total_dump_buf=%x\n",
			ntw, ntw->ice_dump->total_dump_buf);
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
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"__process_jg_list() %d\n",
			retval);
		goto error_jg_desc_process;
	}

	ntw->max_cbdt_entries = retval;
	retval = alloc_and_map_network_fifo(ntw);
	if (retval < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"ERROR:%d alloc_and_map_network_fifo failed\n",
				retval);
		goto err_fifo_alloc;
	}

	memcpy(ntw->pjob_info.num_pjob_remaining,
		ntw->pjob_info.num_pjob,
		NUM_ICE_UNIT * sizeof(ntw->pjob_info.num_pjob[0]));

	sz = (sizeof(*jg_desc_list) * network_desc->num_jg_desc);
	OS_FREE(jg_desc_list, network_desc->num_jg_desc);

	sz = (sizeof(*k_buf_desc_list) * network_desc->num_buf_desc);
	OS_FREE(k_buf_desc_list, sz);

	cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Network processing completed. NtwID=%llx, BufferCount=%d, JG_Count=%d\n",
			ntw->network_id, ntw->num_buf, ntw->num_jg);

	goto out;

err_fifo_alloc:
	__destroy_jg_list(ntw, ntw->num_jg);
error_jg_desc_process:
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

static int __process_infer_desc(
		struct ice_infer_descriptor *inf_desc,
		struct ice_infer *inf)
{
	struct cve_infer_surface_descriptor *k_buf_desc_list;
	u32 sz;
	int retval = 0;
	struct ds_context *context = inf->ntw->wq->context;
	os_domain_handle cve_os_hdomain[MAX_CVE_DEVICES_NR];

	sz = (sizeof(*k_buf_desc_list) * inf_desc->num_buf_desc);
	retval = __alloc_and_copy(inf_desc->buf_desc_list,
		sz, (void **)&k_buf_desc_list);
	if (retval < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"__alloc_and_copy() %d\n",
			retval);
		goto out;
	}

	cve_dev_get_os_domain_arr(context->dev_hctx_list,
		g_cve_dev_group_list->dev_info.active_device_nr,
		cve_os_hdomain);

	inf->num_buf = inf_desc->num_buf_desc;
	inf->user_data = inf_desc->user_data;

	/* Create PT copy during Create Infer */
	retval = ice_mm_domain_copy(cve_os_hdomain, &inf->inf_hdom,
			g_cve_dev_group_list->dev_info.active_device_nr);
	if (retval < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"ice_mm_domain_copy failed %d\n", retval);
		goto free_mem;
	}

	retval = __process_inf_buf_desc_list(inf, k_buf_desc_list);
	if (retval < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"__process_inf_buf_desc_list failed %d\n", retval);
		goto domain_destroy;
	}

	/* Flush the inference surfaces */
	__flush_inf_buffers(inf);

	cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Inference processing completed. InfID=%llx, BufferCount=%d\n",
			inf->infer_id, inf->num_buf);

	sz = (sizeof(*k_buf_desc_list) * inf_desc->num_buf_desc);
	OS_FREE(k_buf_desc_list, sz);

	goto out;

domain_destroy:
	ice_mm_domain_destroy(inf->inf_hdom,
		g_cve_dev_group_list->dev_info.active_device_nr);
free_mem:
	sz = (sizeof(*k_buf_desc_list) * inf_desc->num_buf_desc);
	OS_FREE(k_buf_desc_list, sz);
out:
	return retval;
}

static void __destroy_infer_desc(struct ice_infer *inf)
{
	u32 idx;

	for (idx = 0; idx < inf->num_buf; idx++) {
		cve_mm_destroy_infer_buffer(inf->infer_id,
			&inf->buf_list[idx]);
	}

	OS_FREE(inf->buf_list,
		(inf->num_buf * sizeof(struct cve_infer_buffer)));

	ice_mm_domain_destroy(inf->inf_hdom,
		g_cve_dev_group_list->dev_info.active_device_nr);
}

static struct jobgroup_descriptor *__get_non_dep_jg(struct ice_network *ntw)
{
	u32 i = 0;
	struct jobgroup_descriptor *cur_jg;

	for (; i < ntw->num_jg; i++) {
		cur_jg = &ntw->jg_list[i];

		if (cur_jg->cur_dep_count == 0 && cur_jg->scheduled == 0)
			return cur_jg;
	}

	return NULL;
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

#ifndef RING3_VALIDATION
	u32 ntw_resources[3];

	ntw_resources[0] = network_desc->num_ice;
	ntw_resources[1] = network_desc->llc_size;
	ntw_resources[2] = 0;

	DO_TRACE(trace_icedrvCreateNetwork(SPH_TRACE_DRV_CREATE_NETWORK,
		SPH_TRACE_OP_STATE_START, context_id, 0, ntw_resources,
		SPH_TRACE_OP_STATUS_NULL, 0));
#endif
	/* check if there's place in the cb array */
	retval = cve_os_lock(&g_cve_driver_biglock, CVE_INTERRUPTIBLE);
	if (retval != 0) {
		retval = -ERESTARTSYS;
		goto out;
	}

	if (dev == NULL) {
		retval = -ICEDRV_KERROR_CTX_NODEV;
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"Error:%d dev cannot be NULL\n", retval);
		goto out;
	}

	retval = __get_wq_from_contex_pid(context_pid, context_id, &workqueue);
	if (!workqueue) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"get_wq_from_contex_pid() failed %d\n", retval);
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
	network->exe_status = NTW_EXE_STATUS_IDLE;

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

	if (__get_non_dep_jg(network) == NULL) {
		retval = -ICEDRV_KERROR_NTW_DEADLK;
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"ERROR:%d ntw:%p ntw_id:%lld should have atleast one non dep JG\n",
			retval, network, (u64)network_id);
		goto error_resources;
	}


	/* Flush the network surfaces */
	__flush_ntw_buffers(dev, network);

	/* add to the wq list */
	cve_dle_add_to_list_before(workqueue->ntw_list, list, network);
	/* return the job id to the user */
	*network_id = network->network_id;
	network->id = __get_ntw_id();

#ifndef RING3_VALIDATION
	ice_swc_counter_inc(network->wq->context->hswc,
			ICEDRV_SWC_CONTEXT_COUNTER_INF_TOTAL);
	ice_swc_counter_inc(network->wq->context->hswc,
			ICEDRV_SWC_CONTEXT_COUNTER_INF_CURR);

	retval = ice_swc_create_node(ICEDRV_SWC_CLASS_INFER,
					(*network_id + network->id),
					context_id,
					&network->hswc);
	if (retval < 0) {
		cve_os_log(CVE_LOGLEVEL_DEBUG,
				"Unable to create SW Counter's Infer node\n");
		goto error_sw_counter;
	}
#endif

#ifndef RING3_VALIDATION

	ntw_resources[0] = network->num_ice;
	ntw_resources[1] = network->llc_size;
	__local_builtin_popcount(network->cntr_bitmap, ntw_resources[2]);

	DO_TRACE(trace_icedrvCreateNetwork(SPH_TRACE_DRV_CREATE_NETWORK,
		SPH_TRACE_OP_STATE_COMPLETE, context_id,
		(retval ? 0 : network->network_id),
		ntw_resources,
		(retval ? SPH_TRACE_OP_STATUS_FAIL : SPH_TRACE_OP_STATUS_PASS),
		retval));
#endif

	cve_os_unlock(&g_cve_driver_biglock);

	return retval;

#ifndef RING3_VALIDATION
error_sw_counter:
	ice_swc_counter_dec(network->wq->context->hswc,
			ICEDRV_SWC_CONTEXT_COUNTER_INF_CURR);
	ice_swc_counter_inc(network->wq->context->hswc,
			ICEDRV_SWC_CONTEXT_COUNTER_INF_DEST);
	cve_dle_remove_from_list(workqueue->ntw_list, list, network);
#endif
error_resources:
	__destroy_network(network);
error_process_ntw:
	OS_FREE(network, sizeof(*network));
out:
	cve_os_unlock(&g_cve_driver_biglock);

#ifndef RING3_VALIDATION

	ntw_resources[0] = network_desc->num_ice;
	ntw_resources[1] = network_desc->llc_size;
	ntw_resources[2] = 0;

	DO_TRACE(trace_icedrvCreateNetwork(SPH_TRACE_DRV_CREATE_NETWORK,
		SPH_TRACE_OP_STATE_COMPLETE, context_id, 0,
		ntw_resources, SPH_TRACE_OP_STATUS_FAIL, retval));
#endif
	return retval;
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
		retval = -ICEDRV_KERROR_NTW_INVAL_ID;
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"ERROR:%d Given NETWORK_ID:%lld is not present in this context\n",
				retval, ntw_id);
		goto out;
	}

	retval = OS_ALLOC_ZERO(sizeof(*inf), (void **)&inf);
	if (retval < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"Allocation failed %d\n", retval);
		goto out;
	}

	inf->ntw = ntw;
	inf->infer_id = (u64)inf;
	inf->exe_status = INF_EXE_STATUS_IDLE;

	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"Processing CreateInfer. NtwID=%lx, InfID=%lx\n",
		(uintptr_t)ntw, (uintptr_t)inf);
	retval = __process_infer_desc(inf_desc, inf);
	if (retval < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"CreateInfer Failed:%d\n", retval);
		goto error_process_inf;
	}
	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"Completed CreateInfer. NtwID=%lx, InfID=%lx\n",
		(uintptr_t)ntw, (uintptr_t)inf);

	cve_dle_add_to_list_before(ntw->inf_list, ntw_list, inf);

	*inf_id = inf->infer_id;

	cve_os_unlock(&g_cve_driver_biglock);

	return retval;

error_process_inf:
	OS_FREE(inf, sizeof(*inf));
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
				"ERROR:%d Given NETWORK_ID:%lld is not present in this context\n",
				retval, ntw_id);
		goto out;
	}

	inf = cve_dle_lookup(ntw->inf_list, ntw_list, infer_id, inf_id);
	if (inf == NULL) {
		/* TODO: New Error Code required */
		retval = -ICEDRV_KERROR_NTW_INVAL_ID;
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"Given InfID=0x%llx is not present in NtwId=0x%llx. Error=%d\n",
				inf_id, ntw_id, retval);
		goto out;
	}

	if (inf->exe_status == INF_EXE_STATUS_RUNNING) {

#if 0
		/* TODO: Support this */
		inf->exe_status = INF_EXE_STATUS_ABORTED;
#endif
		retval = -ICEDRV_KERROR_INF_EALREADY;
		goto out;
	}
	inf->exe_status = INF_EXE_STATUS_ABORTED;

	__destroy_infer_desc(inf);

	cve_dle_remove_from_list(ntw->inf_list, ntw_list, inf);

	OS_FREE(inf, sizeof(*inf));

out:
	cve_os_unlock(&g_cve_driver_biglock);

	return retval;
}

int cve_ds_handle_execute_infer(cve_context_process_id_t context_pid,
		cve_context_id_t context_id,
		cve_network_id_t ntw_id,
		cve_infer_id_t inf_id,
		__u32 reserve_resource) {
	int retval = CVE_DEFAULT_ERROR_CODE;
	struct ice_infer *inf;
	struct ice_network *ntw;
	struct cve_device_group *dg = cve_dg_get();

#ifndef RING3_VALIDATION
	DO_TRACE(trace_icedrvExecuteNetwork(SPH_TRACE_DRV_EXECUTE_NETWORK,
		SPH_TRACE_OP_STATE_START, context_id, ntw_id, inf_id,
		SPH_TRACE_OP_STATUS_NULL, 0));
#endif

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
		retval = -ICEDRV_KERROR_NTW_INVAL_ID;
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"ERROR:%d Given NETWORK_ID:%lld is not present in this context\n",
				retval, ntw_id);
		goto out;
	}

	inf = cve_dle_lookup(ntw->inf_list, ntw_list, infer_id, inf_id);
	if (inf == NULL) {
		/* TODO: New Error Code required */
		retval = -ICEDRV_KERROR_NTW_INVAL_ID;
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"Given InfID=0x%llx is not present in NtwId=0x%llx. Error=%d\n",
				inf_id, ntw_id, retval);
		goto out;
	}

	if (inf->exe_status != INF_EXE_STATUS_IDLE) {
		retval = -ICEDRV_KERROR_INF_EALREADY;
		goto out;
	}
	inf->exe_status = INF_EXE_STATUS_QUEUED;
	cve_dle_add_to_list_before(ntw->inf_exe_list, exe_list, inf);

	/* Obsolete */
	ntw->reserve_resource = reserve_resource;

#ifndef RING3_VALIDATION
	DO_TRACE(trace_icedrvExecuteNetwork(SPH_TRACE_DRV_EXECUTE_NETWORK,
		SPH_TRACE_OP_STATE_QUEUED, ntw->wq->context->context_id,
		ntw->network_id, inf->infer_id,
		SPH_TRACE_OP_STATUS_NULL, 0));

	ice_swc_counter_inc(ntw->hswc,
			ICEDRV_SWC_INFER_COUNTER_EXE_TOTAL);
#endif

	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"Processing ExecuteInfer. NtwID=%lx, InfID=%lx\n",
		(uintptr_t)ntw, (uintptr_t)inf);
	ice_schedule_network(ntw);

	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"Completed ExecuteInfer. NtwID=%lx, InfID=%lx\n",
		(uintptr_t)ntw, (uintptr_t)inf);

out:
	cve_os_unlock(&g_cve_driver_biglock);

#ifndef RING3_VALIDATION
DO_TRACE_IF((retval < 0), trace_icedrvExecuteNetwork(
		SPH_TRACE_DRV_EXECUTE_NETWORK,
		SPH_TRACE_OP_STATE_COMPLETE, context_id,
		ntw_id, inf_id,
		SPH_TRACE_OP_STATUS_FAIL,
		retval));
#endif

	return retval;
}

int cve_ds_handle_destroy_network(cve_context_process_id_t context_pid,
		cve_context_id_t context_id,
		cve_context_id_t ntw_id) {
	int retval = CVE_DEFAULT_ERROR_CODE;
	struct ice_network *ntw;

#ifndef RING3_VALIDATION
	DO_TRACE(trace_icedrvDestroyNetwork(SPH_TRACE_DRV_DESTROY_NETWORK,
		SPH_TRACE_OP_STATE_START, context_id,
		ntw_id,
		SPH_TRACE_OP_STATUS_NULL,
		0));
#endif

	retval = cve_os_lock(&g_cve_driver_biglock, CVE_INTERRUPTIBLE);
	if (retval != 0) {
		retval = -ERESTARTSYS;
		goto out;
	}

	ntw = __get_network_from_id(context_pid, context_id, ntw_id);
	if (ntw == NULL) {
		retval = -ICEDRV_KERROR_NTW_INVAL_ID;
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"ERROR:%d Given NETWORK_ID:%lld is not present in this context\n",
				retval, ntw_id);
		goto out;
	}

	if (ntw->exe_status == NTW_EXE_STATUS_RUNNING) {
		retval = -ICEDRV_KERROR_NTW_EALREADY;
		goto out;
	} else if (ntw->exe_status == NTW_EXE_STATUS_QUEUED) {
		/* Remove from scheduler queue */
		ice_deschedule_network(ntw);
	}

	retval = __destroy_network(ntw);
	if (retval < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"__destroy_network failed %d\n", retval);
		goto out;
	}

	ntw->exe_status = NTW_EXE_STATUS_ABORTED;

	/* Since ICE have been released, check if any network can be scheduled
	 * from the queue. Do dummy schedule with current network, it wont be
	 * processed as its in ABORTED state, ut will trigger the schedule
	 * from queue
	 */
	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"Trying to schedule any pending ExecuteInfer. Deleting NtwID=%lx\n",
		(uintptr_t)ntw);
	ice_schedule_network(ntw);

	cve_dle_remove_from_list(ntw->wq->ntw_list, list, ntw);

#ifndef RING3_VALIDATION
	ice_swc_counter_dec(ntw->wq->context->hswc,
			ICEDRV_SWC_CONTEXT_COUNTER_INF_CURR);
	ice_swc_counter_inc(ntw->wq->context->hswc,
			ICEDRV_SWC_CONTEXT_COUNTER_INF_DEST);
	retval = ice_swc_destroy_node(ICEDRV_SWC_CLASS_INFER,
			(ntw->id + ntw_id));
	if (retval)
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"FAILED to delete the ntw sw cntr\n");
#endif
	OS_FREE(ntw, sizeof(*ntw));
out:
	cve_os_unlock(&g_cve_driver_biglock);

#ifndef RING3_VALIDATION
	DO_TRACE(trace_icedrvDestroyNetwork(SPH_TRACE_DRV_DESTROY_NETWORK,
		SPH_TRACE_OP_STATE_COMPLETE, context_id,
		ntw_id,
		(retval ? SPH_TRACE_OP_STATUS_FAIL : SPH_TRACE_OP_STATUS_PASS),
		retval));
#endif

	return retval;
}

static int __set_network_to_abort_state(struct cve_workqueue *wq)
{
	struct ice_network *head = wq->ntw_list;
	struct ice_network *curr = head;

	do {
		curr->abort_ntw = 1;
		if (curr->exe_status == NTW_EXE_STATUS_QUEUED ||
				curr->exe_status == NTW_EXE_STATUS_RUNNING)
			ice_deschedule_network(curr);

		curr->exe_status = NTW_EXE_STATUS_ABORTED;
		curr->active_ice = ice_di_is_network_under_execution(
				curr->network_id,
				wq->dg);
		cve_os_log(CVE_LOGLEVEL_DEBUG,
				"Network:%p %d ICE have active jobs\n",
				curr, curr->active_ice);
		curr = cve_dle_next(curr, list);
	} while (head != curr);

	return 0;
}


static int __do_network_cleanup(struct cve_workqueue *wq)
{
	struct ice_network *head = wq->ntw_list;
	struct ice_network *curr = NULL;
	struct ice_network *next = NULL;
	int ret = 0, status = 1;
	u32 is_last = 0;
	u32 timeout_msec = 2000;

	/* try to destroy all networks within this workqueue */
	if (head == NULL)
		goto exit;

	__set_network_to_abort_state(wq);

	curr = head;
	do {
		next = cve_dle_next(curr, list);

		if (next == curr)
			is_last = 1;

		cve_os_log(CVE_LOGLEVEL_DEBUG,
				"WQ:%p Remove Network:%p\n", wq, curr);

		cve_dle_remove_from_list(wq->ntw_list, list, curr);
		/* release the global lock to enable scheduling of ICE bh */
		if (curr->active_ice) {
			cve_os_unlock(&g_cve_driver_biglock);

			/* Wait for ICE bh to signal resource release,
			 * this function retruns:
			 * -ERESTARTSYS, if interrupted
			 * 0 on timeout [assuming that job would
			 * complete in max 10 sec]
			 * >0 condition evaluated to true before
			 * timeout is elapsed
			 */
			status = cve_os_block_interruptible_timeout(
					&curr->abort_wq,
					(curr->active_ice == 0),
					(timeout_msec * curr->active_ice));
			cve_os_log(CVE_LOGLEVEL_INFO,
					"Network:%p wait status:%d, %d ICE still have active jobs\n",
					curr, status, curr->active_ice);
			ret = cve_os_lock(&g_cve_driver_biglock,
					CVE_INTERRUPTIBLE);
			if (ret != 0) {
				cve_os_log(CVE_LOGLEVEL_ERROR,
						"Network:%p ERROR during lock\n",
						curr);
				goto exit;
			}
		}

		if (status <= 0) {
			/* wait either timed out or an error occured, so do
			 * forced cleanup
			 */
			cve_os_log(CVE_LOGLEVEL_ERROR,
					"Network:%p %d ICE still have active jobs, doing forced cleanup\n",
					curr, curr->active_ice);
			/* If here, make sure to Block MMU access */
			__forced_hw_cleanup(curr);
		}

		/* destroy the network */
		__destroy_network(curr);
		/* setting default value */
		status = 1;

		if (!is_last)
			curr = cve_dle_next(curr, list);
	} while (!is_last);

exit:
	return ret;
}

void ice_ds_handle_ntw_error(struct cve_device *dev,
		u64 icedc_err_status, u8 is_cntr_overflow)
{
	struct ice_network *ntw;
	struct cve_device_group *dg = cve_dg_get();

	ntw = (struct ice_network *)dev->last_network_id;
	if (!is_cntr_overflow)
		ntw->icedc_err_status = icedc_err_status;

	dg->icedc_state = ICEDC_STATE_CARD_RESET_REQUIRED;
}

void ice_ds_handle_ice_error(struct cve_device *dev,
		u64 ice_err_status)
{
	struct ice_network *ntw;

	ntw = (struct ice_network *)dev->last_network_id;
	ntw->ice_err_status |= ice_err_status;
}

void cve_ds_handle_job_completion(struct cve_device *dev,
	cve_ds_job_handle_t ds_job_handle,
	enum cve_job_status job_status, u64 exec_time)
{
	struct jobgroup_descriptor *jobgroup;
	struct cve_workqueue *wq;
	struct ds_context *context;
	struct job_descriptor *job;
	struct ice_network *ntw;

	job = (struct job_descriptor *)ds_job_handle;
	jobgroup = job->jobgroup;
	wq = jobgroup->wq;
	context = wq->context;
	ntw = jobgroup->network;

	ntw->ntw_exec_time[dev->dev_index] += exec_time;

	/* Mark the device as idle */
	dev->state = CVE_DEVICE_IDLE;
	ntw->num_ice_idle++;

	if (ntw->shared_read)
		is_shared_read_error(ntw, dev, dev->dev_index / 2);

	if (ice_ds_is_network_active(dev->last_network_id) == 0) {

		/* TODO: Must verify this flow  */
		/* All resource must be released */
		ntw->reserve_resource = 0x0;
		ice_ds_ntw_resource_release(ntw);

		return;
	}

	/* remove the job from the jobgroup list */
	jobgroup->ended_jobs_nr++;
	jobgroup->exe_num_of_cves--;

	/* keep track the aborted jobs */
	if (job_status == CVE_JOBSTATUS_ABORTED)
		jobgroup->aborted_jobs_nr++;

	if (jobgroup->submitted_jobs_nr ==
			jobgroup->ended_jobs_nr) {

		/* Set dirty dram for all ARC input (CVE output) allocs */
		set_dirty_dram_cve_output_buff(context->buf_list,
			job->cve_alloc_desc,
			job->allocs_nr,
			dev);

		/* mark this JG as completed */
		jobgroup->completed = 1;
		ntw->num_jg_completed++;

		cve_os_log(CVE_LOGLEVEL_DEBUG,
				"NtwID=0x%llx JG_ID=0x%lx Completed. Completed_JG=%d, Scheduled_JG=%d, Total_JG:%d\n",
				ntw->network_id,
				(uintptr_t)jobgroup,
				ntw->num_jg_completed,
				ntw->num_jg_scheduled,
				ntw->num_jg);

		if (ntw->num_jg_completed == ntw->num_jg) {

			ntw->exe_status = NTW_EXE_STATUS_QUEUED;
			ntw->curr_exe->exe_status = INF_EXE_STATUS_IDLE;

			__add_network_completion_event(ntw);
		}

		/* try to dispatch another workload */
		ice_scheduler_engine();
	}
	cve_os_log(CVE_LOGLEVEL_INFO,
			"EXIT: NtwID=0x%llx JG_ID=0x%lx Completed. Completed_JG=%d, Scheduled_JG=%d, Total_JG:%d\n",
			ntw->network_id,
			(uintptr_t)jobgroup,
			ntw->num_jg_completed,
			ntw->num_jg_scheduled,
			ntw->num_jg);
}

int cve_ds_handle_fw_loading(
		cve_context_process_id_t context_pid,
		cve_context_process_id_t context_id,
		u64 fw_image,
		u64 fw_binmap,
		u32 fw_binmap_size_bytes)
{
	int retval = CVE_DEFAULT_ERROR_CODE;
	struct ds_context *context = NULL;
	struct cve_context_process *context_process = NULL;

	retval = cve_os_lock(&g_cve_driver_biglock, CVE_INTERRUPTIBLE);
	if (retval != 0) {
		retval = -ERESTARTSYS;
		goto out;
	}

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

	/*
	 * TODO: This flow can be optimized. This function
	 * load the image and then map it to cve device.
	 * loading operation can be performed only once,
	 * map operation should be performed multiple times
	 * according to number of CVEs in the system
	 */
	retval = cve_dev_fw_load_and_map(context->dev_hctx_list,
			fw_image,
			fw_binmap,
			fw_binmap_size_bytes);

	if (retval < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
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

int cve_ds_open_context(
		cve_context_process_id_t context_pid,
		u64 *out_contextid)
{
	struct cve_context_process *context_process = NULL;
	struct ds_context *new_context = NULL;
	struct cve_workqueue *new_workqueue = NULL;
	struct cve_device_group *dg = NULL;

	int retval = cve_os_lock(&g_cve_driver_biglock, CVE_INTERRUPTIBLE);

#ifndef RING3_VALIDATION
	DO_TRACE(trace_icedrvCreateContext(SPH_TRACE_DRV_CREATE_CONTEXT,
		SPH_TRACE_OP_STATE_START, 0,
		SPH_TRACE_OP_STATUS_NULL, 0));
#endif

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
	retval = cve_dev_open_all_contexts(&new_context->dev_hctx_list);
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"cve_dev_open_all_contexts failed %d\n", retval);
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

	*out_contextid = new_context->context_id;

#ifndef RING3_VALIDATION
	retval = ice_swc_create_node(ICEDRV_SWC_CLASS_CONTEXT,
					new_context->context_id,
					0,
					&new_context->hswc);
	if (retval < 0) {
		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Unable to create SW Counter's Context node\n");
		goto out;
	}

	ice_swc_counter_inc(g_sph_swc_global,
			ICEDRV_SWC_GLOBAL_COUNTER_CTX_TOTAL);
	ice_swc_counter_inc(g_sph_swc_global,
			ICEDRV_SWC_GLOBAL_COUNTER_CTX_CURR);
#endif

	/* success */
	retval = 0;
out:
	if (retval != 0) {
		cleanup_context(new_context);
		OS_FREE(new_context, sizeof(*new_context));
	}

	cve_os_unlock(&g_cve_driver_biglock);

#ifndef RING3_VALIDATION
	DO_TRACE(trace_icedrvCreateContext(SPH_TRACE_DRV_CREATE_CONTEXT,
		SPH_TRACE_OP_STATE_COMPLETE,
		(retval ? 0 : new_context->context_id),
		(retval ? SPH_TRACE_OP_STATUS_FAIL : SPH_TRACE_OP_STATUS_PASS),
		retval));
#endif

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
	OS_FREE(context, sizeof(*context));

#ifndef RING3_VALIDATION
	ice_swc_counter_dec(g_sph_swc_global,
			ICEDRV_SWC_GLOBAL_COUNTER_CTX_CURR);
	ice_swc_counter_inc(g_sph_swc_global,
			ICEDRV_SWC_GLOBAL_COUNTER_CTX_DEST);
#endif

}

int cve_ds_close_context(
		cve_context_process_id_t context_pid,
		cve_context_id_t context_id)
{
	struct ds_context *context = NULL;
	struct cve_context_process *context_process = NULL;
	struct cve_workqueue *workqueue = NULL;

	int retval = cve_os_lock(&g_cve_driver_biglock, CVE_INTERRUPTIBLE);

#ifndef RING3_VALIDATION
	DO_TRACE(trace_icedrvDestroyContext(SPH_TRACE_DRV_DESTROY_CONTEXT,
		SPH_TRACE_OP_STATE_START, context_id,
		SPH_TRACE_OP_STATUS_NULL, 0));
#endif
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
	DO_TRACE(trace_icedrvDestroyContext(SPH_TRACE_DRV_DESTROY_CONTEXT,
		SPH_TRACE_OP_STATE_COMPLETE,
		context_id,
		(retval ? SPH_TRACE_OP_STATUS_FAIL : SPH_TRACE_OP_STATUS_PASS),
		retval));
#endif

	return retval;
}

int cve_ds_wait_for_event(cve_context_process_id_t context_pid,
		struct cve_get_event *event)
{
	u32 timeout_msec = event->timeout_msec;
	enum cve_wait_event_status *wait_status = &event->wait_status;
	struct cve_context_process *context_process = NULL;
	int retval = cve_os_lock(&g_cve_driver_biglock, CVE_INTERRUPTIBLE);

	if (retval != 0) {
		retval = -ERESTARTSYS;
		goto out;
	}

	/* get the process based on the id */
	retval = cve_context_process_get(context_pid, &context_process);
	if (retval != 0)
		goto unlock;

	cve_os_unlock(&g_cve_driver_biglock);

	/*in case debug enabled don't timeout (~1000hours)*/
	if (unlikely(cve_debug_get(DEBUG_TENS_EN)))
		timeout_msec = 0xFFFFFFFF;

	/* Wait for events objects to be available. This functions returns:
	 * -ERESTARTSYS, if interrupted
	 * 0 on timeout
	 * >0 condition evaluated to true before timeout is elapsed
	 */
	retval = cve_os_block_interruptible_timeout(
			&context_process->events_wait_queue,
			context_process->events,
			timeout_msec);

	if (retval == 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "Timeout\n");
		*wait_status = CVE_WAIT_EVENT_TIMEOUT;
		goto out;
	} else if (retval == -ERESTARTSYS) {
		*wait_status = CVE_WAIT_EVENT_ERROR;
		goto out;
	} else {
		*wait_status = CVE_WAIT_EVENT_COMPLETE;
		retval = 0;
	}

	cve_os_lock(&g_cve_driver_biglock,
			CVE_NON_INTERRUPTIBLE);

	copy_event_data_and_remove(context_process,
			context_process->events,
			event);
unlock:
	cve_os_unlock(&g_cve_driver_biglock);
out:
	return retval;

}

int cve_ds_get_version(cve_context_process_id_t context_pid,
		cve_context_id_t context_id,
		struct cve_components_version *out_versions)
{
	struct cve_context_process *context_process = NULL;
	struct ds_context *context = NULL;
	struct cve_components_version versions;
	int retval = cve_os_lock(&g_cve_driver_biglock, CVE_INTERRUPTIBLE);

	if (retval != 0) {
		retval = -ERESTARTSYS;
		goto out;
	}

	/* get the process based on the id */
	retval = cve_context_process_get(context_pid, &context_process);
	if (retval != 0)
		goto unlock;

	/* get the context from the process */
	context = get_context_from_process(
			context_process,
			context_id);
	if (!context) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"get_context_from_process failed\n");
		retval = -EINVAL;
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
	cve_dev_get_custom_fw_version_per_context(context->dev_hctx_list,
			CVE_FW_IVP_BANK0_TYPE,
			&versions.ivp_bank0_version);
	cve_dev_get_custom_fw_version_per_context(context->dev_hctx_list,
			CVE_FW_IVP_BANK1_TYPE,
			&versions.ivp_bank1_version);
	cve_dev_get_custom_fw_version_per_context(context->dev_hctx_list,
			CVE_FW_ASIP_BANK0_TYPE,
			&versions.asip_bank0_version);
	cve_dev_get_custom_fw_version_per_context(context->dev_hctx_list,
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

int ice_ds_is_network_active(u64 network_id)
{
	struct ice_network *network;

	network = (struct ice_network *)network_id;
	if (network->abort_ntw == 1)
		return 0;
	return 1;
}

static int __forced_hw_cleanup(struct ice_network *ntw)
{
	struct cve_device *dev, *dev_head;
	struct cve_device_group *dg = cve_dg_get();
	cve_ds_job_handle_t ds_job_handle;
	struct job_descriptor *job;
	struct jobgroup_descriptor *jg;
	int i;

	for (i = 0; i < MAX_NUM_ICEBO; i++) {
		dev_head = dg->dev_info.icebo_list[i].dev_list;
		dev = dev_head;
		if (!dev_head)
			continue;
		do {
			if (dev->last_network_id == ntw->network_id &&
				dev->state == CVE_DEVICE_BUSY) {
				ice_di_get_job_handle(dev, &ds_job_handle);
				job = (struct job_descriptor *)ds_job_handle;
				jg = job->jobgroup;

				cve_os_log(CVE_LOGLEVEL_INFO,
					"NTW:0x%p JG:%p ICE(%d):%p GlobalJgCount:%d Doing forced cleanup\n",
					ntw, jg, dev->dev_index, dev,
					g_jg_count);

				if (!ice_di_mmu_block_entrance(dev)) {
					cve_os_dev_log(CVE_LOGLEVEL_ERROR,
						dev->dev_index,
						"Unable to set BLOCK_ENTRANCE. ICE may access invalid location.\n");
				}

				/* Mark the device as idle */
				dev->state = CVE_DEVICE_IDLE;
				dev->pnetwork_id = INVALID_NETWORK_ID;

				jg->ended_jobs_nr++;

				ntw->num_ice_idle++;

			/* TODO: Since this is a forced cleanup and means ICE
			 * is probably in a bad state. So we should restart the
			 * ICE itself
			 */
			}
			dev = cve_dle_next(dev, bo_list);
		} while (dev != dev_head);
	}

	return 0;
}

/*
 * Remove ICE from DG and allocate it to Network list
*/
static int __ntw_reserve_ice(struct ice_network *ntw)
{
	int i, ret = 0;
	struct cve_device *dev;
	struct icebo_desc *bo;
	struct cve_device_group *dg = g_cve_dev_group_list;

	/* At this point ice requirement must be satisfied */
	ASSERT((ntw->num_picebo_req + ntw->num_sicebo_req) <=
			dg->dev_info.num_picebo);
	ASSERT(ntw->num_dicebo_req <= ((dg->dev_info.num_picebo -
			ntw->num_picebo_req - ntw->num_sicebo_req) * 2
			+ dg->dev_info.num_dicebo));

	ret = cve_os_lock(&dg->poweroff_dev_list_lock, CVE_INTERRUPTIBLE);
	if (ret != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "cve_os_lock error\n");
		return -1;
	}

	for (i = 0; i < ntw->num_picebo_req; i++) {
		bo = dg->dev_info.picebo_list;

		/* add first device of BOn to ntw ice list */
		dev = bo->dev_list;
		dev->pnetwork_id = ntw->network_id;
		cve_os_log(CVE_LOGLEVEL_INFO,
				"NTW:%p ICEBO:%d reserved ICE%d power_status:%d\n",
				ntw, bo->bo_id, dev->dev_index,
				dev->power_state);

		cve_di_set_device_reset_flag(dev, CVE_DI_RESET_DUE_NTW_SWITCH);
		cve_dle_add_to_list_before(ntw->ice_list, owner_list, dev);
		if (dev->power_state == ICE_POWER_OFF_INITIATED)
			dev->power_state = ICE_POWER_ON;

		/* add second device of BOn to ntw ice list */
		dev = cve_dle_next(dev, bo_list);
		dev->pnetwork_id = ntw->network_id;
		cve_os_log(CVE_LOGLEVEL_INFO,
				"NTW:%p ICEBO:%d reserved ICE%d power_status:%d\n",
				ntw, bo->bo_id, dev->dev_index,
				dev->power_state);

		cve_di_set_device_reset_flag(dev, CVE_DI_RESET_DUE_NTW_SWITCH);
		cve_dle_add_to_list_before(ntw->ice_list, owner_list, dev);
		if (dev->power_state == ICE_POWER_OFF_INITIATED)
			dev->power_state = ICE_POWER_ON;

		/* Update BO list */
		cve_dle_remove_from_list(dg->dev_info.picebo_list, owner_list,
			bo);
		dg->dev_info.num_picebo--;
		dg->dev_info.icebo_list[bo->bo_id].state = NO_ICE;
		ntw->pjob_info.picebo[bo->bo_id] = 1;
	}
	for (i = 0; i < ntw->num_sicebo_req; i++) {
		bo = dg->dev_info.picebo_list;

		/* add first device of BOn to ntw ice list */
		dev = bo->dev_list;
		dev->pnetwork_id = ntw->network_id;
		cve_os_log(CVE_LOGLEVEL_INFO,
				"NTW:%p ICEBO:%d reserved ICE%d power_status:%d\n",
				ntw, bo->bo_id, dev->dev_index,
				dev->power_state);

		cve_di_set_device_reset_flag(dev, CVE_DI_RESET_DUE_NTW_SWITCH);
		cve_dle_add_to_list_before(ntw->ice_list, owner_list, dev);
		if (dev->power_state == ICE_POWER_OFF_INITIATED)
			dev->power_state = ICE_POWER_ON;

		/* Update BO list */
		cve_dle_move(dg->dev_info.sicebo_list, dg->dev_info.picebo_list,
			owner_list, bo);
		dg->dev_info.num_picebo--;
		dg->dev_info.num_sicebo++;
		dg->dev_info.icebo_list[bo->bo_id].state = ONE_ICE;
		ntw->pjob_info.sicebo[bo->bo_id] = dev->dev_index;
	}
	for (i = 0; i < ntw->num_dicebo_req; i++) {
		if (dg->dev_info.dicebo_list) {
			bo = dg->dev_info.dicebo_list;
			dev = bo->dev_list;

			if ((dev->pnetwork_id != INVALID_NETWORK_ID) ||
				(dev->state != CVE_DEVICE_IDLE))
				dev = cve_dle_next(dev, bo_list);

			cve_dle_remove_from_list(dg->dev_info.dicebo_list,
				owner_list, bo);
			dg->dev_info.num_dicebo--;
			dg->dev_info.icebo_list[bo->bo_id].state = NO_ICE;
		} else {
			bo = dg->dev_info.picebo_list;
			dev = bo->dev_list;
			cve_dle_move(dg->dev_info.dicebo_list,
				dg->dev_info.picebo_list, owner_list, bo);
			dg->dev_info.num_dicebo++;
			dg->dev_info.num_picebo--;
			dg->dev_info.icebo_list[bo->bo_id].state = ONE_ICE;
		}
		dev->pnetwork_id = ntw->network_id;
		cve_os_log(CVE_LOGLEVEL_INFO,
				"NTW:%p ICEBO:%d reserved ICE%d power_status:%d\n",
				ntw, bo->bo_id, dev->dev_index,
				dev->power_state);

		cve_di_set_device_reset_flag(dev, CVE_DI_RESET_DUE_NTW_SWITCH);
		cve_dle_add_to_list_before(ntw->ice_list, owner_list, dev);
		if (dev->power_state == ICE_POWER_OFF_INITIATED)
			dev->power_state = ICE_POWER_ON;
		ntw->pjob_info.dicebo[bo->bo_id] = dev->dev_index;
	}

	cve_os_unlock(&dg->poweroff_dev_list_lock);

	ntw->num_ice_idle = ntw->num_ice;

	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"(Ntw: %p) Reserved pICEBO=%d sICEBO=%d dICEBO=%d\n",
		ntw, ntw->num_picebo_req,
		ntw->num_sicebo_req, ntw->num_dicebo_req);

	for (i = 0; i < MAX_NUM_ICEBO; i++) {
		if ((ntw->pjob_info.picebo[i] != INVALID_ENTRY) ||
			(ntw->pjob_info.sicebo[i] != INVALID_ENTRY) ||
			(ntw->pjob_info.dicebo[i] != INVALID_ENTRY))
			cve_os_log(CVE_LOGLEVEL_DEBUG,
			"(Ntw: %p) pICEBO[%d]=%d sICEBO[%d]=%d dICEBO[%d]=%d\n",
			ntw, i, ntw->pjob_info.picebo[i], i,
			ntw->pjob_info.sicebo[i], i, ntw->pjob_info.dicebo[i]);
	}

	ice_swc_create_infer_device_node(ntw);

	return ret;
}

static void __ntw_release_ice(struct ice_network *ntw)
{
	struct cve_device *head;
	struct cve_device_group *dg = g_cve_dev_group_list;
	int bo_id;

	while (ntw->ice_list) {
		head = ntw->ice_list;
		bo_id = head->dev_index / 2;
		cve_dle_remove_from_list(ntw->ice_list, owner_list, head);
		cve_os_log(CVE_LOGLEVEL_INFO,
				"NTW:%p ICEBO:%d released ICE%d\n",
				ntw, bo_id, head->dev_index);

		head->pnetwork_id = INVALID_NETWORK_ID;
		if (dg->dev_info.icebo_list[bo_id].state == NO_ICE) {
			cve_dle_add_to_list_before(dg->dev_info.dicebo_list,
				owner_list, &dg->dev_info.icebo_list[bo_id]);
			dg->dev_info.num_dicebo++;
			dg->dev_info.icebo_list[bo_id].state = ONE_ICE;
		} else if (dg->dev_info.icebo_list[bo_id].state == ONE_ICE) {
			if (ntw->pjob_info.sicebo[bo_id] == head->dev_index) {
				cve_dle_move(dg->dev_info.picebo_list,
				dg->dev_info.sicebo_list, owner_list,
				&dg->dev_info.icebo_list[bo_id]);
				dg->dev_info.num_picebo++;
				dg->dev_info.num_sicebo--;
			} else {
				cve_dle_move(dg->dev_info.picebo_list,
				dg->dev_info.dicebo_list, owner_list,
				&dg->dev_info.icebo_list[bo_id]);
				dg->dev_info.num_picebo++;
				dg->dev_info.num_dicebo--;
			}
			dg->dev_info.icebo_list[bo_id].state = TWO_ICE;
		} else
			ASSERT(false);
	}

	ntw->num_ice_idle = 0;
	cve_os_log(CVE_LOGLEVEL_INFO,
		"Released %d ICE from Ntw:%p\n", ntw->num_ice, ntw);
}

static int __ntw_reserve_cntr(struct ice_network *ntw)
{
	int i, ret = 0;
	u32 mask, cntr_bitmap;
	struct cve_device_group *dg = g_cve_dev_group_list;
	struct cve_hw_cntr_descriptor *hw_cntr;
	u32 count = 0;

	__local_builtin_popcount(ntw->cntr_bitmap, count);

	cntr_bitmap = ntw->cntr_bitmap;
	while (cntr_bitmap) {

		/* #Trailing zero indicates counter_id */
		i = __builtin_ctz(cntr_bitmap);
		mask = (1 << i);

		cntr_bitmap &= ~(mask);

		ASSERT(ntw->cntr_info.cntr_id_map[i] == INVALID_CTR_ID);

		/* Allocate new Counter and map */
		hw_cntr = dg->hw_cntr_list;

		/* Should make sure that enough Counters are available */
		ASSERT(hw_cntr != NULL);

		cve_dle_move(ntw->cntr_list, dg->hw_cntr_list, list, hw_cntr);
		dg->counters_nr--;

		hw_cntr->network_id = ntw->network_id;

		ntw->cntr_info.cntr_id_map[i] = hw_cntr->hw_cntr_id;

		cve_os_log(CVE_LOGLEVEL_INFO,
			"NTW:%p Map Counter[%u]->%u\n",
			ntw, i, hw_cntr->hw_cntr_id);
	}

	cve_os_log(CVE_LOGLEVEL_INFO,
		"Reserved %d Counter for Ntw:%p\n", count, ntw);

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
		dg->counters_nr++;

		head->network_id = INVALID_NETWORK_ID;

		ntw->cntr_info.cntr_id_map[i] = INVALID_CTR_ID;


		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Undo Map Counter [%u] = %u\n",
			i, head->hw_cntr_id);
	}
	cve_os_log(CVE_LOGLEVEL_INFO,
		"Released %d Counter from Ntw:%p\n", count, ntw);
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

static int __ntw_reserve_llc(struct ice_network *ntw)
{
	int ret = 0;
	struct cve_device_group *dg = cve_dg_get();

	dg->available_llc -= ntw->llc_size;

	cve_os_log(CVE_LOGLEVEL_INFO,
			"Reserved %d LLC for Ntw:%p\n",
			ntw->llc_size, ntw);

	return ret;
}

static void __ntw_release_llc(struct ice_network *ntw)
{
	struct cve_device_group *dg = g_cve_dev_group_list;

	dg->available_llc += ntw->llc_size;

	cve_os_log(CVE_LOGLEVEL_INFO,
		"Released %d LLC from Ntw:%p\n", ntw->llc_size, ntw);
}

static void __update_ice_req(struct ice_network *ntw,
				struct cve_device_group *dg)
{
	int temp;

	temp = ntw->num_picebo_req + ntw->num_sicebo_req;
	if (dg->dev_info.num_picebo < temp) {
		/* if here then it means that requested resource is not met
		 * hence fall back to default case
		 */
		ntw->num_picebo_req = dg->dev_info.num_picebo;
		ntw->num_sicebo_req = 0;
		temp = (2 * ntw->num_picebo_req) + ntw->num_sicebo_req;
		ntw->num_dicebo_req = ntw->num_ice - temp;
		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"(Ntw: %p) ICE requirement updated now pICEBO:%d sICEBO:%d dICEBO:%d\n",
			ntw, ntw->num_picebo_req, ntw->num_sicebo_req,
			ntw->num_dicebo_req);
	} else {
		/* If here then it means that requested resource is met
		 * and ICEBO_PREFERRED can act like MANDATORY during scheduling
		 * hence changing icebo_req
		 */
		ntw->icebo_req = (ntw->icebo_req == ICEBO_PREFERRED) ?
					ICEBO_MANDATORY : ntw->icebo_req;
		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"(Ntw: %p) icebo_req:%d\n",
			ntw, ntw->icebo_req);
	}


}

static int __check_resource_availability(struct ice_network *ntw)
{
	struct cve_device_group *dg = cve_dg_get();
	int ret = 0, dice_num;
	u32 count = 0;

	if (dg->available_llc < ntw->llc_size) {
		ret = -ICEDRV_KERROR_RESOURCE_BUSY;
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"Insufficient LLC for Ntw:%p (Avl=%d, Req=%d)\n",
				ntw, dg->available_llc, ntw->llc_size);
	}

	if (ntw->icebo_req == ICEBO_MANDATORY) {
		if (dg->dev_info.num_picebo < ntw->num_picebo_req) {
			cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Insufficient pICEBO for Ntw:%p (Avl=%d, Req=%d)\n",
			ntw, dg->dev_info.num_picebo, ntw->num_picebo_req);
			return -ICEDRV_KERROR_RESOURCE_BUSY;
		}
		if ((dg->dev_info.num_picebo - ntw->num_picebo_req) <
			ntw->num_sicebo_req) {
			cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Insufficient sICEBO for Ntw:%p (Avl=%d, Req=%d)\n",
			ntw, dg->dev_info.num_picebo - ntw->num_picebo_req,
			ntw->num_sicebo_req);
			return -ICEDRV_KERROR_RESOURCE_BUSY;
		}
		dice_num = ((dg->dev_info.num_picebo - ntw->num_picebo_req -
			ntw->num_sicebo_req) * 2) + dg->dev_info.num_dicebo;
		if (dice_num < ntw->num_dicebo_req) {
			cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Insufficient dICEBO for Ntw:%p (Avl=%d, Req=%d)\n",
			ntw, dice_num, ntw->num_dicebo_req);
			return -ICEDRV_KERROR_RESOURCE_BUSY;
		}
	} else {
		dice_num = (2 * dg->dev_info.num_picebo) +
				dg->dev_info.num_dicebo;
		if (dice_num < ntw->num_ice) {
			cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Insufficient ICE for Ntw:%p (Avl=%d, Req=%d)\n",
			ntw, dice_num, ntw->num_ice);
			return -ICEDRV_KERROR_RESOURCE_BUSY;
		}
		__update_ice_req(ntw, dg);
	}

	__local_builtin_popcount(ntw->cntr_bitmap, count);
	if (dg->counters_nr < count) {
		cve_os_log(CVE_LOGLEVEL_DEBUG,
				"Insufficient Counter for Ntw:%p (Avl=%d, Req=%d)\n",
				ntw, dg->counters_nr, count);
		ret = -ICEDRV_KERROR_RESOURCE_BUSY;
	}

	return ret;
}

int ice_ds_ntw_resource_reserve(struct ice_network *ntw)
{
	int res = 0;
	enum pool_status pstatus;

#ifndef RING3_VALIDATION
	struct cve_device *head, *next;
	struct cve_hw_cntr_descriptor *head_cntr, *next_cntr;
	u64 ntwIceMask = 0;
	u64 ntwCntrMask = 0;
#endif
	if (ntw->has_resource)
		goto end;

	pstatus = cve_ds_map_pool_context(ntw->wq->context);
	if (pstatus == POOL_EXHAUSTED) {
		res = -1;
		goto end;
	}

	res = __check_resource_availability(ntw);
	if (res < 0) {
		if (pstatus == POOL_ALLOCATED)
			cve_ds_unmap_pool_context(ntw->wq->context);
		goto end;
	}

	ASSERT(__ntw_reserve_llc(ntw) == 0);

	ASSERT(__ntw_reserve_ice(ntw) == 0);

	ASSERT(__ntw_reserve_cntr(ntw) == 0);

	ntw->wq->num_ntw_reserving_pool++;

	ntw->has_resource = 1;

#ifndef RING3_VALIDATION
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
		DO_TRACE(trace_icedrvNetworkResource(
			SPH_TRACE_DRV_NETWORK_RESOURCE,
			ntw->network_id, ntwIceMask, ntwCntrMask,
			ntw->llc_size));
	}
#endif
end:
	return res;
}

static void __power_off_ntw_devices(struct ice_network *ntw)
{
	int retval;
	struct cve_device *head = ntw->ice_list;
	struct cve_device *next = head;
	struct timespec curr_ts;
	struct cve_device_group *dg = g_cve_dev_group_list;

	getnstimeofday(&curr_ts);

	retval = cve_os_lock(&dg->poweroff_dev_list_lock, CVE_INTERRUPTIBLE);
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "cve_os_lock error\n");
		return;
	}

	do {
		if (next->power_state == ICE_POWER_ON) {

			/* Write current timestamp to Device */
			next->poweroff_ts = curr_ts;

			next->power_state = ICE_POWER_OFF_INITIATED;
			cve_os_log(CVE_LOGLEVEL_INFO,
					"NTW:%p Adding ICE%d to LPM Task\n",
					ntw, next->dev_index);
			cve_dle_add_to_list_before(dg->poweroff_dev_list,
				poweroff_list, next);
		}

		next = cve_dle_next(next, owner_list);
	} while (next != head);

	dg->start_poweroff_thread = 1;
	cve_os_unlock(&dg->poweroff_dev_list_lock);
	cve_os_wakeup(&dg->power_off_wait_queue);
}

void ice_ds_ntw_resource_release(struct ice_network *ntw)
{
	if (!ntw->has_resource)
		return;

	/* In case of RR user can specify if they want to Power Off devices.
	 * This option is not applicable without RR and such request should
	 * be rejected by UMD.
	 */
	if (!(ntw->reserve_resource & ICE_KEEP_ICES_ON))
		__power_off_ntw_devices(ntw);

	/* If ICE reservation not required, release it */
	if (!(ntw->reserve_resource & ICE_RESERVE_ICE)) {
		__ntw_release_ice(ntw);
		/* memset the ICE id map with invalid ICE ID i.e. 255 */
		memset(&ntw->pjob_info.ice_id_map[0], 0xFF,
				(sizeof(u8) * MAX_CVE_DEVICES_NR));
		memset(&ntw->pjob_info.picebo[0], 0xFF,
				(sizeof(u8) * MAX_NUM_ICEBO));
		memset(&ntw->pjob_info.sicebo[0], 0xFF,
				(sizeof(u8) * MAX_NUM_ICEBO));
		memset(&ntw->pjob_info.dicebo[0], 0xFF,
				(sizeof(u8) * MAX_NUM_ICEBO));
	} else {
		cve_os_log(CVE_LOGLEVEL_INFO,
			"ICE Reserved for Ntw=%p\n", ntw);
	}

	__ntw_reset_cntr(ntw);
	/* If Cntr reservation not required, release it */
	if (!(ntw->reserve_resource & ICE_RESERVE_COUNTERS)) {
		__ntw_release_cntr(ntw);
	} else if (ntw->cntr_bitmap) {
		cve_os_log(CVE_LOGLEVEL_INFO,
				"Counter Reserved for Ntw=%p\n", ntw);
	}

	/* If LLC reservation not required, release it */
	if (!(ntw->reserve_resource & ICE_RESERVE_LLC)) {
		__ntw_release_llc(ntw);
	} else {
		cve_os_log(CVE_LOGLEVEL_DEBUG,
				"LLC Reserved for Ntw=%p\n", ntw);
	}

	/* If RR not required by any NTW of the context, release Pool */
	if (ntw->reserve_resource & ICE_RESERVE_POOL) {
		cve_os_log(CVE_LOGLEVEL_INFO,
				"Pool Reserved for Ntw=%p\n", ntw);
	} else
		ntw->wq->num_ntw_reserving_pool--;

	if (ntw->wq->num_ntw_reserving_pool) {
		cve_os_log(CVE_LOGLEVEL_INFO,
			"Pool reserved for context=%p num_ntw_reserving_pool=%d\n",
			ntw->wq->context, ntw->wq->num_ntw_reserving_pool);
	} else {
		cve_di_unset_pool_registers(
			ntw->wq->context->pool_id);
		cve_ds_unmap_pool_context(
			ntw->wq->context);
	}

	if (!(ntw->reserve_resource & ~ICE_SET_BREAK_POINT))
		ntw->has_resource = 0;
}

static void __flush_ntw_buffers(struct cve_device *dev,
		struct ice_network *ntw)
{
	struct cve_user_buffer *buf_list, *cur_buf;
	u32 idx = 0;

	buf_list = ntw->buf_list;

	for (; idx < ntw->num_buf; idx++) {
		cur_buf = &buf_list[idx];
		cve_mm_sync_mem_to_dev(cur_buf->allocation,
			0, dev);
		cve_os_log(CVE_LOGLEVEL_DEBUG,
				"Flushing the buffers. NtwID=0x%lx, Buffer[%d]=0x%lx\n",
				(uintptr_t)ntw, idx, (uintptr_t)cur_buf);
	}
}

static void __flush_inf_buffers(struct ice_infer *inf)
{
	u32 idx;
	struct cve_infer_buffer *cur_buf;
	struct cve_device *dev = ice_get_first_dev();

	for (idx = 0; idx < inf->num_buf; idx++) {
		cur_buf = &inf->buf_list[idx];
		cve_mm_sync_mem_to_dev(cur_buf->allocation,
			inf->infer_id, dev);
		cve_os_log(CVE_LOGLEVEL_DEBUG,
				"Flushing the buffers. InfID=0x%lx, Buffer[%d]=0x%lx\n",
				(uintptr_t)inf, idx, (uintptr_t)cur_buf);
	}
}

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
				IDC_REGS_IDC_MMIO_BAR0_MEM_ICEPE_MMOFFSET);

		/* Check if Device is powered ON */
		if ((value & pe_mask) != pe_mask) {
			/* TODO: check whether to continue or error out */
			cve_os_log(CVE_LOGLEVEL_INFO,
				"ICE-%d is not powered on, skipping\n", i);
			cve_os_unlock(&g_cve_driver_biglock);
			continue;
		}

		cve_di_reset_cve_dump(dev, DUMP_CVE_NOW,
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
	IDC_REGS_ICEPE_t reg;

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
				IDC_REGS_IDC_MMIO_BAR0_MEM_ICEPE_MMOFFSET);
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
