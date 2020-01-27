/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#include "inf_copy.h"
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/scatterlist.h>
#include <linux/limits.h>
#include "sphcs_cs.h"
#include "sphcs_inf.h"
#include "sph_log.h"
#include "ipc_protocol.h"
#include "inf_context.h"
#include "inf_exec_req.h"
#include "sph_error.h"
#include "sphcs_trace.h"

static int inf_copy_req_sched(struct inf_exec_req *req);
static bool inf_copy_req_ready(struct inf_exec_req *req);
static int inf_copy_req_execute(struct inf_exec_req *req);
static void inf_copy_req_complete(struct inf_exec_req *req,
				  int                  err,
				  const void          *error_msg,
				  int32_t              error_msg_size);
static void send_copy_report(struct inf_exec_req *req,
			     enum event_val       eventVal);
static int inf_req_copy_put(struct inf_exec_req *req);
static int inf_copy_migrate_priority(struct inf_exec_req *req, uint8_t priority);
static void inf_copy_req_release(struct kref *kref);

struct func_table const s_copy_funcs = {
	.schedule = inf_copy_req_sched,
	.is_ready = inf_copy_req_ready,
	.execute = inf_copy_req_execute,
	.complete = inf_copy_req_complete,
	.send_report = send_copy_report,
	.obj_put = inf_req_copy_put,
	.migrate_priority = inf_copy_migrate_priority,

	/* This function should not be called directly, use inf_exec_req_put instead */
	.release = inf_copy_req_release
};

static int copy_complete_cb(struct sphcs *sphcs, void *ctx, const void *user_data, int status, u32 xferTimeUS)
{
	int err;
	struct inf_exec_req *req = *((struct inf_exec_req **)user_data);
	struct inf_copy *copy;

	SPH_ASSERT(req != NULL);

	if (unlikely(status == SPHCS_DMA_STATUS_FAILED)) {
		err = -SPHER_DMA_ERROR;
	} else {
		/* if status is not an error - it must be done */
		SPH_ASSERT(status == SPHCS_DMA_STATUS_DONE);
		err = 0;
	}

	copy = req->copy;
	if (xferTimeUS > 0 &&
	    SPH_SW_GROUP_IS_ENABLE(copy->sw_counters,
				   COPY_SPHCS_SW_COUNTERS_GROUP)) {
		SPH_SW_COUNTER_ADD(copy->sw_counters,
					COPY_SPHCS_SW_COUNTERS_HWEXEC_TOTAL_TIME,
					xferTimeUS);

		if (xferTimeUS < copy->min_hw_exec_time) {
			SPH_SW_COUNTER_SET(copy->sw_counters,
						COPY_SPHCS_SW_COUNTERS_HWEXEC_MIN_TIME,
						xferTimeUS);
			copy->min_hw_exec_time = xferTimeUS;
		}

		if (xferTimeUS > copy->max_hw_exec_time) {
			SPH_SW_COUNTER_SET(copy->sw_counters,
						COPY_SPHCS_SW_COUNTERS_HWEXEC_MAX_TIME,
						xferTimeUS);
			copy->max_hw_exec_time = xferTimeUS;
		}
	}

	req->f->complete(req, err, NULL, 0);

	return err;
}

int inf_d2d_copy_create(uint16_t protocolCopyID,
			struct inf_context *context,
			struct inf_devres *from_devres,
			uint64_t dest_host_addr,
			struct inf_copy **out_copy)
{
	struct inf_copy *copy;
	struct sg_table *to_sgt;
	int ret;
	u64 transfer_size;

	copy = kzalloc(sizeof(struct inf_copy), GFP_KERNEL);
	if (unlikely(copy == NULL)) {
		sph_log_err(CREATE_COMMAND_LOG, "FATAL: %s():%u failed to allocate copy object\n", __func__, __LINE__);
		return -ENOMEM;
	}

	to_sgt = &copy->host_sgt;
	ret = sg_alloc_table(to_sgt, 1, GFP_KERNEL);
	if (ret != 0) {
		sph_log_err(CREATE_COMMAND_LOG, "Failed to allocate sg table\n");
		goto failed_to_allocate_sgt;
	}

	to_sgt->sgl->length = from_devres->size;
	to_sgt->sgl->dma_address = dest_host_addr;

	sph_log_debug(GENERAL_LOG, "d2d target dma addr %pad, length %u\n", &to_sgt->sgl->dma_address, to_sgt->sgl->length);

	/* Initialize the copy structure*/
	kref_init(&copy->ref);
	copy->magic = inf_copy_create;
	copy->protocolID = protocolCopyID;
	copy->context = context;
	copy->devres = from_devres;
	copy->lli_buf = NULL;
	copy->destroyed = 0;
	copy->min_block_time = U64_MAX;
	copy->max_block_time = 0;
	copy->min_exec_time = U64_MAX;
	copy->max_exec_time = 0;
	copy->min_hw_exec_time = U64_MAX;
	copy->max_hw_exec_time = 0;
	/* d2d copy needs DMA Wr*/
	copy->card2Host = true;
	copy->d2d = true;

	ret = sph_create_sw_counters_values_node(g_hSwCountersInfo_copy,
						 (u32)protocolCopyID,
						 context->sw_counters,
						 &copy->sw_counters);
	if (unlikely(ret < 0))
		goto failed_to_create_counters;

	/* Increment devres and context refcount as copy has the references to them */
	inf_devres_get(from_devres);
	inf_context_get(context);

	/* Add copy to the context hash */
	SPH_SPIN_LOCK(&copy->context->lock);
	hash_add(copy->context->copy_hash,
		 &copy->hash_node,
		 copy->protocolID);
	SPH_SPIN_UNLOCK(&copy->context->lock);

	/* Calculate DMA LLI size */
	copy->lli_size = g_the_sphcs->hw_ops->dma.calc_lli_size(g_the_sphcs->hw_handle, from_devres->dma_map, to_sgt, 0);
	SPH_ASSERT(copy->lli_size > 0);

	/* Allocate memory for DMA LLI */
	copy->lli_buf = dma_alloc_coherent(g_the_sphcs->hw_device, copy->lli_size, &copy->lli_addr, GFP_KERNEL);
	if (unlikely(copy->lli_buf == NULL)) {
		sph_log_err(CREATE_COMMAND_LOG, "FATAL: line:%u failed to allocate lli buffer\n", __LINE__);
		ret = -ENOMEM;
		goto failed_to_allocate_lli;
	}

	/* Generate LLI */
	transfer_size = g_the_sphcs->hw_ops->dma.gen_lli(g_the_sphcs->hw_handle, from_devres->dma_map, to_sgt, copy->lli_buf, 0);
	SPH_ASSERT(transfer_size == from_devres->size);

	/* Send report to host */
	sphcs_send_event_report(g_the_sphcs,
				SPH_IPC_CREATE_COPY_SUCCESS,
				0,
				copy->context->protocolID,
				copy->protocolID);

	sg_free_table(to_sgt);

	return 0;

failed_to_allocate_lli:
	sph_remove_sw_counters_values_node(copy->sw_counters);
failed_to_create_counters:
	sg_free_table(to_sgt);
failed_to_allocate_sgt:
	kfree(copy);

	return ret;
}

void inf_copy_hostres_pagetable_complete_cb(void                  *cb_ctx,
					    int                    status,
					    struct sg_table       *host_sgt,
					    uint64_t               total_size)
{
	struct inf_copy *copy = (struct inf_copy *)cb_ctx;
	struct sg_table *src_sgt;
	struct sg_table *dst_sgt;
	u64 total_entries_bytes;

	if (status == 0) {
#ifdef _DEBUG
		// set hostres size
		copy->hostres_size = total_size;

		// By definition, copy handle should be created for host resouce and device resource with the same size
		// It should be validated first in the UMD during creation of copy handle, we add this check in the card only in debug.
		SPH_ASSERT(copy->hostres_size == copy->devres->size);
#endif

		if (copy->card2Host) {
			src_sgt = (copy->devres)->dma_map; // sg_table from device resource
			dst_sgt = host_sgt;
		} else {
			src_sgt = host_sgt;
			dst_sgt = (copy->devres)->dma_map; // sg_table from device resource
		}

		copy->lli_size = g_the_sphcs->hw_ops->dma.calc_lli_size(g_the_sphcs->hw_handle, src_sgt, dst_sgt, 0);
		SPH_ASSERT(copy->lli_size > 0);

		// allocate memory in size lli_size
		copy->lli_buf = dma_alloc_coherent(g_the_sphcs->hw_device, copy->lli_size, &copy->lli_addr, GFP_KERNEL);
		if (unlikely(copy->lli_buf == NULL)) {
			sph_log_err(CREATE_COMMAND_LOG, "FATAL: line:%u failed to allocate lli buffer\n", __LINE__);
			status = SPH_IPC_NO_MEMORY;
			goto failed;
		}

		// generate lli buffer for dma
		total_entries_bytes = g_the_sphcs->hw_ops->dma.gen_lli(g_the_sphcs->hw_handle, src_sgt, dst_sgt, copy->lli_buf, 0);
		SPH_ASSERT(total_entries_bytes > 0);

		memcpy(&copy->host_sgt, host_sgt, sizeof(struct sg_table));

		sphcs_send_event_report(g_the_sphcs,
					SPH_IPC_CREATE_COPY_SUCCESS,
					0,
					copy->context->protocolID,
					copy->protocolID);

		DO_TRACE(trace_infer_create((copy->card2Host ? SPH_TRACE_INF_CREATE_C2H_COPY_HANDLE : SPH_TRACE_INF_CREATE_H2C_COPY_HANDLE),
				copy->context->protocolID, copy->protocolID, SPH_TRACE_OP_STATUS_COMPLETE, -1, -1));

		// put refcount, taken for create process
		inf_copy_put(copy);

		return;
	}

failed:
	sphcs_send_event_report(g_the_sphcs,
				SPH_IPC_CREATE_COPY_FAILED,
				status,
				copy->context->protocolID,
				copy->protocolID);

	// put refcount, taken for create process
	inf_copy_put(copy);
	destroy_copy_on_create_failed(copy);
}

int inf_copy_create(uint16_t protocolCopyID,
		    struct inf_context *context,
		    struct inf_devres *devres,
		    uint64_t hostDmaAddr,
		    bool card2Host,
		    bool subres_copy,
		    struct inf_copy **out_copy)
{
	struct inf_copy *copy;
	int res;

	/* copy commands for subres loads must be host-to-card */
	if (subres_copy && card2Host)
		return -EINVAL;

	inf_devres_get(devres);

	copy = kzalloc(sizeof(struct inf_copy), GFP_KERNEL);
	if (unlikely(copy == NULL)) {
		sph_log_err(CREATE_COMMAND_LOG, "FATAL: %s():%u failed to allocate copy object\n", __func__, __LINE__);
		inf_devres_put(devres);
		return -ENOMEM;
	}

	kref_init(&copy->ref);
	copy->magic = inf_copy_create;
	copy->protocolID = protocolCopyID;
	copy->context = context;
	copy->devres = devres;
	copy->card2Host = card2Host;
	copy->lli_buf = NULL;
	copy->lli_size = 0;
	copy->host_sgt.sgl = NULL;
	copy->destroyed = 0;
	copy->min_block_time = U64_MAX;
	copy->max_block_time = 0;
	copy->min_exec_time = U64_MAX;
	copy->max_exec_time = 0;
	copy->min_hw_exec_time = U64_MAX;
	copy->max_hw_exec_time = 0;
	copy->d2d = false;
	copy->subres_copy = subres_copy;
#ifdef _DEBUG
	copy->hostres_size = 0;
#endif

	res = sph_create_sw_counters_values_node(g_hSwCountersInfo_copy,
						 (u32)protocolCopyID,
						 context->sw_counters,
						 &copy->sw_counters);
	if (unlikely(res < 0)) {
		inf_devres_put(devres);
		kfree(copy);
		return res;
	}


	/* make sure the context will exist for the copy handle life */
	inf_context_get(context);
	SPH_SPIN_LOCK(&copy->context->lock);
	hash_add(copy->context->copy_hash,
		 &copy->hash_node,
		 copy->protocolID);
	SPH_SPIN_UNLOCK(&copy->context->lock);

	// get ref to ensure copy will not be destoyed in the middle of create
	inf_copy_get(copy);

	if (subres_copy) {
		// allocate one page to be used for lli buffer
		copy->lli_size = PAGE_SIZE;
		copy->lli_buf = dma_alloc_coherent(g_the_sphcs->hw_device, copy->lli_size, &copy->lli_addr, GFP_KERNEL);
		if (unlikely(copy->lli_buf == NULL)) {
			sph_log_err(CREATE_COMMAND_LOG, "FATAL: line:%u failed to allocate lli buffer\n", __LINE__);
			res = -ENOMEM;
			goto put_copy;
		}

		sphcs_send_event_report(g_the_sphcs,
					SPH_IPC_CREATE_COPY_SUCCESS,
					0,
					copy->context->protocolID,
					copy->protocolID);

		// put refcount, taken for create process
		inf_copy_put(copy);
	} else if (context->chan == NULL) {
		res = sphcs_retrieve_hostres_pagetable(hostDmaAddr,
						       inf_copy_hostres_pagetable_complete_cb,
						       copy);
		if (res != 0)
			goto put_copy;
	} else {
		struct sphcs_hostres_map *hostres_map;

		/* hostDmaAddr is hostres map id */
		SPH_ASSERT(hostDmaAddr <= 0xFFFF);

		hostres_map = sphcs_cmd_chan_find_hostres(context->chan,
							  (uint16_t)hostDmaAddr);
		if (unlikely(hostres_map == NULL)) {
			sph_log_err(CREATE_COMMAND_LOG, "hostres map id not found chan %d map id %lld\n",
				    context->chan->protocolID, hostDmaAddr);
			res = -ENOENT;
			goto put_copy;
		}

		inf_copy_hostres_pagetable_complete_cb(copy,
						       0,
						       &hostres_map->host_sgt,
						       hostres_map->size);
	}

	*out_copy = copy;

	return 0;

put_copy:
	inf_copy_put(copy);
	destroy_copy_on_create_failed(copy);

	return res;
}

static void release_copy(struct work_struct *work)
{
	struct inf_copy *copy = container_of(work, struct inf_copy, work);

	SPH_SPIN_LOCK(&copy->context->lock);
	hash_del(&copy->hash_node);
	SPH_SPIN_UNLOCK(&copy->context->lock);

	/* free the sg table only if not mapped to a channel */
	if (copy->host_sgt.sgl != NULL && copy->context->chan == NULL)
		sg_free_table(&copy->host_sgt);

	if (likely(copy->lli_buf != NULL))
		dma_free_coherent(g_the_sphcs->hw_device,
				copy->lli_size,
				copy->lli_buf,
				copy->lli_addr);
	if (copy->sw_counters)
		sph_remove_sw_counters_values_node(copy->sw_counters);

	inf_devres_put(copy->devres);

	if (likely(copy->destroyed == 1))
		sphcs_send_event_report(g_the_sphcs,
				SPH_IPC_COPY_DESTROYED,
				0,
				copy->context->protocolID,
				copy->protocolID);

	inf_context_put(copy->context);

	kfree(copy);
}

static void sched_release_copy(struct kref *kref)
{
	struct inf_copy *copy;

	copy = container_of(kref, struct inf_copy, ref);

	INIT_WORK(&copy->work, release_copy);
	if (copy->context->chan != NULL)
		queue_work(system_wq, &copy->work);
	else
		queue_work(copy->context->wq, &copy->work);
}

int inf_copy_get(struct inf_copy *copy)
{
	return kref_get_unless_zero(&copy->ref);
}

int inf_copy_put(struct inf_copy *copy)
{
	return kref_put(&copy->ref, sched_release_copy);
}

static void inf_copy_req_release(struct kref *kref)
{
	struct inf_exec_req *req = container_of(kref,
						struct inf_exec_req,
						in_use);
	struct inf_copy *copy;

	SPH_ASSERT(req->cmd_type == CMDLIST_CMD_COPY);

	copy = req->copy;
	inf_devres_del_req_from_queue(copy->devres, req);
	inf_context_seq_id_fini(copy->context, &req->seq);

	/* advance sched tick and try execute next requests */
	atomic_add(2, &req->context->sched_tick);
	inf_devres_try_execute(copy->devres);

	kmem_cache_free(copy->context->exec_req_slab_cache, req);
	inf_copy_put(copy);
}

void inf_copy_req_init(struct inf_exec_req *req,
			struct inf_copy *copy,
			struct inf_cmd_list *cmd,
			size_t size,
			uint8_t priority)
{
	kref_init(&req->in_use);
	req->in_progress = false;
	req->context = copy->context;
	req->last_sched_tick = 0;
	req->cmd_type = CMDLIST_CMD_COPY;
	req->f = &s_copy_funcs;
	req->copy = copy;
	req->cmd = cmd;
	req->size = size ? size : copy->devres->size;
	req->time = 0;
	req->priority = priority;
}

int inf_copy_req_init_subres_copy(struct inf_exec_req *req,
				  struct inf_copy *copy,
				  uint16_t hostres_map_id,
				  uint64_t devres_offset,
				  size_t size)
{
	inf_copy_req_init(req, copy, NULL, size, 0);

	if (copy->context->chan == NULL || !copy->subres_copy)
		return -EINVAL;

	req->hostres_map = sphcs_cmd_chan_find_hostres(copy->context->chan,
						       hostres_map_id);
	if (unlikely(req->hostres_map == NULL)) {
		sph_log_err(CREATE_COMMAND_LOG, "hostres map id not found chan %d map id %d\n",
			    copy->context->chan->protocolID, hostres_map_id);
		return -EINVAL;
	}
	req->devres_offset = devres_offset;

	return 0;
}

static int inf_copy_req_sched(struct inf_exec_req *req)
{
	struct inf_copy *copy;
	int err;

	SPH_ASSERT(req->cmd_type == CMDLIST_CMD_COPY);

	copy = req->copy;
	inf_copy_get(copy);
	spin_lock_init(&req->lock_irq);
	inf_context_seq_id_init(copy->context, &req->seq);

	DO_TRACE_IF(!copy->subres_copy, trace_copy(SPH_TRACE_OP_STATUS_QUEUED,
					 copy->context->protocolID,
					 copy->protocolID,
					 req->cmd ? req->cmd->protocolID : -1,
					 copy->card2Host,
					 req->size,
					 1));

	if (SPH_SW_GROUP_IS_ENABLE(copy->sw_counters,
				   COPY_SPHCS_SW_COUNTERS_GROUP)) {
		req->time = sph_time_us();
	}

	inf_exec_req_get(req);

	err = inf_devres_add_req_to_queue(copy->devres, req, copy->card2Host);
	if (unlikely(err < 0)) {
		inf_context_seq_id_fini(copy->context, &req->seq);
		inf_copy_put(copy);
		return err;
	}
	// Request scheduled

	// First try to execute
	req->last_sched_tick = 0;
	inf_req_try_execute(req);

	inf_exec_req_put(req);

	return 0;
}

static bool inf_copy_req_ready(struct inf_exec_req *req)
{
	struct inf_copy *copy;

	SPH_ASSERT(req->cmd_type == CMDLIST_CMD_COPY);

	copy = req->copy;
	return !copy->active && inf_devres_req_ready(copy->devres,
						     req,
						     copy->card2Host);
}

static int inf_copy_req_execute(struct inf_exec_req *req)
{
	struct sphcs_dma_desc const *desc;
	struct inf_copy *copy;

	SPH_ASSERT(req->cmd_type == CMDLIST_CMD_COPY);
	SPH_ASSERT(req->in_progress);

	copy = req->copy;
	DO_TRACE_IF(!copy->subres_copy, trace_copy(SPH_TRACE_OP_STATUS_START,
		 copy->context->protocolID,
		 copy->protocolID,
		 req->cmd ? req->cmd->protocolID : -1,
		 copy->card2Host,
		 req->size,
		 1));

	if (copy->subres_copy) {
		size_t lli_size;
		u32 transfer_size;

		lli_size = g_the_sphcs->hw_ops->dma.calc_lli_size(g_the_sphcs->hw_handle,
								  &req->hostres_map->host_sgt,
								  copy->devres->dma_map,
								  req->devres_offset);
		if (lli_size > copy->lli_size)
			return -ENOMEM;

		transfer_size = g_the_sphcs->hw_ops->dma.gen_lli(g_the_sphcs->hw_handle,
								 &req->hostres_map->host_sgt,
								 copy->devres->dma_map,
								 copy->lli_buf,
								 req->devres_offset);
		if (transfer_size < 1)
			return -EINVAL;
	}

	if (SPH_SW_GROUP_IS_ENABLE(copy->sw_counters,
				   COPY_SPHCS_SW_COUNTERS_GROUP)) {
		u64 now;

		now = sph_time_us();
		if (req->time) {
			u64 dt;

			dt = now - req->time;
			SPH_SW_COUNTER_ADD(copy->sw_counters,
					   COPY_SPHCS_SW_COUNTERS_BLOCK_TOTAL_TIME,
					   dt);

			SPH_SW_COUNTER_INC(copy->sw_counters,
					   COPY_SPHCS_SW_COUNTERS_BLOCK_COUNT);

			if (dt < copy->min_block_time) {
				SPH_SW_COUNTER_SET(copy->sw_counters,
						   COPY_SPHCS_SW_COUNTERS_BLOCK_MIN_TIME,
						   dt);
				copy->min_block_time = dt;
			}

			if (dt > copy->max_block_time) {
				SPH_SW_COUNTER_SET(copy->sw_counters,
						   COPY_SPHCS_SW_COUNTERS_BLOCK_MAX_TIME,
						   dt);
				copy->max_block_time = dt;
			}
		}
		req->time = now;
	} else
		req->time = 0;

	if (copy->card2Host) {
		switch (req->priority) {
		case 1:
			desc = &g_dma_desc_c2h_high_nowait;
			break;
		case 0:
		default:
			desc = &g_dma_desc_c2h_normal_nowait;
			break;
		}
	} else {
		switch (req->priority) {
		case 1:
			desc = &g_dma_desc_h2c_high_nowait;
			break;
		case 0:
		default:
			desc = &g_dma_desc_h2c_normal_nowait;
			break;
		}
	}

	copy->active = true;

	if (inf_context_get_state(copy->context) != CONTEXT_OK)
		return -SPHER_CONTEXT_BROKEN;

	g_the_sphcs->hw_ops->dma.edit_lli(g_the_sphcs->hw_handle, copy->lli_buf, req->size);

	return sphcs_dma_sched_start_xfer(g_the_sphcs->dmaSched, desc,
					  copy->lli_addr,
					  req->size,
					  copy_complete_cb, NULL,
					  &req, sizeof(req));
}

static void inf_copy_req_complete(struct inf_exec_req *req,
				  int                  err,
				  const void          *error_msg,
				  int32_t              error_msg_size)
{
	enum event_val eventVal;
	struct inf_copy *copy;
	struct inf_devres *devres;
	struct inf_cmd_list *cmd;
	bool is_d2d_copy;
	unsigned long flags;
	bool send_cmdlist_event_report = false;
	struct inf_exec_error_details *err_details = NULL;
	int rc;

	SPH_ASSERT(req->cmd_type == CMDLIST_CMD_COPY);
	SPH_ASSERT(req->in_progress);

	copy = req->copy;
	devres = copy->devres;
	cmd = req->cmd;
	is_d2d_copy = copy->d2d;

	 DO_TRACE_IF(!copy->subres_copy, trace_copy(SPH_TRACE_OP_STATUS_COMPLETE,
					 copy->context->protocolID,
					 copy->protocolID,
					 cmd ? cmd->protocolID : -1,
					 copy->card2Host,
					 req->size,
					 1));

	if (SPH_SW_GROUP_IS_ENABLE(copy->sw_counters,
				   COPY_SPHCS_SW_COUNTERS_GROUP)) {
		u64 now;

		now = sph_time_us();
		if (req->time) {
			u64 dt;

			dt = now - req->time;
			SPH_SW_COUNTER_ADD(copy->sw_counters,
					   COPY_SPHCS_SW_COUNTERS_EXEC_TOTAL_TIME,
					   dt);

			SPH_SW_COUNTER_INC(copy->sw_counters,
					   COPY_SPHCS_SW_COUNTERS_EXEC_COUNT);

			if (dt < copy->min_exec_time) {
				SPH_SW_COUNTER_SET(copy->sw_counters,
						   COPY_SPHCS_SW_COUNTERS_EXEC_MIN_TIME,
						   dt);
				copy->min_exec_time = dt;
			}

			if (dt > copy->max_exec_time) {
				SPH_SW_COUNTER_SET(copy->sw_counters,
						   COPY_SPHCS_SW_COUNTERS_EXEC_MAX_TIME,
						   dt);
				copy->max_exec_time = dt;
			}
		}
	}
	req->time = 0;

	if (unlikely(err < 0)) {
		sph_log_err(EXECUTE_COMMAND_LOG, "Execute copy failed with err=%d\n", err);
		switch (err) {
		case -ENOMEM:
			eventVal = SPH_IPC_NO_MEMORY;
			break;
		case -SPHER_CONTEXT_BROKEN:
			eventVal = SPH_IPC_CONTEXT_BROKEN;
			break;
		default:
			eventVal = SPH_IPC_DMA_ERROR;
		}

		rc = inf_exec_error_details_alloc(CMDLIST_CMD_COPY,
						  copy->protocolID,
						  0,
						  eventVal,
						  error_msg_size > 0 ? error_msg_size : 0,
						  &err_details);
		if (rc == 0) {
			if (error_msg_size != 0)
				memcpy(err_details->error_msg, error_msg, error_msg_size);

			inf_exec_error_list_add(cmd != NULL ? &cmd->error_list :
							      &copy->context->error_list,
						err_details);
		}

		//TODO GLEB: Decide if copy failed brakes context or cmd or ...
		if (cmd == NULL)
			inf_context_set_state(copy->context,
					      CONTEXT_BROKEN_RECOVERABLE);
	} else {
		eventVal = 0;
	}

	if (cmd != NULL) {
		SPH_SPIN_LOCK_IRQSAVE(&cmd->lock_irq, flags);
		if (--cmd->num_left == 0)
			send_cmdlist_event_report = true;
		SPH_SPIN_UNLOCK_IRQRESTORE(&cmd->lock_irq, flags);
	}

	if (eventVal == 0 && send_cmdlist_event_report && !is_d2d_copy) {
		// if success and should send both cmd and copy reports,
		// send one merged report
		sphcs_send_event_report_ext(g_the_sphcs,
					    SPH_IPC_EXECUTE_COPY_SUCCESS,
					    eventVal,
					    copy->context->protocolID,
					    copy->protocolID,
					    cmd->protocolID);
	} else {
		req->f->send_report(req, eventVal);

		if (send_cmdlist_event_report)
			sphcs_send_event_report(g_the_sphcs,
						SPH_IPC_EXECUTE_CMD_COMPLETE,
						0,
						cmd->context->protocolID,
						cmd->protocolID);
	}

	if (send_cmdlist_event_report) {
		DO_TRACE(trace_cmdlist(SPH_TRACE_OP_STATUS_COMPLETE,
			 cmd->context->protocolID, cmd->protocolID));
		// for schedule
		inf_cmd_put(cmd);
	}
	copy->active = false;

	if (is_d2d_copy)
		inf_copy_get(copy);

	inf_exec_req_put(req);

	/* Notify the dst */
	if (is_d2d_copy) {
		sphcs_p2p_send_fw_cr(&devres->p2p_buf);
		sphcs_p2p_ring_doorbell(&devres->p2p_buf);
		inf_copy_put(copy);
	}
}

static void send_copy_report(struct inf_exec_req *req,
			     enum event_val       eventVal)
{
	struct inf_copy *copy;
	uint16_t eventCode = eventVal == 0 ? SPH_IPC_EXECUTE_COPY_SUCCESS : SPH_IPC_EXECUTE_COPY_FAILED;
	int cmdID;

	SPH_ASSERT(req->cmd_type == CMDLIST_CMD_COPY);

	copy = req->copy;
	if (eventVal != 0 && req->cmd != NULL)
		cmdID = req->cmd->protocolID;
	else
		cmdID = -1;
	// report success only when not d2d
	if (eventVal != 0 || !copy->d2d)
		sphcs_send_event_report_ext(g_the_sphcs,
					    eventCode,
					    eventVal,
					    copy->context->protocolID,
					    copy->protocolID,
					    cmdID);
}

static int inf_req_copy_put(struct inf_exec_req *req)
{
	return inf_copy_put(req->copy);
}

static int inf_copy_migrate_priority(struct inf_exec_req *req, uint8_t priority)
{
	int ret = 0;

	if (req->priority != priority)
		ret = inf_update_priority(req,
					  priority,
					  req->copy->card2Host,
					  req->copy->lli_addr);

	return ret;
}

struct sg_table *inf_copy_src_sgt(struct inf_copy *copy)
{
	if (copy->card2Host)
		return (copy->devres)->dma_map;
	else
		return &copy->host_sgt;
}

struct sg_table *inf_copy_dst_sgt(struct inf_copy *copy)
{
	if (copy->card2Host)
		return &copy->host_sgt;
	else
		return (copy->devres)->dma_map;
}
