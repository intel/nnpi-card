/********************************************
 * Copyright (C) 2019 Intel Corporation
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
#include "sph_error.h"
#include "sphcs_trace.h"

static int copy_complete_cb(struct sphcs *sphcs, void *ctx, const void *user_data, int status, u32 xferTimeUS)
{
	int err;

	if (status == SPHCS_DMA_STATUS_FAILED) {
		err = -SPHER_DMA_ERROR;
	} else {
		/* if status is not an error - it must be done */
		SPH_ASSERT(status == SPHCS_DMA_STATUS_DONE);
		err = 0;
	}

	inf_copy_req_complete(*((struct inf_exec_req **)user_data), err, xferTimeUS);

	return err;
}

int inf_d2d_copy_create(uint16_t protocolCopyID,
		    struct inf_context *context,
		    struct inf_devres *from_devres,
		    uint64_t dest_host_addr,
		    struct inf_copy **out_copy)
{
	struct inf_copy *copy;
	struct sg_table to_sgt;
	int ret;
	u64 transfer_size;

	ret = sg_alloc_table(&to_sgt, 1, GFP_KERNEL);
	if (ret != 0) {
		sph_log_err(CREATE_COMMAND_LOG, "Failed to allocate sg table\n");
		return ret;
	}

	to_sgt.sgl->length = from_devres->size;
	to_sgt.sgl->dma_address = dest_host_addr;

	sph_log_debug(GENERAL_LOG, "d2d target dma addr %pad, length %u\n", &to_sgt.sgl->dma_address, to_sgt.sgl->length);

	copy = kzalloc(sizeof(struct inf_copy), GFP_KERNEL);
	if (unlikely(copy == NULL)) {
		sph_log_err(CREATE_COMMAND_LOG, "FATAL: %s():%u failed to allocate copy object\n", __func__, __LINE__);
		ret = -ENOMEM;
		goto failed_to_allocate_copy;
	}

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
	copy->lli_size = g_the_sphcs->hw_ops->dma.calc_lli_size(g_the_sphcs->hw_handle, from_devres->dma_map, &to_sgt, 0);
	SPH_ASSERT(copy->lli_size > 0);

	/* Allocate memory for DMA LLI */
	copy->lli_buf = dma_alloc_coherent(g_the_sphcs->hw_device, copy->lli_size, &copy->lli_addr, GFP_KERNEL);
	if (unlikely(copy->lli_buf == NULL)) {
		sph_log_err(CREATE_COMMAND_LOG, "FATAL: line:%u failed to allocate lli buffer\n", __LINE__);
		ret = -ENOMEM;
		goto failed_to_allocate_lli;
	}

	/* Generate LLI */
	transfer_size = g_the_sphcs->hw_ops->dma.gen_lli(g_the_sphcs->hw_handle, from_devres->dma_map, &to_sgt, copy->lli_buf, 0);
	SPH_ASSERT(transfer_size == from_devres->size);

	/* Send report to host */
	sphcs_send_event_report(g_the_sphcs,
				SPH_IPC_CREATE_COPY_SUCCESS,
				0,
				copy->context->protocolID,
				copy->protocolID);

	sg_free_table(&to_sgt);

	return 0;

failed_to_allocate_lli:
	sph_remove_sw_counters_values_node(copy->sw_counters);
failed_to_create_counters:
	kfree(copy);
failed_to_allocate_copy:
	sg_free_table(&to_sgt);

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

		sphcs_send_event_report(g_the_sphcs,
					SPH_IPC_CREATE_COPY_SUCCESS,
					0,
					copy->context->protocolID,
					copy->protocolID);

		/* free the sg table only if not mapped to a channel */
		if (copy->context->chan == NULL)
			sg_free_table(host_sgt);

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
	int ret;

	if (likely(copy->lli_buf != NULL))
		dma_free_coherent(g_the_sphcs->hw_device,
				copy->lli_size,
				copy->lli_buf,
				copy->lli_addr);
	if (copy->sw_counters)
		sph_remove_sw_counters_values_node(copy->sw_counters);

	ret = inf_devres_put(copy->devres);
	ret = inf_context_put(copy->context);

	if (likely(copy->destroyed == 1))
		sphcs_send_event_report(g_the_sphcs,
				SPH_IPC_COPY_DESTROYED,
				0,
				copy->context->protocolID,
				copy->protocolID);

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

inline void inf_copy_get(struct inf_copy *copy)
{
	int ret;

	ret = kref_get_unless_zero(&copy->ref);
	SPH_ASSERT(ret != 0);
}

inline int inf_copy_put(struct inf_copy *copy)
{
	return kref_put(&copy->ref, sched_release_copy);
}

/* This function should not be called directly, use inf_exec_req_put instead */
void inf_copy_req_release(struct kref *kref)
{
	struct inf_exec_req *copy_req = container_of(kref,
						     struct inf_exec_req,
						     in_use);
	struct inf_copy *copy = copy_req->copy;

	SPH_ASSERT(copy_req->is_copy);

	inf_devres_del_req_from_queue(copy->devres, copy_req);
	inf_context_seq_id_fini(copy->context, &copy_req->seq);


	kmem_cache_free(copy->context->exec_req_slab_cache,
			copy_req);
	inf_copy_put(copy);
}

void inf_copy_req_init(struct inf_exec_req *req, struct inf_copy *copy, size_t size, uint8_t priority)
{
	kref_init(&req->in_use);
	req->in_progress = false;
	req->is_copy = true;
	req->copy = copy;
	req->size = size;
	req->time = 0;
	req->sched_params.priority = priority;
}

int inf_copy_req_init_subres_copy(struct inf_exec_req *req,
				  struct inf_copy *copy,
				  uint16_t hostres_map_id,
				  uint64_t devres_offset,
				  size_t size)
{
	kref_init(&req->in_use);
	req->in_progress = false;
	req->is_copy = true;
	req->copy = copy;
	req->size = size;
	req->time = 0;
	req->sched_params.priority = 0;

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

int inf_copy_req_sched(struct inf_exec_req *req)
{
	int err;

	inf_copy_get(req->copy);
	spin_lock_init(&req->lock_irq);
	inf_context_seq_id_init(req->copy->context, &req->seq);

	if (SPH_SW_GROUP_IS_ENABLE(req->copy->sw_counters,
				   COPY_SPHCS_SW_COUNTERS_GROUP)) {
		req->time = sph_time_us();
	}

	inf_exec_req_get(req);

	err = inf_devres_add_req_to_queue(req->copy->devres, req, req->copy->card2Host);
	if (unlikely(err < 0)) {
		inf_context_seq_id_fini(req->copy->context, &req->seq);
		return err;
	}
	// Request scheduled

	// First try to execute
	inf_req_try_execute(req);

	inf_exec_req_put(req);

	return 0;
}

bool inf_copy_req_ready(struct inf_exec_req *copy_req)
{
	SPH_ASSERT(copy_req->is_copy);

	return !copy_req->copy->active && inf_devres_req_ready(copy_req->copy->devres,
								copy_req,
								copy_req->copy->card2Host);
}

int inf_copy_req_execute(struct inf_exec_req *copy_req)
{
	struct sphcs_dma_desc const *desc;

	SPH_ASSERT(copy_req->is_copy);
	SPH_ASSERT(copy_req->in_progress);

	DO_TRACE(trace_copy(SPH_TRACE_OP_STATUS_START,
		   copy_req->copy->context->protocolID,
		   copy_req->copy->protocolID,
		   copy_req->copy->card2Host,
		   copy_req->size ? copy_req->size : copy_req->copy->devres->size));

	if (copy_req->copy->subres_copy) {
		int lli_size;
		u32 transfer_size;

		lli_size = g_the_sphcs->hw_ops->dma.calc_lli_size(g_the_sphcs->hw_handle,
								  &copy_req->hostres_map->host_sgt,
								  copy_req->copy->devres->dma_map,
								  copy_req->devres_offset);
		if (lli_size > copy_req->copy->lli_size)
			return -ENOMEM;

		transfer_size = g_the_sphcs->hw_ops->dma.gen_lli(g_the_sphcs->hw_handle,
								 &copy_req->hostres_map->host_sgt,
								 copy_req->copy->devres->dma_map,
								 copy_req->copy->lli_buf,
								 copy_req->devres_offset);
		if (transfer_size < 1)
			return -EINVAL;
	}

	if (SPH_SW_GROUP_IS_ENABLE(copy_req->copy->sw_counters,
				   COPY_SPHCS_SW_COUNTERS_GROUP)) {
		u64 now;

		now = sph_time_us();
		if (copy_req->time) {
			u64 dt;

			dt = now - copy_req->time;
			SPH_SW_COUNTER_ADD(copy_req->copy->sw_counters,
					   COPY_SPHCS_SW_COUNTERS_BLOCK_TOTAL_TIME,
					   dt);

			SPH_SW_COUNTER_INC(copy_req->copy->sw_counters,
					   COPY_SPHCS_SW_COUNTERS_BLOCK_COUNT);

			if (dt < copy_req->copy->min_block_time) {
				SPH_SW_COUNTER_SET(copy_req->copy->sw_counters,
						   COPY_SPHCS_SW_COUNTERS_BLOCK_MIN_TIME,
						   dt);
				copy_req->copy->min_block_time = dt;
			}

			if (dt > copy_req->copy->max_block_time) {
				SPH_SW_COUNTER_SET(copy_req->copy->sw_counters,
						   COPY_SPHCS_SW_COUNTERS_BLOCK_MAX_TIME,
						   dt);
				copy_req->copy->max_block_time = dt;
			}
		}
		copy_req->time = now;
	} else
		copy_req->time = 0;

	if (copy_req->copy->card2Host) {
		switch (copy_req->sched_params.priority) {
		case 1:
			desc = &g_dma_desc_c2h_high_nowait;
			break;
		case 0:
		default:
			desc = &g_dma_desc_c2h_normal_nowait;
			break;
		}
	} else {
		switch (copy_req->sched_params.priority) {
		case 1:
			desc = &g_dma_desc_h2c_high_nowait;
			break;
		case 0:
		default:
			desc = &g_dma_desc_h2c_normal_nowait;
			break;
		}
	}

	copy_req->copy->active = true;

	if (inf_context_get_state(copy_req->copy->context) != CONTEXT_OK)
		return -SPHER_CONTEXT_BROKEN;

	g_the_sphcs->hw_ops->dma.edit_lli(g_the_sphcs->hw_handle, copy_req->copy->lli_buf, copy_req->size);

	return sphcs_dma_sched_start_xfer(g_the_sphcs->dmaSched, desc,
					  copy_req->copy->lli_addr,
					  copy_req->size ? copy_req->size : copy_req->copy->devres->size,
					  copy_complete_cb, NULL,
					  &copy_req, sizeof(copy_req));
}

void inf_copy_req_complete(struct inf_exec_req *req, int err, u32 xferTimeUS)
{
	uint16_t status;
	enum event_val eventVal;
	struct inf_devres *devres;
	bool is_d2d_copy;

	SPH_ASSERT(req != NULL);
	SPH_ASSERT(req->is_copy);
	SPH_ASSERT(req->in_progress);

	devres = req->copy->devres;
	is_d2d_copy = req->copy->d2d;

	DO_TRACE(trace_copy(SPH_TRACE_OP_STATUS_COMPLETE,
		   req->copy->context->protocolID,
		   req->copy->protocolID,
		   req->copy->card2Host,
		   req->size ? req->size : req->copy->devres->size));

	if (SPH_SW_GROUP_IS_ENABLE(req->copy->sw_counters,
				   COPY_SPHCS_SW_COUNTERS_GROUP)) {
		u64 now;

		now = sph_time_us();
		if (req->time) {
			u64 dt;

			dt = now - req->time;
			SPH_SW_COUNTER_ADD(req->copy->sw_counters,
					   COPY_SPHCS_SW_COUNTERS_EXEC_TOTAL_TIME,
					   dt);

			SPH_SW_COUNTER_INC(req->copy->sw_counters,
					   COPY_SPHCS_SW_COUNTERS_EXEC_COUNT);

			if (dt < req->copy->min_exec_time) {
				SPH_SW_COUNTER_SET(req->copy->sw_counters,
						   COPY_SPHCS_SW_COUNTERS_EXEC_MIN_TIME,
						   dt);
				req->copy->min_exec_time = dt;
			}

			if (dt > req->copy->max_exec_time) {
				SPH_SW_COUNTER_SET(req->copy->sw_counters,
						   COPY_SPHCS_SW_COUNTERS_EXEC_MAX_TIME,
						   dt);
				req->copy->max_exec_time = dt;
			}

			SPH_SW_COUNTER_ADD(req->copy->sw_counters,
					   COPY_SPHCS_SW_COUNTERS_HWEXEC_TOTAL_TIME,
					   xferTimeUS);

			if (xferTimeUS < req->copy->min_hw_exec_time) {
				SPH_SW_COUNTER_SET(req->copy->sw_counters,
						   COPY_SPHCS_SW_COUNTERS_HWEXEC_MIN_TIME,
						   xferTimeUS);
				req->copy->min_hw_exec_time = xferTimeUS;
			}

			if (xferTimeUS > req->copy->max_hw_exec_time) {
				SPH_SW_COUNTER_SET(req->copy->sw_counters,
						   COPY_SPHCS_SW_COUNTERS_HWEXEC_MAX_TIME,
						   xferTimeUS);
				req->copy->max_hw_exec_time = xferTimeUS;
			}
		}
	}
	req->time = 0;

	if (!is_d2d_copy) {
		if (unlikely(err < 0)) {
			sph_log_err(EXECUTE_COMMAND_LOG, "Execute copy failed with err=%d\n", err);
			status = SPH_IPC_EXECUTE_COPY_FAILED;
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
		} else {
			status = SPH_IPC_EXECUTE_COPY_SUCCESS;
			eventVal = 0;
		}
		sphcs_send_event_report(g_the_sphcs,
					status,
					eventVal,
					req->copy->context->protocolID,
					req->copy->protocolID);
	}

	if (unlikely(err < 0))
		inf_context_set_state(req->copy->context,
				      CONTEXT_BROKEN_RECOVERABLE);

	req->copy->active = false;

	inf_exec_req_put(req);

	/* Notify the dst */
	if (is_d2d_copy) {
		sphcs_p2p_send_fw_cr(&devres->p2p_buf);
		sphcs_p2p_ring_doorbell(&devres->p2p_buf);
	}

}
