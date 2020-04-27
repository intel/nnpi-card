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
#include "nnp_error.h"
#include "sphcs_trace.h"

static int inf_copy_req_sched(struct inf_exec_req *req);
static enum EXEC_REQ_READINESS inf_copy_req_ready(struct inf_exec_req *req);
static int inf_copy_req_execute(struct inf_exec_req *req);
static void inf_copy_req_complete(struct inf_exec_req *req,
				  int                  err,
				  const void          *error_msg,
				  int32_t              error_msg_size);
static void send_copy_report(struct inf_exec_req *req,
			     enum event_val       eventVal);
static int inf_req_copy_put(struct inf_exec_req *req);
static int inf_copy_migrate_priority(struct inf_exec_req *req, uint8_t priority);
static void treat_copy_failure(struct inf_exec_req *req,
				enum event_val       eventVal,
				const void          *error_msg,
				int32_t              error_msg_size);

static void inf_copy_req_release(struct kref *kref);

#define SUBRES_MAX_LLI_SIZE NNP_PAGE_SIZE

struct func_table const s_copy_funcs = {
	.schedule = inf_copy_req_sched,
	.is_ready = inf_copy_req_ready,
	.execute = inf_copy_req_execute,
	.complete = inf_copy_req_complete,
	.send_report = send_copy_report,
	.obj_put = inf_req_copy_put,
	.migrate_priority = inf_copy_migrate_priority,
	.treat_req_failure = treat_copy_failure,

	/* This function should not be called directly, use inf_exec_req_put instead */
	.release = inf_copy_req_release
};

static void inf_copy_update_counters(struct inf_copy *copy, u32 xferTimeUS)
{
	if (xferTimeUS > 0 &&
	    NNP_SW_GROUP_IS_ENABLE(copy->sw_counters,
				   COPY_SPHCS_SW_COUNTERS_GROUP)) {
		NNP_SW_COUNTER_ADD(copy->sw_counters,
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
}

static int copy_complete_cb(struct sphcs *sphcs, void *ctx, const void *user_data, int status, u32 xferTimeUS)
{
	int err = 0;
	struct inf_exec_req *req = (struct inf_exec_req *)ctx;

	NNP_ASSERT(req != NULL);
	NNP_ASSERT(status == SPHCS_DMA_STATUS_DONE || status == SPHCS_DMA_STATUS_FAILED);

	/* Update copy execution counter only on success (otherwise the min/max might not reflect the real values)*/
	if (likely(status == SPHCS_DMA_STATUS_DONE))
		inf_copy_update_counters(req->copy, xferTimeUS);
	else
		err = -NNPER_DMA_ERROR;

	req->f->complete(req, err, NULL, 0);

	return 0;
}

static int d2d_copy_complete_cb(struct sphcs *sphcs, void *ctx, const void *user_data, int status, u32 xferTimeUS)
{
	int err = 0;
	struct inf_exec_req *req = (struct inf_exec_req *)ctx;
	struct inf_copy *copy;

	NNP_ASSERT(req != NULL);
	NNP_ASSERT(status == SPHCS_DMA_STATUS_DONE || status == SPHCS_DMA_STATUS_FAILED);

	if (unlikely(status == SPHCS_DMA_STATUS_FAILED))
		err = -NNPER_DMA_ERROR;

	copy = req->copy;

	/* Should be source p2p buffer */
	NNP_ASSERT(copy->d2d && copy->devres->is_p2p_src);

	/* Forward credit to the consumer only if copy has been successfully completed */
	if (likely(err == 0)) {
		copy->devres->p2p_buf.ready = false;
		err = sphcs_p2p_send_fw_cr_and_ring_db(&copy->devres->p2p_buf, copy_complete_cb, req);
	}

	/* If DMA failed or failed to start credit forwarding */
	if (unlikely(err))
		req->f->complete(req, err, NULL, 0);

	return 0;
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
	copy->lli.vptr = NULL;
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
	sphcs_dma_multi_xfer_handle_init(&copy->multi_xfer_handle);

	ret = nnp_create_sw_counters_values_node(g_hSwCountersInfo_copy,
						 (u32)protocolCopyID,
						 context->sw_counters,
						 &copy->sw_counters);
	if (unlikely(ret < 0))
		goto failed_to_create_counters;

	/* Increment devres and context refcount as copy has the references to them */
	inf_devres_get(from_devres);
	inf_context_get(context);

	/* Add copy to the context hash */
	NNP_SPIN_LOCK(&copy->context->lock);
	hash_add(copy->context->copy_hash,
		 &copy->hash_node,
		 copy->protocolID);
	NNP_SPIN_UNLOCK(&copy->context->lock);

	/* Calculate DMA LLI size */
	ret = g_the_sphcs->hw_ops->dma.init_lli(g_the_sphcs->hw_handle, &copy->lli, from_devres->dma_map, to_sgt, 0, false);
	if (ret != 0) {
		sph_log_err(CREATE_COMMAND_LOG, "FATAL: line:%u failed to init lli buffer\n", __LINE__);
		ret = -ENOMEM;
		goto failed_to_allocate_lli;
	}

	NNP_ASSERT(copy->lli.size > 0);

	/* Allocate memory for DMA LLI */
	copy->lli.vptr = dma_alloc_coherent(g_the_sphcs->hw_device, copy->lli.size, &copy->lli.dma_addr, GFP_KERNEL);
	if (unlikely(copy->lli.vptr == NULL)) {
		sph_log_err(CREATE_COMMAND_LOG, "FATAL: line:%u failed to allocate lli buffer\n", __LINE__);
		ret = -ENOMEM;
		goto failed_to_allocate_lli;
	}

	/* Generate LLI */
	transfer_size = g_the_sphcs->hw_ops->dma.gen_lli(g_the_sphcs->hw_handle, from_devres->dma_map, to_sgt, &copy->lli, 0);
	NNP_ASSERT(transfer_size == from_devres->size);

	/* Send report to host */
	sphcs_send_event_report(g_the_sphcs,
				NNP_IPC_CREATE_COPY_SUCCESS,
				0,
				copy->context->chan->respq,
				copy->context->protocolID,
				copy->protocolID);

	sg_free_table(to_sgt);

	return 0;

failed_to_allocate_lli:
	nnp_remove_sw_counters_values_node(copy->sw_counters);
failed_to_create_counters:
	sg_free_table(to_sgt);
failed_to_allocate_sgt:
	kfree(copy);

	return ret;
}

int inf_copy_create(uint16_t protocolCopyID,
		    struct inf_context *context,
		    struct inf_devres *devres,
		    uint16_t hostres_map_id,
		    bool card2Host,
		    bool subres_copy,
		    struct inf_copy **out_copy)
{
	struct sg_table *src_sgt = NULL;
	struct sg_table *dst_sgt = NULL;
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
	copy->lli.vptr = NULL;
	copy->lli.size = 0;
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
	sphcs_dma_multi_xfer_handle_init(&copy->multi_xfer_handle);

	if (subres_copy) {
		// allocate one page to be used for lli buffer
		copy->lli.size = SUBRES_MAX_LLI_SIZE;
	} else {
		struct sphcs_hostres_map *hostres_map;

		hostres_map = sphcs_cmd_chan_find_hostres(context->chan,
							  hostres_map_id);
		if (unlikely(hostres_map == NULL)) {
			sph_log_err(CREATE_COMMAND_LOG, "hostres map id not found chan %hu map id %hu\n",
				    context->chan->protocolID, hostres_map_id);
			res = -ENOENT;
			goto failed;
		}

		if (copy->card2Host) {
			src_sgt = (copy->devres)->dma_map; // sg_table from device resource
			dst_sgt = &hostres_map->host_sgt;
		} else {
			src_sgt = &hostres_map->host_sgt;
			dst_sgt = (copy->devres)->dma_map; // sg_table from device resource
		}

		res = g_the_sphcs->hw_ops->dma.init_lli(g_the_sphcs->hw_handle, &copy->lli, src_sgt, dst_sgt, 0, false);
		if (unlikely(res != 0)) {
			sph_log_err(CREATE_COMMAND_LOG, "FATAL: line:%u failed to init lli buffer\n", __LINE__);
			res = -ENOMEM;
			goto failed;
		}

		NNP_ASSERT(copy->lli.size > 0);

		memcpy(&copy->host_sgt, &hostres_map->host_sgt, sizeof(struct sg_table));
	}
	// allocate memory in size lli_size
	copy->lli.vptr = dma_alloc_coherent(g_the_sphcs->hw_device, copy->lli.size, &copy->lli.dma_addr, GFP_KERNEL);
	if (unlikely(copy->lli.vptr == NULL)) {
		sph_log_err(CREATE_COMMAND_LOG, "FATAL: line:%u failed to allocate lli buffer\n", __LINE__);
		res = -ENOMEM;
		goto failed;
	}
	if (!subres_copy) {
		// generate lli buffer for dma
		u64 total_entries_bytes = g_the_sphcs->hw_ops->dma.gen_lli(g_the_sphcs->hw_handle, src_sgt, dst_sgt, &copy->lli, 0);

		NNP_ASSERT(total_entries_bytes > 0);
		if (unlikely(total_entries_bytes == 0)) {
			sph_log_err(CREATE_COMMAND_LOG, "FATAL: line:%u failed to gen lli buffer\n", __LINE__);
			res = -ENOMEM;
			goto failed;
		}

		DO_TRACE(trace_infer_create((copy->card2Host ? SPH_TRACE_INF_C2H_COPY_HANDLE : SPH_TRACE_INF_H2C_COPY_HANDLE),
				copy->context->protocolID, copy->protocolID, SPH_TRACE_OP_STATUS_COMPLETE, -1, -1));
	}

	res = nnp_create_sw_counters_values_node(g_hSwCountersInfo_copy,
						 (u32)protocolCopyID,
						 context->sw_counters,
						 &copy->sw_counters);
	if (unlikely(res < 0))
		goto failed;

	/* make sure the context will exist for the copy handle life */
	inf_context_get(context);
	NNP_SPIN_LOCK(&copy->context->lock);
	hash_add(copy->context->copy_hash,
		 &copy->hash_node,
		 copy->protocolID);
	NNP_SPIN_UNLOCK(&copy->context->lock);

	sphcs_send_event_report(g_the_sphcs,
				NNP_IPC_CREATE_COPY_SUCCESS,
				0,
				copy->context->chan->respq,
				copy->context->protocolID,
				copy->protocolID);

	*out_copy = copy;

	return 0;

failed:
	inf_devres_put(devres);
	kfree(copy);

	return res;
}

static void release_copy(struct work_struct *work)
{
	struct inf_copy *copy = container_of(work, struct inf_copy, work);

	NNP_SPIN_LOCK(&copy->context->lock);
	hash_del(&copy->hash_node);
	NNP_SPIN_UNLOCK(&copy->context->lock);

	if (likely(copy->lli.vptr != NULL))
		dma_free_coherent(g_the_sphcs->hw_device,
				copy->lli.size,
				copy->lli.vptr,
				copy->lli.dma_addr);
	if (copy->sw_counters)
		nnp_remove_sw_counters_values_node(copy->sw_counters);

	inf_devres_put(copy->devres);

	if (likely(copy->destroyed == 1))
		sphcs_send_event_report(g_the_sphcs,
				NNP_IPC_COPY_DESTROYED,
				0,
				copy->context->chan->respq,
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
	queue_work(system_wq, &copy->work);
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

	NNP_ASSERT(req->cmd_type == CMDLIST_CMD_COPY);

	copy = req->copy;
	inf_devres_del_req_from_queue(req->depend_devres, req);
	inf_context_seq_id_fini(copy->context, &req->seq);

	/* advance sched tick and try execute next requests */
	atomic_add(2, &req->context->sched_tick);
	inf_devres_try_execute(req->depend_devres);

	inf_devres_put(req->depend_devres);
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
	req->depend_devres = NULL;
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

	NNP_ASSERT(req->cmd_type == CMDLIST_CMD_COPY);

	copy = req->copy;
	inf_copy_get(copy);
	req->depend_devres = inf_devres_get_depend_pivot(copy->devres);
	inf_devres_get(req->depend_devres);
	spin_lock_init(&req->lock_irq);
	inf_context_seq_id_init(copy->context, &req->seq);

	DO_TRACE_IF(!copy->subres_copy, trace_copy(SPH_TRACE_OP_STATUS_QUEUED,
					 copy->context->protocolID,
					 copy->protocolID,
					 req->cmd ? req->cmd->protocolID : -1,
					 copy->card2Host,
					 copy->d2d ? sphcs_p2p_get_peer_dev_id(&(copy->devres->p2p_buf)) : -1,
					 req->size,
					 1,
					 copy->lli.num_lists,
					 copy->lli.num_elements));

	if (NNP_SW_GROUP_IS_ENABLE(copy->sw_counters,
				   COPY_SPHCS_SW_COUNTERS_GROUP)) {
		req->time = nnp_time_us();
	}

	inf_exec_req_get(req);

	/* Add request to the queue */
	err = inf_devres_add_req_to_queue(req->depend_devres, req, copy->card2Host);
	if (unlikely(err < 0)) {
		inf_context_seq_id_fini(copy->context, &req->seq);
		inf_copy_put(copy);
		return err;
	}

	// First try to execute
	req->last_sched_tick = 0;
	inf_req_try_execute(req);

	inf_exec_req_put(req);

	return 0;
}

static enum EXEC_REQ_READINESS inf_copy_req_ready(struct inf_exec_req *req)
{
	struct inf_copy *copy;
	enum DEV_RES_READINESS dev_res_status;
	enum EXEC_REQ_READINESS res;

	NNP_ASSERT(req->cmd_type == CMDLIST_CMD_COPY);

	copy = req->copy;

	if (copy->active)
		return EXEC_REQ_READINESS_NOT_READY;

	dev_res_status = inf_devres_req_ready(req->depend_devres, req, copy->card2Host);
	switch (dev_res_status) {
	case DEV_RES_READINESS_NOT_READY:
		res = EXEC_REQ_READINESS_NOT_READY;
		break;
	case DEV_RES_READINESS_READY:
		res = EXEC_REQ_READINESS_READY_NO_DIRTY_INPUTS;
		break;
	case DEV_RES_READINESS_READY_BUT_DIRTY:
		/* For C2H consider dirty of resource only, discarding group dirty of its potential pivot */
		NNP_ASSERT(copy->card2Host);
		if (!copy->devres->is_dirty)
			res = EXEC_REQ_READINESS_READY_NO_DIRTY_INPUTS;
		else
			res = EXEC_REQ_READINESS_READY_HAS_DIRTY_INPUTS;
		break;
	default:
		res = EXEC_REQ_READINESS_NOT_READY;
	}

	return res;
}

static int inf_copy_req_execute(struct inf_exec_req *req)
{
	struct sphcs_dma_desc const *desc;
	struct inf_copy *copy;

	NNP_ASSERT(req->cmd_type == CMDLIST_CMD_COPY);
	NNP_ASSERT(req->in_progress);

	copy = req->copy;
	DO_TRACE_IF(!copy->subres_copy, trace_copy(SPH_TRACE_OP_STATUS_START,
		 copy->context->protocolID,
		 copy->protocolID,
		 req->cmd ? req->cmd->protocolID : -1,
		 copy->card2Host,
		 copy->d2d ? sphcs_p2p_get_peer_dev_id(&(copy->devres->p2p_buf)) : -1,
		 req->size,
		 1,
		 copy->lli.num_lists,
		 copy->lli.num_elements));

	if (copy->subres_copy) {
		u32 transfer_size;
		u32 lli_size_keep;
		int ret;

		lli_size_keep = copy->lli.size;
		ret = g_the_sphcs->hw_ops->dma.init_lli(g_the_sphcs->hw_handle,
							&copy->lli,
							&req->hostres_map->host_sgt,
							copy->devres->dma_map,
							req->devres_offset, false);
		if (ret != 0 || copy->lli.size > lli_size_keep) {
			sph_log_err(EXECUTE_COMMAND_LOG, "Failed init lli for subres ret=%d size=%u size_keep=%u vptr=0x%lx\n",
				    ret, copy->lli.size, lli_size_keep, (uintptr_t)copy->lli.vptr);
			copy->lli.size = lli_size_keep;
			return -ENOMEM;
		}
		copy->lli.size = lli_size_keep;

		transfer_size = g_the_sphcs->hw_ops->dma.gen_lli(g_the_sphcs->hw_handle,
								 &req->hostres_map->host_sgt,
								 copy->devres->dma_map,
								 &copy->lli,
								 req->devres_offset);
		if (transfer_size < 1)
			return -EINVAL;
	}

	if (NNP_SW_GROUP_IS_ENABLE(copy->sw_counters,
				   COPY_SPHCS_SW_COUNTERS_GROUP)) {
		u64 now;

		now = nnp_time_us();
		if (req->time) {
			u64 dt;

			dt = now - req->time;
			NNP_SW_COUNTER_ADD(copy->sw_counters,
					   COPY_SPHCS_SW_COUNTERS_BLOCK_TOTAL_TIME,
					   dt);

			NNP_SW_COUNTER_INC(copy->sw_counters,
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
		return -NNPER_CONTEXT_BROKEN;

	g_the_sphcs->hw_ops->dma.edit_lli(g_the_sphcs->hw_handle, &copy->lli, req->size);

	return sphcs_dma_sched_start_xfer_multi(g_the_sphcs->dmaSched,
						&copy->multi_xfer_handle,
						desc,
						&copy->lli,
						req->size,
						copy->d2d ? d2d_copy_complete_cb : copy_complete_cb,
						req);
}

static void treat_copy_failure(struct inf_exec_req *req,
				enum event_val       eventVal,
				const void          *error_msg,
				int32_t              error_msg_size)
{
	struct inf_copy *copy;
	struct inf_exec_error_details *err_details;
	int rc;

	NNP_ASSERT(req->cmd_type == CMDLIST_CMD_COPY);

	copy = req->copy;

	rc = inf_exec_error_details_alloc(CMDLIST_CMD_COPY,
					  copy->protocolID,
					  0,
					  eventVal,
					  error_msg_size > 0 ? error_msg_size : 0,
					  &err_details);
	if (likely(rc == 0)) {
		if (error_msg_size > 0)
			memcpy(err_details->error_msg, error_msg, error_msg_size);

		inf_exec_error_list_add(req->cmd != NULL ? &req->cmd->error_list :
							   &copy->context->error_list,
					err_details);
	}

	if (req->cmd == NULL)
		inf_context_set_state(copy->context,
				      CONTEXT_BROKEN_RECOVERABLE);
	if (!copy->card2Host)
		inf_devres_set_dirty(copy->devres, true);
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
	bool send_cmdlist_event_report = false;

	NNP_ASSERT(req->cmd_type == CMDLIST_CMD_COPY);
	NNP_ASSERT(req->in_progress);

	copy = req->copy;
	devres = copy->devres;
	cmd = req->cmd;
	is_d2d_copy = copy->d2d;

	 DO_TRACE_IF(!copy->subres_copy, trace_copy(SPH_TRACE_OP_STATUS_COMPLETE,
					 copy->context->protocolID,
					 copy->protocolID,
					 cmd ? cmd->protocolID : -1,
					 copy->card2Host,
					 copy->d2d ? sphcs_p2p_get_peer_dev_id(&(copy->devres->p2p_buf)) : -1,
					 req->size,
					 1,
					 copy->lli.num_lists,
					 copy->lli.num_elements));

	if (NNP_SW_GROUP_IS_ENABLE(copy->sw_counters,
				   COPY_SPHCS_SW_COUNTERS_GROUP)) {
		u64 now;

		now = nnp_time_us();
		if (req->time) {
			u64 dt;

			dt = now - req->time;
			NNP_SW_COUNTER_ADD(copy->sw_counters,
					   COPY_SPHCS_SW_COUNTERS_EXEC_TOTAL_TIME,
					   dt);

			NNP_SW_COUNTER_INC(copy->sw_counters,
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
			eventVal = NNP_IPC_NO_MEMORY;
			break;
		case -NNPER_CONTEXT_BROKEN:
			eventVal = NNP_IPC_CONTEXT_BROKEN;
			break;
		case -NNPER_INPUT_IS_DIRTY:
			eventVal = NNP_IPC_INPUT_IS_DIRTY;
			break;
		default:
			eventVal = NNP_IPC_DMA_ERROR;
		}

		treat_copy_failure(req, eventVal, error_msg, error_msg_size);
	} else {
		if (!copy->card2Host)
			inf_devres_set_dirty(devres, false);

		eventVal = 0;
	}

	/* If copy from destination p2p resource completed*/
	if (copy->card2Host && copy->devres->is_p2p_dst) {
		/* Resource will be ready again, once d2d copy will succeed */
		devres->p2p_buf.ready = false;

		if (!copy->devres->is_dirty) {
			/* If copy is part of command list, the command list completion will be reported
			 * only when all credits are released
			 */
			if (cmd != NULL)
				atomic_inc(&cmd->num_left);

			/* If failed to send credits and copy is part of command list */
			if (inf_devres_send_release_credit(copy->devres, req) && (cmd != NULL))
				atomic_dec(&cmd->num_left);
		}
	}

	if (cmd != NULL)
		send_cmdlist_event_report = atomic_dec_and_test(&cmd->num_left);

	if (eventVal == 0 && send_cmdlist_event_report && !is_d2d_copy) {
		// if success and should send both cmd and copy reports,
		// send one merged report
		sphcs_send_event_report_ext(g_the_sphcs,
					    NNP_IPC_EXECUTE_COPY_SUCCESS,
					    eventVal,
					    copy->context->chan->respq,
					    copy->context->protocolID,
					    copy->protocolID,
					    cmd->protocolID);
	} else {
		send_copy_report(req, eventVal);

		if (send_cmdlist_event_report)
			sphcs_send_event_report(g_the_sphcs,
						NNP_IPC_EXECUTE_CMD_COMPLETE,
						0,
						cmd->context->chan->respq,
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

	inf_exec_req_put(req);
}

static void send_copy_report(struct inf_exec_req *req,
			     enum event_val       eventVal)
{
	struct inf_copy *copy;
	uint16_t eventCode;
	int cmdID;

	NNP_ASSERT(req->cmd_type == CMDLIST_CMD_COPY);

	copy = req->copy;
	if (eventVal != 0 && req->cmd != NULL)
		cmdID = req->cmd->protocolID;
	else
		cmdID = -1;

	if (copy->subres_copy)
		eventCode = (eventVal == 0) ? NNP_IPC_EXECUTE_COPY_SUBRES_SUCCESS : NNP_IPC_EXECUTE_COPY_SUBRES_FAILED;
	else
		eventCode = (eventVal == 0) ? NNP_IPC_EXECUTE_COPY_SUCCESS : NNP_IPC_EXECUTE_COPY_FAILED;

	// report success only when not d2d
	if (eventVal != 0 || !copy->d2d)
		sphcs_send_event_report_ext(g_the_sphcs,
					    eventCode,
					    eventVal,
					    copy->context->chan->respq,
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
	int i;

	if (req->priority != priority)
		for (i = 0; i < req->copy->lli.num_lists; i++)
			ret |= inf_update_priority(req,
						   priority,
						   req->copy->card2Host,
						   req->copy->lli.dma_addr + req->copy->lli.offsets[i]);

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
