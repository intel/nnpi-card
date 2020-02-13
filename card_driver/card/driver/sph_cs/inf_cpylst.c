/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#include "inf_cpylst.h"
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/scatterlist.h>
#include <linux/limits.h>
#include "sphcs_cs.h"
#include "sphcs_inf.h"
#include "sph_log.h"
#include "ipc_protocol.h"
#include "inf_context.h"
#include "inf_copy.h"
#include "inf_exec_req.h"
#include "sph_error.h"
#include "sphcs_trace.h"

static int inf_cpylst_req_sched(struct inf_exec_req *req);
static bool inf_cpylst_req_ready(struct inf_exec_req *req);
static int inf_cpylst_req_execute(struct inf_exec_req *req);
static void inf_cpylst_req_complete(struct inf_exec_req *req,
				    int                  err,
				    const void          *error_msg,
				    int32_t              error_msg_size);
static void send_cpylst_report(struct inf_exec_req *req,
			       enum event_val       eventVal);
static int inf_req_cpylst_put(struct inf_exec_req *req);
static int inf_cpylst_migrate_priority(struct inf_exec_req *req, uint8_t priority);
static void inf_cpylst_req_release(struct kref *kref);

struct func_table const s_cpylst_funcs = {
	.schedule = inf_cpylst_req_sched,
	.is_ready = inf_cpylst_req_ready,
	.execute = inf_cpylst_req_execute,
	.complete = inf_cpylst_req_complete,
	.send_report = send_cpylst_report,
	.obj_put = inf_req_cpylst_put,
	.migrate_priority = inf_cpylst_migrate_priority,

	/* This function should not be called directly, use inf_exec_req_put instead */
	.release = inf_cpylst_req_release
};

static int cpylst_complete_cb(struct sphcs *sphcs, void *ctx, const void *user_data, int status, u32 xferTimeUS)
{
	int err;
	struct inf_exec_req *req = (struct inf_exec_req *)ctx;
//	struct inf_cpylst *cpylst;

	SPH_ASSERT(req != NULL);

	if (unlikely(status == SPHCS_DMA_STATUS_FAILED)) {
		err = -SPHER_DMA_ERROR;
	} else {
		/* if status is not an error - it must be done */
		SPH_ASSERT(status == SPHCS_DMA_STATUS_DONE);
		err = 0;
	}

#if 0
	cpylst = req->cpylst;
	if (xferTimeUS > 0 &&
	    SPH_SW_GROUP_IS_ENABLE(cpylst->sw_counters,
				   COPY_SPHCS_SW_COUNTERS_GROUP)) {
		SPH_SW_COUNTER_ADD(cpylst->sw_counters,
					COPY_SPHCS_SW_COUNTERS_HWEXEC_TOTAL_TIME,
					xferTimeUS);

		if (xferTimeUS < cpylst->min_hw_exec_time) {
			SPH_SW_COUNTER_SET(cpylst->sw_counters,
						COPY_SPHCS_SW_COUNTERS_HWEXEC_MIN_TIME,
						xferTimeUS);
			cpylst->min_hw_exec_time = xferTimeUS;
		}

		if (xferTimeUS > cpylst->max_hw_exec_time) {
			SPH_SW_COUNTER_SET(cpylst->sw_counters,
						COPY_SPHCS_SW_COUNTERS_HWEXEC_MAX_TIME,
						xferTimeUS);
			copy->max_hw_exec_time = xferTimeUS;
		}
	}
#endif

	req->f->complete(req, err, NULL, 0);

	return err;
}

int inf_cpylst_create(struct inf_cmd_list *cmd,
		      uint16_t             cmdlist_index,
		      uint16_t             num_copies,
		      struct inf_cpylst  **out_cpylst)
{
	struct inf_cpylst *cpylst;
#if 0
	int res;
#endif

	if (unlikely(num_copies == 0))
		return -EINVAL;

	cpylst = kmalloc(sizeof(struct inf_cpylst), GFP_KERNEL);
	if (unlikely(cpylst == NULL)) {
		sph_log_err(CREATE_COMMAND_LOG, "FATAL: line:%u failed to allocate copy list object\n", __LINE__);
		return -ENOMEM;
	}

	cpylst->copies = kcalloc(num_copies, sizeof(struct inf_copy *), GFP_KERNEL);
	if (unlikely(cpylst->copies == NULL)) {
		sph_log_err(CREATE_COMMAND_LOG, "FATAL: line:%u failed to allocate array of copies\n", __LINE__);
		goto free_cpylst;
	}

	cpylst->priorities = kmalloc_array(num_copies, sizeof(uint64_t), GFP_KERNEL);
	if (unlikely(cpylst->priorities == NULL)) {
		sph_log_err(CREATE_COMMAND_LOG, "FATAL: line:%u failed to allocate array of priorities\n", __LINE__);
		goto free_copies;
	}

	cpylst->sizes = kmalloc_array(num_copies, sizeof(uint64_t), GFP_KERNEL);
	if (unlikely(cpylst->sizes == NULL)) {
		sph_log_err(CREATE_COMMAND_LOG, "FATAL: line:%u failed to allocate array of sizes\n", __LINE__);
		goto free_priorities;
	}

	cpylst->cur_sizes = kcalloc(num_copies, sizeof(uint64_t), GFP_KERNEL);
	if (unlikely(cpylst->cur_sizes == NULL)) {
		sph_log_err(CREATE_COMMAND_LOG, "FATAL: line:%u failed to allocate array of current sizes\n", __LINE__);
		goto free_sizes;
	}

	cpylst->devreses = kmalloc_array(num_copies, sizeof(uint64_t), GFP_KERNEL);
	if (unlikely(cpylst->devreses == NULL)) {
		sph_log_err(CREATE_COMMAND_LOG, "FATAL: line:%u failed to allocate array of device resourses\n", __LINE__);
		goto free_cur_sizes;
	}

	cpylst->magic = inf_cpylst_create;
	cpylst->idx_in_cmd = cmdlist_index;
	cpylst->n_copies = num_copies;
	cpylst->added_copies = 0;
	cpylst->size = 0;
	cpylst->lli.vptr = NULL;
	cpylst->cur_lli.vptr = NULL;
	cpylst->destroyed = 0;
	cpylst->min_block_time = U64_MAX;
	cpylst->max_block_time = 0;
	cpylst->min_exec_time = U64_MAX;
	cpylst->max_exec_time = 0;
	cpylst->min_hw_exec_time = U64_MAX;
	cpylst->max_hw_exec_time = 0;

	sphcs_dma_multi_xfer_handle_init(&cpylst->multi_xfer_handle);

#if 0
	res = sph_create_sw_counters_values_node(g_hSwCountersInfo_copy,
						 (u32)protocolCopyID,
						 context->sw_counters,
						 &copy->sw_counters);
	if (unlikely(res < 0)) {
		inf_devres_put(devres);
		kfree(copy);
		return res;
	}
#endif

	*out_cpylst = cpylst;

	return 0;

free_cur_sizes:
	kfree(cpylst->cur_sizes);
free_sizes:
	kfree(cpylst->sizes);
free_priorities:
	kfree(cpylst->priorities);
free_copies:
	kfree(cpylst->copies);
free_cpylst:
	kfree(cpylst);

	return -ENOMEM;
}

struct genlli_iterator {
	struct inf_cpylst *cpylst;
	uint16_t           curr_idx;
	uint64_t          *sizes;
};

static bool genlli_get_next(void             *ctx,
			    struct sg_table **out_src,
			    struct sg_table **out_dst,
			    uint64_t         *out_max_size)
{
	struct genlli_iterator *it = (struct genlli_iterator *)ctx;

	if (it->curr_idx < it->cpylst->n_copies) {
		*out_src = inf_copy_src_sgt(it->cpylst->copies[it->curr_idx]);
		*out_dst = inf_copy_dst_sgt(it->cpylst->copies[it->curr_idx]);
		*out_max_size = it->sizes[it->curr_idx];
		++it->curr_idx;
		return true;
	}

	return false;
}

static int inf_cpylst_init_llis(struct inf_cpylst *cpylst)
{
	struct genlli_iterator it;
	u64 total_entries_bytes;
	int ret;

	it.cpylst = cpylst;

	/* allocate lli for overwrite params */
	it.curr_idx = 0;
	/* all sizes in cur_sizes array are zero,
	 * so we get cur_lli_size be maximum
	 */
	it.sizes = cpylst->cur_sizes;
	ret = g_the_sphcs->hw_ops->dma.init_lli_vec(g_the_sphcs->hw_handle,
						    &cpylst->cur_lli,
						    0,
						    genlli_get_next,
						    &it);
	if (ret != 0 || cpylst->cur_lli.size == 0) {
		sph_log_err(CREATE_COMMAND_LOG, "FATAL: line:%u failed to init current lli buffer\n", __LINE__);
		return -ENOMEM;
	}

	// allocate memory in size lli_size
	cpylst->cur_lli.vptr = dma_alloc_coherent(g_the_sphcs->hw_device, cpylst->cur_lli.size, &cpylst->cur_lli.dma_addr, GFP_KERNEL);
	if (unlikely(cpylst->cur_lli.vptr == NULL)) {
		sph_log_err(CREATE_COMMAND_LOG, "FATAL: line:%u failed to allocate current lli buffer\n", __LINE__);
		return -ENOMEM;
	}

	/* allocate and generate lli for default params */
	it.curr_idx = 0;
	it.sizes = cpylst->sizes;
	ret = g_the_sphcs->hw_ops->dma.init_lli_vec(g_the_sphcs->hw_handle,
						    &cpylst->lli,
						    0,
						    genlli_get_next,
						    &it);
	if (ret != 0 || cpylst->lli.size == 0) {
		sph_log_err(CREATE_COMMAND_LOG, "FATAL: line:%u failed to init lli buffer\n", __LINE__);
		return -ENOMEM;
	}

	// allocate memory in size lli_size
	cpylst->lli.vptr = dma_alloc_coherent(g_the_sphcs->hw_device, cpylst->lli.size, &cpylst->lli.dma_addr, GFP_KERNEL);
	if (unlikely(cpylst->lli.vptr == NULL)) {
		sph_log_err(CREATE_COMMAND_LOG, "FATAL: line:%u failed to allocate lli buffer\n", __LINE__);
		return -ENOMEM;
	}

	// generate lli buffer for dma
	it.curr_idx = 0;
	total_entries_bytes = g_the_sphcs->hw_ops->dma.gen_lli_vec(g_the_sphcs->hw_handle,
								   &cpylst->lli,
								   0,
								   genlli_get_next,
								   &it);
	SPH_ASSERT(total_entries_bytes > 0);

	return 0;
}

int inf_cpylst_build_cur_lli(struct inf_cpylst *cpylst)
{
	struct genlli_iterator it;
	u64 total_entries_bytes;
	u32 prev_lli_size;
	int ret;

	/* we must re-initialize lli since it may be divided to different sub-lists */
	it.cpylst = cpylst;
	it.curr_idx = 0;
	it.sizes = cpylst->cur_sizes;
	prev_lli_size = cpylst->cur_lli.size;
	ret = g_the_sphcs->hw_ops->dma.init_lli_vec(g_the_sphcs->hw_handle,
						    &cpylst->cur_lli,
						    0,
						    genlli_get_next,
						    &it);
	if (ret != 0 || cpylst->cur_lli.size == 0 || cpylst->cur_lli.size > prev_lli_size) {
		sph_log_info(CREATE_COMMAND_LOG, "WARN: modified lli for cpylst larger than allocated %u > %u\n",
			     cpylst->cur_lli.size, prev_lli_size);
		cpylst->cur_lli.size = prev_lli_size;
		return -ENOMEM;
	}
	cpylst->cur_lli.size = prev_lli_size;

	/* generate the lli list content */
	it.cpylst = cpylst;
	it.curr_idx = 0;
	it.sizes = cpylst->cur_sizes;
	total_entries_bytes = g_the_sphcs->hw_ops->dma.gen_lli_vec(g_the_sphcs->hw_handle,
								   &cpylst->cur_lli,
								   0,
								   genlli_get_next,
								   &it);
	SPH_ASSERT(total_entries_bytes > 0);

	return 0;
}

int inf_cpylst_add_copy(struct inf_cpylst *cpylst,
			struct inf_copy *copy,
			uint64_t size,
			uint8_t priority)
{
	int ret = 0;

	if (unlikely(cpylst == NULL))
		return -EINVAL;

	if (unlikely(cpylst->added_copies >= cpylst->n_copies))
		return -EXFULL;

	// Cannot batch different direction copies
	SPH_ASSERT(cpylst->added_copies == 0 ||
		   cpylst->copies[cpylst->added_copies - 1]->card2Host == copy->card2Host);

	inf_copy_get(copy);

	size = size != 0 ? size : copy->devres->size;
	cpylst->copies[cpylst->added_copies] = copy;
	cpylst->sizes[cpylst->added_copies] = size;
	cpylst->priorities[cpylst->added_copies] = priority;
	cpylst->devreses[cpylst->added_copies] = copy->devres;
	++cpylst->added_copies;
	cpylst->size += size;
	if (unlikely(cpylst->added_copies == cpylst->n_copies)) {
		ret = inf_cpylst_init_llis(cpylst);
		memcpy(cpylst->cur_sizes, cpylst->sizes, cpylst->n_copies * sizeof(cpylst->sizes[0]));
		cpylst->active = false;
	}
	return ret;
}

static void release_cpylst(struct inf_cpylst *cpylst)
{
	uint16_t i;

	if (likely(cpylst->lli.vptr != NULL))
		dma_free_coherent(g_the_sphcs->hw_device,
				  cpylst->lli.size,
				  cpylst->lli.vptr,
				  cpylst->lli.dma_addr);

	if (likely(cpylst->cur_lli.vptr != NULL))
		dma_free_coherent(g_the_sphcs->hw_device,
				  cpylst->cur_lli.size,
				  cpylst->cur_lli.vptr,
				  cpylst->cur_lli.dma_addr);
#if 0
	//TODO CPYLST counters
	if (copy->sw_counters)
		sph_remove_sw_counters_values_node(copy->sw_counters);
#endif

	for (i = 0; i < cpylst->n_copies; ++i) {
		if (unlikely(cpylst->copies[i] == NULL))
			break;
		inf_copy_put(cpylst->copies[i]);
	}
	kfree(cpylst->devreses);
	kfree(cpylst->cur_sizes);
	kfree(cpylst->sizes);
	kfree(cpylst->priorities);
	kfree(cpylst->copies);

	kfree(cpylst);
}

static void inf_cpylst_req_release(struct kref *kref)
{
	struct inf_exec_req *req = container_of(kref,
						struct inf_exec_req,
						in_use);
	struct inf_cpylst *cpylst;
	struct inf_cmd_list *cmd = req->cmd;
	uint16_t i;

	SPH_ASSERT(req->cmd_type == CMDLIST_CMD_COPYLIST);
	SPH_ASSERT(cmd != NULL);

	cpylst = req->cpylst;
	for (i = 0; i < req->num_opt_depend_devres; ++i)
		inf_devres_del_req_from_queue(req->opt_depend_devres[i], req);
	inf_context_seq_id_fini(req->context, &req->seq);

	/* advance sched tick and try execute next requests */
	atomic_add(2, &req->context->sched_tick);
	for (i = 0; i < req->num_opt_depend_devres; ++i)
		inf_devres_try_execute(req->opt_depend_devres[i]);

	kmem_cache_free(req->context->exec_req_slab_cache, req);
	inf_cmd_put(cmd);
}

void inf_cpylst_req_init(struct inf_exec_req *req,
			struct inf_cpylst *cpylst,
			struct inf_cmd_list *cmd)
{
	kref_init(&req->in_use);
	req->in_progress = false;
	req->context = cmd->context;
	req->last_sched_tick = 0;
	req->cmd_type = CMDLIST_CMD_COPYLIST;
	req->f = &s_cpylst_funcs;
	req->cpylst = cpylst;
	req->cmd = cmd;
	req->size = 0;
	req->priority = 0;
	req->time = 0;
	req->num_opt_depend_devres = req->cpylst->n_copies;
	req->opt_depend_devres = req->cpylst->devreses;
}

static int inf_cpylst_req_sched(struct inf_exec_req *req)
{
	struct inf_cpylst *cpylst;
	bool read;
	uint16_t i;
	int err;

	SPH_ASSERT(req->cmd_type == CMDLIST_CMD_COPYLIST);
	SPH_ASSERT(req->cmd != NULL);

	cpylst = req->cpylst;
	inf_cmd_get(req->cmd);
	spin_lock_init(&req->lock_irq);
	inf_context_seq_id_init(req->context, &req->seq);

	DO_TRACE(trace_copy(SPH_TRACE_OP_STATUS_QUEUED,
		 req->context->protocolID,
		 cpylst->idx_in_cmd,
		 req->cmd->protocolID,
		 cpylst->copies[0]->card2Host,
		 req->size,
		 cpylst->n_copies,
		 req->lli->num_lists));

#if 0
	if (SPH_SW_GROUP_IS_ENABLE(copy->sw_counters,
				   COPY_SPHCS_SW_COUNTERS_GROUP)) {
		req->time = sph_time_us();
	}
#endif

	inf_exec_req_get(req);

	read = cpylst->copies[0]->card2Host;
	for (i = 0; i < req->num_opt_depend_devres; ++i) {
		err = inf_devres_add_req_to_queue(req->opt_depend_devres[i], req, read);
		if (unlikely(err < 0))
			goto fail;
	}

#if 0
	// Request scheduled
	SPH_SW_COUNTER_INC(infreq->devnet->context->sw_counters,
			   CTX_SPHCS_SW_COUNTERS_INFERENCE_SUBMITTED_INF_REQ);
#endif

	// First try to execute
	req->last_sched_tick = 0;
	inf_req_try_execute(req);

	inf_exec_req_put(req);

	return 0;

fail:
	for (--i; i >= 0; --i)
		inf_devres_del_req_from_queue(req->opt_depend_devres[i], req);
	inf_context_seq_id_fini(req->context, &req->seq);
	inf_cmd_put(req->cmd);

	return err;
}

static bool inf_cpylst_req_ready(struct inf_exec_req *req)
{
	bool read;
	uint16_t i;

	SPH_ASSERT(req->cmd_type == CMDLIST_CMD_COPYLIST);

	if (req->cpylst->active)
		return false;

	read = req->cpylst->copies[0]->card2Host;
	for (i = 0; i < req->num_opt_depend_devres; ++i) {
		if (!inf_devres_req_ready(req->opt_depend_devres[i], req, read))
			return false;
	}

	return true;
}

static int inf_cpylst_req_execute(struct inf_exec_req *req)
{
	struct sphcs_dma_desc const *desc;
	struct inf_cpylst *cpylst;

	SPH_ASSERT(req->cmd_type == CMDLIST_CMD_COPYLIST);
	SPH_ASSERT(req->in_progress);

	cpylst = req->cpylst;

	DO_TRACE(trace_copy(SPH_TRACE_OP_STATUS_START,
		 req->cmd->context->protocolID,
		 cpylst->idx_in_cmd,
		 req->cmd->protocolID,
		 cpylst->copies[0]->card2Host,
		 req->size,
		 req->cpylst->n_copies,
		 req->lli->num_lists));

#if 0

	TODO CPYLST counters
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
#endif

	if (cpylst->copies[0]->card2Host) {
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

	cpylst->active = true;

	if (inf_context_get_state(req->context) != CONTEXT_OK)
		return -SPHER_CONTEXT_BROKEN;

	return sphcs_dma_sched_start_xfer_multi(g_the_sphcs->dmaSched,
						&req->cpylst->multi_xfer_handle,
						desc,
						req->lli,
						req->size,
						cpylst_complete_cb,
						req);
}

static void inf_cpylst_req_complete(struct inf_exec_req *req,
				    int                  err,
				    const void          *error_msg,
				    int32_t              error_msg_size)
{
	enum event_val eventVal;
	struct inf_cpylst *cpylst;
	struct inf_cmd_list *cmd;
	unsigned long flags;
	bool send_cmdlist_event_report = false;
	struct inf_exec_error_details *err_details = NULL;
	int rc;

	SPH_ASSERT(req->cmd_type == CMDLIST_CMD_COPYLIST);
	SPH_ASSERT(req->cmd != NULL);
	SPH_ASSERT(req->in_progress);

	cpylst = req->cpylst;
	cmd = req->cmd;

	DO_TRACE(trace_copy(SPH_TRACE_OP_STATUS_COMPLETE,
		 req->cmd->context->protocolID,
		 cpylst->idx_in_cmd,
		 req->cmd->protocolID,
		 cpylst->copies[0]->card2Host,
		 req->size,
		 req->cpylst->n_copies,
		 req->lli->num_lists));

#if 0
	//TODO CPYLST counters
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
#endif

	if (unlikely(err < 0)) {
		sph_log_err(EXECUTE_COMMAND_LOG, "Execute coylst failed with err=%d\n", err);
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

		rc = inf_exec_error_details_alloc(CMDLIST_CMD_COPYLIST,
						  cpylst->idx_in_cmd,
						  req->cmd->protocolID,
						  eventVal,
						  error_msg_size > 0 ? error_msg_size : 0,
						  &err_details);
		if (rc == 0) {
			if (error_msg_size > 0)
				memcpy(err_details->error_msg, error_msg, error_msg_size);

			inf_exec_error_list_add(&cmd->error_list,
						err_details);
		}

		//TODO GLEB: Decide if copy failed brakes context or cmd or ...
	} else {
		eventVal = 0;
	}
	if (cmd != NULL) {
		SPH_SPIN_LOCK_IRQSAVE(&cmd->lock_irq, flags);
		if (--cmd->num_left == 0)
			send_cmdlist_event_report = true;
		SPH_SPIN_UNLOCK_IRQRESTORE(&cmd->lock_irq, flags);
	}

	if (eventVal == 0 && send_cmdlist_event_report) {
		// if success and should send both cmd and copy reports,
		// send one merged report
		sphcs_send_event_report_ext(g_the_sphcs,
					    SPH_IPC_EXECUTE_CPYLST_SUCCESS,
					    //eventVal isn't 0 to differentiate
					    //between CMD and cpylst
					    SPH_IPC_CMDLIST_FINISHED,
					    cmd->context->protocolID,
					    cmd->protocolID,
					    cpylst->idx_in_cmd);
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

	memcpy(cpylst->cur_sizes, cpylst->sizes, cpylst->n_copies * sizeof(cpylst->sizes[0]));

	cpylst->active = false;

	inf_exec_req_put(req);
}

static void send_cpylst_report(struct inf_exec_req *req,
			       enum event_val       eventVal)
{
	struct inf_cpylst *cpylst;
	uint16_t eventCode = eventVal == 0 ? SPH_IPC_EXECUTE_CPYLST_SUCCESS : SPH_IPC_EXECUTE_CPYLST_FAILED;

	SPH_ASSERT(req->cmd_type == CMDLIST_CMD_COPYLIST);
	SPH_ASSERT(req->cmd != NULL);

	cpylst = req->cpylst;
	sphcs_send_event_report_ext(g_the_sphcs,
				    eventCode,
				    eventVal,
				    req->context->protocolID,
				    req->cmd->protocolID,
				    cpylst->idx_in_cmd);
}

static int inf_req_cpylst_put(struct inf_exec_req *req)
{
	release_cpylst(req->cpylst);

	return 1; //return 1 to be compliant with kref_put
}

static int inf_cpylst_migrate_priority(struct inf_exec_req *req, uint8_t priority)
{
	int ret = 0;
	int i;

	//TODO CPYLST migrate recurcively
	if (req->priority != priority)
		for (i = 0; i < req->cpylst->lli.num_lists; i++)
			ret |= inf_update_priority(req,
						   priority,
						   req->cpylst->copies[0]->card2Host,
						   req->cpylst->lli.dma_addr + req->cpylst->lli.offsets[i]);

	return ret;
}
