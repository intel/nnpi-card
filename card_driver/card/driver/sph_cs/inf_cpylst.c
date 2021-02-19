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
#include "nnp_error.h"
#include "sphcs_trace.h"
#include "sph_safe.h"

static int inf_cpylst_req_sched(struct inf_exec_req *req);
static enum EXEC_REQ_READINESS inf_cpylst_req_ready(struct inf_exec_req *req);
static int inf_cpylst_req_execute(struct inf_exec_req *req);
static void inf_cpylst_req_complete(struct inf_exec_req *req,
				    int                  err,
				    const void          *error_msg,
				    int32_t              error_msg_size);
static void send_cpylst_report(struct inf_exec_req *req,
			       enum event_val       event_val);
static int inf_req_cpylst_put(struct inf_exec_req *req);
static int inf_cpylst_migrate_priority(struct inf_exec_req *req, uint8_t priority);
static void treat_cpylst_failure(struct inf_exec_req *req,
				 enum event_val       event_val,
				 const void          *error_msg,
				 int32_t              error_msg_size);

static void inf_cpylst_req_release(struct kref *kref);


struct func_table const s_cpylst_funcs = {
	.schedule = inf_cpylst_req_sched,
	.is_ready = inf_cpylst_req_ready,
	.execute = inf_cpylst_req_execute,
	.complete = inf_cpylst_req_complete,
	.send_report = send_cpylst_report,
	.obj_put = inf_req_cpylst_put,
	.migrate_priority = inf_cpylst_migrate_priority,
	.treat_req_failure = treat_cpylst_failure,

	/* This function should not be called directly, use inf_exec_req_put instead */
	.release = inf_cpylst_req_release
};

static int cpylst_complete_cb(struct sphcs *sphcs, void *ctx, const void *user_data, int status, u32 xferTimeUS)
{
	int err;
	struct inf_exec_req *req = (struct inf_exec_req *)ctx;

	NNP_ASSERT(req != NULL);

	if (unlikely(status == SPHCS_DMA_STATUS_FAILED)) {
		err = -NNPER_DMA_ERROR;
	} else {
		/* if status is not an error - it must be done */
		NNP_ASSERT(status == SPHCS_DMA_STATUS_DONE);
		err = 0;
	}

	inf_cpylst_req_complete(req, err, NULL, 0);

	return err;
}

int inf_cpylst_create(struct inf_cmd_list *cmd,
		      uint16_t             cmdlist_index,
		      uint16_t             num_copies,
		      struct inf_cpylst  **out_cpylst)
{
	struct inf_cpylst *cpylst;

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

	cpylst->cur_sizes = kmalloc_array(num_copies, sizeof(uint64_t), GFP_KERNEL);
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

	sphcs_dma_multi_xfer_handle_init(&cpylst->multi_xfer_handle);

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

	for ( ; it->curr_idx < it->cpylst->n_copies; ++it->curr_idx) {
		if (it->sizes[it->curr_idx] > 0) {
			*out_src = inf_copy_src_sgt(it->cpylst->copies[it->curr_idx]);
			*out_dst = inf_copy_dst_sgt(it->cpylst->copies[it->curr_idx]);
			*out_max_size = it->sizes[it->curr_idx];
			++it->curr_idx;

			return true;
		}
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

	if (cpylst->size == 0) {
		cpylst->lli.num_lists = 0;
		cpylst->lli.num_elements = 0;

		return 0;
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
	NNP_ASSERT(total_entries_bytes > 0);

	return 0;
}

int inf_cpylst_build_cur_lli(struct inf_cpylst *cpylst)
{
	struct genlli_iterator it;
	u64 total_entries_bytes;
	u32 prev_lli_size;
	int ret;

	if (cpylst->size == 0) {
		cpylst->cur_lli.num_lists = 0;
		cpylst->cur_lli.num_elements = 0;

		return 0;
	}

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
	NNP_ASSERT(total_entries_bytes > 0);

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
	NNP_ASSERT(cpylst->added_copies == 0 ||
		   cpylst->copies[cpylst->added_copies - 1]->card2Host == copy->card2Host);

	inf_copy_get(copy);

	size = size <= copy->devres->size ? size : copy->devres->size;
	cpylst->copies[cpylst->added_copies] = copy;
	cpylst->sizes[cpylst->added_copies] = size;
	cpylst->cur_sizes[cpylst->added_copies] = copy->devres->size;
	cpylst->priorities[cpylst->added_copies] = priority;
	cpylst->devreses[cpylst->added_copies] = copy->devres;
	++cpylst->added_copies;
	cpylst->size += size;
	if (unlikely(cpylst->added_copies == cpylst->n_copies)) {
		ret = inf_cpylst_init_llis(cpylst);
		memcpy(cpylst->cur_sizes, cpylst->sizes, cpylst->n_copies * sizeof(cpylst->sizes[0]));
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

	NNP_ASSERT(req->cmd_type == CMDLIST_CMD_COPYLIST);
	NNP_ASSERT(cmd != NULL);

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
	req->num_opt_depend_devres = req->cpylst->n_copies;
	req->opt_depend_devres = req->cpylst->devreses;
	req->lli = &cpylst->lli;
}

static int inf_cpylst_req_sched(struct inf_exec_req *req)
{
	struct inf_cpylst *cpylst;
	bool read;
	uint16_t i;
	int err;

	NNP_ASSERT(req->cmd_type == CMDLIST_CMD_COPYLIST);
	NNP_ASSERT(req->cmd != NULL);

	cpylst = req->cpylst;
	inf_cmd_get(req->cmd);
	spin_lock_init(&req->lock_irq);
	inf_context_seq_id_init(req->context, &req->seq);

	DO_TRACE(trace_copy(SPH_TRACE_OP_STATUS_QUEUED,
		 req->context->protocol_id,
		 cpylst->idx_in_cmd,
		 req->cmd->protocol_id,
		 cpylst->copies[0]->card2Host,
		 -1,
		 req->size,
		 cpylst->n_copies,
		 req->lli->num_lists,
		 req->lli->num_elements));

	if (NNP_SW_GROUP_IS_ENABLE(cpylst->copies[0]->sw_counters,
				   COPY_SPHCS_SW_COUNTERS_GROUP))
		req->time = nnp_time_us();
	else
		req->time = 0;

	inf_exec_req_get(req);

	read = cpylst->copies[0]->card2Host;
	for (i = 0; i < req->num_opt_depend_devres; ++i) {
		err = inf_devres_add_req_to_queue(req->opt_depend_devres[i], req, read);
		if (unlikely(err < 0))
			goto fail;
	}

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

static enum EXEC_REQ_READINESS inf_cpylst_req_ready(struct inf_exec_req *req)
{
	bool read;
	uint16_t i;
	bool has_dirty_inputs = false;
	enum DEV_RES_READINESS dev_res_status;

	NNP_ASSERT(req->cmd_type == CMDLIST_CMD_COPYLIST);

	read = req->cpylst->copies[0]->card2Host;
	for (i = 0; i < req->num_opt_depend_devres; ++i) {
		dev_res_status = inf_devres_req_ready(req->opt_depend_devres[i], req, read);
		if (dev_res_status == DEV_RES_READINESS_NOT_READY)
			return EXEC_REQ_READINESS_NOT_READY;
		if (read)
			has_dirty_inputs |= (dev_res_status == DEV_RES_READINESS_READY_BUT_DIRTY);

	}

	/* The cpylist is ready, check whether it has some dirty input */
	if (has_dirty_inputs)
		return EXEC_REQ_READINESS_READY_HAS_DIRTY_INPUTS;
	else
		return EXEC_REQ_READINESS_READY_NO_DIRTY_INPUTS;
}

static int inf_cpylst_req_execute(struct inf_exec_req *req)
{
	struct sphcs_dma_desc const *desc;
	struct inf_cpylst *cpylst;
	struct inf_cmd_list *cmd;
	u64 now, dt;
	uint16_t i;
	int ret = 0;

	NNP_ASSERT(req->cmd_type == CMDLIST_CMD_COPYLIST);
	NNP_ASSERT(req->in_progress);

	cpylst = req->cpylst;
	cmd = req->cmd;

	DO_TRACE(trace_copy(SPH_TRACE_OP_STATUS_START,
		 cmd->context->protocol_id,
		 cpylst->idx_in_cmd,
		 cmd->protocol_id,
		 cpylst->copies[0]->card2Host,
		 -1,
		 req->size,
		 req->cpylst->n_copies,
		 req->lli->num_lists,
		 req->lli->num_elements));

	if (req->time > 0 &&
	    NNP_SW_GROUP_IS_ENABLE(cpylst->copies[0]->sw_counters,
				   COPY_SPHCS_SW_COUNTERS_GROUP)) {
		now = nnp_time_us();
		dt = now - req->time;
		req->time = now;
		// make sure cpylst is alive for counters update
		inf_cmd_get(cmd);
	} else {
		now = 0;
		dt = 0;
		req->time = 0;
	}

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

	if (inf_context_get_state(req->context) != CONTEXT_OK) {
		ret = -NNPER_CONTEXT_BROKEN;
		goto finish;
	}

	if (req->size == 0) {
		inf_cpylst_req_complete(req, 0, NULL, 0);

		goto finish;
	}
	ret = sphcs_dma_sched_start_xfer_multi(g_the_sphcs->dmaSched,
						&req->cpylst->multi_xfer_handle,
						desc,
						req->lli,
						req->size,
						cpylst_complete_cb,
						req);
finish:
	if (dt > 0) {
		struct inf_copy *copy;

		i = 0;
		for (copy = cpylst->copies[i]; i < cpylst->n_copies; copy = cpylst->copies[++i]) {
			if (NNP_SW_GROUP_IS_ENABLE(copy->sw_counters,
						   COPY_SPHCS_SW_COUNTERS_GROUP)) {
				NNP_SW_COUNTER_INC(copy->sw_counters,
						   COPY_SPHCS_SW_COUNTERS_BLOCK_COUNT);

				NNP_SW_COUNTER_ADD(copy->sw_counters,
						   COPY_SPHCS_SW_COUNTERS_BLOCK_TOTAL_TIME,
						   dt);

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
		}

		// release kref for counters update
		inf_cmd_put(cmd);
	} else if (now > 0) {
		// release kref for counters update
		inf_cmd_put(cmd);
	}

	return ret;
}

static void treat_cpylst_failure(struct inf_exec_req *req,
				 enum event_val       event_val,
				 const void          *error_msg,
				 int32_t              error_msg_size)
{
	struct inf_cpylst *cpylst;
	struct inf_exec_error_details *err_details;
	uint32_t i;
	int rc;

	NNP_ASSERT(req->cmd_type == CMDLIST_CMD_COPYLIST);

	if (error_msg == NULL)
		error_msg_size = 0;

	cpylst = req->cpylst;

	rc = inf_exec_error_details_alloc(CMDLIST_CMD_COPYLIST,
					  cpylst->idx_in_cmd,
					  req->cmd->protocol_id,
					  event_val,
					  error_msg_size > 0 ? error_msg_size : 0,
					  &err_details);
	if (likely(rc == 0)) {
		if (error_msg_size > 0)
			safe_c_memcpy(err_details->error_msg, error_msg_size, error_msg, error_msg_size);

		inf_exec_error_list_add(&req->cmd->error_list, err_details);
	}

	if (!cpylst->copies[0]->card2Host) {
		for (i = 0; i < cpylst->n_copies; i++)
			inf_devres_set_dirty(cpylst->devreses[i], true);
	}
}

static void inf_cpylst_req_complete(struct inf_exec_req *req,
				    int                  err,
				    const void          *error_msg,
				    int32_t              error_msg_size)
{
	enum event_val event_val;
	struct inf_cpylst *cpylst;
	struct inf_cmd_list *cmd;
	bool send_cmdlist_event_report = false;
	bool has_dirty_outputs = false;
	uint16_t i;
	u64 dt, total_size = req->size;

	NNP_ASSERT(req->cmd_type == CMDLIST_CMD_COPYLIST);
	NNP_ASSERT(req->cmd != NULL);
	NNP_ASSERT(req->in_progress);

	cpylst = req->cpylst;
	cmd = req->cmd;

	DO_TRACE(trace_copy(SPH_TRACE_OP_STATUS_COMPLETE,
		 req->cmd->context->protocol_id,
		 cpylst->idx_in_cmd,
		 req->cmd->protocol_id,
		 cpylst->copies[0]->card2Host,
		 -1,
		 req->size,
		 req->cpylst->n_copies,
		 req->lli->num_lists,
		 req->lli->num_elements));

	if (req->size > 0 &&
	    req->time > 0 &&
	    NNP_SW_GROUP_IS_ENABLE(cpylst->copies[0]->sw_counters,
				   COPY_SPHCS_SW_COUNTERS_GROUP))
		dt = nnp_time_us() - req->time;
	else
		dt = 0;

	if (unlikely(err < 0)) {
		sph_log_err(EXECUTE_COMMAND_LOG, "Execute coylst failed with err=%d\n", err);
		switch (err) {
		case -ENOMEM:
			event_val = NNP_IPC_NO_MEMORY;
			break;
		case -NNPER_CONTEXT_BROKEN:
			event_val = NNP_IPC_CONTEXT_BROKEN;
			break;
		case -NNPER_INPUT_IS_DIRTY:
			event_val = NNP_IPC_INPUT_IS_DIRTY;
			break;
		default:
			event_val = NNP_IPC_DMA_ERROR;
		}

		treat_cpylst_failure(req, event_val, error_msg, error_msg_size);
	} else {
		event_val = 0;
		if (!cpylst->copies[0]->card2Host) {
			for (i = 0; i < req->num_opt_depend_devres; ++i) {
				has_dirty_outputs = req->opt_depend_devres[i]->is_dirty ||
						    req->opt_depend_devres[i]->group_dirty_count > 0;
				if (has_dirty_outputs)
					break;
			}

			if (has_dirty_outputs) {
				for (i = 0; i < cpylst->n_copies; i++)
					inf_devres_set_dirty(cpylst->devreses[i], false);
			}
		}

	}
	NNP_ASSERT(cmd != NULL);
	send_cmdlist_event_report = atomic_dec_and_test(&cmd->num_left);

	if (event_val != 0 || !send_cmdlist_event_report)
		send_cpylst_report(req, event_val);

	inf_exec_req_put(req);

	if (dt > 0) {
		struct inf_copy *copy;

		i = 0;
		for (copy = cpylst->copies[i]; i < cpylst->n_copies; copy = cpylst->copies[++i]) {
			if (NNP_SW_GROUP_IS_ENABLE(copy->sw_counters,
						   COPY_SPHCS_SW_COUNTERS_GROUP)) {
				NNP_SW_COUNTER_INC(copy->sw_counters,
						   COPY_SPHCS_SW_COUNTERS_EXEC_COUNT);

				if (cpylst->cur_sizes[i] > 0) {
					u64 cur_dt = dt * cpylst->cur_sizes[i] / total_size;

					if (cur_dt == 0)
						continue;

					NNP_SW_COUNTER_ADD(copy->sw_counters,
							   COPY_SPHCS_SW_COUNTERS_EXEC_TOTAL_TIME,
							   cur_dt);

					if (cur_dt < copy->min_exec_time) {
						SPH_SW_COUNTER_SET(copy->sw_counters,
								   COPY_SPHCS_SW_COUNTERS_EXEC_MIN_TIME,
								   cur_dt);
						copy->min_exec_time = cur_dt;
					}

					if (cur_dt > copy->max_exec_time) {
						SPH_SW_COUNTER_SET(copy->sw_counters,
								   COPY_SPHCS_SW_COUNTERS_EXEC_MAX_TIME,
								   cur_dt);
						copy->max_exec_time = cur_dt;
					}
				}
			}
		}
	}

	memcpy(cpylst->cur_sizes, cpylst->sizes, cpylst->n_copies * sizeof(cpylst->sizes[0]));

	if (send_cmdlist_event_report) {
		if (event_val == 0) {
			// if success should send both cmd and copy reports,
			// send one merged report
			sphcs_send_event_report_ext(g_the_sphcs,
						NNP_IPC_EXECUTE_CPYLST_SUCCESS,
						//event_val isn't 0 to differentiate
						//between CMD and cpylst
						NNP_IPC_CMDLIST_FINISHED,
						cmd->context->chan->respq,
						cmd->context->protocol_id,
						cmd->protocol_id,
						cpylst->idx_in_cmd);
		} else {
			sphcs_send_event_report(g_the_sphcs,
						NNP_IPC_EXECUTE_CMD_COMPLETE,
						0,
						cmd->context->chan->respq,
						cmd->context->protocol_id,
						cmd->protocol_id);
		}
		DO_TRACE(trace_cmdlist(SPH_TRACE_OP_STATUS_COMPLETE,
			 cmd->context->protocol_id, cmd->protocol_id));
		// for schedule
		inf_cmd_put(cmd);
	}
}

static void send_cpylst_report(struct inf_exec_req *req,
			       enum event_val       event_val)
{
	struct inf_cpylst *cpylst;
	uint16_t event_code = event_val == 0 ? NNP_IPC_EXECUTE_CPYLST_SUCCESS : NNP_IPC_EXECUTE_CPYLST_FAILED;

	NNP_ASSERT(req->cmd_type == CMDLIST_CMD_COPYLIST);
	NNP_ASSERT(req->cmd != NULL);

	cpylst = req->cpylst;
	sphcs_send_event_report_ext(g_the_sphcs,
				    event_code,
				    event_val,
				    req->context->chan->respq,
				    req->context->protocol_id,
				    req->cmd->protocol_id,
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
	if (req->size > 0 && req->priority != priority)
		for (i = 0; i < req->lli->num_lists; i++)
			ret |= inf_update_priority(req,
						   priority,
						   req->cpylst->copies[0]->card2Host,
						   req->lli->dma_addr + req->lli->offsets[i]);

	return ret;
}
