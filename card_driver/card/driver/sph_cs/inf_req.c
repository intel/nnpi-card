/********************************************
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/
#include "inf_req.h"
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/limits.h>
#include "sphcs_cs.h"
#include "sph_log.h"
#include "sph_error.h"
#include "sph_time.h"
#include "inf_context.h"
#include "inf_devnet.h"
#include "inf_devres.h"
#include "ioctl_inf.h"
#include "sphcs_trace.h"
#include "sphcs_sw_counters.h"

static int infreq_req_sched(struct inf_exec_req *req);
static bool inf_req_ready(struct inf_exec_req *req);
static int inf_req_execute(struct inf_exec_req *req);
static void inf_req_complete(struct inf_exec_req *req, int err);
static void send_infreq_report(struct inf_exec_req *req,
			       enum event_val       eventVal);
static int inf_req_infreq_put(struct inf_exec_req *req);
static int inf_req_migrate_priority(struct inf_exec_req *req, uint8_t priority);
static void inf_req_release(struct kref *kref);

struct func_table const s_req_funcs = {
	.schedule = infreq_req_sched,
	.is_ready = inf_req_ready,
	.execute = inf_req_execute,
	.complete = inf_req_complete,
	.send_report = send_infreq_report,
	.obj_put = inf_req_infreq_put,
	//not used for infreq
	.migrate_priority = inf_req_migrate_priority,

	/* This function should not be called directly, use inf_exec_req_put instead */
	.release = inf_req_release
};

int inf_req_create(uint16_t            protocolID,
		   struct inf_devnet  *devnet,
		   struct inf_req    **out_infreq)
{
	struct inf_req *infreq;
	int ret = 0;

	infreq = kzalloc(sizeof(*infreq), GFP_KERNEL);
	if (unlikely(infreq == NULL))
		return -ENOMEM;

	kref_init(&infreq->ref);
	infreq->magic = inf_req_create;
	infreq->protocolID = protocolID;
	infreq->n_inputs = 0;
	infreq->n_outputs = 0;
	infreq->inputs = NULL;
	infreq->outputs = NULL;
	infreq->config_data_size = 0;
	infreq->config_data = NULL;
	spin_lock_init(&infreq->lock_irq);
	infreq->status = CREATE_STARTED;
	infreq->destroyed = 0;
	infreq->min_block_time = U64_MAX;
	infreq->max_block_time = 0;
	infreq->min_exec_time = U64_MAX;
	infreq->max_exec_time = 0;

	ret = sph_create_sw_counters_values_node(g_hSwCountersInfo_infreq,
						 (u32)protocolID,
						 devnet->sw_counters,
						 &infreq->sw_counters);
	if (unlikely(ret < 0))
		goto free_infreq;

	SPH_SW_COUNTER_INC(devnet->sw_counters,
			   NET_SPHCS_SW_COUNTERS_NUM_INFER_CMDS);

	infreq->devnet = devnet;
	inf_devnet_get(devnet);

	infreq->exec_cmd.infreq_drv_handle = (uint64_t)(uintptr_t)infreq;
	infreq->exec_cmd.infreq_rt_handle = 0; /* will be set after runtime
						* created the infer req object
						*/
	infreq->exec_cmd.ready_flags = 0;
	infreq->exec_cmd.sched_params_is_null = 1;

	*out_infreq = infreq;
	return 0;

free_infreq:
	kfree(infreq);
	return ret;
}

int inf_req_add_resources(struct inf_req     *infreq,
			  uint32_t            n_inputs,
			  struct inf_devres **inputs,
			  uint32_t            n_outputs,
			  struct inf_devres **outputs,
			  uint32_t            config_data_size,
			  void               *config_data)
{
	int i;

	if (unlikely(infreq == NULL))
		return -EINVAL;

	infreq->n_inputs = n_inputs;
	infreq->n_outputs = n_outputs;
	infreq->inputs = inputs;
	infreq->outputs = outputs;
	infreq->config_data_size = config_data_size;
	infreq->config_data = config_data;

	for (i = 0; i < n_inputs; i++)
		inf_devres_get(inputs[i]);

	for (i = 0; i < n_outputs; i++)
		inf_devres_get(outputs[i]);

	return 0;
}

int is_inf_req_ptr(void *ptr)
{
	struct inf_req *infreq = (struct inf_req *)ptr;

	return (ptr != NULL && infreq->magic == inf_req_create);
}

void destroy_infreq_on_create_failed(struct inf_req *infreq)
{
	bool dma_completed, should_destroy;
	unsigned long flags;

	SPH_SPIN_LOCK_IRQSAVE(&infreq->lock_irq, flags);

	dma_completed = (infreq->status == DMA_COMPLETED);
	// roll back status, to put kref once
	if (dma_completed)
		infreq->status = CREATE_STARTED;

	should_destroy = (infreq->destroyed == 0);
	if (likely(should_destroy))
		infreq->destroyed = -1;

	SPH_SPIN_UNLOCK_IRQRESTORE(&infreq->lock_irq, flags);


	if (likely(should_destroy))
		inf_req_put(infreq);

	// if got failure from RT
	if (dma_completed)
		inf_req_put(infreq);
}

static void release_infreq(struct kref *kref)
{
	struct inf_req *infreq = container_of(kref, struct inf_req, ref);
	struct inf_destroy_infreq cmd_args;
	uint32_t i;
	int ret;

	SPH_SPIN_LOCK(&infreq->devnet->lock);
	hash_del(&infreq->hash_node);
	SPH_SPIN_UNLOCK(&infreq->devnet->lock);

	for (i = 0; i < infreq->n_inputs; i++) {
		inf_devres_put(infreq->inputs[i]);
	}

	for (i = 0; i < infreq->n_outputs; i++) {
		inf_devres_put(infreq->outputs[i]);
	}

	if (likely(infreq->status == CREATED)) {
		/* send command to runtime to destroy the inference request */
		cmd_args.devnet_rt_handle = infreq->devnet->rt_handle;
		cmd_args.infreq_rt_handle = infreq->exec_cmd.infreq_rt_handle;
		ret = inf_cmd_queue_add(&(infreq->devnet->context->cmdq),
					SPHCS_RUNTIME_CMD_DESTROY_INFREQ,
					&cmd_args,
					sizeof(cmd_args),
					NULL,
					NULL);
		if (unlikely(ret < 0))
			sph_log_err(CREATE_COMMAND_LOG, "Failed to send destroy network command to runtime\n");
	}

	sph_remove_sw_counters_values_node(infreq->sw_counters);

	SPH_SW_COUNTER_DEC(infreq->devnet->sw_counters,
			   NET_SPHCS_SW_COUNTERS_NUM_INFER_CMDS);

	if (likely(infreq->destroyed == 1))
		sphcs_send_event_report_ext(g_the_sphcs,
					SPH_IPC_INFREQ_DESTROYED,
					0,
					infreq->devnet->context->protocolID,
					infreq->protocolID,
					infreq->devnet->protocolID);

	inf_devnet_put(infreq->devnet);

	if (likely(infreq->inputs != NULL))
		kfree(infreq->inputs);
	if (likely(infreq->outputs != NULL))
		kfree(infreq->outputs);
	if (likely(infreq->config_data != NULL))
		kfree(infreq->config_data);
	kfree(infreq);
}

inline void inf_req_get(struct inf_req *infreq)
{
	int ret;

	ret = kref_get_unless_zero(&infreq->ref);
	SPH_ASSERT(ret != 0);
}

inline int inf_req_put(struct inf_req *infreq)
{
	return kref_put(&infreq->ref, release_infreq);
}

static void migrate_priority(struct inf_req *infreq, struct inf_exec_req *req)
{
	int i = 0;
	int j = 0;

	for (i = 0; i < infreq->n_inputs; i++)
		inf_devres_migrate_priority_to_req_queue(infreq->inputs[i], req, true);

	for (j = 0; j < infreq->n_outputs; j++)
		inf_devres_migrate_priority_to_req_queue(infreq->outputs[j], req, false);
}

void infreq_req_init(struct inf_exec_req *req,
		     struct inf_req *infreq,
		     struct inf_cmd_list *cmd,
		     uint8_t priority,
		     bool sched_params_are_null,
		     uint16_t batchSize,
		     uint8_t debugOn,
		     uint8_t collectInfo)
{
	kref_init(&req->in_use);
	req->in_progress = false;
	req->context = infreq->devnet->context;
	req->last_sched_tick = 0;
	req->cmd_type = CMDLIST_CMD_INFREQ;
	req->f = &s_req_funcs;
	req->infreq = infreq;
	req->cmd = cmd;
	req->priority = priority;
	req->sched_params_is_null = sched_params_are_null;
	if (!sched_params_are_null) {
		req->size = batchSize;
		req->debugOn = debugOn;
		req->collectInfo = collectInfo;
	}
	req->time = 0;
	req->i_num_opt_depend_devres = 0;
	req->o_num_opt_depend_devres = 0;
	req->i_opt_depend_devres = NULL;
	req->o_opt_depend_devres = NULL;
}

static int infreq_req_sched(struct inf_exec_req *req)
{
	struct inf_req *infreq;
	int err;
	int i = 0;
	int j = 0;
	int k;

	SPH_ASSERT(req->cmd_type == CMDLIST_CMD_INFREQ);

	infreq = req->infreq;
	if (SPH_SW_GROUP_IS_ENABLE(infreq->sw_counters,
				   INFREQ_SPHCS_SW_COUNTERS_GROUP))
		req->time = sph_time_us();

	inf_req_get(req->infreq);
	spin_lock_init(&req->lock_irq);
	inf_context_seq_id_init(infreq->devnet->context, &req->seq);
	inf_exec_req_get(req);

	DO_TRACE(trace_infreq(SPH_TRACE_OP_STATUS_QUEUED,
					   infreq->devnet->context->protocolID,
					   infreq->devnet->protocolID,
					   infreq->protocolID,
					   req->cmd ? req->cmd->protocolID : -1));

	/* place write dependency on the network resource to prevent
	 * two infer request of the same network to work in parallel.
	 */
	err = inf_devres_add_req_to_queue(infreq->devnet->first_devres,
					  req,
					  !infreq->devnet->serial_infreq_exec);
	if (unlikely(err < 0))
		goto fail_first;

	for (i = 0; i < infreq->n_inputs; i++) {
		err = inf_devres_add_req_to_queue(infreq->inputs[i],
						  req,
						  true);
		if (unlikely(err < 0))
			goto fail;
	}

	for (j = 0; j < infreq->n_outputs; j++) {
		err = inf_devres_add_req_to_queue(infreq->outputs[j],
						  req,
						  false);
		if (unlikely(err < 0))
			goto fail;
	}

	// Migrate high priority
	if (req->priority != 0)
		migrate_priority(infreq, req);

	// Request scheduled
	SPH_SW_COUNTER_INC(infreq->devnet->context->sw_counters,
			   CTX_SPHCS_SW_COUNTERS_INFERENCE_SUBMITTED_INF_REQ);

	// First try to execute
	inf_req_try_execute(req);

	inf_exec_req_put(req);
	return 0;

fail:
	for (k = 0; k < i; k++)
		inf_devres_del_req_from_queue(infreq->inputs[k], req);
	for (k = 0; k < j; k++)
		inf_devres_del_req_from_queue(infreq->outputs[k], req);
	inf_devres_del_req_from_queue(infreq->devnet->first_devres, req);
fail_first:
	inf_context_seq_id_fini(infreq->devnet->context, &req->seq);
	inf_req_put(infreq);

	return err;
}

static void inf_req_release(struct kref *kref)
{
	struct inf_exec_req *req = container_of(kref,
						struct inf_exec_req,
						in_use);
	struct inf_req *infreq;
	int i;

	SPH_ASSERT(req->cmd_type == CMDLIST_CMD_INFREQ);

	infreq = req->infreq;
	inf_devres_del_req_from_queue(infreq->devnet->first_devres, req);
	for (i = 0; i < infreq->n_inputs; i++)
		inf_devres_del_req_from_queue(infreq->inputs[i], req);
	for (i = 0; i < infreq->n_outputs; i++)
		inf_devres_del_req_from_queue(infreq->outputs[i], req);
	inf_context_seq_id_fini(infreq->devnet->context, &req->seq);

	/* advance sched tick and try execute next requests */
	atomic_add(2, &req->context->sched_tick);

	inf_devres_try_execute(infreq->devnet->first_devres);
	for (i = 0; i < infreq->n_inputs; i++)
		inf_devres_try_execute(infreq->inputs[i]);
	for (i = 0; i < infreq->n_outputs; i++)
		inf_devres_try_execute(infreq->outputs[i]);

	kmem_cache_free(infreq->devnet->context->exec_req_slab_cache, req);
	inf_req_put(infreq);
}

static bool inf_req_ready(struct inf_exec_req *req)
{
	struct inf_req *infreq;
	int i;

	SPH_ASSERT(req->cmd_type == CMDLIST_CMD_INFREQ);

	infreq = req->infreq;
	/* cannot start execute if another infreq of the same network is running*/
	if (!inf_devres_req_ready(infreq->devnet->first_devres,
				  req,
				  !infreq->devnet->serial_infreq_exec))
		return false;

	/* check input resources dependency */
	if (req->i_num_opt_depend_devres > 0) {
		for (i = 0; i < req->i_num_opt_depend_devres; i++)
			if (!inf_devres_req_ready(req->i_opt_depend_devres[i], req, true))
				return false;
	} else {
		for (i = 0; i < infreq->n_inputs; i++)
			if (!inf_devres_req_ready(infreq->inputs[i],
						  req,
						  true))
			return false;
	}

	/* check output resources dependency */
	if (req->o_num_opt_depend_devres > 0) {
		for (i = 0; i < req->o_num_opt_depend_devres; i++)
			if (!inf_devres_req_ready(req->o_opt_depend_devres[i], req, false))
				return false;
	} else {
		for (i = 0; i < infreq->n_outputs; i++)
			if (!inf_devres_req_ready(infreq->outputs[i],
						  req,
						  false))
				return false;
	}

	return true;
}

unsigned long inf_req_read_exec_command(char __user *buf,
					void        *ctx,
					uint32_t     offset,
					uint32_t     n_to_read)
{
	struct inf_exec_req *req = (struct inf_exec_req *)ctx;
	uint32_t n = 0;
	unsigned long ret = 0;

	if (offset < sizeof(req->infreq->exec_cmd)) {

		SPH_ASSERT(n_to_read >= sizeof(req->infreq->exec_cmd)-offset);
		n = sizeof(req->infreq->exec_cmd) - offset;

		ret = copy_to_user(buf,
				   ((char *)&req->infreq->exec_cmd) + offset,
				   n);
		offset = 0;
	}

	return ret;
}

static int inf_req_execute(struct inf_exec_req *req)
{
	struct inf_req *infreq;
	struct inf_context *context;
	unsigned long flags, flags2;
	int ret;

	SPH_ASSERT(req->cmd_type == CMDLIST_CMD_INFREQ);
	SPH_ASSERT(req->in_progress);

	infreq = req->infreq;
	context = infreq->devnet->context;

	SPH_ASSERT(infreq->active_req == NULL);

	DO_TRACE(trace_infreq(SPH_TRACE_OP_STATUS_START,
		     infreq->devnet->context->protocolID,
		     infreq->devnet->protocolID,
		     infreq->protocolID,
		     req->cmd ? req->cmd->protocolID : -1));

	if (SPH_SW_GROUP_IS_ENABLE(infreq->sw_counters,
				   INFREQ_SPHCS_SW_COUNTERS_GROUP)) {
		u64 now;

		now = sph_time_us();
		if (req->time) {
			u64 dt;

			dt = now - req->time;
			SPH_SW_COUNTER_ADD(infreq->sw_counters,
					   INFREQ_SPHCS_SW_COUNTERS_BLOCK_TOTAL_TIME,
					   dt);

			SPH_SW_COUNTER_INC(infreq->sw_counters,
					   INFREQ_SPHCS_SW_COUNTERS_BLOCK_COUNT);

			if (dt < infreq->min_block_time) {
				SPH_SW_COUNTER_SET(infreq->sw_counters,
						   INFREQ_SPHCS_SW_COUNTERS_BLOCK_MIN_TIME,
						   dt);
				infreq->min_block_time = dt;
			}

			if (dt > infreq->max_block_time) {
				SPH_SW_COUNTER_SET(infreq->sw_counters,
						   INFREQ_SPHCS_SW_COUNTERS_BLOCK_MAX_TIME,
						   dt);
				infreq->max_block_time = dt;
			}
		}
		req->time = now;
	} else
		req->time = 0;

	SPH_SPIN_LOCK_IRQSAVE(&infreq->lock_irq, flags);
	infreq->exec_cmd.ready_flags = 1;
	infreq->exec_cmd.sched_params_is_null = req->sched_params_is_null;
	if (!req->sched_params_is_null) {
		infreq->exec_cmd.sched_params.batchSize = (uint16_t)req->size;
		infreq->exec_cmd.sched_params.priority = req->priority;
		infreq->exec_cmd.sched_params.debugOn = req->debugOn;
		infreq->exec_cmd.sched_params.collectInfo = req->collectInfo;
	}
	SPH_SPIN_LOCK_IRQSAVE(&context->sw_counters_lock_irq, flags2);
	if (context->infreq_counter == 0 &&
	    SPH_SW_GROUP_IS_ENABLE(context->sw_counters, CTX_SPHCS_SW_COUNTERS_GROUP_INFERENCE))
		context->runtime_busy_starttime = sph_time_us();
	context->infreq_counter++;
	SPH_SPIN_UNLOCK_IRQRESTORE(&context->sw_counters_lock_irq, flags2);

	infreq->active_req = req;

	SPH_SPIN_UNLOCK_IRQRESTORE(&infreq->lock_irq, flags);

	/* If the context is broken we don't want to send the request to
	 * the runtime. Instead, we want to cancel this request by returning
	 * with error. active_req should remain NULL so we know this request
	 * wasn't added to cmdq.
	 */
	if (unlikely(inf_context_get_state(infreq->devnet->context) != CONTEXT_OK)) {
		ret = -SPHER_CONTEXT_BROKEN;
	} else {
		ret = inf_cmd_queue_add(&infreq->devnet->context->cmdq,
					SPHCS_RUNTIME_CMD_EXECUTE_INFREQ,
					NULL,
					sizeof(infreq->exec_cmd),
					inf_req_read_exec_command,
					req);
	}
	/* if ret != 0 then the request was not added to cmdq successfuly
	 * therefore will not be handled by the runtime.
	 * In that case we reset active_req to flag that the request should not
	 * be canceled when runtime dies.
	 */
	if (unlikely(ret < 0)) {
		SPH_SPIN_LOCK_IRQSAVE(&infreq->lock_irq, flags);
		if (unlikely(infreq->active_req == NULL))
			// inf_req_complete will be called
			// from del_all_active_create_and_inf_requests
			ret = 0;
		else
			infreq->active_req = NULL;
		SPH_SPIN_UNLOCK_IRQRESTORE(&infreq->lock_irq, flags);
	}

	return ret;
}

static inline void infreq_send_req_fail(struct inf_exec_req *req,
					enum event_val       eventVal)
{
	union c2h_InfreqFailed msg;
	struct inf_req *infreq;

	SPH_ASSERT(req->cmd_type == CMDLIST_CMD_INFREQ);

	infreq = req->infreq;
	if (infreq->devnet->context->chan != NULL) {
		union c2h_ChanInfReqFailed chan_msg;

		memset(chan_msg.value, 0, sizeof(chan_msg.value));
		chan_msg.opcode = SPH_IPC_C2H_OP_CHAN_INFREQ_FAILED;
		chan_msg.chanID = infreq->devnet->context->chan->protocolID;
		chan_msg.netID = infreq->devnet->protocolID;
		chan_msg.infreqID = infreq->protocolID;
		chan_msg.reason = eventVal;
		if (req->cmd != NULL) {
			chan_msg.cmdID_valid = 1;
			chan_msg.cmdID = req->cmd->protocolID;
		}
		sphcs_msg_scheduler_queue_add_msg(g_the_sphcs->public_respq,
						  &chan_msg.value[0],
						  sizeof(chan_msg.value) / sizeof(u64));
		return;
	} else if (req->cmd == NULL) {
		sphcs_send_event_report_ext(g_the_sphcs,
				SPH_IPC_SCHEDULE_INFREQ_FAILED,
				eventVal,
				infreq->devnet->context->protocolID,
				infreq->protocolID,
				infreq->devnet->protocolID);
		return;
	}

	msg.rep_msg.opcode = SPH_IPC_C2H_OP_INFREQ_FAILED;
	msg.rep_msg.eventCode = SPH_IPC_SCHEDULE_INFREQ_FAILED;
	msg.rep_msg.eventVal = eventVal;
	msg.rep_msg.contextID = infreq->devnet->context->protocolID;
	msg.rep_msg.ctxValid = 1;
	msg.rep_msg.objID = infreq->protocolID;
	msg.rep_msg.objValid = 1;
	msg.rep_msg.objID_2 = infreq->devnet->protocolID;
	msg.rep_msg.objValid_2 = 1;

	msg.cmdID = req->cmd->protocolID;

	sph_log_debug(SCHEDULE_COMMAND_LOG,
		      "Sending infreq failure(%u) val=%u ctx_id=%u (valid=%u) objID=%u (valid=%u) objID_2=%u (valid=%u) cmdID=%u.\n",
		      msg.rep_msg.eventCode,
		      msg.rep_msg.eventVal,
		      msg.rep_msg.contextID, msg.rep_msg.ctxValid,
		      msg.rep_msg.objID, msg.rep_msg.objValid,
		      msg.rep_msg.objID_2, msg.rep_msg.objValid_2,
		      msg.cmdID);
	sphcs_msg_scheduler_queue_add_msg(g_the_sphcs->public_respq, &msg.value[0], sizeof(msg));
}

static void send_infreq_report(struct inf_exec_req *req,
			       enum event_val       eventVal)
{
	if (eventVal != 0)
		infreq_send_req_fail(req, eventVal);
}

static void inf_req_complete(struct inf_exec_req *req, int err)
{
	struct inf_req *infreq;
	struct inf_context *context;
	struct inf_cmd_list *cmd;
	bool send_cmdlist_event_report = false;
	unsigned long flags;
	uint16_t eventVal;
	bool last_completed;

	SPH_ASSERT(req->cmd_type == CMDLIST_CMD_INFREQ);
	SPH_ASSERT(req->in_progress);

	infreq = req->infreq;
	context = infreq->devnet->context;
	cmd = req->cmd;

	SPH_SPIN_LOCK_IRQSAVE(&context->sw_counters_lock_irq, flags);
	context->infreq_counter--;
	last_completed = (context->infreq_counter == 0);
	SPH_SW_COUNTER_INC(g_sph_sw_counters, SPHCS_SW_COUNTERS_INFERENCE_COMPLETED_INF_REQ);
	SPH_SW_COUNTER_INC(context->sw_counters, CTX_SPHCS_SW_COUNTERS_INFERENCE_COMPLETED_INF_REQ);

	if (last_completed &&
	    SPH_SW_GROUP_IS_ENABLE(context->sw_counters, CTX_SPHCS_SW_COUNTERS_GROUP_INFERENCE) &&
	    context->runtime_busy_starttime) {
		SPH_SW_COUNTER_ADD(context->sw_counters,
				   CTX_SPHCS_SW_COUNTERS_INFERENCE_RUNTIME_BUSY_TIME,
				   sph_time_us() - context->runtime_busy_starttime);

		context->runtime_busy_starttime = 0;
	}
	SPH_SPIN_UNLOCK_IRQRESTORE(&context->sw_counters_lock_irq, flags);

	 DO_TRACE(trace_infreq(SPH_TRACE_OP_STATUS_COMPLETE,
				  infreq->devnet->context->protocolID,
				  infreq->devnet->protocolID,
				  infreq->protocolID,
				  cmd ? cmd->protocolID : -1));

	if (SPH_SW_GROUP_IS_ENABLE(infreq->sw_counters,
				   INFREQ_SPHCS_SW_COUNTERS_GROUP)) {
		u64 now;

		now = sph_time_us();
		if (req->time) {
			u64 dt;

			dt = now - req->time;
			SPH_SW_COUNTER_ADD(infreq->sw_counters,
					   INFREQ_SPHCS_SW_COUNTERS_EXEC_TOTAL_TIME,
					   dt);

			SPH_SW_COUNTER_INC(infreq->sw_counters,
					   INFREQ_SPHCS_SW_COUNTERS_EXEC_COUNT);

			if (dt < infreq->min_exec_time) {
				SPH_SW_COUNTER_SET(infreq->sw_counters,
						   INFREQ_SPHCS_SW_COUNTERS_EXEC_MIN_TIME,
						   dt);
				infreq->min_exec_time = dt;
			}

			if (dt > infreq->max_exec_time) {
				SPH_SW_COUNTER_SET(infreq->sw_counters,
						   INFREQ_SPHCS_SW_COUNTERS_EXEC_MAX_TIME,
						   dt);
				infreq->max_exec_time = dt;
			}
		}
	}
	req->time = 0;


	SPH_SPIN_LOCK_IRQSAVE(&infreq->lock_irq, flags);
	infreq->exec_cmd.ready_flags = 0;
	infreq->active_req = NULL;
	SPH_SPIN_UNLOCK_IRQRESTORE(&infreq->lock_irq, flags);

	if (unlikely(err < 0)) {
		switch (err) {
		case -ENOMEM: {
			eventVal = SPH_IPC_NO_MEMORY;
			break;
		}
		case -SPHER_CONTEXT_BROKEN: {
			eventVal = SPH_IPC_CONTEXT_BROKEN;
			break;
		}
		case -SPHER_DMA_ERROR: {
			eventVal = SPH_IPC_DMA_ERROR;
			break;
		}
		case -SPHER_NOT_SUPPORTED: {
			eventVal = SPH_IPC_RUNTIME_NOT_SUPPORTED;
			break;
		}
		case -SPHER_INFER_EXEC_ERROR: {
			eventVal = SPH_IPC_RUNTIME_INFER_EXEC_ERROR;
			break;
		}
		case -SPHER_INFER_SCHEDULE_ERROR: {
			eventVal = SPH_IPC_RUNTIME_INFER_SCHEDULE_ERROR;
			break;
		}
		default:
			eventVal = SPH_IPC_RUNTIME_FAILED;
		}
		sph_log_err(EXECUTE_COMMAND_LOG, "Got Error. errno: %d, eventVal=%u\n", err, eventVal);
		req->f->send_report(req, eventVal);

		//TODO GLEB: decide according to error if brake the context, brake the card or do nothing
		inf_context_set_state(infreq->devnet->context,
				      CONTEXT_BROKEN_RECOVERABLE);
	}

	if (cmd != NULL) {
		SPH_SPIN_LOCK_IRQSAVE(&cmd->lock_irq, flags);
		if (--cmd->num_left == 0)
			send_cmdlist_event_report = true;
		SPH_SPIN_UNLOCK_IRQRESTORE(&cmd->lock_irq, flags);
	}

	 DO_TRACE_IF(send_cmdlist_event_report, trace_cmdlist(SPH_TRACE_OP_STATUS_COMPLETE,
			 cmd->context->protocolID, cmd->protocolID));

	if (send_cmdlist_event_report)
		sphcs_send_event_report(g_the_sphcs,
					SPH_IPC_EXECUTE_CMD_COMPLETE,
					0,
					cmd->context->protocolID,
					cmd->protocolID);

	inf_exec_req_put(req);
}

static int inf_req_infreq_put(struct inf_exec_req *req)
{
	return inf_req_put(req->infreq);
}

static int inf_req_migrate_priority(struct inf_exec_req *req, uint8_t priority)
{
	// don't migrate priority of infreq
	return 0;
}
