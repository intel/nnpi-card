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

static bool serial_infreq_exec; //initialized to false
module_param(serial_infreq_exec, bool, 0660);

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
	int i;
	int ret = 0;

	SPH_SPIN_LOCK(&infreq->devnet->lock);
	hash_del(&infreq->hash_node);
	SPH_SPIN_UNLOCK(&infreq->devnet->lock);

	for (i = 0; i < infreq->n_inputs; i++) {
		ret = inf_devres_put(infreq->inputs[i]);
		SPH_ASSERT(ret == 0);
	}

	for (i = 0; i < infreq->n_outputs; i++) {
		ret = inf_devres_put(infreq->outputs[i]);
		SPH_ASSERT(ret == 0);
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

	ret = inf_devnet_put(infreq->devnet);
	SPH_ASSERT(ret == 0);

	if (likely(infreq->destroyed == 1))
		sphcs_send_event_report_ext(g_the_sphcs,
					SPH_IPC_INFREQ_DESTROYED,
					0,
					infreq->devnet->context->protocolID,
					infreq->protocolID,
					infreq->devnet->protocolID);

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

int inf_req_schedule(struct inf_req *infreq,
		     union h2c_InferenceReqSchedule *cmd)
{
	int err;
	struct inf_exec_req *req;
	int i = 0;
	int j = 0;
	int k;
	struct inf_context *context = infreq->devnet->context;

	inf_req_get(infreq);

	req = kmem_cache_alloc(context->exec_req_slab_cache, GFP_NOWAIT);
	if (unlikely(req == NULL)) {
		inf_req_put(infreq);
		return -ENOMEM;
	}

	kref_init(&req->in_use);
	spin_lock_init(&req->lock_irq);
	req->in_progress = false;
	req->is_copy = false;
	req->infreq = infreq;
	req->sched_params.batchSize = cmd->batchSize;
	req->sched_params.priority = cmd->priority;
	req->sched_params.debugOn = cmd->debugOn;
	req->sched_params.collectInfo = cmd->collectInfo;
	req->sched_params_is_null = cmd->schedParamsIsNull;
	req->time = 0;

	if (SPH_SW_GROUP_IS_ENABLE(infreq->sw_counters,
				   INFREQ_SPHCS_SW_COUNTERS_GROUP)) {
		req->time = sph_time_us();
	} else
		req->time = 0;

	inf_context_seq_id_init(context, &req->seq);
	inf_exec_req_get(req);


	/* place write dependency on the network resource to prevent
	 * two infer request of the same network to work in parallel.
	 */
	err = inf_devres_add_req_to_queue(infreq->devnet->first_devres,
					  req,
					  !serial_infreq_exec);
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
	if (req->sched_params.priority == 0)
		migrate_priority(infreq, req);

	// Request scheduled
	SPH_SW_COUNTER_INC(context->sw_counters,
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
	inf_context_seq_id_fini(context, &req->seq);
	inf_req_put(infreq);
	kmem_cache_free(context->exec_req_slab_cache, req);

	return err;
}

/* This function should not be called directly, use inf_exec_req_put instead */
void inf_req_release(struct kref *kref)
{
	struct inf_exec_req *req = container_of(kref,
						struct inf_exec_req,
						in_use);
	struct inf_req *infreq = req->infreq;
	int i;

	SPH_ASSERT(!req->is_copy);

	inf_devres_del_req_from_queue(infreq->devnet->first_devres, req);
	for (i = 0; i < infreq->n_inputs; i++)
		inf_devres_del_req_from_queue(infreq->inputs[i], req);
	for (i = 0; i < infreq->n_outputs; i++)
		inf_devres_del_req_from_queue(infreq->outputs[i], req);
	inf_context_seq_id_fini(infreq->devnet->context, &req->seq);

	kmem_cache_free(infreq->devnet->context->exec_req_slab_cache, req);
	inf_req_put(infreq);
}

bool inf_req_ready(struct inf_exec_req *req)
{
	struct inf_req *infreq = req->infreq;
	int i;

	SPH_ASSERT(!req->is_copy);

	/* cannot start execute if another infreq of the same network is running*/
	if (!inf_devres_req_ready(infreq->devnet->first_devres,
				  req,
				  !serial_infreq_exec))
		return false;

	/* check input resources dependency */
	for (i = 0; i < infreq->n_inputs; i++)
		if (!inf_devres_req_ready(infreq->inputs[i],
					  req,
					  true))
			return false;

	/* check output resources dependency */
	for (i = 0; i < infreq->n_outputs; i++)
		if (!inf_devres_req_ready(infreq->outputs[i],
					  req,
					  false))
			return false;

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

int inf_req_execute(struct inf_exec_req *req)
{
	struct inf_req *infreq = req->infreq;
	struct inf_context *context = infreq->devnet->context;
	unsigned long flags, flags2;
	int ret;

	SPH_ASSERT(!req->is_copy);
	SPH_ASSERT(req->in_progress);
	SPH_ASSERT(infreq->active_req == NULL);

	DO_TRACE(trace_infreq(SPH_TRACE_OP_STATUS_START,
		     infreq->devnet->context->protocolID,
		     infreq->devnet->protocolID,
		     infreq->protocolID));

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
	infreq->exec_cmd.sched_params = req->sched_params;
	infreq->exec_cmd.sched_params_is_null = req->sched_params_is_null;

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

void inf_req_complete(struct inf_exec_req *req, int err)
{
	struct inf_req *infreq = req->infreq;
	struct inf_context *context = infreq->devnet->context;
	unsigned long flags;
	uint16_t eventVal;
	bool last_completed;

	SPH_ASSERT(!req->is_copy);
	SPH_ASSERT(req->in_progress);

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
		     infreq->protocolID));

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
		sphcs_send_event_report_ext(g_the_sphcs,
					    SPH_IPC_SCHEDULE_INFREQ_FAILED,
					    eventVal,
					    infreq->devnet->context->protocolID,
					    infreq->protocolID,
					    infreq->devnet->protocolID);

		inf_context_set_state(req->infreq->devnet->context,
				      CONTEXT_BROKEN_RECOVERABLE);
	}

	inf_exec_req_put(req);
}
