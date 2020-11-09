/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
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
#include "nnp_error.h"
#include "nnp_time.h"
#include "inf_context.h"
#include "inf_devnet.h"
#include "inf_devres.h"
#include "ioctl_inf.h"
#include "sphcs_trace.h"
#include "sphcs_sw_counters.h"
#include "sphcs_ibecc.h"
#include "sph_safe.h"
#include "inf_ptr2id.h"
#include "nnp_hwtrace_protocol.h"

static struct inf_devres *devres_for_err_inj;
static void *addr_for_err_inj;

static enum EXEC_REQ_READINESS inf_req_ready(struct inf_exec_req *req);
static int inf_req_execute(struct inf_exec_req *req);
static void send_infreq_report(struct inf_exec_req *req,
			       enum event_val       event_val);
static int inf_req_infreq_put(struct inf_exec_req *req);
static int inf_req_migrate_priority(struct inf_exec_req *req, uint8_t priority);
static void treat_infreq_failure(struct inf_exec_req *req,
				 enum event_val       event_val,
				 const void          *error_msg,
				 int32_t              error_msg_size);

static void inf_req_release(struct kref *kref);

struct func_table const s_req_funcs = {
	.schedule = infreq_req_sched,
	.is_ready = inf_req_ready,
	.execute = inf_req_execute,
	.complete = inf_req_complete,
	.send_report = send_infreq_report,
	.obj_put = inf_req_infreq_put,
	/* not used for infreq */
	.migrate_priority = inf_req_migrate_priority,
	.treat_req_failure = treat_infreq_failure,

	/* This function should not be called directly, use inf_exec_req_put instead */
	.release = inf_req_release
};

static void ibecc_inject_error(struct inf_devnet *);
static void ibecc_clean_error(void);

int inf_req_create(uint16_t            protocol_id,
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
	infreq->protocol_id = protocol_id;
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

	ret = nnp_create_sw_counters_values_node(g_hSwCountersInfo_infreq,
						 (u32)protocol_id,
						 devnet->sw_counters,
						 &infreq->sw_counters);
	if (unlikely(ret < 0))
		goto free_infreq;

	NNP_SW_COUNTER_INC(devnet->sw_counters,
			   NET_SPHCS_SW_COUNTERS_NUM_INFER_CMDS);

	infreq->devnet = devnet;
	infreq->ptr2id = add_ptr2id(infreq);
	if (unlikely(infreq->ptr2id == 0)) {
		ret = -ENOMEM;
		goto free_infreq;
	}
	infreq->exec_cmd.infreq_drv_handle = infreq->ptr2id;
	inf_devnet_get(devnet);
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

	NNP_SPIN_LOCK_IRQSAVE(&infreq->lock_irq, flags);

	dma_completed = (infreq->status == DMA_COMPLETED);
	// roll back status, to put kref once
	if (dma_completed)
		infreq->status = CREATE_STARTED;

	should_destroy = (infreq->destroyed == 0);
	if (likely(should_destroy))
		infreq->destroyed = -1;

	NNP_SPIN_UNLOCK_IRQRESTORE(&infreq->lock_irq, flags);


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

	NNP_SPIN_LOCK(&infreq->devnet->lock);
	hash_del(&infreq->hash_node);
	NNP_SPIN_UNLOCK(&infreq->devnet->lock);

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

	nnp_remove_sw_counters_values_node(infreq->sw_counters);

	SPH_SW_COUNTER_DEC(infreq->devnet->sw_counters,
			   NET_SPHCS_SW_COUNTERS_NUM_INFER_CMDS);

	if (likely(infreq->destroyed == 1))
		sphcs_send_event_report_ext(g_the_sphcs,
					NNP_IPC_INFREQ_DESTROYED,
					0,
					infreq->devnet->context->chan->respq,
					infreq->devnet->context->protocol_id,
					infreq->protocol_id,
					infreq->devnet->protocol_id);

	inf_devnet_put(infreq->devnet);

	if (likely(infreq->inputs != NULL))
		kfree(infreq->inputs);
	if (likely(infreq->outputs != NULL))
		kfree(infreq->outputs);
	if (likely(infreq->config_data != NULL))
		kfree(infreq->config_data);
	del_ptr2id(infreq);
	kfree(infreq);
}

int inf_req_get(struct inf_req *infreq)
{
	return kref_get_unless_zero(&infreq->ref);
}

int inf_req_put(struct inf_req *infreq)
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
	req->i_num_opt_depend_devres = infreq->n_inputs;
	req->o_num_opt_depend_devres = infreq->n_outputs;
	req->i_opt_depend_devres = infreq->inputs;
	req->o_opt_depend_devres = infreq->outputs;
}

int infreq_req_sched(struct inf_exec_req *req)
{
	struct inf_req *infreq;
	int err;
	int i = 0;
	int j = 0;
	int k;

	NNP_ASSERT(req->cmd_type == CMDLIST_CMD_INFREQ);

	infreq = req->infreq;
	if (NNP_SW_GROUP_IS_ENABLE(infreq->sw_counters,
				   INFREQ_SPHCS_SW_COUNTERS_GROUP))
		req->time = nnp_time_us();
	else
		req->time = 0;
	inf_req_get(req->infreq);
	spin_lock_init(&req->lock_irq);
	inf_context_seq_id_init(infreq->devnet->context, &req->seq);
	inf_exec_req_get(req);

	DO_TRACE(trace_infreq(SPH_TRACE_OP_STATUS_QUEUED,
					   infreq->devnet->context->protocol_id,
					   infreq->devnet->protocol_id,
					   infreq->protocol_id,
					   req->cmd ? req->cmd->protocol_id : -1));

	/* place write dependency on the network resource to prevent
	 * two infer request of the same network to work in parallel.
	 */
	err = inf_devres_add_req_to_queue(infreq->devnet->first_devres,
					  req,
					  !infreq->devnet->serial_infreq_exec);
	if (unlikely(err < 0))
		goto fail_first;

	for (i = 0; i < req->i_num_opt_depend_devres; ++i) {
		err = inf_devres_add_req_to_queue(req->i_opt_depend_devres[i],
						  req,
						  true);
		if (unlikely(err < 0))
			goto fail;
	}

	for (j = 0; j < req->o_num_opt_depend_devres; ++j) {
		err = inf_devres_add_req_to_queue(req->o_opt_depend_devres[j],
						  req,
						  false);
		if (unlikely(err < 0))
			goto fail;
	}

	// Migrate high priority
	if (req->priority != 0)
		migrate_priority(infreq, req);

	// Request scheduled
	NNP_SW_COUNTER_INC(infreq->devnet->context->sw_counters,
			   CTX_SPHCS_SW_COUNTERS_INFERENCE_SUBMITTED_INF_REQ);

	// First try to execute
	req->last_sched_tick = 0;
	inf_req_try_execute(req);

	inf_exec_req_put(req);
	return 0;

fail:
	for (k = 0; k < i; k++)
		inf_devres_del_req_from_queue(req->i_opt_depend_devres[k], req);
	for (k = 0; k < j; k++)
		inf_devres_del_req_from_queue(req->o_opt_depend_devres[k], req);
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

	NNP_ASSERT(req->cmd_type == CMDLIST_CMD_INFREQ);

	infreq = req->infreq;
	inf_devres_del_req_from_queue(infreq->devnet->first_devres, req);
	for (i = 0; i < req->i_num_opt_depend_devres; ++i)
		inf_devres_del_req_from_queue(req->i_opt_depend_devres[i], req);
	for (i = 0; i < req->o_num_opt_depend_devres; ++i)
		inf_devres_del_req_from_queue(req->o_opt_depend_devres[i], req);
	inf_context_seq_id_fini(infreq->devnet->context, &req->seq);

	/* advance sched tick and try execute next requests */
	atomic_add(2, &req->context->sched_tick);

	inf_devres_try_execute(infreq->devnet->first_devres);
	for (i = 0; i < req->i_num_opt_depend_devres; ++i)
		inf_devres_try_execute(req->i_opt_depend_devres[i]);
	for (i = 0; i < req->o_num_opt_depend_devres; ++i)
		inf_devres_try_execute(req->o_opt_depend_devres[i]);

	kmem_cache_free(infreq->devnet->context->exec_req_slab_cache, req);
	inf_req_put(infreq);
}

static enum EXEC_REQ_READINESS inf_req_ready(struct inf_exec_req *req)
{
	struct inf_req *infreq;
	int i;
	bool has_dirty_inputs = false;
	enum DEV_RES_READINESS dev_res_status;

	NNP_ASSERT(req->cmd_type == CMDLIST_CMD_INFREQ);

	infreq = req->infreq;
	/* cannot start execute if another infreq of the same network is running*/
	if (!inf_devres_req_ready(infreq->devnet->first_devres,
				  req,
				  !infreq->devnet->serial_infreq_exec))
		return EXEC_REQ_READINESS_NOT_READY;

	/* check input resources dependency */
	for (i = 0; i < req->i_num_opt_depend_devres; ++i) {
		dev_res_status = inf_devres_req_ready(req->i_opt_depend_devres[i], req, true);
		if (dev_res_status == DEV_RES_READINESS_NOT_READY)
			return EXEC_REQ_READINESS_NOT_READY;
		has_dirty_inputs |= (dev_res_status == DEV_RES_READINESS_READY_BUT_DIRTY);
	}

	/* check output resources dependency */
	for (i = 0; i < req->o_num_opt_depend_devres; ++i) {
		dev_res_status = inf_devres_req_ready(req->o_opt_depend_devres[i], req, false);
		if (dev_res_status == DEV_RES_READINESS_NOT_READY)
			return EXEC_REQ_READINESS_NOT_READY;
	}

	/* All inputs are ready, check whether some of them is dirty */
	if (has_dirty_inputs)
		return EXEC_REQ_READINESS_READY_HAS_DIRTY_INPUTS;

	return EXEC_REQ_READINESS_READY_NO_DIRTY_INPUTS;
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

		NNP_ASSERT(n_to_read >= sizeof(req->infreq->exec_cmd)-offset);
		n = sizeof(req->infreq->exec_cmd) - offset;

		ret = copy_to_user(buf,
				   ((char *)&req->infreq->exec_cmd) + offset,
				   n);
		offset = 0;
	}

	return ret;
}

static void ibecc_inject_error(struct inf_devnet *devnet)
{
	u32 usage;
	struct page *page;

	if (likely(!ibecc_error_injection_requested))
		return;

	if (sphcs_ibecc_correctable_error_requested())
		usage = IOCTL_INF_RES_ECC;
	else
		usage = sphcs_ibecc_get_uc_severity_ctxt_requested() ? IOCTL_INF_RES_ECC : (IOCTL_INF_RES_ECC | IOCTL_INF_RES_FORCE_4G_ALLOC);

	/* Device resource for error injection must be :
	 * - allocated from the ECC protected region
	 * - at least 64 byte size (cache line size)
	 * - aligned on cache line boundary
	 */
	devres_for_err_inj = inf_devnet_find_ecc_devres(devnet, usage);

	if ((devres_for_err_inj == NULL) || (devres_for_err_inj->dma_map == NULL)) {
		sph_log_info(EXECUTE_COMMAND_LOG, "IBECC error injection - no appropriate device resource found\n");
		return;
	}

	page = sg_page(devres_for_err_inj->dma_map->sgl);
	addr_for_err_inj = vm_map_ram(&page, 1, -1, PAGE_KERNEL);
	sphcs_ibecc_inject_ctxt_err(sg_phys(devres_for_err_inj->dma_map->sgl), addr_for_err_inj);

}

static void ibecc_clean_error(void)
{
	if (likely(!ibecc_error_injection_requested))
		return;

	if (addr_for_err_inj) {
		sphcs_ibecc_clean_ctxt_err(addr_for_err_inj);
		vm_unmap_ram(addr_for_err_inj, 1);
	}

	devres_for_err_inj = NULL;
	addr_for_err_inj = NULL;
}

static int inf_req_execute(struct inf_exec_req *req)
{
	struct inf_req *infreq;
	struct inf_context *context;
	unsigned long flags, flags2;
	int ret;

	NNP_ASSERT(req->cmd_type == CMDLIST_CMD_INFREQ);
	NNP_ASSERT(req->in_progress);

	infreq = req->infreq;
	context = infreq->devnet->context;

	NNP_ASSERT(infreq->active_req == NULL);

	DO_TRACE(trace_infreq(SPH_TRACE_OP_STATUS_START,
		     infreq->devnet->context->protocol_id,
		     infreq->devnet->protocol_id,
		     infreq->protocol_id,
		     req->cmd ? req->cmd->protocol_id : -1));

	if (NNP_SW_GROUP_IS_ENABLE(infreq->sw_counters,
				   INFREQ_SPHCS_SW_COUNTERS_GROUP)) {
		u64 now = nnp_time_us();

		if (req->time > 0) {
			u64 dt = now - req->time;

			NNP_SW_COUNTER_ADD(infreq->sw_counters,
					   INFREQ_SPHCS_SW_COUNTERS_BLOCK_TOTAL_TIME,
					   dt);

			NNP_SW_COUNTER_INC(infreq->sw_counters,
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
	} else {
		req->time = 0;
	}

	NNP_SPIN_LOCK_IRQSAVE(&infreq->lock_irq, flags);
	infreq->exec_cmd.ready_flags = 1;
	infreq->exec_cmd.sched_params_is_null = req->sched_params_is_null;
	if (!req->sched_params_is_null) {
		infreq->exec_cmd.sched_params.batchSize = (uint16_t)req->size;
		infreq->exec_cmd.sched_params.priority = req->priority;
		infreq->exec_cmd.sched_params.debugOn = req->debugOn;
		infreq->exec_cmd.sched_params.collectInfo = req->collectInfo;
		infreq->exec_cmd.sched_params.hwtraceEnabled = (g_the_sphcs->hw_tracing.hwtrace_status == NNPCS_HWTRACE_ACTIVATED);
	} else {
		memset(&infreq->exec_cmd.sched_params, 0, sizeof(infreq->exec_cmd.sched_params));
		infreq->exec_cmd.sched_params_is_null = 0;
		infreq->exec_cmd.sched_params.hwtraceEnabled = (g_the_sphcs->hw_tracing.hwtrace_status == NNPCS_HWTRACE_ACTIVATED);
	}
	NNP_SPIN_LOCK_IRQSAVE(&context->sw_counters_lock_irq, flags2);
	if (context->infreq_counter == 0 &&
	    NNP_SW_GROUP_IS_ENABLE(context->sw_counters, CTX_SPHCS_SW_COUNTERS_GROUP_INFERENCE))
		context->runtime_busy_starttime = nnp_time_us();
	context->infreq_counter++;
	NNP_SPIN_UNLOCK_IRQRESTORE(&context->sw_counters_lock_irq, flags2);

	infreq->active_req = req;

	NNP_SPIN_UNLOCK_IRQRESTORE(&infreq->lock_irq, flags);

	/* If the context is broken we don't want to send the request to
	 * the runtime. Instead, we want to cancel this request by returning
	 * with error. active_req should remain NULL so we know this request
	 * wasn't added to cmdq.
	 */
	if (unlikely(inf_context_get_state(infreq->devnet->context) != CONTEXT_OK)) {
		ret = -NNPER_CONTEXT_BROKEN;
	} else {
		ibecc_inject_error(infreq->devnet);
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
		NNP_SPIN_LOCK_IRQSAVE(&infreq->lock_irq, flags);
		if (unlikely(infreq->active_req == NULL))
			// inf_req_complete will be called
			// from del_all_active_create_and_inf_requests
			ret = 0;
		else
			infreq->active_req = NULL;
		NNP_SPIN_UNLOCK_IRQRESTORE(&infreq->lock_irq, flags);
	}

	return ret;
}

static inline void infreq_send_req_fail(struct inf_exec_req *req,
					enum event_val       event_val)
{
	union c2h_ChanInfReqFailed chan_msg;
	struct inf_req *infreq;

	NNP_ASSERT(req->cmd_type == CMDLIST_CMD_INFREQ);

	infreq = req->infreq;

	memset(chan_msg.value, 0, sizeof(chan_msg.value));
	chan_msg.opcode = NNP_IPC_C2H_OP_CHAN_INFREQ_FAILED;
	chan_msg.chan_id = infreq->devnet->context->chan->protocol_id;
	chan_msg.netID = infreq->devnet->protocol_id;
	chan_msg.infreqID = infreq->protocol_id;
	chan_msg.reason = event_val;
	if (req->cmd != NULL) {
		chan_msg.cmdID_valid = 1;
		chan_msg.cmdID = req->cmd->protocol_id;
	}

	sph_log_debug(IPC_LOG, "Sending event: SCHEDULE_INFREQ_FAILED(%u) val=%u ctx_id=%u infreqID=%u netID=%u cmdID_2=%u (valid=%u)\n",
		chan_msg.opcode,
		chan_msg.reason,
		chan_msg.chan_id,
		chan_msg.infreqID,
		chan_msg.netID,
		chan_msg.cmdID, chan_msg.cmdID_valid);

	sphcs_msg_scheduler_queue_add_msg(g_the_sphcs->public_respq,
					  &chan_msg.value[0],
					  sizeof(chan_msg.value) / sizeof(u64));
}

static void send_infreq_report(struct inf_exec_req *req,
			       enum event_val       event_val)
{
	if (event_val != 0)
		infreq_send_req_fail(req, event_val);
}

static void treat_infreq_failure(struct inf_exec_req *req,
				 enum event_val       event_val,
				 const void          *error_msg,
				 int32_t              error_msg_size)
{
	struct inf_req *infreq;
	struct inf_exec_error_details *err_details;
	uint32_t i;
	int rc;

	NNP_ASSERT(req->cmd_type == CMDLIST_CMD_INFREQ);

	if (error_msg == NULL)
		error_msg_size = 0;

	infreq = req->infreq;
	rc = inf_exec_error_details_alloc(CMDLIST_CMD_INFREQ,
					  infreq->protocol_id,
					  infreq->devnet->protocol_id,
					  event_val,
					  error_msg_size < 0 ? -error_msg_size : error_msg_size,
					  &err_details);
	if (likely(rc == 0)) {
		if (error_msg_size < 0) {
			rc = copy_from_user(err_details->error_msg,
					    error_msg,
					    err_details->error_msg_size);
			if (unlikely(rc != 0))
				strncpy(err_details->error_msg, "<Failed to get error message>", err_details->error_msg_size);
		} else if (error_msg_size > 0) {
			safe_c_memcpy(err_details->error_msg, error_msg_size, error_msg, error_msg_size);
		}

		inf_exec_error_list_add(req->cmd != NULL ? &req->cmd->error_list :
							   &infreq->devnet->context->error_list,
					err_details);
	}

	if (event_val == NNP_IPC_ICEDRV_INFER_EXEC_ERROR_NEED_CARD_RESET) {
		sphcs_send_event_report(g_the_sphcs,
					NNP_IPC_ERROR_FATAL_ICE_ERROR,
					infreq->devnet->context->protocol_id,
					NULL,
					-1,
					-1);

		inf_context_set_state(infreq->devnet->context,
				      CONTEXT_BROKEN_NON_RECOVERABLE);
	} else if (req->cmd == NULL) {
		inf_context_set_state(infreq->devnet->context,
				      CONTEXT_BROKEN_RECOVERABLE);
	}

	for (i = 0; i < infreq->n_outputs; i++)
		inf_devres_set_dirty(infreq->outputs[i], true);
}

void inf_req_complete(struct inf_exec_req *req,
		      int                  err,
		      const void          *error_msg,
		      int32_t              error_msg_size)
{
	struct inf_req *infreq;
	struct inf_context *context;
	struct inf_cmd_list *cmd;
	unsigned long flags;
	enum event_val event_val;
	bool last_completed;
	uint32_t i;
	bool has_dirty_outputs = false;

	NNP_ASSERT(req->cmd_type == CMDLIST_CMD_INFREQ);
	NNP_ASSERT(req->in_progress);

	infreq = req->infreq;
	context = infreq->devnet->context;
	cmd = req->cmd;

	NNP_SPIN_LOCK_IRQSAVE(&context->sw_counters_lock_irq, flags);
	context->infreq_counter--;
	last_completed = (context->infreq_counter == 0);
	NNP_SW_COUNTER_INC(context->sw_counters, CTX_SPHCS_SW_COUNTERS_INFERENCE_COMPLETED_INF_REQ);

	if (last_completed &&
	    NNP_SW_GROUP_IS_ENABLE(context->sw_counters, CTX_SPHCS_SW_COUNTERS_GROUP_INFERENCE) &&
	    context->runtime_busy_starttime) {
		NNP_SW_COUNTER_ADD(context->sw_counters,
				   CTX_SPHCS_SW_COUNTERS_INFERENCE_RUNTIME_BUSY_TIME,
				   nnp_time_us() - context->runtime_busy_starttime);

		context->runtime_busy_starttime = 0;
	}
	NNP_SPIN_UNLOCK_IRQRESTORE(&context->sw_counters_lock_irq, flags);
	SPH_SW_COUNTER_ATOMIC_INC(g_nnp_sw_counters, SPHCS_SW_COUNTERS_INFERENCE_COMPLETED_INF_REQ);

	 DO_TRACE(trace_infreq(SPH_TRACE_OP_STATUS_COMPLETE,
				  infreq->devnet->context->protocol_id,
				  infreq->devnet->protocol_id,
				  infreq->protocol_id,
				  cmd ? cmd->protocol_id : -1));

	if (req->time > 0 &&
	    NNP_SW_GROUP_IS_ENABLE(infreq->sw_counters,
				   INFREQ_SPHCS_SW_COUNTERS_GROUP)) {
		u64 dt = nnp_time_us() - req->time;

		NNP_SW_COUNTER_ADD(infreq->sw_counters,
				   INFREQ_SPHCS_SW_COUNTERS_EXEC_TOTAL_TIME,
				   dt);

		NNP_SW_COUNTER_INC(infreq->sw_counters,
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


	NNP_SPIN_LOCK_IRQSAVE(&infreq->lock_irq, flags);
	infreq->exec_cmd.ready_flags = 0;
	infreq->active_req = NULL;
	NNP_SPIN_UNLOCK_IRQRESTORE(&infreq->lock_irq, flags);

	if (unlikely(err < 0)) {
		switch (err) {
		case -ENOMEM: {
			event_val = NNP_IPC_NO_MEMORY;
			break;
		}
		case -NNPER_CONTEXT_BROKEN: {
			event_val = NNP_IPC_CONTEXT_BROKEN;
			break;
		}
		case -NNPER_DMA_ERROR: {
			event_val = NNP_IPC_DMA_ERROR;
			break;
		}
		case -NNPER_NOT_SUPPORTED: {
			event_val = NNP_IPC_RUNTIME_NOT_SUPPORTED;
			break;
		}
		case -NNPER_INFER_EXEC_ERROR: {
			event_val = NNP_IPC_RUNTIME_INFER_EXEC_ERROR;
			break;
		}
		case -NNPER_INFER_ICEDRV_ERROR: {
			event_val = NNP_IPC_ICEDRV_INFER_EXEC_ERROR;
			break;
		}
		case -NNPER_INFER_ICEDRV_ERROR_RESET: {
			event_val = NNP_IPC_ICEDRV_INFER_EXEC_ERROR_NEED_RESET;
			break;
		}
		case -NNPER_INFER_ICEDRV_ERROR_CARD_RESET: {
			event_val = NNP_IPC_ICEDRV_INFER_EXEC_ERROR_NEED_CARD_RESET;
			break;
		}
		case -NNPER_INFER_SCHEDULE_ERROR: {
			event_val = NNP_IPC_RUNTIME_INFER_SCHEDULE_ERROR;
			break;
		}
		case -NNPER_INPUT_IS_DIRTY: {
			event_val = NNP_IPC_INPUT_IS_DIRTY;
			break;
		}
		default:
			event_val = NNP_IPC_RUNTIME_FAILED;
		}

		sph_log_err(EXECUTE_COMMAND_LOG, "Got Error. errno: %d, event_val=%u (contextID=%u, netID=%u, inferID=%u, cmdlist=%d)\n", err, event_val,
			infreq->devnet->context->protocol_id,
			infreq->devnet->protocol_id,
			infreq->protocol_id,
			cmd ? (int)(cmd->protocol_id) : -1);

		treat_infreq_failure(req, event_val, error_msg, error_msg_size);

		infreq_send_req_fail(req, event_val);
	} else {
		for (i = 0; i < req->o_num_opt_depend_devres; ++i) {
			has_dirty_outputs = req->o_opt_depend_devres[i]->is_dirty ||
					    req->o_opt_depend_devres[i]->group_dirty_count > 0;
			if (has_dirty_outputs)
				break;
		}

		if (has_dirty_outputs) {
			for (i = 0; i < infreq->n_outputs; i++)
				inf_devres_set_dirty(infreq->outputs[i], false);
		}
	}

	/* If inference request is completed and some inputs are destination p2p resources */
	/* TODO: create list of p2p destination inputs on infreq creation and loop over it */
	for (i = 0; i < infreq->n_inputs; i++) {
		if (infreq->inputs[i]->is_p2p_dst) {
			/* Resource will be ready again, once d2d copy will succeed */
			infreq->inputs[i]->p2p_buf.ready = false;

			if (!infreq->inputs[i]->is_dirty) {
				/* If inference request is part of command list, the command list completion will be reported
				 * only when all credits are released
				 */
				if (cmd != NULL)
					atomic_inc(&cmd->num_left);
				if (inf_devres_send_release_credit(infreq->inputs[i], req) && (cmd != NULL))
					atomic_dec(&cmd->num_left);
			}
		}
	}

	ibecc_clean_error();

	inf_exec_req_put(req);

	/* If command list execution completed, send completion event */
	send_cmd_list_completed_event(cmd);
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

