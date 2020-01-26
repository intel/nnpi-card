/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#include "inf_exec_req.h"
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/atomic.h>
#include "ioctl_inf.h"

void inf_req_try_execute(struct inf_exec_req *req)
{
	int err;
	unsigned long flags;
	u32 curr_sched_tick;

	SPH_ASSERT(req != NULL);

	SPH_SPIN_LOCK_IRQSAVE(&req->lock_irq, flags);
	curr_sched_tick = atomic_read(&req->context->sched_tick);
	if (req->in_progress || req->last_sched_tick == curr_sched_tick) {
		SPH_SPIN_UNLOCK_IRQRESTORE(&req->lock_irq, flags);
		return;
	}
	req->last_sched_tick = curr_sched_tick;
	SPH_SPIN_UNLOCK_IRQRESTORE(&req->lock_irq, flags);

	if (!req->f->is_ready(req))
		return;

	SPH_SPIN_LOCK_IRQSAVE(&req->lock_irq, flags);
	if (req->in_progress) {
		SPH_SPIN_UNLOCK_IRQRESTORE(&req->lock_irq, flags);
		return;
	}
	req->in_progress = true;
	SPH_SPIN_UNLOCK_IRQRESTORE(&req->lock_irq, flags);

	err = req->f->execute(req);

	if (unlikely(err < 0))
		req->f->complete(req, err, NULL, 0);

}

int inf_exec_req_get(struct inf_exec_req *req)
{
	return kref_get_unless_zero(&req->in_use);
}

int inf_exec_req_put(struct inf_exec_req *req)
{
	return kref_put(&req->in_use, req->f->release);
}

int inf_update_priority(struct inf_exec_req *req,
			uint8_t priority,
			bool card2host,
			dma_addr_t lli_addr)
{
	unsigned long flags;
	int ret = 0;

	SPH_SPIN_LOCK_IRQSAVE(&req->lock_irq, flags);
	if (!req->in_progress) {
		//Request didn't reached HW yet , just update priority here
		req->priority = priority;
	} else {
		//Call Dma scheduler for update
		ret = sphcs_dma_sched_update_priority(g_the_sphcs->dmaSched,
							sph_dma_direction(card2host),
							req->priority,
							sph_dma_priority(priority),
							lli_addr);
		if (ret == 0)
			req->priority = priority;
	}
	SPH_SPIN_UNLOCK_IRQRESTORE(&req->lock_irq, flags);

	return ret;
}

void inf_exec_error_list_init(struct inf_exec_error_list *error_list,
			      struct inf_context *context)
{
	spin_lock_init(&error_list->lock);
	INIT_LIST_HEAD(&error_list->list);
	error_list->context = context;
	error_list->is_cmdlist = (error_list == &context->error_list ? false : true);
	error_list->need_card_reset = false;
	error_list->clear_started = 0;
	error_list->failed_devnets = NULL;
	error_list->num_failed_devnets = 0;
}

void inf_exec_error_list_fini(struct inf_exec_error_list *error_list)
{
	struct inf_exec_error_details *err, *tmp;

	list_for_each_entry_safe(err, tmp, &error_list->list, node) {
		list_del(&err->node);
		kfree(err);
	}
	kfree(error_list->failed_devnets);
}

void inf_exec_error_list_add(struct inf_exec_error_list    *error_list,
			     struct inf_exec_error_details *err)
{
	bool is_first;

	SPH_SPIN_LOCK(&error_list->lock);
	is_first = list_empty(&error_list->list) ? true : false;
	list_add_tail(&err->node, &error_list->list);
	if (err->eventVal == SPH_IPC_ICEDRV_INFER_EXEC_ERROR_NEED_CARD_RESET)
		error_list->need_card_reset = true;
	SPH_SPIN_UNLOCK(&error_list->lock);

	/*
	 * If this is the first error added to the context error list
	 * send also report to host to make the context broken.
	 */
	if (is_first && !error_list->is_cmdlist)
		sphcs_send_event_report_ext(g_the_sphcs,
					    SPH_IPC_CONTEXT_EXEC_ERROR,
					    err->cmd_type,
					    error_list->context->protocolID,
					    err->obj_id,
					    err->devnet_id);
}

int inf_exec_error_details_alloc(enum CmdListCommandType cmd_type,
				 uint16_t                obj_id,
				 uint16_t                devnet_id,
				 uint16_t                eventVal,
				 int32_t                 error_msg_size,
				 struct inf_exec_error_details **out_err)
{
	if (error_msg_size < 0 || out_err == NULL)
		return -EINVAL;

	*out_err = kzalloc(sizeof(struct inf_exec_error_details) + error_msg_size, GFP_KERNEL);
	if (!(*out_err))
		return -ENOMEM;

	(*out_err)->cmd_type = cmd_type;
	(*out_err)->obj_id = obj_id;
	(*out_err)->devnet_id = devnet_id;
	(*out_err)->eventVal = eventVal;
	(*out_err)->error_msg_size = error_msg_size;

	if (error_msg_size > 0)
		(*out_err)->error_msg = (*out_err) + 1;
	else
		(*out_err)->error_msg = NULL;

	return 0;
}

int inf_exec_error_list_buffer_pack(struct inf_exec_error_list *error_list,
				    void            **out_buffer,
				    uint16_t         *out_buffer_size)
{
	struct inf_exec_error_details *err;
	uint32_t n;
	uint32_t elem_size;
	struct ipc_exec_error_desc *desc;
	uint8_t *buf, *ptr;
	uint32_t total_size = 0;
	uint32_t nerrors = 0;
	uint32_t total_nerrors = 0;

	SPH_SPIN_LOCK(&error_list->lock);
	list_for_each_entry(err, &error_list->list, node) {
		total_nerrors++;
		elem_size = sizeof(struct ipc_exec_error_desc) + err->error_msg_size;
		if (total_size + elem_size <= USHRT_MAX) {
			total_size += elem_size;
			nerrors++;
		}
	}
	SPH_SPIN_UNLOCK(&error_list->lock);

	if (total_size == 0)
		return total_nerrors == 0 ? -ENOENT : -ENOSPC;

	buf = kmalloc(total_size, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	SPH_SPIN_LOCK(&error_list->lock);
	n = 0;
	ptr = buf;
	list_for_each_entry(err, &error_list->list, node) {
		elem_size = sizeof(struct ipc_exec_error_desc) + err->error_msg_size;
		if ((ptr - buf) + elem_size > total_size)
			break;

		desc = (struct ipc_exec_error_desc *)ptr;
		desc->cmd_type = err->cmd_type;
		desc->obj_id = err->obj_id;
		desc->devnet_id = err->devnet_id;
		desc->eventVal = err->eventVal;
		desc->error_msg_size = err->error_msg_size;
		ptr += sizeof(struct ipc_exec_error_desc);
		if (err->error_msg_size > 0) {
			memcpy(desc+1, err+1, err->error_msg_size);
			ptr += err->error_msg_size;
		}

		n++;
	}
	SPH_SPIN_UNLOCK(&error_list->lock);

	*out_buffer = buf;
	*out_buffer_size = (ptr - buf);

	return 0;
}

void inf_exec_error_list_clear(struct inf_exec_error_list *error_list,
			       struct inf_cmd_list        *cmdlist)
{
	struct inf_exec_error_details *err, *tmp;
	struct inf_devnet_reset reset_cmd;
	uint16_t n_need_reset = 0;
	struct inf_devnet *devnet;
	union c2h_ExecErrorList reply;
	uint16_t i;
	int ret;

	reply.value = 0;
	reply.opcode = SPH_IPC_C2H_OP_CHAN_EXEC_ERROR_LIST;
	reply.chanID = error_list->context->chan->protocolID;
	if (cmdlist != NULL) {
		reply.cmdID = cmdlist->protocolID;
		reply.cmdID_valid = 1;
	}
	reply.clear_status = 1;

	if (error_list->need_card_reset) {
		reply.is_error = 1;
		reply.total_size = SPH_IPC_CONTEXT_BROKEN;
		goto send_reply;
	}

	/*
	 * Remove from error list all elements that does not need a network
	 * reset
	 */
	SPH_SPIN_LOCK(&error_list->lock);
	error_list->clear_started = true;
	list_for_each_entry_safe(err, tmp, &error_list->list, node) {
		if (err->eventVal != SPH_IPC_ICEDRV_INFER_EXEC_ERROR_NEED_RESET) {
			list_del(&err->node);
			SPH_SPIN_UNLOCK(&error_list->lock);
			kfree(err);
			SPH_SPIN_LOCK(&error_list->lock);
		} else
			n_need_reset++;
	}
	SPH_SPIN_UNLOCK(&error_list->lock);

	if (n_need_reset == 0) {
		if (cmdlist == NULL)
			inf_context_set_state(error_list->context, CONTEXT_OK);
		goto send_reply;
	}

	/*
	 * Build list of failed networks and send reset request to runtime
	 */
	error_list->failed_devnets = kcalloc(n_need_reset, sizeof(uint16_t), GFP_KERNEL);
	if (!error_list->failed_devnets) {
		reply.is_error = 1;
		reply.total_size = SPH_IPC_NO_MEMORY;
		goto send_reply;
	}

	SPH_SPIN_LOCK(&error_list->lock);
	error_list->num_failed_devnets = 0;
	list_for_each_entry_safe(err, tmp, &error_list->list, node) {
		for (i = 0; i < error_list->num_failed_devnets; i++)
			if (err->devnet_id == error_list->failed_devnets[i])
				break;
		if (i >= error_list->num_failed_devnets)
			error_list->failed_devnets[error_list->num_failed_devnets++] = err->devnet_id;
		list_del(&err->node);
		SPH_SPIN_UNLOCK(&error_list->lock);
		kfree(err);
		SPH_SPIN_LOCK(&error_list->lock);
	}
	SPH_SPIN_UNLOCK(&error_list->lock);

	for (i = 0; i < error_list->num_failed_devnets; i++) {
		devnet = inf_context_find_devnet(error_list->context,
						 error_list->failed_devnets[i]);
		if (!devnet) {
			reply.is_error = 1;
			reply.total_size = SPH_IPC_NO_SUCH_NET;
			goto send_reply;
		}

		reset_cmd.devnet_drv_handle = (uint64_t)devnet;
		reset_cmd.cmdlist_drv_handle = (uint64_t)(uintptr_t)cmdlist;
		reset_cmd.devnet_rt_handle = devnet->rt_handle;
		reset_cmd.flags = 0;
		ret = inf_cmd_queue_add(&error_list->context->cmdq,
					SPHCS_RUNTIME_CMD_DEVNET_RESET,
					&reset_cmd,
					sizeof(reset_cmd),
					NULL, NULL);
		if (unlikely(ret < 0)) {
			reply.is_error = 1;
			reply.total_size = SPH_IPC_NO_MEMORY;
			goto send_reply;
		}
	}

	return;

send_reply:
	error_list->clear_started = false;
	sphcs_msg_scheduler_queue_add_msg(g_the_sphcs->public_respq, &reply.value, 1);
}

void inf_exec_error_list_devnet_reset_done(struct inf_exec_error_list *error_list,
					   uint16_t                    devnet_id,
					   struct inf_cmd_list        *cmdlist,
					   bool                        failed)
{
	uint32_t i;
	bool found = false;
	union c2h_ExecErrorList reply;

	if (!error_list->clear_started)
		return;

	reply.value = 0;
	reply.opcode = SPH_IPC_C2H_OP_CHAN_EXEC_ERROR_LIST;
	reply.chanID = error_list->context->chan->protocolID;
	if (cmdlist != NULL) {
		reply.cmdID = cmdlist->protocolID;
		reply.cmdID_valid = 1;
	}
	reply.clear_status = 1;

	if (failed) {
		reply.is_error = 1;
		reply.total_size = SPH_IPC_CONTEXT_BROKEN;
		goto send_reply;
	}

	SPH_SPIN_LOCK(&error_list->lock);
	for (i = 0; i < error_list->num_failed_devnets; i++)
		if (devnet_id == error_list->failed_devnets[i]) {
			if (i < error_list->num_failed_devnets - 1)
				memcpy(&error_list->failed_devnets[i],
				       &error_list->failed_devnets[i+1],
				       sizeof(uint16_t) * (error_list->num_failed_devnets - i - 1));
			error_list->num_failed_devnets--;
			found = true;
			break;
		}
	SPH_SPIN_UNLOCK(&error_list->lock);

	if (found && error_list->num_failed_devnets == 0) {
		/*
		 * All reset requests replied from runtime without failure.
		 * If for some reason we have new errors in the list, beging the
		 * clear flow again, otherwise reply host with clear sucessfull
		 */
		if (!list_empty(&error_list->list))
			inf_exec_error_list_clear(error_list, cmdlist);
		else
			goto send_reply;
	}

	return;

send_reply:
	error_list->clear_started = false;
	if (!reply.is_error && cmdlist == NULL)
		inf_context_set_state(error_list->context, CONTEXT_OK);
	sphcs_msg_scheduler_queue_add_msg(g_the_sphcs->public_respq, &reply.value, 1);
}
