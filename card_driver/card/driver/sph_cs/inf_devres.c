/********************************************
 * Copyright (C) 2019-2021 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#include "inf_devres.h"
#include <linux/kernel.h>
#include <linux/slab.h>
#include "sphcs_cs.h"
#include "sph_log.h"
#include "inf_context.h"
#include "inf_copy.h"
#include "inf_exec_req.h"
#include "ioctl_inf.h"
#include "inf_ptr2id.h"

static void treat_credit_release_failure(struct inf_exec_req *req, enum event_val event_val)
{
	struct inf_exec_error_details *err_details;
	int rc;

	NNP_ASSERT(req->cmd_type != CMDLIST_CMD_COPYLIST);

	rc = inf_exec_error_details_alloc(req->cmd_type,
					  req->cmd_type == CMDLIST_CMD_INFREQ ? req->infreq->protocol_id : req->copy->protocol_id,
					  req->cmd_type == CMDLIST_CMD_INFREQ ? req->infreq->devnet->protocol_id : 0,
					  NNP_IPC_FAILED_TO_RELEASE_CREDIT,
					  0,
					  &err_details);
	if (likely(rc == 0))
		inf_exec_error_list_add(req->cmd != NULL ? &req->cmd->error_list :
							   &req->context->error_list,
					err_details);

	if (req->cmd == NULL)
		inf_context_set_state(req->context,
				      CONTEXT_BROKEN_RECOVERABLE);
	else
		/* Send event only when exec request is part of some command list. Otherwise,
		 * the NNP_IPC_CONTEXT_EXEC_ERROR is sent by inf_exec_error_list_add
		 */
		sphcs_send_event_report(g_the_sphcs,
					NNP_IPC_EC_FAILED_TO_RELEASE_CREDIT,
					event_val,
					req->context->chan->respq,
					req->context->protocol_id,
					req->cmd->protocol_id);
}

static int credit_released_cb(struct sphcs *sphcs, void *ctx, const void *user_data, int status, u32 xferTimeUS)
{
	struct inf_exec_req *req = (struct inf_exec_req *)ctx;
	struct inf_cmd_list *cmd = req->cmd;

	NNP_ASSERT(req != NULL);
	NNP_ASSERT(status == SPHCS_DMA_STATUS_DONE || status == SPHCS_DMA_STATUS_FAILED);

	/* If the DMA failed */
	if (unlikely(status == SPHCS_DMA_STATUS_FAILED)) {
		sph_log_err(EXECUTE_COMMAND_LOG, "Failed to release credit.\n");
		treat_credit_release_failure(req, NNP_IPC_DMA_ERROR);
	}

	inf_exec_req_put(req);

	/* If the command list is completed and all credits are sent */
	send_cmd_list_completed_event(cmd);

	return 0;
}

int inf_devres_create(uint16_t            protocol_id,
		      struct inf_context *context,
		      uint64_t            size,
		      uint8_t             depth,
		      uint64_t            align,
		      uint32_t            usage_flags,
		      struct inf_devres **out_devres)
{
	struct inf_devres *devres;
	int rc;

	if ((usage_flags & IOCTL_INF_RES_P2P_SRC) && (usage_flags & IOCTL_INF_RES_P2P_DST))
		return -EINVAL;

	devres = kzalloc(sizeof(*devres), GFP_KERNEL);
	if (unlikely(devres == NULL))
		return -ENOMEM;

	kref_init(&devres->ref);
	devres->magic = inf_devres_create;
	devres->protocol_id = protocol_id;
	INIT_LIST_HEAD(&devres->exec_queue);
	devres->queue_version = 0;
	atomic_set(&devres->pivot_usecount, 0);
	devres->pivot = NULL;
	devres->context = context;
	spin_lock_init(&devres->lock_irq);
	devres->is_dirty = false;
	devres->size = size;
	devres->align = align;
	devres->depth = depth;
	devres->usage_flags = usage_flags;
	if ((usage_flags & IOCTL_INF_RES_INPUT) &&
	    (usage_flags & IOCTL_INF_RES_OUTPUT))
		devres->dir = DMA_BIDIRECTIONAL;
	else if (usage_flags & IOCTL_INF_RES_INPUT)
		devres->dir = DMA_FROM_DEVICE;
	else if (usage_flags & IOCTL_INF_RES_OUTPUT)
		devres->dir = DMA_TO_DEVICE;
	else
		devres->dir = DMA_NONE;
	devres->status = CREATE_STARTED;
	devres->destroyed = 0;
	devres->is_p2p_src = (devres->usage_flags & IOCTL_INF_RES_P2P_SRC) ? true : false;
	devres->is_p2p_dst = (devres->usage_flags & IOCTL_INF_RES_P2P_DST) ? true : false;
	devres->ptr2id = add_ptr2id(devres);
	if (unlikely(devres->ptr2id == 0)) {
		kfree(devres);
		return -ENOMEM;
	}

	if (inf_devres_is_p2p(devres)) {
		rc = sphcs_p2p_init_p2p_buf(devres->is_p2p_src, &devres->p2p_buf);
		if (unlikely(rc < 0)) {
			del_ptr2id(devres);
			kfree(devres);
			return rc;
		}
	}

	/* make sure context will not be destroyed during devres life */
	inf_context_get(context);

	NNP_SW_COUNTER_ADD(context->sw_counters, CTX_SPHCS_SW_COUNTERS_INFERENCE_DEVICE_RESOURCE_SIZE, size);

	*out_devres = devres;
	return 0;
}

int inf_devres_attach_buf(struct inf_devres *devres,
			  int                fd)
{
	int ret;
	NNP_ASSERT(devres != NULL);

	if (unlikely(devres->destroyed != 0))
		return -EPERM;

	devres->buf_fd = fd;
	devres->dma_buf = dma_buf_get(fd);
	ret = PTR_ERR_OR_ZERO(devres->dma_buf);
	if (unlikely(ret < 0))
		return ret;

	devres->dma_att = dma_buf_attach(devres->dma_buf,
					 g_the_sphcs->hw_device);

	ret = PTR_ERR_OR_ZERO(devres->dma_att);
	if (unlikely(ret < 0))
		goto failed_to_att;

	devres->dma_map = dma_buf_map_attachment(devres->dma_att,
						 devres->dir);
	ret = PTR_ERR_OR_ZERO(devres->dma_map);
	if (unlikely(ret < 0))
		goto failed_to_map;

	devres->status = CREATED;

	sph_log_debug_ratelimited(CREATE_COMMAND_LOG, "mapped device resource "
		      "protocol_id=%u nents=%u\n",
		      devres->protocol_id,
		      devres->dma_map->nents);

	return 0;

failed_to_map:
	dma_buf_detach(devres->dma_buf, devres->dma_att);
failed_to_att:
	dma_buf_put(devres->dma_buf);
	return ret;
}

static void inf_devres_detach_buf(struct inf_devres *devres)
{
	NNP_ASSERT(devres != NULL);
	NNP_ASSERT(devres->status == CREATED);

	dma_buf_unmap_attachment(devres->dma_att,
				devres->dma_map,
				devres->dir);
	dma_buf_detach(devres->dma_buf, devres->dma_att);
	dma_buf_put(devres->dma_buf);
}

int is_inf_devres_ptr(void *ptr)
{
	struct inf_devres *devres = (struct inf_devres *)ptr;

	return (ptr != NULL && devres->magic == inf_devres_create);
}

void send_runtime_destroy_devres(struct inf_devres *devres)
{
	struct inf_destroy_resource cmd_args;
	int ret;

	/* send runtime command to destroy the device resource */
	cmd_args.drv_handle = devres->ptr2id;
	cmd_args.rt_handle = devres->rt_handle;
	ret = inf_cmd_queue_add(&devres->context->cmdq,
				SPHCS_RUNTIME_CMD_DESTROY_RESOURCE,
				&cmd_args,
				sizeof(cmd_args),
				NULL, NULL);
	if (unlikely(ret < 0))
		sph_log_err(CREATE_COMMAND_LOG, "Failed to send destroy resource command to runtime\n");
}

/* This function is called only when creation is failed,
 * to destroy already created part
 */
void destroy_devres_on_create_failed(struct inf_devres *devres)
{
	bool dma_completed, should_destroy;
	unsigned long flags;

	NNP_SPIN_LOCK_IRQSAVE(&devres->lock_irq, flags);

	dma_completed = (devres->status == DMA_COMPLETED);
	// roll back status, to put kref once
	if (dma_completed)
		devres->status = CREATE_STARTED;

	should_destroy = (devres->destroyed == 0);
	if (likely(should_destroy))
		devres->destroyed = -1;

	NNP_SPIN_UNLOCK_IRQRESTORE(&devres->lock_irq, flags);


	if (likely(should_destroy))
		inf_devres_put(devres);

	// if got failure from RT
	if (dma_completed)
		inf_devres_put(devres);
}

static void release_devres(struct kref *kref)
{
	struct inf_devres *devres = container_of(kref,
						 struct inf_devres,
						 ref);

	NNP_ASSERT(is_inf_devres_ptr(devres));
	NNP_ASSERT(list_empty(&devres->exec_queue));

	devres->magic = 0;

	NNP_SPIN_LOCK(&devres->context->lock);
	hash_del(&devres->hash_node);
	NNP_SPIN_UNLOCK(&devres->context->lock);

	if (inf_devres_is_p2p(devres))
		sphcs_p2p_remove_buffer(&devres->p2p_buf);

	if (likely(devres->status == CREATED)) {
		inf_devres_detach_buf(devres);
		send_runtime_destroy_devres(devres);
	}

	SPH_SW_COUNTER_DEC_VAL(devres->context->sw_counters, CTX_SPHCS_SW_COUNTERS_INFERENCE_DEVICE_RESOURCE_SIZE, devres->size);


	if (likely(devres->destroyed == 1))
		sphcs_send_event_report(g_the_sphcs,
					NNP_IPC_DEVRES_DESTROYED,
					0,
					devres->context->chan->respq,
					devres->context->protocol_id,
					devres->protocol_id);

	inf_context_put(devres->context);
	del_ptr2id(devres);

	kfree(devres);
}

int inf_devres_get(struct inf_devres *devres)
{
	return kref_get_unless_zero(&devres->ref);
}

int inf_devres_put(struct inf_devres *devres)
{
	return kref_put(&devres->ref, release_devres);
}


void inf_devres_migrate_priority_to_req_queue(struct inf_devres *devres, struct inf_exec_req *exec_infreq, bool read)
{
	struct exec_queue_entry *pos;
	unsigned long flags;
	int ret;

	//TODO Fix the migration logic
	NNP_SPIN_LOCK_IRQSAVE(&devres->lock_irq, flags);
	list_for_each_entry(pos, &devres->exec_queue, node) {
		struct inf_exec_req *req = pos->req;
		//reached infreq
		if (req == exec_infreq)
			break;
		if (pos->read && read)
			continue;
		ret = req->f->migrate_priority(req, exec_infreq->priority);
		if (ret < 0)
			sph_log_debug(SCHEDULE_COMMAND_LOG, "Failed to migrate priority.\n");
	}
	NNP_SPIN_UNLOCK_IRQRESTORE(&devres->lock_irq, flags);
}

int inf_devres_add_req_to_queue(struct inf_devres *devres, struct inf_exec_req *req, bool read)
{
	struct exec_queue_entry *queue_ent;
	unsigned long flags;

	NNP_ASSERT(devres != NULL);
	NNP_ASSERT(req != NULL);

	queue_ent = kmalloc(sizeof(struct exec_queue_entry), GFP_NOWAIT);
	if (unlikely(queue_ent == NULL))
		return -ENOMEM;

	queue_ent->req = req;
	queue_ent->read = read;

	NNP_SPIN_LOCK_IRQSAVE(&devres->lock_irq, flags);
	list_add_tail(&queue_ent->node, &devres->exec_queue);
	NNP_SPIN_UNLOCK_IRQRESTORE(&devres->lock_irq, flags);

	return 0;
}

int inf_devres_send_release_credit(struct inf_devres *devres, struct inf_exec_req *req)
{
	int rc;

	NNP_ASSERT(devres->is_p2p_dst && !devres->is_dirty);

	inf_exec_req_get(req);
	rc = -EIO;
	if (likely(devres->p2p_buf.peer_dev != NULL))
		rc = sphcs_p2p_send_rel_cr_and_ring_db(&devres->p2p_buf, credit_released_cb, req);
	if (unlikely(rc != 0)) {
		sph_log_err(EXECUTE_COMMAND_LOG, "Failed to initiate credit release(devres %hu), buf(%hhu) was diconnected, rc:%d.\n",
			    devres->protocol_id, devres->p2p_buf.buf_id, rc);
		treat_credit_release_failure(req, NNP_IPC_NO_MEMORY);
		inf_exec_req_put(req);
	}

	return rc;
}

void inf_devres_del_req_from_queue(struct inf_devres   *devres,
				   struct inf_exec_req *req)
{
	struct exec_queue_entry *pos;
	unsigned long flags;

	NNP_SPIN_LOCK_IRQSAVE(&devres->lock_irq, flags);
	list_for_each_entry(pos, &devres->exec_queue, node) {
		if (pos->req == req)
			break;
	}
	// Should be found
	NNP_ASSERT(&pos->node != &devres->exec_queue);
	list_del(&pos->node);
	++devres->queue_version;

	NNP_SPIN_UNLOCK_IRQRESTORE(&devres->lock_irq, flags);

	kfree(pos);
}

void inf_devres_try_execute(struct inf_devres *devres)
{
	struct exec_queue_entry *pos;
	unsigned int old_ver;
	unsigned long flags;

	NNP_ASSERT(devres != NULL);

	// try all reads
	NNP_SPIN_LOCK_IRQSAVE(&devres->lock_irq, flags);
	list_for_each_entry(pos, &devres->exec_queue, node) {
		bool is_write = !pos->read;

		// if pos is write and it is not the first in the queue exit
		if (is_write && pos->node.prev != &devres->exec_queue)
			break;

		// if get in_use failed, the req is being destroyed
		if (inf_exec_req_get(pos->req) == 0)
			break;
		old_ver = devres->queue_version;
		NNP_SPIN_UNLOCK_IRQRESTORE(&devres->lock_irq, flags);
		inf_req_try_execute(pos->req);
		inf_exec_req_put(pos->req);
		NNP_SPIN_LOCK_IRQSAVE(&devres->lock_irq, flags);

		// if from exec_queue was removed entries or
		// we tried to execute write don't continue
		if (old_ver != devres->queue_version || is_write)
			break;
	}
	NNP_SPIN_UNLOCK_IRQRESTORE(&devres->lock_irq, flags);
}

enum DEV_RES_READINESS inf_devres_req_ready(struct inf_devres *devres, struct inf_exec_req *req, bool for_read)
{
	struct exec_queue_entry *pos;
	unsigned long flags;
	enum DEV_RES_READINESS res = DEV_RES_READINESS_NOT_READY;

	NNP_ASSERT(devres != NULL);

	/* If the request is the first one in the queue or
	 * it is read request and all previous requests are read requests
	 */
	NNP_SPIN_LOCK_IRQSAVE(&devres->lock_irq, flags);
	list_for_each_entry(pos, &devres->exec_queue, node) {
		if (pos->req == req) {
			NNP_ASSERT(pos->read == for_read);
			res = DEV_RES_READINESS_READY;
			break;
		}
		if (!pos->read || !for_read)
			break;
	}

	if ((res == DEV_RES_READINESS_READY) && inf_devres_is_p2p(devres) && for_read) {
		if (devres->p2p_buf.ready)
			sph_log_debug(EXECUTE_COMMAND_LOG, "p2p buffer ready\n");
		else
			res = DEV_RES_READINESS_NOT_READY;
	}

	if (for_read && (res == DEV_RES_READINESS_READY) &&
	    (devres->is_dirty || devres->group_dirty_count > 0))
		res = DEV_RES_READINESS_READY_BUT_DIRTY;

	NNP_SPIN_UNLOCK_IRQRESTORE(&devres->lock_irq, flags);

	return res;

}

int inf_devres_set_depend_pivot(struct inf_devres *devres,
				struct inf_devres *pivot)
{
	int ret = 0;

	if (devres->pivot == pivot)
		return 0;

	if (atomic_inc_return(&devres->pivot_usecount) == 1)
		devres->pivot = pivot;
	else
		ret = -EBUSY;

	atomic_dec(&devres->pivot_usecount);

	return ret;
}

void inf_devres_pivot_usecount_inc(struct inf_devres *devres)
{
	if (devres->pivot != NULL) {
		if (atomic_inc_return(&devres->pivot_usecount) == 1 && devres->is_dirty)
			devres->pivot->group_dirty_count++;
	}
}

void inf_devres_pivot_usecount_dec(struct inf_devres *devres)
{
	if (devres->pivot != NULL) {
		if (atomic_dec_return(&devres->pivot_usecount) == 0) {
			if (devres->is_dirty) {
				NNP_ASSERT(devres->pivot->group_dirty_count > 0);
				devres->pivot->group_dirty_count--;
			}
		}
	}
}

struct inf_devres *inf_devres_get_depend_pivot(struct inf_devres *devres)
{
	if (atomic_read(&devres->pivot_usecount) > 0)
		return devres->pivot;
	else
		return devres;
}

void inf_devres_set_dirty(struct inf_devres *devres, bool dirty)
{
	if (devres->is_dirty == dirty)
		return;

	devres->is_dirty = dirty;
	if (atomic_read(&devres->pivot_usecount) > 0) {
		if (dirty) {
			devres->pivot->group_dirty_count++;
		} else {
			NNP_ASSERT(devres->pivot->group_dirty_count > 0);
			devres->pivot->group_dirty_count--;
		}
	}
}
