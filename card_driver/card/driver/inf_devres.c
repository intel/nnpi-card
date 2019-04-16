/********************************************
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#include "inf_devres.h"
#include <linux/kernel.h>
#include <linux/slab.h>
#include "sphcs_cs.h"
#include "sph_log.h"
#include "inf_context.h"
#include "ioctl_inf.h"

int inf_devres_create(uint16_t            protocolID,
		      struct inf_context *context,
		      uint32_t            size,
		      int                 is_input,
		      int                 is_output,
		      struct inf_devres **out_devres)
{
	struct inf_devres *devres;

	devres = kzalloc(sizeof(*devres), GFP_KERNEL);
	if (unlikely(devres == NULL))
		return -ENOMEM;

	kref_init(&devres->ref);
	devres->magic = inf_devres_create;
	devres->protocolID = protocolID;
	INIT_LIST_HEAD(&devres->exec_queue);
	devres->queue_version = 0;

	/* make sure context will not be destroyed during devres life */
	inf_context_get(context);
	devres->context = context;

	spin_lock_init(&devres->lock_irq);
	devres->size = size;
	if (is_input && is_output)
		devres->dir = DMA_BIDIRECTIONAL;
	else if (is_input)
		devres->dir = DMA_FROM_DEVICE;
	else if (is_output)
		devres->dir = DMA_TO_DEVICE;
	else
		devres->dir = DMA_NONE;
	devres->status = CREATE_STARTED;
	devres->destroyed = 0;

	SPH_SW_COUNTER_ADD(context->sw_counters, CTX_SPHCS_SW_COUNTERS_INFERENCE_DEVICE_RESOURCE_SIZE, size);

	*out_devres = devres;
	return 0;
}

int inf_devres_attach_buf(struct inf_devres *devres,
			  int                fd)
{
	int ret;
	SPH_ASSERT(devres != NULL);

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

#ifdef _DEBUG
	{
	unsigned int i;
	struct scatterlist *sg;

	sph_log_debug(CREATE_COMMAND_LOG, "mapped device resource protocolID=%u nents=%u\n",
		      devres->protocolID,
		      devres->dma_map->nents);
	sg = devres->dma_map->sgl;
	for (i = 0; i < devres->dma_map->nents; i++) {
		sph_log_debug(CREATE_COMMAND_LOG, "\t0x%llx - len 0x%x\n",
			      sg_dma_address(sg),
			      sg_dma_len(sg));
		sg = sg_next(sg);
	}
	}
#endif

	return 0;

failed_to_map:
	dma_buf_detach(devres->dma_buf, devres->dma_att);
failed_to_att:
	dma_buf_put(devres->dma_buf);
	return ret;
}

static void inf_devres_detach_buf(struct inf_devres *devres)
{
	SPH_ASSERT(devres != NULL);
	SPH_ASSERT(devres->status == CREATED);

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
	cmd_args.drv_handle = (uint64_t)(uintptr_t)devres;
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

	SPH_SPIN_LOCK_IRQSAVE(&devres->lock_irq, flags);

	dma_completed = (devres->status == DMA_COMPLETED);
	// roll back status, to put kref once
	if (dma_completed)
		devres->status = CREATE_STARTED;

	should_destroy = (devres->destroyed == 0);
	if (likely(should_destroy))
		devres->destroyed = -1;

	SPH_SPIN_UNLOCK_IRQRESTORE(&devres->lock_irq, flags);


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

	SPH_ASSERT(devres != NULL);

	SPH_SPIN_LOCK(&devres->context->lock);
	hash_del(&devres->hash_node);
	SPH_SPIN_UNLOCK(&devres->context->lock);

	if (likely(devres->status == CREATED)) {
		inf_devres_detach_buf(devres);
		send_runtime_destroy_devres(devres);
	}

	if (likely(devres->destroyed == 1))
		sphcs_send_event_report(g_the_sphcs,
					SPH_IPC_DEVRES_DESTROYED,
					0,
					devres->context->protocolID,
					devres->protocolID);

	SPH_SW_COUNTER_DEC_VAL(devres->context->sw_counters, CTX_SPHCS_SW_COUNTERS_INFERENCE_DEVICE_RESOURCE_SIZE, devres->size);

	inf_context_put(devres->context);

	kfree(devres);
}

inline void inf_devres_get(struct inf_devres *devres)
{
	int ret;

	ret = kref_get_unless_zero(&devres->ref);
	SPH_ASSERT(ret != 0);
}

inline int inf_devres_put(struct inf_devres *devres)
{
	return kref_put(&devres->ref, release_devres);
}

int inf_devres_add_req_to_queue(struct inf_devres *devres, struct inf_exec_req *req, bool read)
{
	struct exec_queue_entry *queue_ent;
	unsigned long flags;

	SPH_ASSERT(devres != NULL);
	SPH_ASSERT(req != NULL);

	queue_ent = kmalloc(sizeof(struct exec_queue_entry), GFP_NOWAIT);
	if (unlikely(queue_ent == NULL))
		return -ENOMEM;

	queue_ent->req = req;
	queue_ent->read = read;

	SPH_SPIN_LOCK_IRQSAVE(&devres->lock_irq, flags);
	list_add_tail(&queue_ent->node, &devres->exec_queue);
	SPH_SPIN_UNLOCK_IRQRESTORE(&devres->lock_irq, flags);

	return 0;
}

void inf_devres_del_req_from_queue(struct inf_devres   *devres,
				   struct inf_exec_req *req)
{
	struct exec_queue_entry *pos;
	unsigned long flags;

	SPH_SPIN_LOCK_IRQSAVE(&devres->lock_irq, flags);
	list_for_each_entry(pos, &devres->exec_queue, node) {
		if (pos->req == req)
			break;
	}
	// Should be found
	SPH_ASSERT(&pos->node != &devres->exec_queue);
	list_del(&pos->node);
	++devres->queue_version;
	SPH_SPIN_UNLOCK_IRQRESTORE(&devres->lock_irq, flags);

	kfree(pos);

	inf_devres_try_execute(devres);
}

void inf_devres_try_execute(struct inf_devres *devres)
{
	struct exec_queue_entry *pos;
	unsigned int old_ver;
	unsigned long flags;

	SPH_ASSERT(devres != NULL);

	// try all reads
	SPH_SPIN_LOCK_IRQSAVE(&devres->lock_irq, flags);
	list_for_each_entry(pos, &devres->exec_queue, node) {
		// if pos is write and it is not the first in the queue exit
		if (!pos->read && pos->node.prev != &devres->exec_queue)
			break;

		old_ver = devres->queue_version;
		SPH_SPIN_UNLOCK_IRQRESTORE(&devres->lock_irq, flags);
		inf_req_try_execute(pos->req);
		SPH_SPIN_LOCK_IRQSAVE(&devres->lock_irq, flags);

		// if from exec_queue was removed entries or
		// we tried to execute write don't continue
		if (old_ver != devres->queue_version || !pos->read)
			break;
	}
	SPH_SPIN_UNLOCK_IRQRESTORE(&devres->lock_irq, flags);
}

bool inf_devres_req_ready(struct inf_devres *devres, struct inf_exec_req *req, bool for_read)
{
	struct exec_queue_entry *pos;
	bool ready = false;
	unsigned long flags;

	SPH_ASSERT(devres != NULL);

	SPH_SPIN_LOCK_IRQSAVE(&devres->lock_irq, flags);
	list_for_each_entry(pos, &devres->exec_queue, node) {
		if (pos->req == req) {
			SPH_ASSERT(pos->read == for_read);
			ready = true;
			break;
		}
		if (!pos->read || !for_read)
			break;
	}
	SPH_SPIN_UNLOCK_IRQRESTORE(&devres->lock_irq, flags);

	return ready;

}
