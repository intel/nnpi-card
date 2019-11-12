/********************************************
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#include "inf_cmd_list.h"
#include <linux/slab.h>
#include "sph_log.h"
#include "inf_context.h"
#include "inf_copy.h"
#include "inf_req.h"

int inf_cmd_create(uint16_t              protocolID,
		   struct inf_context   *context,
		   struct inf_cmd_list **out_cmd)
{
	struct inf_cmd_list *cmd;

	cmd = kzalloc(sizeof(*cmd), GFP_KERNEL);
	if (unlikely(cmd == NULL))
		return -ENOMEM;

	kref_init(&cmd->ref);
	cmd->magic = inf_cmd_create;
	cmd->protocolID = protocolID;
	INIT_LIST_HEAD(&cmd->req_list);

	/* make sure context will not be destroyed during cmd life */
	inf_context_get(context);
	cmd->context = context;

	spin_lock_init(&cmd->lock_irq);
	cmd->status = CREATE_STARTED;
	cmd->destroyed = 0;
	// not ready to schedule until create completes
	cmd->reqs_left = 1;

	*out_cmd = cmd;
	return 0;
}

int is_inf_cmd_ptr(void *ptr)
{
	struct inf_cmd_list *cmd = (struct inf_cmd_list *)ptr;

	return (ptr != NULL && cmd->magic == inf_cmd_create);
}

/* This function is called only when creation is failed,
 * to destroy already created part
 */
void destroy_cmd_on_create_failed(struct inf_cmd_list *cmd)
{
	bool dma_completed, should_destroy;
	unsigned long flags;

	SPH_SPIN_LOCK_IRQSAVE(&cmd->lock_irq, flags);

	dma_completed = (cmd->status == DMA_COMPLETED);
	// roll back status, to put kref once
	if (dma_completed)
		cmd->status = CREATE_STARTED;

	should_destroy = (cmd->destroyed == 0);
	if (likely(should_destroy))
		cmd->destroyed = -1;

	SPH_SPIN_UNLOCK_IRQRESTORE(&cmd->lock_irq, flags);


	if (likely(should_destroy))
		inf_cmd_put(cmd);

	// if got failure from RT
	if (dma_completed)
		inf_cmd_put(cmd);
}

static void release_cmd(struct kref *kref)
{
	struct inf_cmd_list *cmd = container_of(kref,
						struct inf_cmd_list,
						ref);
	struct inf_cmd_list_entry *entry;
	int ret;

	SPH_ASSERT(is_inf_cmd_ptr(cmd));

	SPH_SPIN_LOCK(&cmd->context->lock);
	hash_del(&cmd->hash_node);
	SPH_SPIN_UNLOCK(&cmd->context->lock);

	ret = inf_context_put(cmd->context);
	SPH_ASSERT(ret == 0);

	entry = list_first_entry_or_null(&cmd->req_list, struct inf_cmd_list_entry, node);
	while (entry != NULL) {
		list_del(&entry->node);
		if (entry->templ.is_copy)
			inf_copy_put(entry->templ.copy);
		else
			inf_req_put(entry->templ.infreq);
		kfree(entry);
		entry = list_first_entry_or_null(&cmd->req_list, struct inf_cmd_list_entry, node);
	}

	if (likely(cmd->destroyed == 1))
		sphcs_send_event_report(g_the_sphcs,
					SPH_IPC_CMD_DESTROYED,
					0,
					cmd->context->protocolID,
					cmd->protocolID);

	kfree(cmd);
}

inline void inf_cmd_get(struct inf_cmd_list *cmd)
{
	int ret;

	ret = kref_get_unless_zero(&cmd->ref);
	SPH_ASSERT(ret != 0);
}

inline int inf_cmd_put(struct inf_cmd_list *cmd)
{
	return kref_put(&cmd->ref, release_cmd);
}

