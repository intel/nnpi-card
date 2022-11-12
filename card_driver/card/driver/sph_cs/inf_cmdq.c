/********************************************
 * Copyright (C) 2019-2021 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#include "inf_cmdq.h"
#include <linux/slab.h>
#include <linux/poll.h>
#include "nnp_debug.h"

void inf_cmd_queue_init(struct inf_cmd_queue *cmdq)
{
	spin_lock_init(&cmdq->lock_irq);
	INIT_LIST_HEAD(&cmdq->pending_commands);
	init_waitqueue_head(&cmdq->waitq);
}

void inf_cmd_queue_fini(struct inf_cmd_queue *cmdq)
{
	struct inf_command *cmd;
	unsigned long flags;

	// This list normally should be empty, clean it in case runtime crashed
	NNP_SPIN_LOCK_IRQSAVE(&cmdq->lock_irq, flags);
	while (!list_empty(&cmdq->pending_commands)) {
		cmd = list_first_entry(&cmdq->pending_commands,
				       struct inf_command,
				       node);
		list_del(&cmd->node);
		NNP_SPIN_UNLOCK_IRQRESTORE(&cmdq->lock_irq, flags);
		kfree(cmd);
		NNP_SPIN_LOCK_IRQSAVE(&cmdq->lock_irq, flags);
	}
	NNP_SPIN_UNLOCK_IRQRESTORE(&cmdq->lock_irq, flags);
}

int inf_cmd_queue_add(struct inf_cmd_queue *cmdq,
		      uint32_t opcode,
		      void    *cmd_args,
		      uint32_t args_size,
		      unsigned long    (*read_payload)(char __user *buf,
						       void        *ctx,
						       uint32_t     offset,
						       uint32_t     n_to_read),
		      void             *read_payload_ctx)
{
	struct inf_command *cmd;
	unsigned long flags;
	uint32_t extra_size = read_payload == NULL && args_size > 0 ? args_size-1 : 0;

	cmd = kzalloc(sizeof(struct inf_command)+extra_size,
		      GFP_NOWAIT);
	if (unlikely(cmd == NULL))
		return -ENOMEM;

	cmd->header.opcode = opcode;
	cmd->header.size = args_size;
	cmd->read_payload = read_payload;
	cmd->read_payload_ctx = read_payload_ctx;
	if (read_payload == NULL && args_size > 0)
		memcpy(&cmd->cmd_args[0], cmd_args, args_size);

	NNP_SPIN_LOCK_IRQSAVE(&cmdq->lock_irq, flags);
	list_add_tail(&cmd->node, &cmdq->pending_commands);
	NNP_SPIN_UNLOCK_IRQRESTORE(&cmdq->lock_irq, flags);

	wake_up_all(&cmdq->waitq);

	return 0;
}

void inf_cmd_queue_exe(struct inf_cmd_queue *cmdq,
		      uint32_t opcode,
		      void (*exe_cmd)(void *cmd_args))
{
	unsigned long flags;
	struct inf_command *cmd = list_first_entry(&cmdq->pending_commands, struct inf_command, node);

	NNP_SPIN_LOCK_IRQSAVE(&cmdq->lock_irq, flags);
	while (&cmd->node != &cmdq->pending_commands) {
		if (cmd->header.opcode == opcode) {
			NNP_SPIN_UNLOCK_IRQRESTORE(&cmdq->lock_irq, flags);
			exe_cmd(cmd->cmd_args);
			NNP_SPIN_LOCK_IRQSAVE(&cmdq->lock_irq, flags);
		}

		cmd = list_next_entry(cmd, node);
	}
	NNP_SPIN_UNLOCK_IRQRESTORE(&cmdq->lock_irq, flags);
}

void inf_cmd_queue_hangup(struct inf_cmd_queue *cmdq)
{
	unsigned long flags;

	NNP_SPIN_LOCK_IRQSAVE(&cmdq->lock_irq, flags);
	cmdq->hangup = 1;
	NNP_SPIN_UNLOCK_IRQRESTORE(&cmdq->lock_irq, flags);

	wake_up_all(&cmdq->waitq);
}

unsigned int inf_cmd_queue_poll(struct inf_cmd_queue *cmdq,
				struct file *f,
				struct poll_table_struct *pt)
{
	unsigned int mask = 0;
	unsigned long flags;

	poll_wait(f, &cmdq->waitq, pt);
	NNP_SPIN_LOCK_IRQSAVE(&cmdq->lock_irq, flags);
	if (!list_empty(&cmdq->pending_commands) || cmdq->hangup)
		mask |= (POLLIN | POLLRDNORM);
	NNP_SPIN_UNLOCK_IRQRESTORE(&cmdq->lock_irq, flags);

	return mask;
}

ssize_t inf_cmd_queue_read(struct inf_cmd_queue *cmdq,
			   char __user          *buf,
			   size_t                size,
			   loff_t               *off)
{
	ssize_t n_to_read, was_read = 0;
	struct inf_command *cmd;
	int err;
	unsigned long flags;

	err = wait_event_interruptible(cmdq->waitq,
				       !list_empty(&cmdq->pending_commands) || cmdq->hangup);
	if (unlikely(err < 0))
		return err;

	if (cmdq->hangup)
		return -1;

	NNP_SPIN_LOCK_IRQSAVE(&cmdq->lock_irq, flags);
	cmd = list_first_entry(&cmdq->pending_commands, struct inf_command, node);
	NNP_SPIN_UNLOCK_IRQRESTORE(&cmdq->lock_irq, flags);

	if (!cmd->header_read) {
		if (size < sizeof(cmd->header))
			return -1;
		err = copy_to_user(buf, &cmd->header, sizeof(cmd->header));
		if (unlikely(err != 0))
			return -1;
		cmd->header_read = 1;
		cmd->offset = 0;
		size -= sizeof(cmd->header);
		buf += sizeof(cmd->header);
		was_read = sizeof(cmd->header);
		if (size == 0)
			goto done;
	}

	n_to_read = min(size, (size_t)(cmd->header.size - cmd->offset));

	if (cmd->read_payload == NULL) {
		err = copy_to_user(buf, (&cmd->cmd_args[0]) + cmd->offset, n_to_read);
		NNP_ASSERT(err == 0);
	} else {
		cmd->read_payload(buf,
				  cmd->read_payload_ctx,
				  cmd->offset,
				  n_to_read);
	}

	cmd->offset += n_to_read;
	was_read += n_to_read;

done:
	if (cmd->offset >= cmd->header.size) {
		NNP_SPIN_LOCK_IRQSAVE(&cmdq->lock_irq, flags);
		list_del(&cmd->node);
		NNP_SPIN_UNLOCK_IRQRESTORE(&cmdq->lock_irq, flags);
		kfree(cmd);
	}

	return was_read;
}
