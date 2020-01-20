/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#ifndef _SPHCS_INF_CMDQ_H
#define _SPHCS_INF_CMDQ_H

#include <linux/list.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/spinlock.h>
#include <linux/fs.h>
#include "ioctl_inf.h"
#include "sph_log.h"

struct inf_command {
	struct list_head node;
	uint32_t         header_read;
	uint32_t         offset;
	struct inf_cmd_header header;
	unsigned long    (*read_payload)(char __user *buf,
					 void        *ctx,
					 uint32_t     offset,
					 uint32_t     n_to_read);
	void            *read_payload_ctx;
	u8               cmd_args[1];
};

struct inf_cmd_queue {
	struct list_head  pending_commands;
	int               hangup;
	wait_queue_head_t waitq;
	spinlock_t        lock;
};

void inf_cmd_queue_init(struct inf_cmd_queue *cmdq);
void inf_cmd_queue_fini(struct inf_cmd_queue *cmdq);

int inf_cmd_queue_add(struct inf_cmd_queue *cmdq,
		      uint32_t opcode,
		      void    *cmd_args,
		      uint32_t args_size,
		      unsigned long    (*read_payload)(char __user *buf,
						       void        *ctx,
						       uint32_t     offset,
						       uint32_t     n_to_read),
		      void             *read_payload_ctx);

void inf_cmd_queue_exe(struct inf_cmd_queue *cmdq,
		      uint32_t opcode,
		      void (*exe_cmd)(void *cmd_args));

void inf_cmd_queue_hangup(struct inf_cmd_queue *cmdq);

unsigned int inf_cmd_queue_poll(struct inf_cmd_queue *cmdq,
				struct file *f,
				struct poll_table_struct *pt);

ssize_t inf_cmd_queue_read(struct inf_cmd_queue *cmdq,
			   char __user          *buf,
			   size_t                size,
			   loff_t               *off);

#endif
