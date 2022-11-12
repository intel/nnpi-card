/********************************************
 * Copyright (C) 2019-2021 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#ifndef SPHCS_INF_CMD_LIST_H
#define SPHCS_INF_CMD_LIST_H

#include <linux/kref.h>
#include <linux/hashtable.h>
#include <linux/spinlock.h>
#include "inf_types.h"
#include "sphcs_dma_sched.h"

struct inf_context;

struct inf_cmd_list {
	void                *magic;
	struct kref          ref;
	uint16_t             protocol_id;
	uint64_t             user_handle;
	struct inf_context  *context;
	struct hlist_node    hash_node;
	spinlock_t           lock_irq;
	struct inf_exec_req *req_list;
	enum create_status   status;
	int                  destroyed;
	uint16_t             num_reqs;
	atomic_t             num_left;

	struct inf_exec_error_list  error_list;

	//for edit params
	struct req_params   *edits;
	uint16_t             edits_idx;
	enum event_val       sched_failed;
	unsigned int         ptr2id;

	// list of devres ids acccessed by this command list.
	// Used for devres_group optimization
	struct list_head     devres_id_ranges;
};

int inf_cmd_create(uint16_t              protocol_id,
		   struct inf_context   *context,
		   struct inf_cmd_list **out_cmd);
void destroy_cmd_on_create_failed(struct inf_cmd_list *cmd);

int is_inf_cmd_ptr(void *ptr);

void inf_cmd_get(struct inf_cmd_list *cmd);
int inf_cmd_put(struct inf_cmd_list *cmd);

void inf_cmd_optimize_group_devres(struct inf_cmd_list *cmd);
void send_cmd_list_completed_event(struct inf_cmd_list *cmd);
#endif
