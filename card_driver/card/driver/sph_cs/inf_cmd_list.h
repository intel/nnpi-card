/********************************************
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#ifndef SPHCS_INF_CMD_LIST_H
#define SPHCS_INF_CMD_LIST_H

#include <linux/kref.h>
#include <linux/hashtable.h>
#include <linux/spinlock.h>
#include "inf_types.h"

struct inf_context;

struct inf_cmd_list {
	void               *magic;
	struct kref         ref;
	uint16_t            protocolID;
	struct inf_context *context;
	struct hlist_node   hash_node;
	spinlock_t          lock;
	struct list_head    req_list;
	enum create_status  status;
	int                 destroyed;
};

int inf_cmd_create(uint16_t              protocolID,
		   struct inf_context   *context,
		   struct inf_cmd_list **out_cmd);
void destroy_cmd_on_create_failed(struct inf_cmd_list *cmd);

int is_inf_cmd_ptr(void *ptr);

void inf_cmd_get(struct inf_cmd_list *cmd);
int inf_cmd_put(struct inf_cmd_list *cmd);


#endif
