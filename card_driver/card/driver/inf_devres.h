/********************************************
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#ifndef SPHCS_INF_DEVRES_H
#define SPHCS_INF_DEVRES_H

#include <linux/kref.h>
#include <linux/hashtable.h>
#include <linux/spinlock.h>
#include <linux/dma-buf.h>
#include "inf_types.h"

struct exec_queue_entry {
	struct inf_exec_req *req;
	bool                 read;
	struct list_head     node;
};

struct inf_context;

struct inf_devres {
	void             *magic;
	struct kref       ref;
	uint16_t          protocolID;
	struct inf_context *context;
	struct hlist_node hash_node;
	spinlock_t        lock_irq;

	enum dma_data_direction dir;
	uint32_t                size;

	int               buf_fd;
	struct dma_buf   *dma_buf;
	struct dma_buf_attachment *dma_att;
	struct sg_table  *dma_map;
	uint64_t          rt_handle;
	struct list_head  exec_queue;
	unsigned int      queue_version;
	enum create_status status;
	int                destroyed;
};

int inf_devres_create(uint16_t            protocolID,
		      struct inf_context *context,
		      uint32_t            size,
		      int                 is_input,
		      int                 is_output,
		      struct inf_devres **out_devres);
void destroy_devres_on_create_failed(struct inf_devres *devres);

int inf_devres_attach_buf(struct inf_devres *devres,
			  int                fd);

void send_runtime_destroy_devres(struct inf_devres *devres);

int is_inf_devres_ptr(void *ptr);

void inf_devres_get(struct inf_devres *devres);
int inf_devres_put(struct inf_devres *devres);

int inf_devres_add_req_to_queue(struct inf_devres *devres, struct inf_exec_req *req, bool read);
void inf_devres_del_req_from_queue(struct inf_devres   *devres,
				   struct inf_exec_req *req);
void inf_devres_try_execute(struct inf_devres *devres);
bool inf_devres_req_ready(struct inf_devres *devres, struct inf_exec_req *req, bool for_read);

#endif
