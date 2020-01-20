/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
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
#include "sphcs_p2p.h"

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
	uint64_t                size;
	uint64_t                align;
	uint8_t                 depth;
	uint32_t                usage_flags;

	int               buf_fd;
	struct dma_buf   *dma_buf;
	struct dma_buf_attachment *dma_att;
	struct sg_table  *dma_map;
	uint64_t          rt_handle;
	struct list_head  exec_queue;
	unsigned int      queue_version;
	enum create_status status;
	int                destroyed;

	bool is_p2p_buf;
	struct sphcs_p2p_buf p2p_buf;
};

int inf_devres_create(uint16_t            protocolID,
		      struct inf_context *context,
		      uint64_t            size,
		      uint8_t             depth,
		      uint64_t            align,
		      uint32_t            usage_flags,
		      struct inf_devres **out_devres);
void destroy_devres_on_create_failed(struct inf_devres *devres);

int inf_devres_attach_buf(struct inf_devres *devres,
			  int                fd);

void send_runtime_destroy_devres(struct inf_devres *devres);

int is_inf_devres_ptr(void *ptr);

int inf_devres_get(struct inf_devres *devres);
int inf_devres_put(struct inf_devres *devres);

void inf_devres_migrate_priority_to_req_queue(struct inf_devres *devres, struct inf_exec_req *exec_infreq, bool read);
int inf_devres_add_req_to_queue(struct inf_devres *devres, struct inf_exec_req *req, bool read);
void inf_devres_del_req_from_queue(struct inf_devres   *devres,
				   struct inf_exec_req *req);
void inf_devres_try_execute(struct inf_devres *devres);
bool inf_devres_req_ready(struct inf_devres *devres, struct inf_exec_req *req, bool for_read);

void inf_devres_add_to_p2p(struct inf_devres *devres);
void inf_devres_remove_from_p2p(struct inf_devres *devres);

#endif
