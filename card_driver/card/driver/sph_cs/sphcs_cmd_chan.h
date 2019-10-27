/********************************************
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#ifndef SPHCS_CMD_CHAN_H
#define SPHCS_CMD_CHAN_H

#include <linux/kref.h>
#include <linux/hashtable.h>
#include <linux/spinlock.h>
#include <linux/scatterlist.h>
#include <linux/workqueue.h>
#include "ipc_protocol.h"
#include "ipc_chan_protocol.h"
#include "msg_scheduler.h"
#include "sphcs_dma_sched.h"
#include "sphcs_cs.h"
#include "sph_debug.h"

struct sphcs_host_rb {
	struct sg_table host_sgt;
	wait_queue_head_t  waitq;
	spinlock_t         lock_bh;
	uint32_t size;
	uint32_t head;
	uint32_t tail;
};

struct sphcs_hostres_map {
	struct sg_table host_sgt;
	uint16_t protocolID;
	uint32_t size;
	struct hlist_node hash_node;
};

struct sphcs_cmd_chan {
	void             *magic;
	struct kref       ref;
	uint16_t          protocolID;
	uint32_t          uid;
	bool              privileged;
	struct hlist_node hash_node;
	int               destroyed;
	struct workqueue_struct *wq;
	struct msg_scheduler_queue *respq;

	struct sphcs_dma_desc c2h_dma_desc;
	struct sphcs_dma_desc h2c_dma_desc;

	spinlock_t lock_bh;
	DECLARE_HASHTABLE(hostres_hash, 6);

	void (*destroy_cb)(struct sphcs_cmd_chan *chan, void *cb_ctx);
	void *destroy_cb_ctx;

	struct sphcs_host_rb     h2c_rb[SPH_IPC_MAX_CHANNEL_RINGBUFS];
	struct sphcs_host_rb     c2h_rb[SPH_IPC_MAX_CHANNEL_RINGBUFS];
};

int sphcs_cmd_chan_create(uint16_t            protocolID,
			  uint32_t            uid,
			  bool                privileged,
			  struct sphcs_cmd_chan **out_cmd_chan);

int is_cmd_chan_ptr(void *ptr);

void sphcs_cmd_chan_get(struct sphcs_cmd_chan *cmd_chan);
int sphcs_cmd_chan_put(struct sphcs_cmd_chan *cmd_chan);

void IPC_OPCODE_HANDLER(CHANNEL_RB_OP)(
			struct sphcs        *sphcs,
			union h2c_ChannelDataRingbufOp *cmd);

void IPC_OPCODE_HANDLER(CHANNEL_RB_UPDATE)(
			struct sphcs        *sphcs,
			union h2c_ChanRingBufUpdate *cmd);

void IPC_OPCODE_HANDLER(CHANNEL_HOSTRES_OP)(
			struct sphcs               *sphcs,
			union h2c_ChannelHostresOp *cmd);

void sphcs_cmd_chan_update_cmd_head(struct sphcs_cmd_chan *chan, uint16_t rbID, uint32_t size);

dma_addr_t host_rb_get_addr(struct    sphcs_host_rb *rb,
			    uint32_t  offset,
			    uint32_t *out_cont_size);

int host_rb_get_addr_range(struct    sphcs_host_rb *rb,
			   uint32_t  offset,
			   uint32_t  size,
			   uint32_t  array_size,
			   dma_addr_t *addr_array,
			   uint32_t   *size_array,
			   uint32_t   *out_left);

static inline u32 host_rb_free_bytes(struct sphcs_host_rb *rb)
{
	u32 ret;

	SPH_SPIN_LOCK_BH(&rb->lock_bh);
	ret = (rb->head + rb->size - 1 - rb->tail) % rb->size;
	SPH_SPIN_UNLOCK_BH(&rb->lock_bh);

	return ret;
}

static inline u32 host_rb_avail_bytes(struct sphcs_host_rb *rb)
{
	u32 ret;

	SPH_SPIN_LOCK_BH(&rb->lock_bh);
	ret = (rb->tail + rb->size - rb->head) % rb->size;
	SPH_SPIN_UNLOCK_BH(&rb->lock_bh);

	return ret;
}

int host_rb_wait_free_space(struct sphcs_host_rb *rb,
			    uint32_t              size,
			    uint32_t              array_size,
			    dma_addr_t           *addr_array,
			    uint32_t             *size_addr);

void host_rb_update_free_space(struct sphcs_host_rb *rb,
			       uint32_t              size);

int host_rb_get_avail_space(struct sphcs_host_rb *rb,
			    uint32_t              size,
			    uint32_t              array_size,
			    dma_addr_t           *addr_array,
			    uint32_t             *size_array);

void host_rb_update_avail_space(struct sphcs_host_rb *rb,
				uint32_t              size);

struct sphcs_hostres_map *sphcs_cmd_chan_find_hostres(struct sphcs_cmd_chan *chan, uint16_t protocolID);
#endif
