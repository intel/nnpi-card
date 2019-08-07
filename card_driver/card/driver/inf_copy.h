/********************************************
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#ifndef SPHCS_INF_COPY_H
#define SPHCS_INF_COPY_H

#include <linux/kref.h>
#include <linux/hashtable.h>
#include <linux/spinlock.h>
#include <linux/dma-buf.h>
#include <linux/list.h>
#include "inf_devres.h"
#include "sphcs_sw_counters.h"

struct inf_copy {
	void                 *magic;
	struct kref           ref;
	uint16_t              protocolID;
	struct inf_devres    *devres;
	struct inf_context   *context;
	bool                  card2Host;
	bool                  active;

	dma_addr_t  lli_addr;
	int         lli_size;
	void       *lli_buf;

	struct sph_sw_counters *sw_counters;

	struct hlist_node hash_node;
	struct work_struct  work;
	bool destroyed;
	u64 min_block_time;
	u64 max_block_time;
	u64 min_exec_time;
	u64 max_exec_time;
	u64 min_hw_exec_time;
	u64 max_hw_exec_time;

#ifdef _DEBUG
	// store the size (bytes) of host resource for
	// size validations during copy execution
	uint64_t    hostres_size;
#endif
};

int inf_copy_create(uint16_t protocolCopyID, struct inf_context *context, struct inf_devres *devres, uint64_t hostDmaAddr, bool card2Host,
		    struct inf_copy **out_copy);

void inf_copy_get(struct inf_copy *copy);
int inf_copy_put(struct inf_copy *copy);

int inf_copy_sched(struct inf_copy *copy, size_t size, uint8_t priority);
bool inf_copy_req_ready(struct inf_exec_req *copy_req);
int inf_copy_req_execute(struct inf_exec_req *copy_req);
void inf_copy_req_complete(struct inf_exec_req *copy_req, int err, u32 xferTimeUS);

/* This function should not be called directly, use inf_exec_req_put instead */
void inf_copy_req_release(struct kref *kref);

#endif
