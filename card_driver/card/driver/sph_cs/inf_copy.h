/********************************************
 * Copyright (C) 2019-2021 Intel Corporation
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
#include "inf_cmd_list.h"
#include "sphcs_sw_counters.h"
#include "sphcs_pcie.h"

struct inf_copy {
	void                 *magic;
	struct kref           ref;
	uint16_t              protocol_id;
	uint64_t              user_handle;
	struct inf_devres    *devres;
	struct inf_context   *context;
	bool                  card2Host;
	bool                  subres_copy;
	bool                  active;


	struct sg_table host_sgt;
	struct lli_desc lli;
	struct sphcs_dma_multi_xfer_handle multi_xfer_handle;

	struct nnp_sw_counters *sw_counters;

	struct hlist_node hash_node;
	struct work_struct  work;
	int destroyed;
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

	bool d2d;
};

int inf_d2d_copy_create(union h2c_ChanInferenceCopyOp *cmd,
			struct inf_context *context,
			struct inf_devres *devres,
			struct inf_copy **out_copy);

int inf_copy_create(union h2c_ChanInferenceCopyOp *cmd,
		    struct inf_context *context,
		    struct inf_devres  *devres,
		    struct inf_copy   **out_copy);

int inf_copy_get(struct inf_copy *copy);
int inf_copy_put(struct inf_copy *copy);

void inf_copy_req_init(struct inf_exec_req *req,
			struct inf_copy *copy,
			struct inf_cmd_list *cmd,
			size_t size,
			uint8_t priority);
int inf_copy_req_init_subres_copy(struct inf_exec_req *req,
				  struct inf_copy *copy,
				  uint16_t hostres_map_id,
				  uint64_t devres_offset,
				  size_t size);

struct sg_table *inf_copy_src_sgt(struct inf_copy *copy);
struct sg_table *inf_copy_dst_sgt(struct inf_copy *copy);

int inf_copy_req_sched(struct inf_exec_req *req);

#endif
