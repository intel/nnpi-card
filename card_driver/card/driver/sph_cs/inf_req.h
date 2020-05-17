/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/
#ifndef _SPHCS_INF_REQ_H
#define _SPHCS_INF_REQ_H

#include <linux/kref.h>
#include <linux/hashtable.h>
#include <linux/spinlock.h>
#include "ioctl_inf.h"
#include "ipc_protocol.h"
#include "inf_types.h"
#include "inf_cmd_list.h"
#include "inf_exec_req.h"
#include "sphcs_sw_counters.h"

struct inf_devnet;
struct inf_devres;
struct inf_exec_req;

struct inf_req {
	void              *magic;
	struct kref        ref;
	uint16_t           protocolID;
	uint64_t           user_handle;
	struct inf_devnet *devnet;
	struct hlist_node  hash_node;
	spinlock_t         lock_irq;

	uint32_t           n_inputs;
	struct inf_devres **inputs;
	uint32_t           n_outputs;
	struct inf_devres **outputs;
	uint32_t           config_data_size;
	void              *config_data;

	struct inf_exec_infreq exec_cmd;
	struct inf_exec_req *active_req;

	dma_addr_t         exec_config_data_dma_addr;
	void              *exec_config_data_vptr;

	enum create_status status;
	// 0 - not destroyed, 1 - destroyed by user, -1 - failed to create
	int                destroyed;

	struct nnp_sw_counters *sw_counters;
	u64                min_block_time;
	u64                max_block_time;
	u64                min_exec_time;
	u64                max_exec_time;
	unsigned int       ptr2id;
};

int inf_req_create(uint16_t            protocolID,
		   struct inf_devnet  *devnet,
		   struct inf_req    **out_infreq);
int inf_req_add_resources(struct inf_req     *infreq,
			  uint32_t            n_inputs,
			  struct inf_devres **inputs,
			  uint32_t            n_outputs,
			  struct inf_devres **outputs,
			  uint32_t            config_data_size,
			  void               *config_data);
void destroy_infreq_on_create_failed(struct inf_req *infreq);

int is_inf_req_ptr(void *ptr);

int inf_req_get(struct inf_req *infreq);
int inf_req_put(struct inf_req *infreq);

void infreq_req_init(struct inf_exec_req *req,
		     struct inf_req *infreq,
		     struct inf_cmd_list *cmd,
		     uint8_t priority,
		     bool sched_params_are_null,
		     uint16_t batchSize,
		     uint8_t debugOn,
		     uint8_t collectInfo);

int infreq_req_sched(struct inf_exec_req *req);
void inf_req_complete(struct inf_exec_req *req,
		      int                  err,
		      const void          *error_msg,
		      int32_t              error_msg_size);

#endif
