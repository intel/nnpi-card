/********************************************
 * Copyright (C) 2019 Intel Corporation
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
#include "sphcs_sw_counters.h"

struct inf_devnet;
struct inf_devres;
struct inf_exec_req;

struct inf_req {
	void              *magic;
	struct kref        ref;
	uint16_t           protocolID;
	struct inf_devnet *devnet;
	struct hlist_node  hash_node;
	spinlock_t         lock_irq;

	uint32_t           n_inputs;
	struct inf_devres **inputs;
	uint32_t           n_outputs;
	struct inf_devres **outputs;
	uint32_t           config_data_size;
	uint32_t           max_exec_config_size;
	void              *config_data;

	struct inf_exec_infreq exec_cmd;
	struct inf_exec_req *active_req;

	dma_addr_t         exec_config_data_dma_addr;
	void              *exec_config_data_vptr;
	bool               exec_config_data_empty;

	enum create_status status;
	// 0 - not destroyed, 1 - destroyed by user, -1 - failed to create
	int                destroyed;

	struct sph_sw_counters *sw_counters;
	u64                min_block_time;
	u64                max_block_time;
	u64                min_exec_time;
	u64                max_exec_time;
};

int inf_req_create(uint16_t            protocolID,
		   struct inf_devnet  *devnet,
		   uint16_t            max_exec_config_size,
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

void inf_req_get(struct inf_req *infreq);
int inf_req_put(struct inf_req *infreq);

int inf_req_schedule(struct inf_req *infreq,
		     union h2c_InferenceReqSchedule *cmd);
bool inf_req_ready(struct inf_exec_req *req);
int inf_req_execute(struct inf_exec_req *req);
void inf_req_complete(struct inf_exec_req *req, int err);
void inf_req_release(struct inf_exec_req *req);

#endif
