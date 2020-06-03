/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#ifndef _SPHCS_INF_CONTEXT_H
#define _SPHCS_INF_CONTEXT_H

#include <linux/kref.h>
#include <linux/spinlock.h>
#include <linux/hashtable.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/idr.h>
#include <linux/workqueue.h>
#include <linux/atomic.h>
#include "ipc_protocol.h"
#include "inf_devres.h"
#include "inf_cmd_list.h"
#include "inf_devnet.h"
#include "inf_cmdq.h"
#include "inf_types.h"
#include "sphcs_cs.h"
#include "sphcs_sw_counters.h"
#include "sphcs_cmd_chan.h"
#include "inf_exec_req.h"

struct nnp_device;

enum context_state {
	CONTEXT_STATE_MIN = 0,
	CONTEXT_OK = CONTEXT_STATE_MIN,
	CONTEXT_BROKEN_RECOVERABLE = 1,
	CONTEXT_BROKEN_NON_RECOVERABLE = 2,
	CONTEXT_STATE_MAX = CONTEXT_BROKEN_NON_RECOVERABLE
};

struct inf_context {
	void              *magic;
	struct kref        ref;
	uint16_t           protocol_id;
	uint64_t           user_handle;
	struct hlist_node  hash_node;
	struct sphcs_cmd_chan *chan;

	spinlock_t         lock;
	spinlock_t         sync_lock_irq;
	spinlock_t         sw_counters_lock_irq;
	int                attached;
	int                destroyed;
	bool               runtime_detach_sent;
	DECLARE_HASHTABLE(cmd_hash, 6);
	DECLARE_HASHTABLE(devres_hash, 6);
	DECLARE_HASHTABLE(devnet_hash, 6);
	DECLARE_HASHTABLE(copy_hash, 6);

	struct list_head     sync_points;
	struct list_head     active_seq_list;
	wait_queue_head_t    sched_waitq;
	u32                  next_seq_id;
	atomic_t             sched_tick;
	u32                  num_optimized_cmd_lists;

	struct inf_exec_error_list error_list;

	struct inf_cmd_queue cmdq;

	struct nnp_sw_counters *sw_counters;
	u64                 runtime_busy_starttime;
	u32                 infreq_counter;
	uint64_t            counters_cb_data_handler;

	enum context_state state;
	struct kmem_cache *exec_req_slab_cache;
	bool daemon_ref_released;
};

struct inf_sync_point {
	struct list_head node;
	u32              seq_id;
	u16              host_sync_id;
};

int inf_context_create(uint16_t             protocol_id,
		       struct sphcs_cmd_chan *chan,
		       struct inf_context **out_context);

int inf_context_runtime_attach(struct inf_context *context);

void inf_context_runtime_detach(struct inf_context *context);

int is_inf_context_ptr(void *ptr);

void inf_context_destroy_objects(struct inf_context *context);
int inf_context_get(struct inf_context *context);
int inf_context_put(struct inf_context *context);

void inf_context_seq_id_init(struct inf_context      *context,
			     struct inf_req_sequence *seq);

void inf_context_seq_id_fini(struct inf_context      *context,
			     struct inf_req_sequence *seq);

void del_all_active_create_and_inf_requests(struct inf_context *context);

void inf_context_set_state(struct inf_context *context,
			   enum context_state  state);

enum context_state inf_context_get_state(struct inf_context *context);

void inf_context_add_sync_point(struct inf_context *context,
				u16                 host_sync_id);

int inf_context_create_devres(struct inf_context *context,
			      uint16_t            protocol_id,
			      uint64_t            byte_size,
			      uint8_t             depth,
			      uint64_t            align,
			      uint32_t            usage_flags,
			      struct inf_devres **out_devres);

int inf_context_find_and_destroy_devres(struct inf_context *context,
					uint16_t            devresID);
struct inf_devres *inf_context_find_devres(struct inf_context *context,
					   uint16_t            protocol_id);
struct inf_devres *inf_context_find_and_get_devres(struct inf_context *context,
						   uint16_t            protocol_id);
int inf_context_create_cmd(struct inf_context   *context,
			   uint16_t              protocol_id,
			   struct inf_cmd_list **out_devres);

int inf_context_find_and_destroy_cmd(struct inf_context *context,
				     uint16_t            cmdID);
struct inf_cmd_list *inf_context_find_cmd(struct inf_context *context,
					  uint16_t            protocol_id);

int inf_context_find_and_destroy_devnet(struct inf_context *context,
					uint16_t            devnetID);
struct inf_devnet *inf_context_find_devnet(struct inf_context *context,
					   uint16_t            protocol_id);
struct inf_devnet *inf_context_find_and_get_devnet(struct inf_context *context,
						   uint16_t            protocol_id,
						   bool                alive,
						   bool                created);

struct inf_copy *inf_context_find_copy(struct inf_context *context, uint16_t protocol_id);
struct inf_copy *inf_context_find_and_get_copy(struct inf_context *context, uint16_t protocol_id);

void destroy_copy_on_create_failed(struct inf_copy *copy);
int inf_context_find_and_destroy_copy(struct inf_context *context,
				      uint16_t            copyID);
#endif
