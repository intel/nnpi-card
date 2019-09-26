/********************************************
 * Copyright (C) 2019 Intel Corporation
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
#include "ipc_protocol.h"
#include "inf_devres.h"
#include "inf_devnet.h"
#include "inf_cmdq.h"
#include "inf_types.h"
#include "sphcs_cs.h"
#include "sphcs_sw_counters.h"

struct sph_device;
struct inf_subres_load_session;

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
	uint16_t           protocolID;
	struct hlist_node  hash_node;

	spinlock_t         lock;
	spinlock_t         sync_lock_irq;
	spinlock_t         sw_counters_lock_irq;
	int                attached;
	int                destroyed;
	DECLARE_HASHTABLE(devres_hash, 6);
	DECLARE_HASHTABLE(devnet_hash, 6);
	DECLARE_HASHTABLE(copy_hash, 6);

	struct workqueue_struct *wq;
	struct list_head     sync_points;
	struct list_head     active_seq_list;
	u32                  next_seq_id;

	struct inf_cmd_queue cmdq;

	struct list_head subresload_sessions;

	struct sph_sw_counters *sw_counters;
	u64                 runtime_busy_starttime;
	u32                 infreq_counter;
	uint64_t            counters_cb_data_handler;

	enum context_state state;
	struct kmem_cache *exec_req_slab_cache;
};

struct inf_subres_load_session {
	uint16_t             sessionID;
	struct inf_devres *devres;

	dma_addr_t lli_addr;
	int lli_size;
	void *lli_buf;

	int                lli_space_need_wake;
	wait_queue_head_t  lli_waitq;

	struct list_head lli_space_list;
	spinlock_t       lock;

	struct list_head node;
};

struct inf_exec_req {
	bool                      in_progress;
	bool                      is_copy;
	spinlock_t                lock_irq;
	struct kref               in_use;
	struct inf_req_sequence   seq;
	u64                       time; // queued or start execute time

	union {
		struct inf_copy  *copy;
		struct inf_req   *infreq;
	};

	size_t            size;

	/* following fields are used only by infer exec req */
	/* priority field in sched_params is used for copy priority */
	struct inf_sched_params   sched_params;
	bool              sched_params_is_null;
};

int inf_context_create(uint16_t             protocolID,
		       struct inf_context **out_context);

int inf_context_runtime_attach(struct inf_context *context);

void inf_context_runtime_detach(struct inf_context *context);

int is_inf_context_ptr(void *ptr);

void inf_context_remove_objects(struct inf_context *context);
void inf_context_get(struct inf_context *context);
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
			      uint16_t            protocolID,
			      uint64_t            byte_size,
			      uint8_t             depth,
			      uint32_t            usage_flags,
			      struct inf_devres **out_devres);

int inf_context_find_and_destroy_devres(struct inf_context *context,
					uint16_t            devresID);
struct inf_devres *inf_context_find_devres(struct inf_context *context,
					   uint16_t            protocolID);

int inf_context_create_devnet(struct inf_context *context,
			      uint16_t protocolID,
			      struct inf_devnet **out_devnet);
int inf_context_find_and_destroy_devnet(struct inf_context *context,
					uint16_t            devnetID);
struct inf_devnet *inf_context_find_devnet(struct inf_context *context,
					   uint16_t            protocolID);

struct inf_copy *inf_context_find_copy(struct inf_context *context, uint16_t protocolID);

void destroy_copy_on_create_failed(struct inf_copy *copy);
int inf_context_find_and_destroy_copy(struct inf_context *context,
				      uint16_t            copyID);

void inf_req_try_execute(struct inf_exec_req *req);

struct inf_subres_load_session *inf_context_create_subres_load_session(struct inf_context *context,
								       struct inf_devres *devres,
								       union h2c_SubResourceLoadCreateRemoveSession *cmd);

struct inf_subres_load_session *inf_context_get_subres_load_session(struct inf_context *context, uint16_t sessionID);

void inf_context_remove_subres_load_session(struct inf_context *context, uint16_t sessionID);

int inf_exec_req_get(struct inf_exec_req *req);
int inf_exec_req_put(struct inf_exec_req *req);

#endif
