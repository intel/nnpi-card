/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#ifndef _SPHCS_INF_EXEC_REQ_H
#define _SPHCS_INF_EXEC_REQ_H

#include <linux/kref.h>
#include <linux/spinlock.h>
#include "inf_context.h"
#include "inf_devres.h"
#include "inf_copy.h"
#include "inf_cpylst.h"
#include "inf_req.h"
#include "inf_cmd_list.h"
#include "inf_types.h"

enum EXEC_REQ_READINESS {
	EXEC_REQ_READINESS_NOT_READY = 0,
	EXEC_REQ_READINESS_READY_NO_DIRTY_INPUTS = 1,
	EXEC_REQ_READINESS_READY_HAS_DIRTY_INPUTS = 2
};

struct func_table {
	int (*schedule)(struct inf_exec_req *req);
	/* Returns: 0 - not ready, 1 - ready, no dirty inputs, 2 - ready, has dirty inputs */
	enum EXEC_REQ_READINESS (*is_ready)(struct inf_exec_req *req);
	int (*execute)(struct inf_exec_req *req);
	void (*send_report)(struct inf_exec_req *req,
			    enum event_val       event_val);
	void (*complete)(struct inf_exec_req *req,
			 int                  err,
			 const void          *error_msg,
			 int32_t              error_msg_size);
	int (*obj_put)(struct inf_exec_req *req);
	int (*migrate_priority)(struct inf_exec_req *req, uint8_t priority);
	void (*treat_req_failure)(struct inf_exec_req *req,
				  enum event_val       event_val,
				  const void          *error_msg,
				  int32_t              error_msg_size);

	/* This function should not be called directly, use inf_exec_req_put instead */
	void (*release)(struct kref *kref);
};

struct inf_exec_req {
	bool                      in_progress;
	enum CmdListCommandType   cmd_type;
	spinlock_t                lock_irq;
	struct kref               in_use;
	struct inf_req_sequence   seq;
	u64                       time; // queued or start execute time

	struct inf_context *context;
	u32                 last_sched_tick;

	struct inf_cmd_list *cmd;
	struct func_table const *f;

	size_t               size;
	//priority 0 == normal, 1 == high
	uint8_t              priority;

	union {
		struct {
			struct inf_cpylst *cpylst;
			struct lli_desc   *lli;
			uint16_t           num_opt_depend_devres;
			struct inf_devres **opt_depend_devres;
		};
		struct {
			struct inf_copy *copy;
			struct inf_devres *depend_devres;

			/* following fields are used for "dynamic copy" only */
			struct sphcs_hostres_map *hostres_map;
			uint64_t devres_offset;
		};
		struct {
			struct inf_req   *infreq;
			uint16_t          i_num_opt_depend_devres;
			uint16_t          o_num_opt_depend_devres;
			struct inf_devres **i_opt_depend_devres;
			struct inf_devres **o_opt_depend_devres;
			bool              sched_params_is_null;
			uint8_t           debugOn : 1;
			uint8_t           collectInfo : 1;
			uint8_t           reserved : 6;
		};
	};
};

void inf_req_try_execute(struct inf_exec_req *req);

int inf_exec_req_get(struct inf_exec_req *req);
int inf_exec_req_put(struct inf_exec_req *req);

int inf_update_priority(struct inf_exec_req *req,
			uint8_t priority,
			bool card2host,
			dma_addr_t lli_addr);

void inf_exec_error_list_init(struct inf_exec_error_list *error_list,
			      struct inf_context         *context);

void inf_exec_error_list_fini(struct inf_exec_error_list *error_list);

void inf_exec_error_list_add(struct inf_exec_error_list    *error_list,
			     struct inf_exec_error_details *err);

int inf_exec_error_details_alloc(enum CmdListCommandType cmd_type,
				 uint16_t                obj_id,
				 uint16_t                devnet_id,
				 uint16_t                event_val,
				 int32_t                 error_msg_size,
				 struct inf_exec_error_details **out_err);

int inf_exec_error_list_buffer_pack(struct inf_exec_error_list *error_list,
				    void            **out_buffer,
				    uint16_t         *out_buffer_size);

void inf_exec_error_list_clear(struct inf_exec_error_list *error_list,
			       struct inf_cmd_list        *cmdlist);

void inf_exec_error_list_devnet_reset_done(struct inf_exec_error_list *error_list,
					   uint16_t                    devnet_id,
					   struct inf_cmd_list        *cmdlist,
					   bool                        failed);
#endif
