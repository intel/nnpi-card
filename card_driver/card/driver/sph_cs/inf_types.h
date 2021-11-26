/********************************************
 * Copyright (C) 2019-2021 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/
#ifndef _SPHCS_INF_TYPES_H
#define _SPHCS_INF_TYPES_H

#include <linux/list.h>
#include <linux/spinlock.h>
#include "nnp_types.h"
#include "ipc_chan_protocol.h"

struct inf_req_sequence {
	u32              seq_id;
	struct list_head node;
};

enum create_status {
	CREATE_STARTED	= 0,
	DMA_COMPLETED	= 1,
	CREATED		= 2
};

struct inf_exec_error_details {
	struct list_head        node;
	enum CmdListCommandType cmd_type;
	uint16_t                obj_id;
	uint16_t                devnet_id;
	uint16_t                event_val;
	uint32_t                error_msg_size;
	void                   *error_msg;
};

struct inf_context;

struct inf_exec_error_list {
	struct list_head    list;
	struct inf_context *context;
	uint16_t            cmdlist_id;
	bool                is_cmdlist;
	spinlock_t          lock;
	bool                need_card_reset;
	bool                clear_started;

	uint16_t           *failed_devnets;
	uint16_t            num_failed_devnets;
};
#endif
