/* SPDX-License-Identifier: GPL-2.0-or-later */

/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 ********************************************/

#ifndef _NNPDRV_INF_PROC_H
#define _NNPDRV_INF_PROC_H

#include <linux/workqueue.h>
#include <linux/kref.h>
#include "idr_allocator.h"
#include "hostres.h"

/**
 * @struct inf_process_info
 * structure to hold per process inference related data
 */
struct inf_process_info {
	struct list_head hostres_list;
	struct kref ref;
	struct completion *close_completion;
	struct mutex lock; /* protects hostres_list modifications */
	struct nnp_proc_idr objects_idr;
	pid_t  pid;
	struct list_head proc_list_node;
};

struct inf_hostres {
	void             *magic;
	struct list_head  node;
	struct kref       ref;
	struct nnpdrv_host_resource   *hostres;
	s32           fd;
	struct inf_process_info *proc_info;
};

void inf_proc_init(struct inf_process_info *proc_info, pid_t curr_pid);

void inf_proc_get(struct inf_process_info *proc_info);
int inf_proc_put(struct inf_process_info *proc_info);

int inf_proc_add_hostres(struct inf_process_info *proc_info,
			 struct nnpdrv_host_resource *hostres,
			 s32 fd,
			 struct inf_hostres **inf_hostres_entry);

bool is_inf_hostres_ptr(void *ptr);
bool inf_hostres_check_and_get(void *ptr);
bool inf_hostres_put(struct inf_hostres *inf_hostres_entry);

void inf_proc_destroy_all(struct inf_process_info *proc_info);

#endif
