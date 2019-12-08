/********************************************
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

/**
 * @file sph_types.h
 *
 * @brief Header file defining sph hwtrace types
 *
 * This header file defines common types used in the sph hwtrace interface library.
 *
 */


#ifndef _SPHCS_HWTRACE_H
#define _SPHCS_HWTRACE_H


#include "sph_types.h"
#include <linux/kernel.h>
#include "ipc_protocol.h"
#include "ipc_chan_protocol.h"
#include <linux/wait.h>

#define HWTRACING_POOL_MEMORY_SIZE ((uint32_t)(1U<<20))
#define SPHCS_HWTRACING_MAX_POOL_LENGTH 10


struct sphcs;
struct device;

struct sphcs_hwtrace_mem_pool {
	struct page	*pages;
	uint32_t	used;
};

struct sphcs_hwtrace_data {
	struct list_head	dma_stream_list;
	struct sphcs_cmd_chan	*chan;
	uint32_t		host_resource_count;
	uint32_t		hwtrace_status;
	uint32_t		nr_pool_pages;
	struct device		*intel_th_device;
	struct sphcs_hwtrace_mem_pool mem_pool[SPHCS_HWTRACING_MAX_POOL_LENGTH];
	wait_queue_head_t waitq;
	struct workqueue_struct *cmd_wq;
	spinlock_t lock_irq;
};

void *intel_th_assign_mode(struct device *intel_th_dev, int *mode);

void intel_th_unassign(void *priv);

int intel_th_alloc_window(void *priv, struct sg_table **sgt, size_t size);

void intel_th_free_window(void *priv, struct sg_table *sgt);

void intel_th_activate(void *priv);

void intel_th_deactivate(void *priv);

int intel_th_window_ready(void *priv, struct sg_table *sgt, size_t bytes);

void hwtrace_init_debugfs(struct sphcs_hwtrace_data *hw_tracing,
				struct dentry *parent,
				const char    *dirname);

void IPC_OPCODE_HANDLER(CHAN_HWTRACE_ADD_RESOURCE)(struct sphcs *sphcs,
						     union h2c_ChanHwTraceAddResource *msg);

void IPC_OPCODE_HANDLER(HWTRACE_ADD_RESOURCE)(struct sphcs *sphcs,
						     union h2c_HwTraceAddResource *msg);

void IPC_OPCODE_HANDLER(CHAN_HWTRACE_STATE)(struct sphcs *sphcs,
					    union h2c_ChanHwTraceState *msg);


void IPC_OPCODE_HANDLER(HWTRACE_STATE)(struct sphcs *sphcs,
					    union h2c_HwTraceState *msg);


#endif //_SPHCS_HWTRACE_H
