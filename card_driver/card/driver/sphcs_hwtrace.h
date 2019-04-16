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
#include <linux/wait.h>


struct sphcs;
struct sphcs_hwtrace_res_inf;
struct device;
struct sphcs_dma_res_info;

struct sphcs_hwtrace_data {
	struct list_head	dma_stream_list;
	uint32_t		host_resource_count;
	uint32_t		hwtrace_status;
	struct device		*intel_th_device;
	wait_queue_head_t waitq;
	spinlock_t lock_irq;
};

void *intel_th_assign_mode(struct device *intel_th_dev, int *mode);

void intel_th_unassign(void *priv);

int intel_th_alloc_window(void *priv, struct sg_table **sgt, size_t size);

void intel_th_free_window(void *priv, struct sg_table *sgt);

void intel_th_activate(void *priv);

void intel_th_deactivate(void *priv);

int intel_th_window_ready(void *priv, struct sg_table *sgt, size_t bytes);

void IPC_OPCODE_HANDLER(HWTRACE_ADD_RESOURCE)(struct sphcs *sphcs,
						     union h2c_HwTraceAddResource *msg);

void IPC_OPCODE_HANDLER(HWTRACE_STATE)(struct sphcs *sphcs,
					    union h2c_HwTraceState *msg);


#endif //_SPHCS_HWTRACE_H
