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


#include <linux/module.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/interrupt.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>
#include <linux/scatterlist.h>
#include <linux/sort.h>
#include <linux/spinlock.h>
#include <linux/dma-buf.h>
#include <linux/intel_th.h>

#include "sph_hwtrace_protocol.h"
#include "sphcs_hwtrace.h"
#include "sphcs_intel_th.h"
#include "sphcs_cs.h"
#include "sph_log.h"
#include "sph_debug.h"

struct msu_buffer_driver g_msu = {"sph_hwtrace",
	NULL,
	intel_th_assign_mode,
	intel_th_unassign,
	intel_th_alloc_window,
	intel_th_free_window,
	intel_th_activate,
	intel_th_deactivate,
	intel_th_window_ready};

void sphcs_assign_intel_th_mode(int *mode)
{
	*mode = MSC_MODE_MULTI;
}

int sphcs_init_th_driver(void)
{
	struct sphcs_hwtrace_data *hw_tracing = &g_the_sphcs->hw_tracing;
	int ret = 0;

	g_msu.owner = THIS_MODULE;
	hw_tracing->hwtrace_status = SPHCS_HWTRACE_NOT_SUPPORTED;

	ret = intel_th_msu_buffer_register(&g_msu);
	if (ret) {
		sph_log_err(HWTRACE_LOG, "unable to register intel_th service - err %d", ret);
		return ret;
	}

	hw_tracing->hwtrace_status = SPHCS_HWTRACE_REGISTERED;

	init_waitqueue_head(&hw_tracing->waitq);
	spin_lock_init(&hw_tracing->lock_irq);
	INIT_LIST_HEAD(&(hw_tracing->dma_stream_list));
	hw_tracing->host_resource_count = 0;
	return ret;
}

void sphcs_deinit_th_driver(void)
{
	intel_th_msu_buffer_unregister(&g_msu);
}


void sphcs_intel_th_window_unlock(struct device *dev, struct sg_table *sgt)
{
	intel_th_msc_window_unlock(dev, sgt);
}




