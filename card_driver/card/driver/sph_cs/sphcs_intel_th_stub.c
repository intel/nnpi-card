/********************************************
 * Copyright (C) 2019-2021 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>
#include <linux/spinlock.h>

#include "nnp_hwtrace_protocol.h"
#include "sphcs_hwtrace.h"
#include "sphcs_cs.h"

void sphcs_assign_intel_th_mode(int *mode)
{
}


int sphcs_init_th_driver(void)
{
	struct sphcs_hwtrace_data *hw_tracing = &g_the_sphcs->hw_tracing;

	hw_tracing->hwtrace_status = NNPCS_HWTRACE_NOT_SUPPORTED;

	init_waitqueue_head(&hw_tracing->waitq);
	spin_lock_init(&hw_tracing->lock_irq);
	INIT_LIST_HEAD(&(hw_tracing->dma_stream_list));
	hw_tracing->host_resource_count = 0;

	return 0;
}

void sphcs_deinit_th_driver(void)
{
}


void sphcs_intel_th_window_unlock(struct device *dev, struct sg_table *sgt)
{
}


