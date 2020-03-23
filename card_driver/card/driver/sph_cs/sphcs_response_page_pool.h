/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#ifndef _SPHCS_RESPONSEPOOL_H
#define _SPHCS_RESPONSEPOOL_H

#include "sph_types.h"
#include "sphcs_pcie.h"
#include <linux/device.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>
#include <linux/debugfs.h>
#include "sphcs_dma_sched.h"
#include "dma_page_pool.h"
#include "msg_scheduler.h"
#include "sphcs_sw_counters.h"


struct sphcs_response_page_pool {
	struct list_head  host_response_pages_list;
	spinlock_t        host_response_pages_list_lock_irq;
	wait_queue_head_t hrp_waitq;
	struct msg_scheduler_queue *msg_queue;
};

extern struct sphcs_response_page_pool *g_sphcs_response_pools[];

extern int sphcs_response_pool_get_response_page(uint32_t index, dma_addr_t *out_host_dma_addr, page_handle *out_host_page_hndl);

void IPC_OPCODE_HANDLER(HOST_RESPONSE_PAGES)(struct sphcs *sphcs,
					union h2c_HostResponsePagesMsg *req);

int sphcs_create_response_page_pool(struct msg_scheduler_queue *msg_queue, uint32_t index);
void sphcs_response_pool_clean_page_pool(uint32_t index);
void sphcs_response_pool_destroy_page_pool(uint32_t index);

#endif
