/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#include "sphcs_response_page_pool.h"
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/jiffies.h>
#include <linux/workqueue.h>
#include "ipc_protocol.h"
#include "sph_log.h"
#include "sphcs_cs.h"
#include <linux/delay.h>
#include <linux/reboot.h>
#include <linux/version.h>
#include <linux/sched.h>


struct host_response_pages_work {
	struct work_struct work;
	u64 num_of_pages;
	u64 host_pfn;
	uint32_t response_pool_index;
};

struct host_response_pages_entry {
	int                         n_pages;
	int                         next_to_use;
	page_handle                 dma_page_hndl;
	dma_addr_t                  dma_addr;
	void                       *dma_vptr;
	struct list_head            node;
	struct response_list_entry  pages[1];      /* real size depends on n_pages */
};

#define SPHCS_RESPONSE_POOLS_SIZE 1

struct sphcs_response_page_pool *g_sphcs_response_pools[SPHCS_RESPONSE_POOLS_SIZE];

static int sphcs_response_page_list_dma_completed(struct sphcs *sphcs, void *ctx, const void *user_data, int status, u32 timeus)
{
	struct host_response_pages_entry *ent = (struct host_response_pages_entry *)ctx;
	uint32_t *response_pool_index = (uint32_t *)(user_data);
	struct sphcs_response_page_pool *pool;
	unsigned long flags;

	pool = g_sphcs_response_pools[*response_pool_index];

	SPH_ASSERT(pool != NULL);
	if (unlikely(pool == NULL))
		return -EINVAL;

	SPH_ASSERT(ent != NULL);
	if (unlikely(ent == NULL))
		return -EINVAL;

	SPH_ASSERT(ent->dma_vptr != NULL);
	if (unlikely(ent->dma_vptr == NULL))
		return -EINVAL;

	if (status == SPHCS_DMA_STATUS_FAILED) {
		/* dma failed */
		/* return the dma page back to the pool */
		dma_page_pool_set_page_free(sphcs->dma_page_pool, ent->dma_page_hndl);
		kfree(ent);
		/* TODO: send error event to host */
	} else {
		/* if it is not an error - it must be done */
		SPH_ASSERT(status == SPHCS_DMA_STATUS_DONE);

		/* copy the page entries */
		memcpy(&ent->pages[0], ent->dma_vptr, ent->n_pages * sizeof(struct response_list_entry));

		/* return the dma page back to the pool */
		dma_page_pool_set_page_free(sphcs->dma_page_pool, ent->dma_page_hndl);
		ent->dma_vptr = NULL;

		/* add the new entries to the host response pages list */
		SPH_SPIN_LOCK_IRQSAVE(&pool->host_response_pages_list_lock_irq, flags);
		list_add_tail(&ent->node, &pool->host_response_pages_list);
		SPH_SPIN_UNLOCK_IRQRESTORE(&pool->host_response_pages_list_lock_irq, flags);

		wake_up_all(&pool->hrp_waitq);
	}


	return 0;
}

static void process_host_response_pages_message(struct work_struct *work)
{
	struct host_response_pages_entry *ent;
	int rc;
	struct host_response_pages_work *host_response_pages_work;

	host_response_pages_work = container_of(work, struct host_response_pages_work, work);
	if (host_response_pages_work->num_of_pages) {
		ent = kzalloc(sizeof(*ent) + sizeof(struct response_list_entry)*(host_response_pages_work->num_of_pages-1), GFP_KERNEL);
		if (!ent) {
			sph_log_err(SERVICE_LOG, "FAILED to allocate space for response pages list\n");
			/* TODO: send error event to host */
			goto done;
		}

		ent->n_pages = host_response_pages_work->num_of_pages;
		ent->next_to_use = 0;
		INIT_LIST_HEAD(&ent->node);

		/* get dma free page for transferring the list data from host */
		rc = dma_page_pool_get_free_page(g_the_sphcs->dma_page_pool, &ent->dma_page_hndl, &ent->dma_vptr, &ent->dma_addr);
		if (rc) {
			sph_log_err(SERVICE_LOG, "Failed to get free dma page for transfer\n");
			kfree(ent);
			/* TODO: send error event to host */
			goto done;
		}

		/* start the dma transfer */
		sphcs_dma_sched_start_xfer_single(g_the_sphcs->dmaSched,
						  &g_dma_desc_h2c_normal,
						  SPH_IPC_DMA_PFN_TO_ADDR(host_response_pages_work->host_pfn),
						  ent->dma_addr,
						  host_response_pages_work->num_of_pages * sizeof(struct response_list_entry),
						  sphcs_response_page_list_dma_completed,
						  ent,
						  &host_response_pages_work->response_pool_index,
						  sizeof(host_response_pages_work->response_pool_index));

	}
done:
	kfree(host_response_pages_work);
}

void IPC_OPCODE_HANDLER(HOST_RESPONSE_PAGES)(
				struct sphcs *sphcs,
				union h2c_HostResponsePagesMsg *req)
{
	struct host_response_pages_work *host_response_pages_work;

	host_response_pages_work = kmalloc(sizeof(struct host_response_pages_work), GFP_ATOMIC);
	if (!host_response_pages_work) {
		sph_log_err(GENERAL_LOG, "No memory handling host response page\n");
		return;
	}
	host_response_pages_work->host_pfn = req->host_pfn;
	host_response_pages_work->num_of_pages = req->num_pages;
	host_response_pages_work->response_pool_index = req->response_pool_index;
	INIT_WORK(&host_response_pages_work->work, process_host_response_pages_message);

	queue_work(sphcs->wq, &host_response_pages_work->work);
}


int sphcs_create_response_page_pool(struct msg_scheduler_queue *msg_queue, uint32_t index)
{
	struct sphcs_response_page_pool *pool;

	SPH_ASSERT(index < SPHCS_RESPONSE_POOLS_SIZE);
	if (unlikely(index >= SPHCS_RESPONSE_POOLS_SIZE)) {
		sph_log_err(SERVICE_LOG, "index too big");
		return -EINVAL;
	}

	if (g_sphcs_response_pools[index] != NULL) {
		sph_log_err(SERVICE_LOG, "override existing pool");
		return -EFAULT;
	}

	pool = kmalloc(sizeof(struct sphcs_response_page_pool), GFP_KERNEL);
	if (pool == NULL)
		return -ENOMEM;

	pool->msg_queue = msg_queue;

	INIT_LIST_HEAD(&pool->host_response_pages_list);
	spin_lock_init(&pool->host_response_pages_list_lock_irq);
	init_waitqueue_head(&pool->hrp_waitq);

	g_sphcs_response_pools[index] = pool;
	return 0;
}

static void sphcs_clean_host_resp_page_list(uint32_t index)
{
	struct host_response_pages_entry *ent;
	struct sphcs_response_page_pool *pool = g_sphcs_response_pools[index];
	unsigned long flags;

	SPH_ASSERT(index < SPHCS_RESPONSE_POOLS_SIZE);
	if (unlikely(index >= SPHCS_RESPONSE_POOLS_SIZE)) {
		sph_log_err(SERVICE_LOG, "index too big");
		return;
	}

	SPH_ASSERT(pool != NULL);
	if (unlikely(pool == NULL)) {
		sph_log_err(SERVICE_LOG, "no pool in index");
		return;
	}
	SPH_SPIN_LOCK_IRQSAVE(&pool->host_response_pages_list_lock_irq, flags);
	while (!list_empty(&pool->host_response_pages_list)) {
		ent = list_first_entry(&pool->host_response_pages_list,
				       struct host_response_pages_entry, node);
		list_del(&ent->node);
		kfree(ent);
	}
	SPH_SPIN_UNLOCK_IRQRESTORE(&pool->host_response_pages_list_lock_irq, flags);
}

void sphcs_response_pool_clean_page_pool(uint32_t index)
{
	SPH_ASSERT(index < SPHCS_RESPONSE_POOLS_SIZE);
	if (unlikely(index >= SPHCS_RESPONSE_POOLS_SIZE)) {
		sph_log_err(SERVICE_LOG, "index too big");
		return;
	}
	sphcs_clean_host_resp_page_list(index);
}

void sphcs_response_pool_destroy_page_pool(uint32_t index)
{
	struct sphcs_response_page_pool *pool;

	SPH_ASSERT(index < SPHCS_RESPONSE_POOLS_SIZE);
	if (unlikely(index >= SPHCS_RESPONSE_POOLS_SIZE)) {
		sph_log_err(SERVICE_LOG, "index too big");
		return;
	}
	pool = g_sphcs_response_pools[index];

	SPH_ASSERT(pool != NULL);
	if (unlikely(pool == NULL)) {
		sph_log_err(SERVICE_LOG, "no pool in index");
		return;
	}
	sphcs_clean_host_resp_page_list(index);
	kfree(pool);
	g_sphcs_response_pools[index] = NULL;
}

int sphcs_response_pool_get_response_page(uint32_t index, dma_addr_t *out_host_dma_addr, page_handle *out_host_page_hndl)
{
	int ret;
	struct host_response_pages_entry *ent, *ent_to_free = NULL;
	struct sphcs_response_page_pool *pool;
	unsigned long flags;

	SPH_ASSERT(index < SPHCS_RESPONSE_POOLS_SIZE);
	if (unlikely(index >= SPHCS_RESPONSE_POOLS_SIZE)) {
		sph_log_err(SERVICE_LOG, "index too big");
		return -EINVAL;
	}
	pool = g_sphcs_response_pools[index];
	SPH_ASSERT(pool != NULL);
	if (unlikely(pool == NULL)) {
		sph_log_err(SERVICE_LOG, "no pool in index");
		return -EINVAL;
	}

	SPH_SPIN_LOCK_IRQSAVE(&pool->host_response_pages_list_lock_irq, flags);
	if (list_empty(&pool->host_response_pages_list)) {
		ret = -ENOENT;
	} else {
		ent = list_first_entry(&pool->host_response_pages_list, struct host_response_pages_entry, node);
		*out_host_page_hndl = ent->pages[ent->next_to_use].page_hdl;
		*out_host_dma_addr = SPH_IPC_DMA_PFN_TO_ADDR(ent->pages[ent->next_to_use].dma_pfn);

		ent->next_to_use++;
		if (ent->next_to_use >= ent->n_pages) {
			list_del(&ent->node);
			ent_to_free = ent;
		}

		ret = 0;
	}

	SPH_SPIN_UNLOCK_IRQRESTORE(&pool->host_response_pages_list_lock_irq, flags);

	kfree(ent_to_free);

	return ret;
}
