/********************************************
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#include "dma_page_pool.h"
#include <linux/slab.h>
#include <linux/err.h>
#include <linux/interrupt.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/spinlock.h>
#include <linux/seq_file.h>
#include "sph_debug.h"
#include "sph_log.h"

/* Size of the free pages' list, which is sent to device */
#define LIST_SIZE (MAX_HOST_RESPONSE_PAGES - MIN_HOST_RESPONSE_PAGES)

/* Theoretical maximum size of the table, limited by index size */
#define HASH_TABLE_MAX_SIZE	 (1 << PAGE_HANDLE_BITS)
#define PAGE_ID_MASK		 (HASH_TABLE_MAX_SIZE - 1)

enum page_state {
	p_null = 0,
	p_free = 1,
	p_sent = 2,
	p_full = 3
};

#define STATE2STATE(state, from, to)		\
	do {					\
		SPH_ASSERT((state) == (from));	\
		(state) = (to);			\
	} while (0)

struct dma_page {
	struct list_head  node;
	void		 *vaddr;
	dma_addr_t	  dma_addr;
	enum page_state	  state;
};

struct dma_page_pool {
	struct device	 *dev;
	struct list_head  free_pool;
	unsigned int	  free_page_count;
	struct list_head  null_pool;
	unsigned int	  null_page_count;
	unsigned int	  sent_page_count;
	unsigned int	  full_page_count;
	struct dma_page	 *hash_table;
	unsigned int	  ht_size;
	bool		  is_response_pool;
	unsigned int	  unused_page_count;  //Minimum of unused pages, since last deallocation
	wait_queue_head_t free_waitq;
	spinlock_t	  lock;

	//for response pool only
	struct response_list_entry	*list;
	dma_addr_t			 list_dma;
	send_free_pages_cb		 send_free_pages_list_cb;
	void				*ctx;
	struct workqueue_struct		*send_free_wq;
	struct work_struct		 send_free_work;
	unsigned int			 cb_failures;
};

//Static asserts
SPH_STATIC_ASSERT(SPH_IPC_DMA_ADDR_ALIGN_MASK >= PAGE_ID_MASK,
"page_handle doesn't fit to be set in alignment bits");

SPH_STATIC_ASSERT(sizeof(page_handle) == 1, "page_handle is not 8bit size");

//response asserts
SPH_STATIC_ASSERT(MIN_HOST_RESPONSE_PAGES < LIST_SIZE,
"response list size is not big enough");

SPH_STATIC_ASSERT(SPH_PAGE_SIZE / sizeof(struct response_list_entry) >= LIST_SIZE,
"response list doesn't fit in 1 page");


/* Return free pages to the pool */
static void return_free_pages_to_pool(struct dma_page_pool *p, struct list_head *free_pages)
{
	int count = 0;
	struct dma_page *page;

	SPH_ASSERT(p != NULL);
	SPH_ASSERT(free_pages != NULL);

	if (list_empty(free_pages))
		return;

	sph_log_debug(SERVICE_LOG, "Return free pages back to pool: %u)\n", p->free_page_count);
	list_for_each_entry(page, free_pages, node) {
		page->state = p_free;
		++count;
	}

	SPH_SPIN_LOCK(&p->lock);
	list_splice(free_pages, &p->free_pool);
	p->free_page_count += count;
	SPH_SPIN_UNLOCK(&p->lock);

	// wake up clients waiting for a free page
	wake_up_all(&p->free_waitq);
}

/* Allocate if needed and extract n free pages from the pool,	  */
/* return number of pages extracted or negative error code	  */
static int extract_free_pages_from_pool(struct dma_page_pool *p,
					bool for_send,
					unsigned int min,
					unsigned int wanted,
					struct list_head *free_pages)
{
	struct dma_page *pg;
	struct list_head *pos;
	LIST_HEAD(alloced);
	LIST_HEAD(candidates);
	unsigned int i, j;
	unsigned int reserve = 0;

	SPH_ASSERT(p != NULL);
	SPH_ASSERT(free_pages != NULL);
	SPH_ASSERT(min <= wanted);

	if (unlikely(wanted == 0))
		return 0;


	SPH_SPIN_LOCK(&p->lock);

	// see related computations at dma_page_pool_get_free_page function
	if (p->is_response_pool && !for_send &&
	    p->sent_page_count < 2 * MIN_HOST_RESPONSE_PAGES + 1)
		reserve = 2 * MIN_HOST_RESPONSE_PAGES + 1 - p->sent_page_count;

	// Not enough pages
	if ((p->free_page_count + p->null_page_count) < (min + reserve)) {
		SPH_SPIN_UNLOCK(&p->lock);

		sph_log_debug(SERVICE_LOG, "The pool is full! %u pages cannot be extracted\n", min);
		return -EXFULL;
	}

	// Try to extract all need pages from allocated free ones
	for (i = 0, pos = p->free_pool.next;
		 i < wanted && pos != &p->free_pool;
		 ++i, pos = pos->next) {

		SPH_ASSERT(list_entry(pos, struct dma_page, node)->state == p_free);
	}
	list_cut_position(free_pages, &p->free_pool, pos->prev);
	p->free_page_count -= i;

	//Observe usage for deallocation purposes
	if (p->unused_page_count > p->free_page_count)
		p->unused_page_count = p->free_page_count;


	// Try to extract the rest pages from unallocated ones
	for (j = 0, pos = p->null_pool.next;
		 j < wanted - i && pos != &p->null_pool;
		 ++j, pos = pos->next) {

		SPH_ASSERT(list_entry(pos, struct dma_page, node)->state == p_null);
	}
	list_cut_position(&candidates, &p->null_pool, pos->prev);
	p->null_page_count -= j;

#ifdef _DEBUG
	// if hash table is full
	if (i + j < wanted) {
		sph_log_debug(SERVICE_LOG, "The pool is full!\n"
			"Only %u free pages extracted and %u pages to be alloced\n", i, j);
		SPH_ASSERT(list_empty(&p->free_pool));
		SPH_ASSERT(list_empty(&p->null_pool));
	}
#endif

	SPH_SPIN_UNLOCK(&p->lock);


	// Allocate DMA addresses for each null page
	list_for_each_entry(pg, &candidates, node) {

		SPH_ASSERT(pg->vaddr == NULL);
		pg->vaddr = dma_alloc_coherent(p->dev,
					       SPH_PAGE_SIZE,
					       &pg->dma_addr,
					       GFP_KERNEL);
		if (unlikely(pg->vaddr == NULL))
			break;

		sph_log_debug(SERVICE_LOG, "dma page pool page alloced.fpc: %d, upc: %d, spc: %d\n",
				p->free_page_count, p->unused_page_count, p->sent_page_count);

#ifdef _DEBUG
		// SECURITY?
		memset(pg->vaddr, 0xcc, SPH_PAGE_SIZE);
#endif

		// Check that 4K aligned dma_addr can fit 45 bit pfn
		SPH_ASSERT(SPH_IPC_DMA_PFN_TO_ADDR(SPH_IPC_DMA_ADDR_TO_PFN(pg->dma_addr)) == pg->dma_addr);

		++i;
		--j;
	}

	list_cut_position(&alloced, &candidates, pg->node.prev);
	list_splice_tail(&alloced, free_pages);

	// Out of memory
	if (j != 0) {
		SPH_ASSERT(!list_empty(&candidates));
		sph_log_err(SERVICE_LOG, "Out of memory. %u pages cannot be allocated\n", j);

		// Return not allocated pages to null
		SPH_SPIN_LOCK(&p->lock);
		list_splice_tail(&candidates, &p->null_pool);
		p->null_page_count += j;
		SPH_SPIN_UNLOCK(&p->lock);

		if (i < min) {
			sph_log_debug(SERVICE_LOG, "free_page_count too low: %u!\n", i);
			return_free_pages_to_pool(p, free_pages);
			return -ENOMEM;
		}
	} else {
		SPH_ASSERT(list_empty(&candidates));
	}

	return i;
}

/* Prepare the list of free pages from the pool and send to device */
static int send_free_pages_to_device(struct dma_page_pool *p)
{
	struct dma_page *page;
	int err;
	unsigned int i;
	int list_size = LIST_SIZE;
	LIST_HEAD(removed_pages);

	SPH_ASSERT(p != NULL);

	sph_log_debug(SERVICE_LOG, "dma_page_pool allocate %u response pages\n", LIST_SIZE);
	list_size = extract_free_pages_from_pool(p,
						 true,
						 MIN_HOST_RESPONSE_PAGES + 1,
						 LIST_SIZE,
						 &removed_pages);

	//if there are too few free pages, don't send
	if (list_size <= 0) {
		sph_log_debug(SERVICE_LOG, "Not enough pages to send. err=%d\n", list_size);
		return list_size;
	}

	SPH_SPIN_LOCK(&p->lock);

	// already sent
	if (p->sent_page_count > MIN_HOST_RESPONSE_PAGES) {
		SPH_SPIN_UNLOCK(&p->lock);

		sph_log_debug(SERVICE_LOG, "Nothing to do: free pages already sent(sent pages:%u)\n",
			      p->free_page_count);
		return_free_pages_to_pool(p, &removed_pages);
		return 0;
	}

	sph_log_debug(SERVICE_LOG, "Prepare to send %u free pages\n", list_size);
	for (i = 0, page = list_first_entry(&removed_pages, struct dma_page, node);
	     i < list_size;
	     ++i, page = list_next_entry(page, node)) {

		p->list[i].dma_pfn = SPH_IPC_DMA_ADDR_TO_PFN(page->dma_addr);
	//page id
		p->list[i].page_hdl = (page - p->hash_table);
		page->state = p_sent;
	}

#ifdef _DEBUG
	//SECURITY?
	//Zero other entries of the list
	memset(p->list + i, 0xcc, SPH_PAGE_SIZE - sizeof(p->list[0]) * i);
#endif

	p->sent_page_count += list_size;

	//Unlock mutex before sending the pages, because it can be expensive
	SPH_SPIN_UNLOCK(&p->lock);

	sph_log_debug(SERVICE_LOG, "sending the list of free pages: size=%u\n", list_size);
	err = p->send_free_pages_list_cb(p->ctx, p->list_dma, list_size);

	if (unlikely(err < 0)) {
		sph_log_err(SERVICE_LOG, "dma page pool Callback failed with error:%d\n", err);

		SPH_SPIN_LOCK(&p->lock);
		++p->cb_failures;
		sph_log_info(SERVICE_LOG, "dma page pool Callback failed %u times\n", p->cb_failures);
		p->sent_page_count -= list_size;
		SPH_SPIN_UNLOCK(&p->lock);

		return_free_pages_to_pool(p, &removed_pages);
	}

	return err;

} // send_free_pages_to_device

int dma_page_pool_create(struct device *dev, unsigned int max_size, pool_handle *pool)
{
	unsigned int i;
	struct dma_page_pool *p;


	sph_log_info(SERVICE_LOG, "dma page pool: create\n");

	if (unlikely((pool == NULL) || (max_size > HASH_TABLE_MAX_SIZE)))
		return -EINVAL;

	p = kmalloc(sizeof(struct dma_page_pool), GFP_KERNEL);
	if (unlikely(p == NULL))
		return -ENOMEM;

	p->dev = dev;
	sph_log_debug(SERVICE_LOG, "Allocate hash_table\n");
	p->ht_size = max_size;
	p->hash_table = kcalloc(p->ht_size, sizeof(struct dma_page), GFP_KERNEL);
	if (unlikely(p->hash_table == NULL)) {
		kfree(p);
		return -ENOMEM;
	}

	sph_log_debug(SERVICE_LOG, "init null_pool\n");
	INIT_LIST_HEAD(&p->null_pool);
	sph_log_debug(SERVICE_LOG, "create null_pool\n");
	for (i = 0; i < p->ht_size; ++i) {
#ifdef _DEBUG
		p->hash_table[i].vaddr = NULL;
#endif
		p->hash_table[i].state = p_null;
		list_add_tail(&(p->hash_table[i].node), &p->null_pool);
	}
	p->null_page_count = p->ht_size;
	INIT_LIST_HEAD(&p->free_pool);
	p->free_page_count = 0;
	p->full_page_count = 0;
	p->unused_page_count = 0;
	init_waitqueue_head(&p->free_waitq);

	//response related stuff
	p->is_response_pool = false;
	p->sent_page_count = 0;
	p->cb_failures = 0;
#ifdef _DEBUG
	p->list = NULL;
	p->send_free_pages_list_cb = NULL;
	p->ctx = NULL;
	p->send_free_wq = NULL;
#endif

	spin_lock_init(&p->lock);

	*pool = p;
	return 0;
}

static void dma_page_pool_send_free_pages_work(struct work_struct *work)
{
	struct dma_page_pool *pool =
		container_of(work, struct dma_page_pool, send_free_work);

	send_free_pages_to_device(pool);
}

static void reset_response_pages(pool_handle pool)
{
	int i;

	/*
	 * temporary mark the pool as not a response pool
	 * and cancel any repsponse pages send work
	 */
	pool->is_response_pool = false;
	cancel_work_sync(&pool->send_free_work);

	SPH_SPIN_LOCK(&pool->lock);

	/* Move all sent pages to the free list */
	for (i = 0; i < pool->ht_size; ++i) {
		if (pool->hash_table[i].state == p_sent) {
			SPH_ASSERT(pool->sent_page_count > 0);
			--pool->sent_page_count;
			++pool->free_page_count;
			STATE2STATE(pool->hash_table[i].state, p_sent, p_free);
			list_add_tail(&pool->hash_table[i].node,
				      &pool->free_pool);
		}
	}

	SPH_ASSERT(pool->sent_page_count == 0);

	pool->is_response_pool = true;
	SPH_SPIN_UNLOCK(&pool->lock);
}

void dma_page_pool_reset_response_pages(pool_handle pool)
{
	if (pool->is_response_pool)
		reset_response_pages(pool);
}

int dma_page_pool_response_setup(pool_handle pool,
				 send_free_pages_cb cb,
				 void *ctx,
				 struct workqueue_struct *send_wq)
{
	if (unlikely(pool == NULL || cb == NULL))
		return -EINVAL;

	if (unlikely(pool->ht_size < MAX_HOST_RESPONSE_PAGES))
		return -EXFULL;

	if (pool->is_response_pool) {
		/* This is re-setup - move all previously sent pages to free list */
		SPH_ASSERT(pool->list != NULL);
		reset_response_pages(pool);
	} else {
		sph_log_debug(SERVICE_LOG, "Allocate dma page for list\n");
		SPH_ASSERT(pool->list == NULL);
		pool->list = dma_alloc_coherent(pool->dev, SPH_PAGE_SIZE, &pool->list_dma, GFP_KERNEL);
		if (unlikely(pool->list == NULL))
			return -ENOMEM;
	}

	pool->send_free_pages_list_cb = cb;
	pool->ctx = ctx;
	pool->send_free_wq = send_wq;
	INIT_WORK(&pool->send_free_work, dma_page_pool_send_free_pages_work);

	pool->is_response_pool = true;

	send_free_pages_to_device(pool); //send the list for the first time

	return 0;
}

void dma_page_pool_destroy(pool_handle pool)
{
	unsigned int i;

	if (unlikely(pool == NULL))
		return;

	sph_log_info(SERVICE_LOG, "dma page pool: destroy\n");

	if (pool->is_response_pool) {
		sph_log_debug(SERVICE_LOG, "dma page pool: wait for workqueue to finish\n");
		SPH_ASSERT(pool->send_free_wq != NULL);
		flush_workqueue(pool->send_free_wq);

		SPH_ASSERT(pool->list != NULL);
		dma_free_coherent(pool->dev, SPH_PAGE_SIZE, pool->list, pool->list_dma);
	}

	if (unlikely(pool->full_page_count != 0))
		sph_log_err(SERVICE_LOG, "full_page_count is not 0. There are %u full pages.\n",
			    pool->full_page_count);

	for (i = 0; i < pool->ht_size; ++i) {
		if (pool->hash_table[i].state != p_null) {
			SPH_ASSERT(pool->hash_table[i].vaddr != NULL);
			//free allocated page
			dma_free_coherent(pool->dev, SPH_PAGE_SIZE, pool->hash_table[i].vaddr, pool->hash_table[i].dma_addr);
			sph_log_debug(SERVICE_LOG, "dma page deallocated.\n");
		}
	}

	kfree(pool->hash_table);
	kfree(pool);
	sph_log_info(SERVICE_LOG, "dma_page_pool DESTROYED!\n");
}

int dma_page_pool_get_free_page_nowait(pool_handle  pool,
				       page_handle *page,
				       void       **ptr,
				       dma_addr_t  *dma_addr)
{
	struct dma_page *free_page;
	unsigned int min = 0;

	if (unlikely(pool == NULL ||
		     page == NULL ||
		     ptr == NULL  ||
		     dma_addr == NULL))
		return -EINVAL;

	if (pool->is_response_pool)
		min = 2 * MIN_HOST_RESPONSE_PAGES + 1;

	SPH_SPIN_LOCK(&pool->lock);

	//no free pages left
	if (pool->free_page_count +
	    pool->null_page_count +
	    pool->sent_page_count <= min ||
	    pool->free_page_count == 0) {
		SPH_ASSERT(list_empty(&pool->free_pool));

		SPH_SPIN_UNLOCK(&pool->lock);
		return -EXFULL;
	}

	free_page = list_first_entry(&pool->free_pool, struct dma_page, node);
	list_del(&free_page->node);
	--pool->free_page_count;
	++pool->full_page_count;

	//Observe usage for deallocation purposes
	if (pool->unused_page_count > pool->free_page_count)
		pool->unused_page_count = pool->free_page_count;

	SPH_SPIN_UNLOCK(&pool->lock);

	STATE2STATE(free_page->state, p_free, p_full);

	*page = free_page - pool->hash_table;
	*ptr = free_page->vaddr;
	*dma_addr = free_page->dma_addr;
	return 0;
}

int dma_page_pool_get_free_page(pool_handle  pool,
				page_handle *page,
				void       **ptr,
				dma_addr_t  *dma_addr)
{
	int ret;
	LIST_HEAD(free_page_list);
	struct dma_page *free_page;
	unsigned int min = 0;

	if (unlikely(pool == NULL ||
			page == NULL ||
			ptr == NULL  ||
			dma_addr == NULL))
		return -EINVAL;

	/*
	 * In order to prevent deadlock we need to reserve minimum number
	 * of response pages for the card. On the other hand there is no need
	 * to reserve too many pages which may result in slowing down
	 * requests sending.
	 * What we seek is to have at least (2 * MIN_HOST_RESPONSE_PAGES + 1)
	 * amount of pages dedicated for response pages. Each time we send page
	 * to card we increment counter called sent_page_count, and we decrement it
	 * upon receiving a response.
	 * So in order to decide whether to allow extracting free page or not,
	 * we must meet the following condition:
	 * available_pages + sent_page_count >= 2 * MIN_HOST_RESPONSE_PAGES + 1,
	 * which is equal to the below:
	 * free_page_count + null_page_count + sent_page_count > 2 * MIN_HOST_RESPONSE_PAGES + 1
	 * by using such calculation we take into consideration the amount of pages
	 * already sent to the card, before deciding whether to block extracting
	 * free pages or not, and we will not be reserving too many pages
	 * of the host pool for response pages.
	 */
	if (pool->is_response_pool)
		min = 2 * MIN_HOST_RESPONSE_PAGES + 1;
	do {
		ret = wait_event_interruptible(pool->free_waitq,
					       (pool->free_page_count +
						pool->null_page_count) > 0 &&
					       (pool->free_page_count +
						pool->null_page_count +
						pool->sent_page_count > min));
		if (unlikely(ret < 0))
			return -EINTR;

		ret = extract_free_pages_from_pool(pool, false,
						   1, 1, &free_page_list);
	} while (ret == -EXFULL);

	if (unlikely(ret < 0))
		return ret;

	SPH_ASSERT(list_is_singular(&free_page_list));
	free_page = list_first_entry(&free_page_list, struct dma_page, node);
	free_page->state = p_full;

	SPH_SPIN_LOCK(&pool->lock);
	++pool->full_page_count;
	SPH_SPIN_UNLOCK(&pool->lock);

	*page = free_page - pool->hash_table;
	*ptr = free_page->vaddr;
	*dma_addr = free_page->dma_addr;
	return 0;
}

void dma_page_pool_free_page_poll_wait(pool_handle pool,
				       struct file *f,
				       struct poll_table_struct *pt)
{
	poll_wait(f, &pool->free_waitq, pt);
}

int dma_page_pool_set_response_page_full(pool_handle pool, page_handle page)
{
	if (unlikely((pool == NULL) || (page >= pool->ht_size)))
		return -EINVAL;

	SPH_SPIN_LOCK(&pool->lock);

	--pool->sent_page_count;
	++pool->full_page_count;
	STATE2STATE(pool->hash_table[page].state, p_sent, p_full);

	if (pool->is_response_pool &&
	    pool->sent_page_count <= MIN_HOST_RESPONSE_PAGES &&
	    pool->free_page_count + pool->null_page_count > MIN_HOST_RESPONSE_PAGES) {
		queue_work(pool->send_free_wq, &pool->send_free_work);
		sph_log_debug(SERVICE_LOG, "Send free pages triggered.\n");
	}

	SPH_SPIN_UNLOCK(&pool->lock);

	return 0;
}

int dma_page_pool_get_page_pointer(pool_handle pool, page_handle page, const void **p)
{
	if (unlikely((pool == NULL) || (page >= pool->ht_size) || (p == NULL)))
		return -EINVAL;

	if (pool->hash_table[page].state == p_sent)
		dma_page_pool_set_response_page_full(pool, page);

	SPH_ASSERT(pool->hash_table[page].state == p_full);
	*p = pool->hash_table[page].vaddr;
	return 0;
}

int dma_page_pool_get_page_addr(pool_handle pool, page_handle page, dma_addr_t *addr)
{
	if (unlikely((pool == NULL) || (page >= pool->ht_size) || (addr == NULL)))
		return -EINVAL;

	SPH_ASSERT(pool->hash_table[page].state == p_full);
	*addr = pool->hash_table[page].dma_addr;
	return 0;
}

int dma_page_pool_set_page_free(pool_handle pool, page_handle page)
{
	if (unlikely((pool == NULL) || (page >= pool->ht_size)))
		return -EINVAL;

	SPH_SPIN_LOCK(&pool->lock);

	list_add_tail(&pool->hash_table[page].node, &pool->free_pool);
	--pool->full_page_count;
	++pool->free_page_count;
	STATE2STATE(pool->hash_table[page].state, p_full, p_free);

#ifdef _DEBUG
	//SECURITY?
	memset(pool->hash_table[page].vaddr, 0xcc, SPH_PAGE_SIZE);
#endif

	// Do this in case that hash table is full and
	// there were not enough free pages to send
	// In this case we are waiting for full pages to be freed.
	if (pool->is_response_pool &&
	    pool->sent_page_count <= MIN_HOST_RESPONSE_PAGES &&
	    pool->free_page_count + pool->null_page_count > MIN_HOST_RESPONSE_PAGES) {
		queue_work(pool->send_free_wq, &pool->send_free_work);
		sph_log_debug(SERVICE_LOG, "Send free pages triggered.\n");
	}

	SPH_SPIN_UNLOCK(&pool->lock);

	// wake up clients waiting for a free page
	wake_up_all(&pool->free_waitq);

	return 0;
}

int dma_page_pool_get_stats(pool_handle pool, struct dma_pool_stat *stat)
{

	if (unlikely(pool == NULL || stat == NULL))
		return -EINVAL;

	SPH_SPIN_LOCK(&pool->lock);

	stat->free_pages  = pool->free_page_count;
	stat->sent_pages  = pool->sent_page_count;
	stat->full_pages  = pool->full_page_count;

	//Minimum of unused pages, since last deallocation
	stat->unused_page_count = pool->unused_page_count;

	// Number of times callback function failed
	stat->cb_failures = pool->cb_failures;

	SPH_SPIN_UNLOCK(&pool->lock);
	return 0;
}

void dma_page_pool_deallocate_unused_pages(pool_handle pool)
{
	unsigned int i;
	struct dma_page *pg;
	struct list_head removed_pages;
	struct list_head *pos;
	unsigned int unused_pages;

	sph_log_debug(SERVICE_LOG, "deallocating unused DMA pages. Number of free pages:%u\n",
					 pool->free_page_count);

	SPH_SPIN_LOCK(&pool->lock);

	unused_pages = pool->unused_page_count;

	SPH_ASSERT(pool->unused_page_count <= pool->free_page_count);
	pool->free_page_count -= unused_pages;
	pool->unused_page_count = pool->free_page_count;

	if (unused_pages > 0) {
		/* pull pages out of the free list */
		pos = pool->free_pool.next;
		for (i = 0; i < unused_pages; ++i)
			pos = pos->next;
		list_cut_position(&removed_pages, &pool->free_pool, pos->prev);
		SPH_SPIN_UNLOCK(&pool->lock);

		/* deallocate memory of the pulled out pages */
		list_for_each_entry(pg, &removed_pages, node) {
			dma_free_coherent(pool->dev, SPH_PAGE_SIZE, pg->vaddr, pg->dma_addr);
#ifdef _DEBUG
			pg->vaddr = NULL;
#endif
			STATE2STATE(pg->state, p_free, p_null);
			sph_log_debug(SERVICE_LOG, "free dma page deallocated.\n");
		}

		/* add the pulled out pages to the null pull */
		SPH_SPIN_LOCK(&pool->lock);
		list_splice(&removed_pages, &pool->null_pool);
		pool->null_page_count += unused_pages;
	}

	SPH_SPIN_UNLOCK(&pool->lock);
}

#ifdef ULT
int dma_page_pool_get_resp_list_pointer(pool_handle pool, const struct response_list_entry **list)
{
	if (unlikely(pool == NULL || list == NULL))
		return -EINVAL;

	if (unlikely(!pool->is_response_pool))
		return -EPERM;

	SPH_ASSERT(pool->list != NULL);
	*list = pool->list;
	return 0;
}
#endif

static int debug_status_show(struct seq_file *m, void *v)
{
	pool_handle pool = m->private;

	if (unlikely(pool == NULL))
		return -EINVAL;

	SPH_SPIN_LOCK(&pool->lock);

	seq_printf(m, "free_pages   : %d\n", pool->free_page_count);
	if (pool->is_response_pool)
		seq_printf(m, "sent_pages   : %d\n", pool->sent_page_count);
	seq_printf(m, "null_pages   : %d\n", pool->null_page_count);
	seq_printf(m, "full_pages   : %d\n", pool->full_page_count);
	seq_printf(m, "unused_pages : %d\n", pool->unused_page_count);
	if (pool->is_response_pool)
		seq_printf(m, "send failures: %d\n", pool->cb_failures);

	SPH_SPIN_UNLOCK(&pool->lock);
	return 0;
}

static int debug_status_open(struct inode *inode, struct file *filp)
{
	return single_open(filp, debug_status_show, inode->i_private);
}

static const struct file_operations debug_status_fops = {
	.open		= debug_status_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

void dma_page_pool_init_debugfs(pool_handle    pool,
				struct dentry *parent,
				const char    *dirname)
{
	struct dentry *dir, *stats;

	if (!parent)
		return;

	dir = debugfs_create_dir(dirname, parent);
	if (IS_ERR_OR_NULL(dir))
		return;


	stats = debugfs_create_file("status",
				    0444,
				    dir,
				    (void *)pool,
				    &debug_status_fops);
	if (IS_ERR_OR_NULL(stats)) {
		debugfs_remove(dir);
		return;
	}
}
