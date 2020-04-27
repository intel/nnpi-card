/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
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
#include "nnp_debug.h"
#include "sph_log.h"

/* Size of the free pages' list, which is sent to device */
#define LIST_SIZE (MAX_HOST_RESPONSE_PAGES - MIN_HOST_RESPONSE_PAGES)

/* Theoretical maximum size of the table, limited by index size */
#define HASH_TABLE_MAX_SIZE	 (1 << 8)
#define PAGE_ID_MASK		 (HASH_TABLE_MAX_SIZE - 1)

enum page_state {
	p_null = 0,
	p_free = 1,
	p_full = 2
};

#define STATE2STATE(state, from, to)		\
	do {					\
		NNP_ASSERT((state) == (from));	\
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
	unsigned int	  unused_page_count;  //Minimum of unused pages, since last deallocation
	wait_queue_head_t free_waitq;
	spinlock_t	  lock;
};

//Static asserts
NNP_STATIC_ASSERT(NNP_IPC_DMA_ADDR_ALIGN_MASK >= PAGE_ID_MASK,
"page_handle doesn't fit to be set in alignment bits");

NNP_STATIC_ASSERT(sizeof(page_handle) == 1, "page_handle is not 8bit size");

/* Return free pages to the pool */
static void return_free_pages_to_pool(struct dma_page_pool *p, struct list_head *free_pages)
{
	int count = 0;
	struct dma_page *page;

	NNP_ASSERT(p != NULL);
	NNP_ASSERT(free_pages != NULL);

	if (list_empty(free_pages))
		return;

	sph_log_debug(SERVICE_LOG, "Return free pages back to pool: %u)\n", p->free_page_count);
	list_for_each_entry(page, free_pages, node) {
		page->state = p_free;
		++count;
	}

	NNP_SPIN_LOCK(&p->lock);
	list_splice(free_pages, &p->free_pool);
	p->free_page_count += count;
	NNP_SPIN_UNLOCK(&p->lock);

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

	NNP_ASSERT(p != NULL);
	NNP_ASSERT(free_pages != NULL);

	NNP_ASSERT(min <= wanted);
	if (unlikely(min > wanted))
		return -EINVAL;

	if (unlikely(wanted == 0))
		return 0;

	NNP_SPIN_LOCK(&p->lock);

	// Not enough pages
	if ((p->free_page_count + p->null_page_count) < (min + reserve)) {
		NNP_SPIN_UNLOCK(&p->lock);

		sph_log_debug(SERVICE_LOG, "The pool is full! %u pages cannot be extracted\n", min);
		return -EXFULL;
	}

	// Try to extract all need pages from allocated free ones
	for (i = 0, pos = p->free_pool.next;
		 i < wanted && pos != &p->free_pool;
		 ++i, pos = pos->next) {

		NNP_ASSERT(list_entry(pos, struct dma_page, node)->state == p_free);
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

		NNP_ASSERT(list_entry(pos, struct dma_page, node)->state == p_null);
	}
	list_cut_position(&candidates, &p->null_pool, pos->prev);
	p->null_page_count -= j;

#ifdef _DEBUG
	// if hash table is full
	if (i + j < wanted) {
		sph_log_debug(SERVICE_LOG, "The pool is full!\n"
			"Only %u free pages extracted and %u pages to be alloced\n", i, j);
		NNP_ASSERT(list_empty(&p->free_pool));
		NNP_ASSERT(list_empty(&p->null_pool));
	}
#endif

	NNP_SPIN_UNLOCK(&p->lock);


	// Allocate DMA addresses for each null page
	list_for_each_entry(pg, &candidates, node) {

		NNP_ASSERT(pg->vaddr == NULL);
		pg->vaddr = dma_alloc_coherent(p->dev,
					       NNP_PAGE_SIZE,
					       &pg->dma_addr,
					       GFP_KERNEL);
		if (unlikely(pg->vaddr == NULL))
			break;

		sph_log_debug(SERVICE_LOG, "dma page pool page alloced.fpc: %d, upc: %d, spc: %d\n",
				p->free_page_count, p->unused_page_count, p->sent_page_count);

#ifdef _DEBUG
		// SECURITY?
		memset(pg->vaddr, 0xcc, NNP_PAGE_SIZE);
#endif

		// Check that 4K aligned dma_addr can fit 45 bit pfn
		NNP_ASSERT(NNP_IPC_DMA_PFN_TO_ADDR(NNP_IPC_DMA_ADDR_TO_PFN(pg->dma_addr)) == pg->dma_addr);

		++i;
		--j;
	}

	list_cut_position(&alloced, &candidates, pg->node.prev);
	list_splice_tail(&alloced, free_pages);

	// Out of memory
	if (j != 0) {
		NNP_ASSERT(!list_empty(&candidates));
		sph_log_err(SERVICE_LOG, "Out of memory. %u pages cannot be allocated\n", j);

		// Return not allocated pages to null
		NNP_SPIN_LOCK(&p->lock);
		list_splice_tail(&candidates, &p->null_pool);
		p->null_page_count += j;
		NNP_SPIN_UNLOCK(&p->lock);

		if (i < min) {
			sph_log_debug(SERVICE_LOG, "free_page_count too low: %u!\n", i);
			return_free_pages_to_pool(p, free_pages);
			return -ENOMEM;
		}
	} else {
		NNP_ASSERT(list_empty(&candidates));
	}

	return i;
}

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

	spin_lock_init(&p->lock);

	*pool = p;
	return 0;
}

void dma_page_pool_destroy(pool_handle pool)
{
	unsigned int i;

	if (unlikely(pool == NULL))
		return;

	sph_log_info(SERVICE_LOG, "dma page pool: destroy\n");

	if (unlikely(pool->full_page_count != 0))
		sph_log_err(SERVICE_LOG, "full_page_count is not 0. There are %u full pages.\n",
			    pool->full_page_count);

	for (i = 0; i < pool->ht_size; ++i) {
		if (pool->hash_table[i].state != p_null) {
			NNP_ASSERT(pool->hash_table[i].vaddr != NULL);
			//free allocated page
			dma_free_coherent(pool->dev, NNP_PAGE_SIZE, pool->hash_table[i].vaddr, pool->hash_table[i].dma_addr);
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

	NNP_SPIN_LOCK(&pool->lock);

	//no free pages left
	if (pool->free_page_count +
	    pool->null_page_count +
	    pool->sent_page_count <= min ||
	    pool->free_page_count == 0) {
		NNP_SPIN_UNLOCK(&pool->lock);
		return -EXFULL;
	}

	free_page = list_first_entry(&pool->free_pool, struct dma_page, node);
	list_del(&free_page->node);
	--pool->free_page_count;
	++pool->full_page_count;

	//Observe usage for deallocation purposes
	if (pool->unused_page_count > pool->free_page_count)
		pool->unused_page_count = pool->free_page_count;

	NNP_SPIN_UNLOCK(&pool->lock);

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

	NNP_ASSERT(list_is_singular(&free_page_list));
	free_page = list_first_entry(&free_page_list, struct dma_page, node);
	free_page->state = p_full;

	NNP_SPIN_LOCK(&pool->lock);
	++pool->full_page_count;
	NNP_SPIN_UNLOCK(&pool->lock);

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

int dma_page_pool_get_page_pointer(pool_handle pool, page_handle page, const void **p)
{
	if (unlikely((pool == NULL) || (page >= pool->ht_size) || (p == NULL)))
		return -EINVAL;

	NNP_ASSERT(pool->hash_table[page].state == p_full);

	*p = pool->hash_table[page].vaddr;
	return 0;
}

int dma_page_pool_get_page_addr(pool_handle pool, page_handle page, dma_addr_t *addr)
{
	if (unlikely((pool == NULL) || (page >= pool->ht_size) || (addr == NULL)))
		return -EINVAL;

	NNP_ASSERT(pool->hash_table[page].state == p_full);

	*addr = pool->hash_table[page].dma_addr;
	return 0;
}

int dma_page_pool_set_page_free(pool_handle pool, page_handle page)
{
	if (unlikely((pool == NULL) || (page >= pool->ht_size)))
		return -EINVAL;

	NNP_SPIN_LOCK(&pool->lock);

	list_add_tail(&pool->hash_table[page].node, &pool->free_pool);
	--pool->full_page_count;
	++pool->free_page_count;
	STATE2STATE(pool->hash_table[page].state, p_full, p_free);

#ifdef _DEBUG
	//SECURITY?
	memset(pool->hash_table[page].vaddr, 0xcc, NNP_PAGE_SIZE);
#endif

	NNP_SPIN_UNLOCK(&pool->lock);

	// wake up clients waiting for a free page
	wake_up_all(&pool->free_waitq);

	return 0;
}

int dma_page_pool_get_stats(pool_handle pool, struct dma_pool_stat *stat)
{

	if (unlikely(pool == NULL || stat == NULL))
		return -EINVAL;

	NNP_SPIN_LOCK(&pool->lock);

	stat->free_pages  = pool->free_page_count;
	stat->sent_pages  = pool->sent_page_count;
	stat->full_pages  = pool->full_page_count;

	//Minimum of unused pages, since last deallocation
	stat->unused_page_count = pool->unused_page_count;

	NNP_SPIN_UNLOCK(&pool->lock);
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

	NNP_SPIN_LOCK(&pool->lock);

	unused_pages = pool->unused_page_count;

	NNP_ASSERT(pool->unused_page_count <= pool->free_page_count);
	pool->free_page_count -= unused_pages;
	pool->unused_page_count = pool->free_page_count;

	if (unused_pages > 0) {
		/* pull pages out of the free list */
		pos = pool->free_pool.next;
		for (i = 0; i < unused_pages; ++i)
			pos = pos->next;
		list_cut_position(&removed_pages, &pool->free_pool, pos->prev);
		NNP_SPIN_UNLOCK(&pool->lock);

		/* deallocate memory of the pulled out pages */
		list_for_each_entry(pg, &removed_pages, node) {
			dma_free_coherent(pool->dev, NNP_PAGE_SIZE, pg->vaddr, pg->dma_addr);
#ifdef _DEBUG
			pg->vaddr = NULL;
#endif
			STATE2STATE(pg->state, p_free, p_null);
			sph_log_debug(SERVICE_LOG, "free dma page deallocated.\n");
		}

		/* add the pulled out pages to the null pull */
		NNP_SPIN_LOCK(&pool->lock);
		list_splice(&removed_pages, &pool->null_pool);
		pool->null_page_count += unused_pages;
	}

	NNP_SPIN_UNLOCK(&pool->lock);
}

static int debug_status_show(struct seq_file *m, void *v)
{
	pool_handle pool = m->private;

	if (unlikely(pool == NULL))
		return -EINVAL;

	NNP_SPIN_LOCK(&pool->lock);

	seq_printf(m, "free_pages   : %d\n", pool->free_page_count);
	seq_printf(m, "null_pages   : %d\n", pool->null_page_count);
	seq_printf(m, "full_pages   : %d\n", pool->full_page_count);
	seq_printf(m, "unused_pages : %d\n", pool->unused_page_count);

	NNP_SPIN_UNLOCK(&pool->lock);
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
