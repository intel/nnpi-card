/*
 * NNP-I Linux Driver
 * Copyright (c) 2017-2019, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 */

#ifndef _LINUX_KERNEL_MOCK_H_
#define _LINUX_KERNEL_MOCK_H_

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <malloc.h>
#include <assert.h>

#include "cve_driver_internal_macros.h"
#include "os_interface.h"
#include "coral_memory.h"

#define spinlock_t cve_os_lock_t
#define spin_lock_irqsave(_l, _f) {cve_os_lock(_l, 0); _f=0;}
#define spin_unlock_irqrestore(_l, _f) {cve_os_unlock(_l); _f=_f;}
#define spin_lock_init(_l)
#define down_read(_l)
#define up_read(_l)

#define usleep_range(_1, _2) usleep(_1)

#define container_of(ptr, type, member) \
	((type *)((char *)(ptr)-(char *)(&((type *)0)->member)))
#define ilog2(_n) (31 - __builtin_clz(_n))
#define BUG() assert( ! "this should not happen" )
#define BUG_ON(_c) assert( ! (_c) )
#define printk fprintf
#define KERN_ERR stderr,
#define __user
static inline __attribute__((const))
unsigned long __roundup_pow_of_two(unsigned long n) {
	return 1UL << ilog2(n - 1);
}


#define WARN_ON(_c) ({  \
	if (_c) { \
		cve_os_log(CVE_LOGLEVEL_ERROR, \
			"WARNING! Something bad happened\n"); \
	} \
	(_c); \
})
# define __iomem

struct list_head {
	struct list_head *next, *prev;
};

static inline void * ERR_PTR(long error) {
	return (void *) error;
}

static inline long PTR_ERR(const void *ptr) {
	return (long) ptr;
}

static inline long IS_ERR(const void *ptr) {
	return (unsigned long)ptr > (unsigned long)-1000L;
}


#define SZ_4K				0x00001000

#define __ALIGN_KERNEL(x, a)		__ALIGN_KERNEL_MASK(x, (typeof(x))(a) - 1)
#define __ALIGN_KERNEL_MASK(x, mask)	(((x) + (mask)) & ~(mask))
#define ALIGN(x, a)		__ALIGN_KERNEL((x), (a))
#define __round_mask(x, y) ((__typeof__(x))((y)-1))
#define round_up(x, y) ((((x)-1) | __round_mask(x, y))+1)
#define round_down(x, y) ((x) & ~__round_mask(x, y))

#define PAGE_ALIGN(addr) ALIGN(addr, PAGE_SIZE)
#define IS_ALIGNED(x, a)		(((x) & ((typeof(x))(a) - 1)) == 0)
#define L1_CACHE_BYTES 64

#define GFP_KERNEL 0
#define GFP_ATOMIC 1
#define GFP_DMA32  2

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(_a) (sizeof(_a) / sizeof(_a[0]))
#endif

void * kzalloc(size_t size_bytes, int flags);
void kfree(void * p);
void * __get_free_page(int flags);
void free_page(unsigned long p);

#define devm_kzalloc(_d, _s, _f) kzalloc(_s, _f)
#define vzalloc(_s) kzalloc(_s, 1)
#define vfree(_p) kfree(_p)

static inline int is_vmalloc_addr(void * _p) {
	return 1;
}

#define dev_dbg(_d, _s,...) os_log(CVE_LOGLEVEL_DEBUG, _s, ##__VA_ARGS__)

#define DMA_BIT_MASK(n)	(((n) == 64) ? ~0ULL : ((1ULL<<(n))-1))

static inline void clflush(volatile void *__p) {
	asm volatile("clflush %0" : "+m" (*(volatile char *)__p));
}

#define X86_FEATURE_XMM2	(0*32+26) /* "sse2" */

#define mb()	asm volatile ("mfence"::: "memory" )

static inline void clflush_cache_range(void *vaddr, unsigned int size) {
	void *vend = (uint8_t*) vaddr + size - 1;

	mb();

	for (; vaddr < vend; vaddr = (uint8_t*) vaddr + CACHE_LINE_SIZE)
		clflush(vaddr);
	/*
	 * Flush any possible final partial cacheline:
	 */
	clflush(vend);

	mb();
}

struct page {
	void * addr;
};

struct task {
	void * mm;
};
extern struct task * current;

struct scatterlist {
	unsigned long sg_magic;
	unsigned int offset;
	unsigned long long length; /* size in bytes */
	struct page ** page_link;
	cve_dma_addr_t dma_address;
	unsigned long long dma_length;
};

#define sg_dma_address(sg)	((sg)->dma_address)

static inline struct scatterlist *sg_next(struct scatterlist *sg) {
	return NULL;
}

#ifdef CONFIG_NEED_SG_DMA_LENGTH
#define sg_dma_len(sg)		((sg)->dma_length)
#else
#define sg_dma_len(sg)		((sg)->length)
#endif

#define for_each_sg(sglist, sg, nr, __i)	\
	for (__i = 0, sg = (sglist); __i < (nr); __i++, sg = sg_next(sg))

__attribute__((unused)) static int dma_map_sg(void * dev, struct scatterlist * sgl, int nelems,
		int dir) {
	struct scatterlist * sg;
	int i;
	for_each_sg(sgl, sg, nelems, i)
	{
		if (sg)
			sg->dma_address = (cve_dma_addr_t) (uintptr_t) (sg->page_link);
	}
	return i;
}

#define dma_unmap_sg(_dev,_sgl,_orig_nents,_dir) {_dev=_dev;_sgl=_sgl;_orig_nents=_orig_nents,_dir=_dir;}
static inline void put_page(void * p) {
	kfree(p);
}
#define for_each_sg(sglist, sg, nr, __i)	\
	for (__i = 0, sg = (sglist); __i < (nr); __i++, sg = sg_next(sg))

#define SetPageDirty(_p)   {}

static inline int get_user_pages(void * _c, void * _mm, unsigned long _start,
		int _npages, int _write, int _force, struct page ** _pages,
		void * vmas) {
	BUG_ON(_pages == NULL);
	void * start = (void*) (_start & ~(PAGE_SIZE - 1));
	int i;
	for (i = 0; i < _npages; i++) {
		struct page *_p = kzalloc(sizeof(struct page), 0);
		BUG_ON(_p == NULL);
		_p->addr = (void *)coral_pa_mem_get_phy_addr_for_ptr(start);
		_pages[i] = _p;
		start = (uint8_t*) start + PAGE_SIZE;
	}
	return _npages;
}

static inline int sg_alloc_table_from_pages(struct sg_table *sgt,
		struct page **pages, unsigned int n_pages, unsigned long offset,
		unsigned long long size_bytes, unsigned gfp_mask) {
	sgt->nents = 1; /* there's only one range in ring3 validation */
	sgt->orig_nents = 1;
	sgt->sgl = kzalloc(sizeof(struct scatterlist), gfp_mask);
	BUG_ON(sgt->sgl == NULL);
	sgt->sgl[0].offset = offset;
	sgt->sgl[0].length = size_bytes;
	// sgt->sgl[0].dma_address = will be populated at later stage
	sgt->sgl[0].dma_length = size_bytes;
	sgt->sgl[0].page_link = (struct page**) (*pages)[0].addr;
	return 0;
}

static inline void sg_free_table(struct sg_table * sgt) {
	kfree(sgt->sgl);
}


enum dma_data_direction {
	DMA_BIDIRECTIONAL = 0, DMA_TO_DEVICE = 1, DMA_FROM_DEVICE = 2, DMA_NONE = 3,
};

#define __maybe_unused			__attribute__((unused))

#define dma_sync_sg_for_cpu(a1,a2,a3,a4)
#define dma_sync_sg_for_device(a1,a2,a3,a4)

#define BUILD_BUG_ON(condition) ((void)sizeof(char[1 - 2*!!(condition)]))

static inline void *kmap(struct page *page)
{
	return page->addr;
}

static inline void kunmap(struct page *page)
{
}

struct firmware {
	size_t size;
	const u8 *data;
};

int request_firmware(const struct firmware **fw,
		const char *filename,
		struct device *device);
void release_firmware(const struct firmware *fw);

void atomic_set(atomic_t *v, int i);
int atomic_read(const atomic_t *v);
int atomic_xchg(atomic_t *v, int n);
int atomic_add_return(int i, atomic_t *v);
int atomic_sub_return(int i, atomic_t *v);
void atomic64_set(atomic64_t *v, u64 i);
u64 atomic64_read(const atomic64_t *v);
u64 atomic64_xchg(atomic64_t *v, u64 n);
u64 atomic64_add_return(u64 i, atomic64_t *v);

struct dma_buf { };

struct dma_buf_attachment { };


static inline struct dma_buf *dma_buf_get(int buffer_handle) 
{
	struct dma_buf *dmabuf = NULL;
	return dmabuf;
}


static inline struct dma_buf_attachment *dma_buf_attach(struct dma_buf *dmabuf,
		struct device *dev) 
{
	struct dma_buf_attachment *dbuf_attach = NULL;
	return dbuf_attach;
}


static inline struct sg_table *dma_buf_map_attachment(
	struct dma_buf_attachment *dbuf_attach,
		enum dma_data_direction direction) 
{
	struct sg_table *sgt = NULL;
	return sgt;
}

static inline void dma_buf_unmap_attachment(
	struct dma_buf_attachment *dbuf_attach,
	struct sg_table *sgt,
	enum dma_data_direction direction)
{ }

static inline void dma_buf_detach(struct dma_buf *dmabuf,
	struct dma_buf_attachment *dbuf_attach)
{ }

static inline void dma_buf_put(struct dma_buf *dmabuf)
{ }        

static inline int dma_buf_begin_cpu_access(struct dma_buf *dmabuf,
		       enum dma_data_direction direction)
{
	return 0;
}

static inline void *dma_buf_vmap(struct dma_buf *dmabuf)
{
	return NULL;
}

static inline void dma_buf_end_cpu_access(struct dma_buf *dmabuf,
		enum dma_data_direction direction)
{ }

static inline void dma_buf_vunmap(struct dma_buf *dmabuf, void *vaddr)
{ }

#endif // _LINUX_KERNEL_MOCK_H_
