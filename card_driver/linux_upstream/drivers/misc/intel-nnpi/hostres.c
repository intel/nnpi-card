// SPDX-License-Identifier: GPL-2.0-or-later

/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 ********************************************/

#include "hostres.h"
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <linux/sort.h>
#include <linux/sched.h>
#include <linux/jiffies.h>
#include <linux/wait.h>
#include <linux/atomic.h>
#include <linux/dma-buf.h>
#include <linux/pagemap.h>
#include "ipc_protocol.h"
#include "nnp_debug.h"
#include "nnp_log.h"
#include "trace.h"

struct dma_list {
	void             *vaddr;
	dma_addr_t        dma_addr;
};

struct dev_mapping {
	struct kref       ref;
	struct nnpdrv_host_resource *res;
	struct device    *dev;
	enum dma_data_direction dir;
	struct sg_table  *sgt;
	struct dma_list  *list;
	unsigned int      num;
	unsigned int      entry_pages;
	struct list_head  node;

	struct dma_buf_attachment *dma_att;
};

struct nnpdrv_host_resource {
	void             *magic;
	struct kref       ref;
	size_t            size;
	struct list_head  devices;
	spinlock_t        lock; /* protects struct field modifications */
#ifdef DEBUG
	bool              destroyed;
#endif
	enum dma_data_direction dir;
	wait_queue_head_t access_waitq;
	/* == 0 => unlocked; > 0 => locked for read; -1 => locked for write */
	int               readers;
	bool              user_locked;

	bool external_buf;
	bool user_memory_buf;
	u16 start_offset;

	union {
		struct {
			struct page **pages;
			unsigned int n_pages;
		};
		struct {
			struct dma_buf *buf;
		};
	};
};

/* Static asserts */
NNP_STATIC_ASSERT(NENTS_PER_PAGE >= 1,
		  "There should be place for at least 1 DMA chunk addr in every DMA chain page");

static int hostres_min_order;
module_param(hostres_min_order, int, 0600);

static atomic64_t s_total_hostres_size;

/* Destroys DMA page list of DMA addresses */
static void destroy_dma_list(struct dev_mapping *m)
{
	unsigned int i;

	for (i = 0; i < m->num; ++i) {
		NNP_ASSERT(m->list[i].vaddr);
		dma_free_coherent(m->dev, m->entry_pages * NNP_PAGE_SIZE,
				  m->list[i].vaddr, m->list[i].dma_addr);
	}
	kfree(m->list);
}

/* Really destroys host resource, when all references to it were released */
static void release_hostres(struct kref *kref)
{
	struct nnpdrv_host_resource *r =
		container_of(kref,
			     struct nnpdrv_host_resource,
			     ref);
	unsigned int i, n, order;

	NNP_ASSERT(list_empty(&r->devices));

	if (r->external_buf) {
		dma_buf_put(r->buf);
		kfree(r);
		return;
	}

	if (!r->user_memory_buf) {
		for (i = 0; i < r->n_pages; i += n) {
			NNP_ASSERT(r->pages[i]);
			order = compound_order(r->pages[i]);
			n = (1u << order);
			__free_pages(r->pages[i], order);
		}
		vfree(r->pages);
	} else {
		release_pages(r->pages, r->n_pages);
		vfree(r->pages);
	}

	kfree(r);
}

void nnpdrv_hostres_get(struct nnpdrv_host_resource *res)
{
	int ret;

	NNP_ASSERT(res);

	ret = kref_get_unless_zero(&res->ref);
	NNP_ASSERT(ret != 0);
};

bool nnpdrv_hostres_put(struct nnpdrv_host_resource *res)
{
	NNP_ASSERT(res);

	return kref_put(&res->ref, release_hostres);
}

/* Really destroys mapping to device, when refcount is zero */
static void release_mapping(struct kref *kref)
{
	struct dev_mapping *m = container_of(kref,
					     struct dev_mapping,
					     ref);

	destroy_dma_list(m);

	if (m->res->external_buf) {
		dma_buf_unmap_attachment(m->dma_att, m->sgt, m->res->dir);
		dma_buf_detach(m->res->buf, m->dma_att);
	} else {
		dma_unmap_sg(m->dev, m->sgt->sgl,
			     m->sgt->orig_nents, m->res->dir);
		sg_free_table(m->sgt);
		kfree(m->sgt);
	}

	spin_lock(&m->res->lock);
	list_del(&m->node);
	spin_unlock(&m->res->lock);

	nnpdrv_hostres_put(m->res);

	kfree(m);
}

/* Increase reference count to mapping to the specific device */
static inline int mapping_get(struct dev_mapping *m)
{
	return kref_get_unless_zero(&m->ref);
};

/* Decrease reference count to mapping to the specific device
 * and destroy it, if reference count is decreased to zero
 */
static inline int mapping_put(struct dev_mapping *m)
{
	return kref_put(&m->ref, release_mapping);
}

/* Compare callback function for sort, to compare 2 pages */
static int cmp_pfn(const void *p1, const void *p2)
{
	NNP_ASSERT(page_to_pfn(*(const struct page **)p1) -
		   page_to_pfn(*(const struct page **)p2) != 0);
	return page_to_pfn(*(const struct page **)p1) -
	       page_to_pfn(*(const struct page **)p2);
}

static struct nnpdrv_host_resource *alloc_hostres(size_t                  size,
						  enum dma_data_direction dir)
{
	struct nnpdrv_host_resource *r;

	r = kmalloc(sizeof(sizeof(*r)), GFP_KERNEL);
	if (unlikely(!r))
		return r;

	r->magic = nnpdrv_hostres_create;
#ifdef DEBUG
	r->destroyed = false;
#endif
	kref_init(&r->ref);
	spin_lock_init(&r->lock);
	init_waitqueue_head(&r->access_waitq);
	r->readers = 0;
	r->dir = dir;
	r->size = size;
	r->user_locked = false;
	r->start_offset = 0;
	INIT_LIST_HEAD(&r->devices);

	return r;
}

int nnpdrv_hostres_create(size_t                        size,
			  enum dma_data_direction       dir,
			  struct nnpdrv_host_resource **out_resource)
{
	int err;
	struct nnpdrv_host_resource *r;
	unsigned int i, j, n;
	unsigned int order;

	if (unlikely(!out_resource || size == 0 || dir == DMA_NONE))
		return -EINVAL;

	r = alloc_hostres(size, dir);
	if (unlikely(!r))
		return -ENOMEM;

	r->user_memory_buf = false;
	r->external_buf = false;

	/*
	 * In this place actual pages are allocated of PAGE_SIZE and not
	 * NNP_PAGE_SIZE, This list will be used for sg_alloc_table
	 */
	r->n_pages = DIV_ROUND_UP(size, PAGE_SIZE);
	r->pages = vmalloc(r->n_pages * sizeof(struct page *));
	if (IS_ERR_OR_NULL(r->pages)) {
		nnp_log_err(CREATE_COMMAND_LOG,
			    "failed to vmalloc %zu bytes array\n",
			    (r->n_pages * sizeof(struct page *)));
		err = -ENOMEM;
		goto free_res;
	}

	order = hostres_min_order;
	n = (1u << order);

	for (i = 0; i < r->n_pages; i += n) {
		while (order > 0 && (r->n_pages - i < n)) {
			order--;
			n >>= 1;
		}

		do {
			r->pages[i] = alloc_pages(GFP_KERNEL | __GFP_COMP,
						  order);
			if (!r->pages[i] && order > 0) {
				order--;
				n >>= 1;
			} else {
				break;
			}
		} while (1);

		if (unlikely(!r->pages[i])) {
			nnp_log_err(CREATE_COMMAND_LOG,
				    "failed to alloc page%u\n", i);
			err = -ENOMEM;
			goto free_pages;
		}

		for (j = 1; j < n; j++)
			r->pages[i + j] = r->pages[i] + j;
	}
	/* adjacent pages can be joined to 1 chunk */
	sort(r->pages, r->n_pages, sizeof(r->pages[0]), cmp_pfn, NULL);

	atomic64_add(size, &s_total_hostres_size);

	*out_resource = r;
	return 0;

free_pages:
	for (i = 0; i < r->n_pages; i += n) {
		if (!r->pages[i])
			break;
		order = compound_order(r->pages[i]);
		n = (1u << order);
		__free_pages(r->pages[i], order);
	}
	vfree(r->pages);
free_res:
	kfree(r);
	return err;
}

int nnpdrv_hostres_create_usermem(void __user                  *user_ptr,
				  size_t                        size,
				  enum dma_data_direction       dir,
				  struct nnpdrv_host_resource **out_resource)
{
	int err;
	struct nnpdrv_host_resource *r;
	unsigned int pinned_pages = 0;
	uintptr_t user_addr = (uintptr_t)user_ptr;
	int gup_flags;

	if (unlikely(!out_resource || size == 0 || dir == DMA_NONE))
		return -EINVAL;

	/* restrict for 4 byte alignment - is this enough? */
	if ((user_addr & 0x3) != 0)
		return -EINVAL;

	r = alloc_hostres(size, dir);
	if (unlikely(!r))
		return -ENOMEM;

	r->user_memory_buf = true;
	r->external_buf = false;

	r->start_offset = user_addr & (PAGE_SIZE - 1);
	user_addr &= ~(PAGE_SIZE - 1);

	/*
	 * In this place actual pages are allocated of PAGE_SIZE and not
	 * NNP_PAGE_SIZE, This list will be used for sg_alloc_table
	 */
	r->n_pages = DIV_ROUND_UP(size + r->start_offset, PAGE_SIZE);
	r->pages = vmalloc(r->n_pages * sizeof(struct page *));
	if (IS_ERR_OR_NULL(r->pages)) {
		nnp_log_err(CREATE_COMMAND_LOG,
			    "failed to vmalloc %zu bytes array\n",
			    (r->n_pages * sizeof(struct page *)));
		err = -ENOMEM;
		goto free_res;
	}

	gup_flags = (dir == DMA_TO_DEVICE ||
		     dir == DMA_BIDIRECTIONAL) ? FOLL_WRITE : 0;

	/*
	 * The host resource is being re-used for multiple DMA
	 * transfers for streaming data into the device.
	 * In most situations will live long term.
	 */
	gup_flags |= FOLL_LONGTERM;

	do {
		int n = pin_user_pages(user_addr + pinned_pages * PAGE_SIZE,
				       r->n_pages - pinned_pages,
				       gup_flags,
				       &r->pages[pinned_pages],
				       NULL);
		if (n < 0) {
			err = -ENOMEM;
			goto free_pages;
		}

		pinned_pages += n;
	} while (pinned_pages < r->n_pages);

	atomic64_add(size, &s_total_hostres_size);

	*out_resource = r;
	return 0;

free_pages:
	release_pages(r->pages, pinned_pages);
	vfree(r->pages);
free_res:
	kfree(r);
	return err;
}

int nnpdrv_hostres_dma_buf_create(int                           dma_buf_fd,
				  enum dma_data_direction       dir,
				  struct nnpdrv_host_resource **out_resource)
{
	int err;
	struct nnpdrv_host_resource *r;
	struct dma_buf *dmabuf;

	if (unlikely(!out_resource || dma_buf_fd < 0 || dir == DMA_NONE))
		return -EINVAL;

	dmabuf = dma_buf_get(dma_buf_fd);
	err = PTR_ERR_OR_ZERO(dmabuf);
	if (unlikely(err < 0))
		/*
		 * EBADF in case of dma_buf_fd is not fd;
		 * EINVAL in case dma_buf_fd is fd, but not of dma_buf
		 * in any case report invalid value
		 */
		return -EINVAL;

	r = alloc_hostres(dmabuf->size, dir);
	if (unlikely(!r)) {
		dma_buf_put(dmabuf);
		return -ENOMEM;
	}

	r->buf = dmabuf;
	r->user_memory_buf = false;
	r->external_buf = true;

	*out_resource = r;
	return 0;
}

int nnpdrv_hostres_vmap(struct nnpdrv_host_resource *res,
			void                       **out_ptr)
{
	if (!res || !out_ptr)
		return -EINVAL;

	/*
	 * dma-buf case
	 */
	if (res->external_buf) {
		*out_ptr = dma_buf_vmap(res->buf);
		if (*out_ptr)
			return 0;

		return -ENOMEM;
	}

	/*
	 * no dma-buf case
	 */
	*out_ptr = vmap(res->pages, res->n_pages, 0, PAGE_KERNEL);
	if (*out_ptr)
		return 0;

	return -ENOMEM;
}

void nnpdrv_hostres_vunmap(struct nnpdrv_host_resource *res, void *ptr)
{
	/*
	 * dma-buf case
	 */
	if (res->external_buf) {
		dma_buf_vunmap(res->buf, ptr);
		return;
	}

	/*
	 * no dma-buf case
	 */
	vunmap(ptr);
}

int nnpdrv_hostres_read_refcount(struct nnpdrv_host_resource *res)
{
	return kref_read(&res->ref);
}

bool nnpdrv_hostres_destroy(struct nnpdrv_host_resource *res)
{
	NNP_ASSERT(res);

#ifdef DEBUG
	spin_lock(&res->lock);
	NNP_ASSERT(!res->destroyed);
	res->destroyed = true;
	spin_unlock(&res->lock);
#endif

	if (!res->external_buf)
		atomic64_sub(res->size, &s_total_hostres_size);

	return nnpdrv_hostres_put(res);
}

/* Finds mapping by device. NULL if not found*/
static struct dev_mapping *mapping_for_dev(struct nnpdrv_host_resource *res,
					   struct device               *dev)
{
	struct dev_mapping *m;

	spin_lock(&res->lock);

	list_for_each_entry(m, &res->devices, node) {
		if (m->dev == dev)
			break;
	}

	spin_unlock(&res->lock);

	/* Check if no mapping found */
	if (&m->node == &res->devices)
		return NULL;

	return m;
}

/* builds DMA page list with DMA addresses of the mapped host resource */
static int build_dma_list(struct dev_mapping *m,
			  bool                use_one_entry,
			  u32                 start_offset)
{
	unsigned int i, k = 0;
	int err;
#ifdef DEBUG
	unsigned int j = 0;
#endif
	struct dma_chain_entry *p = NULL;
	struct dma_chain_header *h;
	struct scatterlist *sg;
	unsigned int nents_per_entry;

	if (unlikely(use_one_entry)) {
		nents_per_entry = m->sgt->nents;
		m->entry_pages = DIV_ROUND_UP(sizeof(struct dma_chain_header) +
				m->sgt->nents * sizeof(struct dma_chain_entry),
				NNP_PAGE_SIZE);
		m->num = 1;
	} else {
		nents_per_entry = NENTS_PER_PAGE;
		m->entry_pages = 1;
		m->num = DIV_ROUND_UP(m->sgt->nents, NENTS_PER_PAGE);
	}

	m->list = kmalloc_array(m->num, sizeof(struct dma_list), GFP_KERNEL);
	if (unlikely(!m->list))
		return -ENOMEM;

	for (i = 0; i < m->num; ++i) {
		m->list[i].vaddr = dma_alloc_coherent(m->dev,
						 m->entry_pages * NNP_PAGE_SIZE,
						 &m->list[i].dma_addr,
						 GFP_KERNEL);
		if (IS_ERR_OR_NULL(m->list[i].vaddr)) {
			err = -ENOMEM;
			goto free_pages;
		}
		/* Check that 4K aligned dma_addr can fit 45 bit pfn */
		NNP_ASSERT(NNP_IPC_DMA_PFN_TO_ADDR(
				NNP_IPC_DMA_ADDR_TO_PFN(m->list[i].dma_addr)) ==
				m->list[i].dma_addr);
	}

	/* join links in the chain */
	for (i = 0; i < m->num - 1; ++i) {
		h = (struct dma_chain_header *)m->list[i].vaddr;
		h->dma_next = m->list[i + 1].dma_addr;
		h->total_nents = m->sgt->nents;
		h->start_offset = (i == 0 ? start_offset : 0);
	}
	h = (struct dma_chain_header *)m->list[i].vaddr;
	h->dma_next = 0;
	h->total_nents = m->sgt->nents;
	h->start_offset = (i == 0 ? start_offset : 0);

	sg = m->sgt->sgl;
	NNP_ASSERT(m->num > 0);
	for (i = 0; i < m->num; ++i) {
		h = (struct dma_chain_header *)m->list[i].vaddr;
		h->size = 0;
		p = (struct dma_chain_entry *)(m->list[i].vaddr +
					       sizeof(struct dma_chain_header));
		for (k = 0; k < nents_per_entry && !sg_is_last(sg); ++k) {
#ifdef DEBUG
			NNP_ASSERT(sg);
			NNP_ASSERT(j < m->sgt->nents - 1);
			++j;
#endif
			p[k].dma_chunk_pfn =
				NNP_IPC_DMA_ADDR_TO_PFN(sg_dma_address(sg));
			/* Check that 4K aligned dma_addr can fit 45 bit pfn */
			NNP_ASSERT(NNP_IPC_DMA_PFN_TO_ADDR(p[k].dma_chunk_pfn)
				   == sg_dma_address(sg));
			/* chunk size in pages */
			p[k].n_pages = sg_dma_len(sg) / NNP_PAGE_SIZE;
			/* Assert that sg_dma_len is aligned to NNP_PAGE_SIZE */
			NNP_ASSERT(sg_dma_len(sg) % NNP_PAGE_SIZE == 0);
			/* Assert that chunk size fits in 19 bits */
			NNP_ASSERT(p[k].n_pages * NNP_PAGE_SIZE ==
				   sg_dma_len(sg));

			h->size += sg_dma_len(sg);

			sg = sg_next(sg);
		}
	}

	NNP_ASSERT(sg_is_last(sg));
	p[k].dma_chunk_pfn = NNP_IPC_DMA_ADDR_TO_PFN(sg_dma_address(sg));
	/* last chunk size in pages rounded up */
	p[k].n_pages = DIV_ROUND_UP(sg_dma_len(sg), NNP_PAGE_SIZE);
	NNP_ASSERT(p[k].n_pages * NNP_PAGE_SIZE >= sg_dma_len(sg));
	NNP_ASSERT(p[k].n_pages * NNP_PAGE_SIZE - sg_dma_len(sg) <=
		   NNP_PAGE_SIZE);

	h->size += sg_dma_len(sg);

#ifdef DEBUG
	++k;
	memset(p + k, 0xcc,
	       m->entry_pages * NNP_PAGE_SIZE -
	       sizeof(struct dma_chain_header) -
	       sizeof(struct dma_chain_entry) * k);
#endif

	return 0;

free_pages:
	for (i = 0; i < m->num; ++i) {
		if (!m->list[i].vaddr)
			break;
		dma_free_coherent(m->dev, m->entry_pages * NNP_PAGE_SIZE,
				  m->list[i].vaddr, m->list[i].dma_addr);
	}
	kfree(m->list);

	return err;
}

int nnpdrv_hostres_map_device(struct nnpdrv_host_resource *res,
			      struct nnp_device           *nnpdev,
			      bool                         use_one_entry,
			      dma_addr_t                  *page_list,
			      u32                         *total_chunks)
{
	int ret;
	struct dev_mapping *m;

	if (unlikely(!res || !nnpdev || !page_list))
		return -EINVAL;

	/* Check if already mapped for the device */
	m = mapping_for_dev(res, nnpdev->hw_device_info->hw_device);
	/*
	 * "mapping_get" will fail and return 0, if m is at destroy stage
	 * so if mapping is exist and it is not being destroyed,
	 * "mapping_get" will successfully increase ref and will return 1
	 */
	if (likely(m && mapping_get(m) == 1)) {
		*page_list = m->list[0].dma_addr;
		return 0;
	}

	nnpdrv_hostres_get(res);

	m = kmalloc(sizeof(*m), GFP_KERNEL);
	if (unlikely(!m)) {
		ret = -ENOMEM;
		goto put_resource;
	}

	kref_init(&m->ref);

	m->dev = nnpdev->hw_device_info->hw_device;
	m->res = res;

	if (res->external_buf) {
		m->dma_att = dma_buf_attach(res->buf, m->dev);
		ret = PTR_ERR_OR_ZERO(m->dma_att);
		if (unlikely(ret < 0))
			goto free_mapping;

		m->sgt = dma_buf_map_attachment(m->dma_att, res->dir);
		ret = PTR_ERR_OR_ZERO(m->sgt);
		if (unlikely(ret < 0))
			goto buf_detach;
	} else {
		m->sgt = kmalloc(sizeof(*m->sgt), GFP_KERNEL);
		if (unlikely(!m->sgt)) {
			ret = -ENOMEM;
			goto free_mapping;
		}

		ret = __sg_alloc_table_from_pages(m->sgt,
						res->pages,
						res->n_pages,
						0,
						res->size + res->start_offset,
						NNP_MAX_CHUNK_SIZE,
						GFP_KERNEL);
		if (unlikely(ret < 0))
			goto free_sgt_struct;

		ret = dma_map_sg(m->dev, m->sgt->sgl,
				 m->sgt->orig_nents, res->dir);
		if (unlikely(ret < 0))
			goto free_sgt;

		m->sgt->nents = ret;
	}

	ret = build_dma_list(m, use_one_entry, res->start_offset);
	if (unlikely(ret < 0))
		goto unmap;

	spin_lock(&res->lock);
	list_add(&m->node, &res->devices);
	spin_unlock(&res->lock);

	*page_list = m->list[0].dma_addr;
	if (total_chunks)
		*total_chunks = m->sgt->nents;

	return 0;

unmap:
	if (res->external_buf) {
		dma_buf_unmap_attachment(m->dma_att, m->sgt, res->dir);
buf_detach:
		dma_buf_detach(res->buf, m->dma_att);
	} else {
		dma_unmap_sg(m->dev, m->sgt->sgl,
			     m->sgt->orig_nents, res->dir);
free_sgt:
		sg_free_table(m->sgt);
free_sgt_struct:
		kfree(m->sgt);
	}
free_mapping:
	kfree(m);
put_resource:
	nnpdrv_hostres_put(res);
	return ret;
}

int nnpdrv_hostres_unmap_device(struct nnpdrv_host_resource *res,
				struct nnp_device           *nnpdev)
{
	struct dev_mapping *m;

	if (unlikely(!res))
		return -EINVAL;

	m = mapping_for_dev(res, nnpdev->hw_device_info->hw_device);
	if (unlikely(!m))
		return -ENXIO;

	mapping_put(m);

	return 0;
}

int nnpdrv_hostres_map_user(struct nnpdrv_host_resource *res,
			    struct vm_area_struct       *vma)
{
	unsigned int i, j, offset = 0, seg_len, s;
	int err;

	if (unlikely(!res || !vma))
		return -EINVAL;

	if (res->external_buf)
		return -EPERM;

	if (res->user_memory_buf)
		return -EINVAL;

	if (unlikely(vma->vm_end - vma->vm_start < res->size))
		return -EINVAL;

	s = res->size;
	for (i = 0; i < res->n_pages - 1; i += j) {
		seg_len = 0;
		for (j = 0; i + j < res->n_pages - 1; ++j) {
			seg_len += NNP_PAGE_SIZE;
			if (page_to_pfn(res->pages[i + j]) !=
			    page_to_pfn(res->pages[i + j + 1]) + 1) {
				err = remap_pfn_range(vma,
						    vma->vm_start + offset,
						    page_to_pfn(res->pages[i]),
						    seg_len, vma->vm_page_prot);
				if (unlikely(err < 0))
					return err;
				++j;
				s -= seg_len;
				offset += seg_len;
				break;
			}
		}
	}
	err = remap_pfn_range(vma, vma->vm_start + offset,
			      page_to_pfn(res->pages[i]), s, vma->vm_page_prot);

	return err;
}

int nnpdrv_hostres_dev_lock(struct nnpdrv_host_resource *res,
			    struct nnp_device           *nnpdev,
			    enum dma_data_direction      dir)
{
	if (unlikely(!res)) {
		nnp_log_err(GENERAL_LOG, "Host resource is null\n");
		return -EINVAL;
	}
	if (unlikely(dir == DMA_NONE)) {
		nnp_log_err(GENERAL_LOG,
			    "Host resource must have a direction\n");
		return -EINVAL;
	}

	if (unlikely(res->dir != DMA_BIDIRECTIONAL && dir != res->dir)) {
		nnp_log_err(GENERAL_LOG,
			    "Host resource direction (%u) must fit lock direction (%u)\n",
			    res->dir, dir);
		return -EPERM;
	}

	NNP_ASSERT(mapping_for_dev(res, nnpdev->hw_device_info->hw_device) !=
		   NULL);

	DO_TRACE(trace_hostres(NNP_TRACE_LOCK_ENTER,
			       0,
			       (u64)(uintptr_t)res,
			       res->readers,
			       res->dir == DMA_TO_DEVICE));

	spin_lock(&res->lock);
	/* Check if requested access is Read Only */
	if (dir == DMA_TO_DEVICE) {
		if (unlikely(res->readers < 0)) {
			nnp_log_err(GENERAL_LOG, "Error: lock is busy for read\n");
			NNP_ASSERT(res->readers == -1);
			spin_unlock(&res->lock);
			return -EBUSY;
		}
		++res->readers;
	} else {
		if (unlikely(res->readers != 0)) {
			nnp_log_err(GENERAL_LOG, "Error: lock is busy for write\n");
			spin_unlock(&res->lock);
			return -EBUSY;
		}
		res->readers = -1;
	}
	spin_unlock(&res->lock);

	DO_TRACE(trace_hostres(NNP_TRACE_LOCK_EXIT,
			       0,
			       (u64)(uintptr_t)res,
			       res->readers,
			       res->dir == DMA_TO_DEVICE));

	return 0;
}

int nnpdrv_hostres_dev_unlock(struct nnpdrv_host_resource *res,
			      struct nnp_device           *nnpdev,
			      enum dma_data_direction      dir)
{
	if (unlikely(!res || !nnpdev || dir == DMA_NONE))
		return -EINVAL;

	if (unlikely(res->dir != DMA_BIDIRECTIONAL && dir != res->dir))
		return -EPERM;

	NNP_ASSERT(mapping_for_dev(res, nnpdev->hw_device_info->hw_device) !=
		   NULL);

	DO_TRACE(trace_hostres(NNP_TRACE_UNLOCK_ENTER,
			       0,
			       (u64)(uintptr_t)res,
			       res->readers,
			       res->dir == DMA_TO_DEVICE));

	spin_lock(&res->lock);
	/* Check if requested access is Read Only */
	if (dir == DMA_TO_DEVICE) {
		NNP_ASSERT(res->readers > 0);
		--res->readers;
	} else {
		NNP_ASSERT(res->readers == -1);
		res->readers = 0;
	}
	spin_unlock(&res->lock);

	DO_TRACE(trace_hostres(NNP_TRACE_UNLOCK_EXIT,
			       0,
			       (u64)(uintptr_t)res,
			       res->readers,
			       res->dir == DMA_TO_DEVICE));

	wake_up_all(&res->access_waitq);

	return 0;
}

#define GET_WAIT_EVENT_ERR(ret)					\
	((ret) > 0 ?						\
		(0) /* wait completed before timeout elapsed */	\
	:							\
		((ret) == 0 ?					\
			(-ETIME) /* timed out */		\
		:						\
			/* replace ERESTARTSYS with EINTR. */   \
			((ret) == -ERESTARTSYS ?		\
				(-EINTR)			\
			:					\
				(ret)				\
			)					\
		)						\
	)

int nnpdrv_hostres_user_lock(struct nnpdrv_host_resource *res,
			     unsigned int                 timeout)
{
	long ret, left, before;

	left = (timeout != U32_MAX ? usecs_to_jiffies(timeout) :
				     MAX_SCHEDULE_TIMEOUT);

	if (unlikely(!res || (unsigned long)left > MAX_SCHEDULE_TIMEOUT))
		return -EINVAL;

	/* No need to get kref, as it should be already got */
	spin_lock(&res->lock);
	if (res->user_locked) {
		spin_unlock(&res->lock);
		return -EINVAL;
	}
	spin_unlock(&res->lock);

	DO_TRACE(trace_hostres(NNP_TRACE_LOCK_ENTER,
			       1,
			       (u64)(uintptr_t)res,
			       res->readers,
			       res->dir == DMA_FROM_DEVICE));

	spin_lock(&res->lock);
	/* Check if requested access is Read Only */
	if (res->dir == DMA_FROM_DEVICE) {
		while (res->readers < 0 && left > 0) {
			NNP_ASSERT(res->readers == -1);

			spin_unlock(&res->lock);

			before = jiffies;
			ret = wait_event_interruptible_timeout(
							res->access_waitq,
							(res->readers >= 0),
							left);
			ret = GET_WAIT_EVENT_ERR(ret);
			if (unlikely(ret < 0))
				return ret;

			spin_lock(&res->lock);
			left -= jiffies - before;
		}

		if (likely(res->readers >= 0)) {
			++res->readers;
			ret = 0;
		} else {
			ret = -ETIME;
		}
	} else {
		while (res->readers != 0 && left > 0) {
			spin_unlock(&res->lock);

			before = jiffies;
			ret = wait_event_interruptible_timeout(
							res->access_waitq,
							(res->readers == 0),
							left);
			ret = GET_WAIT_EVENT_ERR(ret);
			if (unlikely(ret < 0))
				return ret;

			spin_lock(&res->lock);
			left -= jiffies - before;
		}

		if (likely(res->readers == 0)) {
			res->readers = -1;
			ret = 0;
		} else {
			ret = -ETIME;
		}
	}

	if (ret == -ETIME && timeout == 0)
		ret = -EBUSY;

	if (unlikely(ret < 0)) {
		spin_unlock(&res->lock);
		return ret;
	}

	res->user_locked = true;

	if (res->external_buf) {
		spin_unlock(&res->lock);
		ret = dma_buf_begin_cpu_access(res->buf, res->dir);
	} else {
		struct dev_mapping *m;

		list_for_each_entry(m, &res->devices, node)
			dma_sync_sg_for_cpu(m->dev, m->sgt->sgl,
					    m->sgt->orig_nents, res->dir);

		spin_unlock(&res->lock);
	}

	DO_TRACE(trace_hostres(NNP_TRACE_LOCK_EXIT,
			       1,
			       (u64)(uintptr_t)res,
			       res->readers,
			       res->dir == DMA_FROM_DEVICE));

	return ret;
}

int nnpdrv_hostres_user_unlock(struct nnpdrv_host_resource *res)
{
	if (unlikely(!res))
		return -EINVAL;

	/* No need to get kref, as it should be already got */
	spin_lock(&res->lock);
	if (!res->user_locked) {
		spin_unlock(&res->lock);
		return -EINVAL;
	}
	spin_unlock(&res->lock);

	DO_TRACE(trace_hostres(NNP_TRACE_UNLOCK_ENTER,
			       1,
			       (u64)(uintptr_t)res,
			       res->readers,
			       res->dir == DMA_FROM_DEVICE));

	spin_lock(&res->lock);
	/* Check if requested access is Read Only */
	if (res->dir == DMA_FROM_DEVICE) {
		NNP_ASSERT(res->readers > 0);
		--res->readers;
	} else {
		NNP_ASSERT(res->readers == -1);
		res->readers = 0;
	}

	res->user_locked = false;

	if (res->external_buf) {
		spin_unlock(&res->lock);
		dma_buf_end_cpu_access(res->buf, res->dir);
	} else {
		struct dev_mapping *m;

		list_for_each_entry(m, &res->devices, node)
			dma_sync_sg_for_device(m->dev, m->sgt->sgl,
					       m->sgt->orig_nents, res->dir);

		spin_unlock(&res->lock);
	}

	DO_TRACE(trace_hostres(NNP_TRACE_UNLOCK_EXIT,
			       1,
			       (u64)(uintptr_t)res,
			       res->readers,
			       res->dir == DMA_FROM_DEVICE));

	wake_up_all(&res->access_waitq);

	return 0;
}

bool nnpdrv_hostres_is_input(struct nnpdrv_host_resource *res)
{
	NNP_ASSERT(res);

	return (res->dir == DMA_TO_DEVICE || res->dir == DMA_BIDIRECTIONAL);
}

bool nnpdrv_hostres_is_output(struct nnpdrv_host_resource *res)
{
	NNP_ASSERT(res);

	return (res->dir == DMA_FROM_DEVICE || res->dir == DMA_BIDIRECTIONAL);
}

size_t nnpdrv_hostres_get_size(struct nnpdrv_host_resource *res)
{
	if (unlikely(!res))
		return 0;

	return res->size;
}

bool nnpdrv_hostres_is_usermem(struct nnpdrv_host_resource *res)
{
	NNP_ASSERT(res);

	return res->user_memory_buf;
}

static ssize_t total_hostres_size_show(struct device           *dev,
				       struct device_attribute *attr,
				       char                    *buf)
{
	ssize_t ret = 0;

	ret += snprintf(&buf[ret], PAGE_SIZE - ret, "%llu\n",
			(u64)atomic64_read(&s_total_hostres_size));

	return ret;
}
static DEVICE_ATTR_RO(total_hostres_size);

static struct attribute *nnp_host_attrs[] = {
	&dev_attr_total_hostres_size.attr,
	NULL
};

static struct attribute_group nnp_host_attrs_grp = {
		.attrs = nnp_host_attrs
};

int nnpdrv_hostres_init_sysfs(struct kobject *kobj)
{
	int ret;

	atomic64_set(&s_total_hostres_size, 0);

	ret = sysfs_create_group(kobj, &nnp_host_attrs_grp);

	return ret;
}

void nnpdrv_hostres_fini_sysfs(struct kobject *kobj)
{
	sysfs_remove_group(kobj, &nnp_host_attrs_grp);
}
