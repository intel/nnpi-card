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

#ifndef _IOVA_H_
#define _IOVA_H_

//#include <linux/types.h>
//#include <linux/kernel.h>
//#include <linux/rbtree.h>
//#include <linux/dma-mapping.h>
#include "rbtree.h"
#include "linux_kernel_mock.h"


/* IO virtual address start page frame number */
#define IOVA_START_PFN		(1)

/* iova structure */
struct iova {
	struct rb_node	node;
	unsigned long	pfn_hi; /* IOMMU dish out addr hi */
	unsigned long	pfn_lo; /* IOMMU dish out addr lo */
};

/* holds all the iova translations for a domain */
struct iova_domain {
	spinlock_t iova_rbtree_lock; /* Lock to protect update of rbtree */
	struct rb_root	rbroot;		/* iova domain rbtree root */
	struct rb_node	*cached32_node; /* Save last alloced node */
	unsigned long	dma_32bit_pfn;
};

void free_iova(struct iova_domain *iovad, unsigned long pfn);
void __free_iova(struct iova_domain *iovad, struct iova *iova);
struct iova *alloc_iova(struct iova_domain *iovad, unsigned long size,
	unsigned long limit_pfn,
	bool size_aligned);
struct iova *reserve_iova(struct iova_domain *iovad, unsigned long pfn_lo,
	unsigned long pfn_hi);
void copy_reserved_iova(struct iova_domain *from, struct iova_domain *to);
void init_iova_domain(struct iova_domain *iovad, unsigned long pfn_32bit);
struct iova *find_iova(struct iova_domain *iovad, unsigned long pfn);
void put_iova_domain(struct iova_domain *iovad);
struct iova *split_and_remove_iova(struct iova_domain *iovad,
	struct iova *iova, unsigned long pfn_lo, unsigned long pfn_hi);

static inline struct iova *alloc_iova_mem(void)
{
	return kzalloc(sizeof(struct iova), GFP_ATOMIC);
}

static inline void free_iova_mem(struct iova *iova)
{
	kfree(iova);
}

#endif
