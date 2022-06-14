/* SPDX-License-Identifier: GPL-2.0-or-later */

/********************************************
 * Copyright (C) 2019-2021 Intel Corporation
 ********************************************/

#ifndef _NNPDRV_IDR_ALLOCATOR_H
#define _NNPDRV_IDR_ALLOCATOR_H

#include <linux/spinlock.h>
#include <linux/idr.h>
#include "nnp_debug.h"

struct nnp_proc_idr {
	struct idr idr;
	spinlock_t lock; /* protects idr modifications */
};

static inline void nnp_idr_init(struct nnp_proc_idr *idr)
{
	idr_init(&idr->idr);
	spin_lock_init(&idr->lock);
}

static inline int nnp_idr_alloc(struct nnp_proc_idr *idr, void *p)
{
	int id;

	spin_lock(&idr->lock);
	id = idr_alloc(&idr->idr, p, 1, -1, GFP_NOWAIT);
	spin_unlock(&idr->lock);

	return id;
}

static inline void *nnp_idr_get_object(struct nnp_proc_idr *idr,
				       int id,
				       bool (*fn_check_and_get)(void *))
{
	void *p;

	spin_lock(&idr->lock);
	p = idr_find(&idr->idr, id);
	NNP_ASSERT(fn_check_and_get);
	if (unlikely(!fn_check_and_get(p)))
		p = NULL;
	spin_unlock(&idr->lock);

	return p;
}

static inline void nnp_idr_remove_object(struct nnp_proc_idr *idr, int id)
{
	spin_lock(&idr->lock);
	idr_remove(&idr->idr, id);
	spin_unlock(&idr->lock);
}

static inline void *nnp_idr_check_and_remove_object(struct nnp_proc_idr *idr,
						    int                  id,
						    bool   (*fn_check)(void *))
{
	void *p;

	spin_lock(&idr->lock);
	p = idr_find(&idr->idr, id);
	if (likely(fn_check(p)))
		idr_remove(&idr->idr, id);
	else
		p = NULL;
	spin_unlock(&idr->lock);

	return p;
}

#endif
