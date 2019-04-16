/********************************************
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/
#ifndef _SPH_UTILS_H
#define _SPH_UTILS_H

#include <linux/kref.h>
#include <linux/dma-buf.h>
#include <linux/version.h>
#include "sph_debug.h"

#ifndef _LINUX_REFCOUNT_H
static inline unsigned int kref_read(const struct kref *kref)
{
	return atomic_read(&kref->refcount);
}

static inline int kref_put_lock(struct kref *kref,
				void (*release)(struct kref *kref),
				spinlock_t *lock)
{
	WARN_ON(release == NULL);
	if (unlikely(!atomic_add_unless(&kref->refcount, -1, 1))) {
		SPH_SPIN_LOCK(lock);
		if (unlikely(!atomic_dec_and_test(&kref->refcount))) {
			SPH_SPIN_UNLOCK(lock);
			return 0;
		}
		release(kref);
		return 1;
	}
	return 0;
}
#endif

#if ((LINUX_VERSION_CODE < KERNEL_VERSION(4, 6, 0)) && /* SPH_IGNORE_STYLE_CHECK */ \
	((!defined(RHEL_RELEASE_CODE)) || (RHEL_RELEASE_CODE < ((7 << 8) + 3)))) //RHEL_RELEASE_VERSION(7, 3)

static inline int sph_dma_buf_begin_cpu_access(struct dma_buf *dma_buf,
			     enum dma_data_direction dir)
{
	return dma_buf_begin_cpu_access(dma_buf, 0, dma_buf->size, dir);
}

static inline void sph_dma_buf_end_cpu_access(struct dma_buf *dma_buf,
			    enum dma_data_direction dir)
{
	dma_buf_end_cpu_access(dma_buf, 0, dma_buf->size, dir);
}

#define dma_buf_begin_cpu_access(buf, dir) (sph_dma_buf_begin_cpu_access((buf), (dir)))
#define dma_buf_end_cpu_access(buf, dir) (sph_dma_buf_begin_cpu_access((buf), (dir)))

#endif


#endif
