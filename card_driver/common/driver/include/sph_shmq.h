/********************************************
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#ifndef _SPH_SHMQ_Q_H
#define _SPH_SHMQ_Q_H

#include <linux/delay.h>
#include <linux/types.h>
#include <linux/atomic.h>
#include <linux/io.h>
#include <sph_debug.h>

/**
 * sph_shmq is an implementatoin of a simple queue using a ring buffer in memory.
 * There are *no* locking implemented in the queue - if needed locking should be handled
 * by the caller.
 * It is also assumes that the client will not call to push an element to the queue before
 * checking there is a room for it. Also that the client check if there is element ready to
 * pop before reading it.
 */

// -O0 needed for card(arc)
#pragma GCC push_options
#pragma GCC optimize("O0")

#define sph_shmq_magic 0x514d48535f687073LLU /* the value of 'sph_SHMQ' */

#ifdef SPH_SHMQ_IN_MMIO

#define _SPH_SHMQ_SET32(lhs, rhs) iowrite32((rhs), &(lhs))
// Wait after write until the value is actually updated(needed for host)
#define SPH_SHMQ_SET32(lhs, rhs)					\
	do {								\
		volatile u32 const __tmp_shmq = (rhs);	/* SPH_IGNORE_STYLE_CHECK */ \
		unsigned int i;						\
									\
		_SPH_SHMQ_SET32((lhs), __tmp_shmq);			\
		mb();							\
		for (i = 0; __tmp_shmq != SPH_SHMQ_READ32((lhs)) && i < 200000; ++i) \
			udelay(5);					\
		SPH_ASSERT(__tmp_shmq == SPH_SHMQ_READ32((lhs)));	\
	} while (0)

#define SPH_SHMQ_SET64(lhs, rhs)					      \
	do {								      \
		SPH_SHMQ_SET32(*(u32 *)&(lhs), lower_32_bits((rhs)));	      \
		SPH_SHMQ_SET32(*(((u32 *)&(lhs)) + 1), upper_32_bits((rhs))); \
	} while (0)


#ifdef _DEBUG
static inline u32 _SPH_SHMQ_READ32(u32 *m)
{
	u32 __tmp_shmq_r = ioread32(m);

	//ioread returns all 1's if error occurs.
	SPH_ASSERT(__tmp_shmq_r != 0xffffffff);

	return __tmp_shmq_r;
}
#else
#define _SPH_SHMQ_READ32(m) (ioread32((m)))
#endif

#define SPH_SHMQ_READ32(m) _SPH_SHMQ_READ32(&(m))
#define SPH_SHMQ_READ64(m) (((u64)_SPH_SHMQ_READ32((u32 *)&(m))) | (u64)(_SPH_SHMQ_READ32(((u32 *)&(m)) + 1)) << 32)
#define SPH_SHMQ_READ_MSG(m) (((u64)ioread32(&(m))) | (u64)(ioread32(((u32 *)(&(m))) + 1)) << 32)

#else
#define _SPH_SHMQ_SET32(lhs, rhs) ((lhs) = (rhs))
#define SPH_SHMQ_SET32(lhs, rhs) _SPH_SHMQ_SET32(lhs, rhs)
#define SPH_SHMQ_SET64(lhs, rhs) ((lhs) = (rhs))
#define SPH_SHMQ_READ32(m) (m)
#define SPH_SHMQ_READ64(m) (m)
#define SPH_SHMQ_READ_MSG(m) SPH_SHMQ_READ64(m)
#endif

/**
 * sph_shmq_header - structure included as a header in the shm area.
 */
#pragma pack(push, 1)
struct sph_shmq_header {
	u64 magic;      /**< magic number to identify the shmq object */
	u32 elemSize;   /**< size of an element in the queue          */
	u32 ringSize;   /**< number of elements allocated in the ring */
	u32 head;       /**< index of the next element to pop         */
	u32 tail;       /**< index of the next element to push        */
	u32 markedFull; /**< the producer marked the queue full, consumer should notify */
};
#pragma pack(pop)

/**
 * sph_shmq - structure of the shmq object
 */
struct sph_shmq {
	u32 elemSize;		     /**< size of an element in the queue */
	u32 ringSize;		     /**< number of elements allocated in ring */
	struct sph_shmq_header *hdr; /**< pointer to the ring header */
	unsigned char *ring;         /**< pointer to the ring buffer */
};

/**
 * sph_shmq_memsize - returns the memory size needed for the ring
 */
#define sph_shmq_memsize(numElem, elemSize) \
	(sizeof(struct sph_shmq_header) + ((numElem) + 1) * (elemSize))

/**
 * sph_shmq_init - initialize the given sph_shmq object with an empty queue
 *    on the givven memory pointed by memptr. The memory pointer should point to a
 *    memory block which is big enough to hold the ring, based on shh_shmq_memsize.
 */
static inline void sph_shmq_init(struct sph_shmq *q, u32 numElem, u32 elementSize, void *memptr)
{
	q->hdr = (struct sph_shmq_header *)memptr;
	q->ring = (unsigned char *)(q->hdr + 1);
	q->elemSize = elementSize;
	q->ringSize = numElem + 1;
	SPH_SHMQ_SET64(q->hdr->magic, sph_shmq_magic);
	SPH_SHMQ_SET32(q->hdr->elemSize, elementSize);
	SPH_SHMQ_SET32(q->hdr->ringSize, numElem + 1);
	SPH_SHMQ_SET32(q->hdr->head, 0);
	SPH_SHMQ_SET32(q->hdr->tail, 0);
	SPH_SHMQ_SET32(q->hdr->markedFull, 0);
	wmb();
}

/**
 * sph_shmq_is_validq - returns true if the memory pointer points to  valid
 *    initialized sph_shmq ring.
 */
static inline bool sph_shmq_is_validq(void *memptr)
{
	return memptr && (SPH_SHMQ_READ64(((struct sph_shmq_header *)memptr)->magic) == sph_shmq_magic);
}

/**
 * sph_shmq_attach - initialize the givven sph_shmq object with the ring q pointed by
 *      the memptr pinter without initializing the queue to an empty state.
 */
static inline void sph_shmq_attach(struct sph_shmq *q, void *memptr)
{
	q->hdr = (struct sph_shmq_header *)memptr;
	q->ring = (unsigned char *)(q->hdr + 1);
	rmb();
	q->elemSize = SPH_SHMQ_READ32(q->hdr->elemSize);
	q->ringSize = SPH_SHMQ_READ32(q->hdr->ringSize);
}

/**
 * sph_shmq_num_free_elements - returns the number of elements that can be pushed into
 *      the queue before it becomes full.
 */
static inline u32 sph_shmq_num_free_elements(struct sph_shmq *q)
{
	rmb();
	return (SPH_SHMQ_READ32(q->hdr->head) + q->ringSize - 1
		- SPH_SHMQ_READ32(q->hdr->tail)) % q->ringSize;
}

/**
 * sph_shmq_num_avail_elements - returns the number of elements that exist in the queue and
 * can be popped from the queue before it becomes empty.
 */
static inline u32 sph_shmq_num_avail_elements(struct sph_shmq *q)
{
	rmb();
	return (SPH_SHMQ_READ32(q->hdr->tail) + q->ringSize
		- SPH_SHMQ_READ32(q->hdr->head)) % q->ringSize;
}

/**
 * sph_shmq_is_marked_full - check if the producer marked the queue as being full and
 *    needs the consumer to notify him after consuming some entries.
 */
static inline bool sph_shmq_is_marked_full(struct sph_shmq *q)
{
	rmb();
	return SPH_SHMQ_READ32(q->hdr->markedFull) != 0;
}

/**
 * sph_shmq_set_full_mark - sets the full mark status - set by the producer, reset by the
 *     consumer.
 */
static inline void sph_shmq_set_full_mark(struct sph_shmq *q, bool isFull)
{
	rmb();
	if (isFull)
		_SPH_SHMQ_SET32(q->hdr->markedFull, SPH_SHMQ_READ32(q->hdr->markedFull) + 1);
	else if (q->hdr->markedFull > 0)
		_SPH_SHMQ_SET32(q->hdr->markedFull, SPH_SHMQ_READ32(q->hdr->markedFull) - 1);
	wmb();
}

/**
 * sph_shmq_push_u64 - pushes a a 64-bit element into the queue head.
 *     The function assume that there
 *     is space in the queue for the element.
 */
static inline void sph_shmq_push_u64(struct sph_shmq *q, u64 elem)
{
	u64 *ptr;

	SPH_ASSERT(q->elemSize >= 8);
	rmb();
	ptr = (u64 *)(q->ring + SPH_SHMQ_READ32(q->hdr->tail) * 8);
	mb();
	SPH_SHMQ_SET64(*ptr, elem);
	SPH_SHMQ_SET32(q->hdr->tail, (SPH_SHMQ_READ32(q->hdr->tail) + 1) % q->ringSize);
	wmb();
}

/**
 * sph_shmq_pop_u64 - same as sph_shmq_pop for queue with element size of 8 bytes
 */
static inline void sph_shmq_pop_u64(struct sph_shmq *q, u64 *elem)
{
	u64 *ptr;

	SPH_ASSERT(q->elemSize >= 8);
	rmb();
	ptr = (u64 *)(q->ring + SPH_SHMQ_READ32(q->hdr->head) * 8);
	rmb();
	*elem = SPH_SHMQ_READ_MSG(*ptr);
	SPH_SHMQ_SET32(q->hdr->head, (SPH_SHMQ_READ32(q->hdr->head) + 1) % q->ringSize);
	wmb();
}

#pragma GCC pop_options

#endif //of _SPH_SHMQ_Q_H
