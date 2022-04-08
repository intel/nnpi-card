/* SPDX-License-Identifier: GPL-2.0-or-later */

/********************************************
 * Copyright (C) 2019-2021 Intel Corporation
 ********************************************/
#ifndef _NNPDRV_RINGBUF_HEAD_TAIL_H
#define _NNPDRV_RINGBUF_HEAD_TAIL_H

#include <linux/types.h>

struct nnp_ringbuf {
	u8 *buf;
	u32 ring_size;
	u32 head;
	u32 tail;
	bool is_full;
};

static inline void nnp_ringbuf_init(struct nnp_ringbuf *rb,
				    u8                 *buf,
				    u32                 size)
{
	rb->buf = buf;
	rb->ring_size = size;
	rb->head = 0;
	rb->tail = 0;
	rb->is_full = false;
}

static inline u32 nnp_ringbuf_free_bytes(struct nnp_ringbuf *rb)
{
	if (rb->is_full)
		return 0;
	else if (rb->tail >= rb->head)
		return (rb->head + rb->ring_size - rb->tail);
	else
		return (rb->head - rb->tail);
}

static inline u32 nnp_ringbuf_avail_bytes(struct nnp_ringbuf *rb)
{
	if (rb->is_full)
		return rb->ring_size;
	else if (rb->head > rb->tail)
		return (rb->tail + rb->ring_size - rb->head);
	else
		return (rb->tail - rb->head);
}

static inline void nnp_ringbuf_push(struct nnp_ringbuf *rb,
				    u8                 *buf,
				    u32                 count)
{
	u8 *dst = rb->buf + rb->tail;
	u32 t = rb->ring_size - rb->tail;

	if (t >= count) {
		memcpy(dst, buf, count);
	} else {
		memcpy(dst, buf, t);
		memcpy(rb->buf, buf + t, count - t);
	}
	rb->tail = (rb->tail + count) % rb->ring_size;
	if (rb->tail == rb->head)
		rb->is_full = true;
}

static inline void nnp_ringbuf_pop(struct nnp_ringbuf *rb,
				   u8                 *buf,
				   u32                 count)
{
	u8 *src = rb->buf + rb->head;
	u32 t = rb->ring_size - rb->head;

	if (t >= count) {
		memcpy(buf, src, count);
	} else {
		memcpy(buf, src, t);
		memcpy(buf + t, rb->buf, count - t);
	}
	rb->head = (rb->head + count) % rb->ring_size;
	rb->is_full = false;
}
#endif
