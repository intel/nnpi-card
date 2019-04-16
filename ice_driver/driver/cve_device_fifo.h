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

#ifndef CVE_DEVICE_FIFO_H_
#define CVE_DEVICE_FIFO_H_

#include "os_interface.h"
#include <cve_hw_forSw.h>

/* number of entries in the command buffer descriptors array */
#define CVE_FIFO_ENTRIES_NR 64

/* hold FIFO info */
struct di_fifo {
	/* true iif the fifo is emtpy */
	int is_empty;

	/* command buffer descriptors. shared with the device */
	union cve_shared_cb_descriptor *cb_desc_vaddr;

	/*size*/
	u32 size_bytes;

	/* holds number of fifo entries */
	u32 entries;

	/* descriptor's DMA handle */
	struct cve_dma_handle cb_desc_dma_handle;

	/* fifo head and tail for the dispatched cb_desc (SHARED WITH THE HW)
	 * MUST be modified only with utility functions:
	 * fifo_head_increment, fifo_tail_increment, fifo_reset
	 * when dispatching a command-buffer, this is next desc to use
	 */
	u32 head;

	/* when receiving a completion interrupt this is the
	 * first desc that was dispatched and not yet completed
	 */
	u32 tail;

	/* 1 iff the currently executing job will be completed when
	 * the next completion interrupt is received. in case of jobs
	 * with large number of command buffers, it is possible that
	 * not all the commands buffers are dispatched at once, and the
	 * completion interrupt from the device will be received while
	 * the job has still more command buffers that need
	 * to be dispatched
	 */
	int is_final;
};

static inline u32 fifo_ptr_add(u32 fifo_ptr, u32 addend, u32 fifo_entries)
{
	ASSERT(addend < fifo_entries);
	return (fifo_ptr + addend) % fifo_entries;
}

static inline u32 fifo_ptr_sub(u32 fifo_ptr, u32 subtrahend, u32 fifo_entries)
{
	ASSERT(subtrahend < fifo_entries);
	return (subtrahend <= fifo_ptr)  ? fifo_ptr - subtrahend :
		fifo_ptr - subtrahend + fifo_entries;
}

static inline void fifo_head_increment(struct di_fifo *fifo)
{
	fifo->head = fifo_ptr_add(fifo->head, 1, fifo->entries);
	fifo->is_empty = 0;
}

static inline void fifo_tail_increment(struct di_fifo *fifo)
{
	fifo->tail = fifo_ptr_add(fifo->tail, 1, fifo->entries);
	fifo->is_empty = !!(fifo->tail == fifo->head);
}

static inline int fifo_is_full(struct di_fifo *fifo)
{
	int is_full = !fifo->is_empty && (fifo->tail == fifo->head);
	return is_full;
}

static inline u32 fifo_ptr_distance(u32 head,
		u32 tail,
		u32 size)
{
	u32 distance = (head >= tail) ? size - head + tail : tail - head;
	return distance;
}

static inline u32 fifo_free_slots_nr(struct di_fifo *fifo)
{
	u32 free_slots_nr;

	if (fifo->is_empty)
		free_slots_nr = fifo->entries;
	else if (fifo->tail == fifo->head)
		free_slots_nr = 0;
	else if (fifo->tail > fifo->head)
		free_slots_nr = fifo->tail - fifo->head;
	else
		free_slots_nr = fifo->tail + fifo->entries - fifo->head;

	ASSERT((free_slots_nr > 0) || fifo_is_full(fifo));
	return free_slots_nr;
}

static inline void do_fifo_reset(struct di_fifo *fifo)
{
	fifo->tail = 0;
	fifo->head = 0;
	fifo->is_empty = 1;
}

static inline void fifo_set_empty(struct di_fifo *fifo)
{
	fifo->tail = fifo->head;
	fifo->is_empty = 1;
}

#endif /* CVE_DEVICE_FIFO_H_ */
