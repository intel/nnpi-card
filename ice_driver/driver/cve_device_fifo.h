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

static inline u32 fifo_ptr_distance(u32 head,
		u32 tail,
		u32 size)
{
	u32 distance = (head >= tail) ? size - head + tail : tail - head;
	return distance;
}

#endif /* CVE_DEVICE_FIFO_H_ */
