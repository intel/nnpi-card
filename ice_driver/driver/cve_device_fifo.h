/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/



#ifndef CVE_DEVICE_FIFO_H_
#define CVE_DEVICE_FIFO_H_

#include "os_interface.h"

/* number of entries in the command buffer descriptors array */
#define CVE_FIFO_ENTRIES_NR 64

/* hold FIFO info */
struct di_fifo {
	/* true iif the fifo is emtpy */
	int is_empty;

	/* command buffer descriptors. shared with the device */
	union CVE_SHARED_CB_DESCRIPTOR *cb_desc_vaddr;

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
