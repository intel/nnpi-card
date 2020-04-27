/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/



#ifndef _IOVA_ALLOCATOR_H_
#define _IOVA_ALLOCATOR_H_

#ifdef RING3_VALIDATION
#  include <stdint.h>
#else
#  include <linux/types.h>
#endif

#include "cve_driver_internal.h"

#define IOVA_TO_VADDR(_iova, page_shift) ((u64)(_iova) << (u64)page_shift)
#define VADDR_TO_IOVA(_vaddr, page_shift) ((_vaddr) >> page_shift)

typedef void *cve_iova_allocator_handle_t;

struct ice_iova_desc {
	/* LLC policy */
	u32 llc_policy;
	/* represents the partion used to allocate the VA */
	u8 partition_id;
	/* if enabled, allocate VA from higher address space i.e. above 4GB*/
	u8 alloc_higher_va;
	/* Page size alignment requirement */
	u32 page_sz;
	/* Page size alignment requirement */
	u8 page_shift;
	/* va allocated */
	u64 va;
};

/*
 * initialize an iova allocator
 * inputs : bottom - the lowest iova that can be allocated (as page frame index)
 *          top - the highest iova (page frame index) that can be allocated
 *              (address of the first page above the available region)
 * outputs: out_allocator - will hold the allocator handle
 * returns: 0 on success, a negative error code on failure
 */
int cve_iova_allocator_init(u32 bottom,
		u32 top,
		cve_iova_allocator_handle_t *out_allocator);

/*
 * get a range of free iova
 * inputs :	allocator - a handle to the allocator
 *          cve_pages_nr - number of pages to allocate
 * outputs: out_first_page_iova - will hold the iova of the first page
 * returns: 0 on success, a negative error code on faillure
 */
int cve_iova_alloc(cve_iova_allocator_handle_t allocator,
		u32 cve_pages_nr,
		u32 *out_first_page_iova);

/*
 * allocate the given range of iova
 * inputs :	allocator - a handle to the allocator
 *          first_page_iova - the range's base address
 *          cve_pages_nr - number of pages to allocate
 * outputs:
 * returns: 0 on success, a negative error code on faillure
 */
int cve_iova_claim(cve_iova_allocator_handle_t allocator,
		u32 first_page_iova,
		u32 cve_pages_nr);

/*
 * free a range of iova
 * inputs :	allocator - a handle to the allocator
 *          first_page_iova - the iova of the first page
 *          cve_pages_nr - number of pages to free
 * outputs:
 * returns: 0 on success, a negative error code on failure
 */
int cve_iova_free(cve_iova_allocator_handle_t allocator,
		u32 first_page_iova,
		u32 cve_pages_nr);

/*
 * copy iova free list
 * inputs : dest_allocator - handle to the destination allocator
 *          source_allocator - handle to the source allocator
 * outputs:
 * returns: 0 on success, a negative error code on failure
 */
int cve_iova_copy_free_list(cve_iova_allocator_handle_t dest_allocator,
		cve_iova_allocator_handle_t source_allocator);

/*
 * reclaims all the resources taken by an iova allocator
 * inputs :	allocator - a pointer to the allocator's handle
 * outputs:
 * returns:
 */
void cve_iova_allocator_destroy(cve_iova_allocator_handle_t *pallocator);

#if defined _DEBUG  && defined RING3_VALIDATION && defined PRINT_IOVA
void cve_iova_print_free_list(cve_iova_allocator_handle_t allocator);
#else
#define cve_iova_print_free_list(input)
#endif

#endif /* _IOVA_ALLOCATOR_H_ */
