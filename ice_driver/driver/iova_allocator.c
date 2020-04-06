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

#ifdef RING3_VALIDATION
#include <stdio.h>
#include <errno.h>
#else
#include <linux/errno.h>
#endif
#include "iova_allocator.h"
#include "doubly_linked_list.h"
#include "cve_driver_internal.h"

/* DATA TYPES */

/* a range of iova */
struct ia_node {
	/* links to the list of nodes in the allocator */
	struct cve_dle_t list;
	/* first page frame in the range */
	u32 start;
	/* last page frame in the range (actually one pass it) */
	u32 end;
};

/* allocator */
struct ia_allocator {
	/* the lowest iova that can be allocated (as page frame index) */
	u32 bottom;
	/* the highest iova (page frame index) that can be allocated */
	u32 top;
	/* list of free ranges */
	struct ia_node *free_list;
};

/* MODULE LEVEL VARIABLES */

/* INTERNAL FUNCTIONS */

/*
 * initialize the allocator's free
 * list with a single node that holds the given range
 * inputs :
 *	allocator -
 *	start - the lowest iova that can be
 *			allocated (as page frame index)
 *	end -	the highest iova (page frame index)
 *			that can be allocated (address
 *			of the first page above the
 *			available region)
 *	outputs:
 * returns: 0 on success, a negative error code on failure
 */
static int init_allocator_list(struct ia_allocator *allocator,
		u32 start,
		u32 end)
{
	struct ia_node *node = NULL;
	int retval = OS_ALLOC_ZERO(sizeof(*node),
			(void **)&node);

	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"OS_ALLOC_ZERO failed %d\n", retval);
		goto out;
	}

	node->start = start;
	node->end = end;
	cve_dle_add_to_list_after(allocator->free_list, list, node);

	retval = 0;
out:
	return retval;
}

/* INTERFACE FUNCTIONS */

int cve_iova_allocator_init(u32 bottom,
		u32 top,
		cve_iova_allocator_handle_t *out_allocator)
{
	struct ia_allocator *allocator = NULL;
	int retval = OS_ALLOC_ZERO(sizeof(*allocator),
			(void **)&allocator);

	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"OS_ALLOC_ZERO failed %d\n", retval);
		goto out;
	}

	retval = init_allocator_list(allocator, bottom, top);
	if (retval != 0) {
		cve_os_log_default(CVE_LOGLEVEL_ERROR,
				"init_allocator_list failed %d\n", retval);
		goto out;
	}
	allocator->bottom = bottom;
	allocator->top = top;

	*out_allocator = allocator;
	retval = 0;
out:
	if (retval < 0) {
		if (allocator)
			OS_FREE(allocator, sizeof(*allocator));
	}
	return retval;
}

int cve_iova_alloc(cve_iova_allocator_handle_t _allocator,
		u32 cve_pages_nr,
		u32 *out_first_page_iova)
{
	struct ia_allocator *allocator = (struct ia_allocator *)_allocator;
	struct ia_node *free_node = allocator->free_list;
	int retval = CVE_DEFAULT_ERROR_CODE;
	u32 first_page_iova;
	int found = 0;

	if (cve_pages_nr == 0) {
		cve_os_log_default(CVE_LOGLEVEL_ERROR,
				"illegal number of pages %u\n", cve_pages_nr);
		retval = -EINVAL;
		goto out;
	}

	cve_iova_print_free_list(allocator);

	if (free_node) {
		do {
			u32 node_pages_nr =
					free_node->end - free_node->start;

			if (free_node->end <= free_node->start) {
				cve_os_log_default(CVE_LOGLEVEL_ERROR,
						"start=%u end=%u\n",
						free_node->start,
						free_node->end);
			}
			ASSERT(free_node->end > free_node->start);
			if (node_pages_nr >= cve_pages_nr) {
				u32 new_node_pages_nr =
						node_pages_nr - cve_pages_nr;
				found = 1;
				/* remove the range from the free list */
				first_page_iova = free_node->start;
				if (new_node_pages_nr == 0) {
					cve_dle_remove_from_list(
							allocator->free_list,
							list,
							free_node);
					OS_FREE(free_node,
							sizeof(*free_node));
				} else {
					free_node->start += cve_pages_nr;
				}
			}
			if (!found)
				free_node = cve_dle_next(free_node, list);
		} while (!found && free_node != allocator->free_list);
	}

	if (!found) {
		retval = -ICEDRV_KERROR_IOVA_NOMEM;
		goto out;
	}

	/* success */
	*out_first_page_iova = first_page_iova;
	cve_os_log(CVE_LOGLEVEL_DEBUG,
			"[IOVA] Allocated %u pages starting from 0x%x\n",
			cve_pages_nr, first_page_iova);

	cve_iova_print_free_list(allocator);

	retval = 0;
out:
	return retval;
}

int cve_iova_claim(cve_iova_allocator_handle_t _allocator,
		u32 first_page_iova,
		u32 cve_pages_nr)
{
	struct ia_allocator *allocator = (struct ia_allocator *)_allocator;
	int retval = -ICEDRV_KERROR_IOVA_NOMEM;

	if (cve_pages_nr == 0) {
		cve_os_log(CVE_LOGLEVEL_DEBUG,
				"illegal number of pages %u\n", cve_pages_nr);
		retval = -ICEDRV_KERROR_IOVA_INVALID_PAGE_COUNT;
		goto out;
	}

	cve_iova_print_free_list(allocator);

	if (!allocator->free_list) {
		retval = -ICEDRV_KERROR_IOVA_NOMEM;
		goto out;
	} else {
		int done = 0;
		struct ia_node *freenode = allocator->free_list;
		u32 start = first_page_iova;
		u32 end = first_page_iova + cve_pages_nr;

		do {
			if ((freenode->start <= start) &&
					(freenode->end >= end)) {
				if ((start == freenode->start) &&
						(end == freenode->end)) {
					cve_dle_remove_from_list(
							allocator->free_list,
							list, freenode);
					OS_FREE(freenode,
							sizeof(*freenode));
				} else if ((start == freenode->start) &&
						(end < freenode->end)) {
					freenode->start = end;
				} else if ((start > freenode->start) &&
						(end == freenode->end)) {
					freenode->end = start;
					/* start > freenode->start
					 * && end < freenode->end
					 */
				} else {
					struct ia_node *new_node = NULL;

					retval = OS_ALLOC_ZERO(
							sizeof(*new_node),
							(void **)&new_node);
					if (retval != 0) {
						cve_os_log(CVE_LOGLEVEL_ERROR,
								"OS_ALLOC_ZERO failed %d\n"
								, retval);
						goto out;
					}
					new_node->start = end;
					new_node->end = freenode->end;
					cve_dle_add_to_list_after(
							freenode, list,
							new_node);
					freenode->end = start;
				}
				done = 1;
				retval = 0;
			} else {
				freenode = cve_dle_next(freenode, list);
			}
		} while (!done && (freenode != allocator->free_list));
	}

	cve_os_log(CVE_LOGLEVEL_DEBUG,
			"[IOVA] Claimed %u pages starting from 0x%x\n",
			cve_pages_nr, first_page_iova);

	cve_iova_print_free_list(allocator);

out:
	return retval;
}

int cve_iova_free(cve_iova_allocator_handle_t _allocator,
		u32 first_page_iova,
		u32 cve_pages_nr)
{
	struct ia_allocator *allocator =
			(struct ia_allocator *)_allocator;
	int retval = CVE_DEFAULT_ERROR_CODE;

	cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Freeing %u pages starting from 0x%x\n",
			cve_pages_nr, first_page_iova);

	cve_iova_print_free_list(allocator);

	if (cve_pages_nr == 0) {
		cve_os_log_default(CVE_LOGLEVEL_ERROR,
				"illegal number of pages %u\n", cve_pages_nr);
		retval = -EINVAL;
		goto out;
	}

	if ((first_page_iova < allocator->bottom) ||
			(first_page_iova + cve_pages_nr > allocator->top)) {
		cve_os_log_default(CVE_LOGLEVEL_ERROR,
				"range out of bound %u(%u)\n"
				, first_page_iova, cve_pages_nr);
		retval = -EINVAL;
		goto out;
	}

	if (!allocator->free_list) {
		/* case 0) free list is empty
		 * - init the list with a newly
		 * created node
		 */
		retval = init_allocator_list(allocator,
				first_page_iova,
				first_page_iova + cve_pages_nr);
		if (retval != 0) {
			cve_os_log_default(CVE_LOGLEVEL_ERROR,
					"init_allocator_list failed %d\n"
					, retval);
			goto out;
		}
	} else {
		/* look for the right place to insert the new range.
		 * the free list is sorted by 'start', and the ranges are
		 * distinct. so consequently it is sorted by 'end' too
		 */
		int done = 0;
		struct ia_node *next = allocator->free_list;
		struct ia_node *prev = NULL;
		u32 start = first_page_iova;
		u32 end = first_page_iova + cve_pages_nr;

		do {
			if ((!prev) &&
					(next) &&
					(end < next->start)) {
				/* create a new node
				 * and add it to the free list
				 */
				struct ia_node *new_node = NULL;

				retval = OS_ALLOC_ZERO(sizeof(*new_node)
						, (void **)&new_node);

				if (retval != 0) {
					cve_os_log(CVE_LOGLEVEL_ERROR,
							"OS_ALLOC_ZERO failed %d\n"
							, retval);
					goto out;
				}
				new_node->start = start;
				new_node->end = end;
				cve_dle_add_to_list_before(
						next, list, new_node);
				allocator->free_list = new_node;
				done = 1;
			} else if ((!prev) &&
					(next) &&
					(end == next->start)) {
				/* merge the reclaimed
				 * range with the next node
				 */
				next->start = start;
				done = 1;
			} else if ((prev) &&
					(next) &&
					(start == prev->end) &&
					(end < next->start)) {
				/* merge the reclaimed
				 * range with the prev node
				 */
				prev->end = end;
				done = 1;
			} else if ((prev) &&
					(next) &&
					(start > prev->end) &&
					(end < next->start)) {
				/* create a new node and
				 * add it to the free list
				 */
				struct ia_node *new_node = NULL;

				retval = OS_ALLOC_ZERO(sizeof(*new_node),
						(void **)&new_node);
				if (retval != 0) {
					cve_os_log(CVE_LOGLEVEL_ERROR,
							"OS_ALLOC_ZERO failed %d\n",
							retval);
					goto out;
				}
				new_node->start = start;
				new_node->end = end;
				cve_dle_add_to_list_after(prev, list, new_node);
				done = 1;
			} else if ((prev) &&
					(next) &&
					(start == prev->end) &&
					(end == next->start)) {
				/* merge 2 nodes and
				 * free one of them
				 */
				prev->end = next->end;
				cve_dle_remove_from_list(
						allocator->free_list,
						list, next);
				OS_FREE(next, sizeof(*next));
				done = 1;
			} else if ((prev) &&
					(next) &&
					(start > prev->end) &&
					(end == next->start)) {
				/* merge the reclaimed
				 * range with the next node
				 */
				next->start = start;
				done = 1;
			} else if ((prev) &&
					(!next)	&&
					(start == prev->end)) {
				/* merge the reclaimed
				 * range with the prev node
				 */
				prev->end = end;
				done = 1;
			} else if ((prev) &&
					(!next)	&&
					(start > prev->end)) {
				/* create a new node and
				 * add it to the free list
				 */
				struct ia_node *new_node = NULL;

				retval = OS_ALLOC_ZERO(sizeof(*new_node),
						(void **)&new_node);
				if (retval != 0) {
					cve_os_log(CVE_LOGLEVEL_ERROR,
							"OS_ALLOC_ZERO failed %d\n",
							retval);
					goto out;
				}
				new_node->start = start;
				new_node->end = end;
				cve_dle_add_to_list_after(prev, list, new_node);
				done = 1;
			} else if ((next) &&
					(start <= next->start) &&
					(end > next->start)) {
				/* trying to reclaim a
				 * region that is already free
				 */
				cve_os_log_default(CVE_LOGLEVEL_ERROR,
						"reclaiming non-distinct region 1 %u(%u)\n",
						first_page_iova,
						cve_pages_nr);
				retval = -EINVAL;
				goto out;
			} else if ((prev) &&
					(start < prev->end) &&
					(end >= prev->start)) {
				/* trying to reclaim a
				 * region that is already free
				 */
				cve_os_log_default(CVE_LOGLEVEL_ERROR,
						"reclaiming non-distinct region 2 %u(%u)\n",
						first_page_iova,
						cve_pages_nr);
				retval = -EINVAL;
				goto out;
			} else {
				prev = next;
				if (next) {
					next = cve_dle_next(next, list);
					if (next == allocator->free_list)
						next = NULL;
				}
			}
		} while (!done && (prev));
	}

	cve_iova_print_free_list(allocator);

	retval = 0;
out:
	return retval;
}

int cve_iova_copy_free_list(
		cve_iova_allocator_handle_t dest_allocator,
		cve_iova_allocator_handle_t source_allocator)
{
	struct ia_allocator *pinput_allocator =
			(struct ia_allocator *)source_allocator;
	struct ia_allocator *poutput_allocator =
			(struct ia_allocator *)dest_allocator;
	int retval = -EBUSY;

	/* remove all nodes from destination allocator */
	if (poutput_allocator->free_list) {
		struct cve_dle_t *ne = &poutput_allocator->free_list->list;
		struct cve_dle_t *e = NULL;

		do {
			e = ne;
			ne = cve_dle_remove(e);
			OS_FREE(e->container,
					sizeof(struct ia_node));
		} while (ne != e);
		poutput_allocator->free_list = NULL;
	}

	/* copy source nodes to destination allocator */
	if (pinput_allocator->free_list) {
		struct ia_node *source_node = pinput_allocator->free_list;

		do {
			struct ia_node *new_node = NULL;

			retval = OS_ALLOC_ZERO(sizeof(*new_node),
					(void **)&new_node);
			if (retval != 0) {
				cve_os_log(CVE_LOGLEVEL_ERROR,
						"OS_ALLOC_ZERO failed %d\n"
						, retval);
				goto out;
			}
			new_node->start = source_node->start;
			new_node->end = source_node->end;
			cve_dle_add_to_list_before(poutput_allocator->free_list,
					list,
					new_node);
			source_node = cve_dle_next(source_node, list);
		} while (source_node != pinput_allocator->free_list);
	}

	retval = 0;
out:
	return retval;
}

void cve_iova_allocator_destroy(cve_iova_allocator_handle_t *pallocator)
{
	struct ia_allocator *allocator = (struct ia_allocator *)*pallocator;

	/* "allocator" is Null for InferDomain */
	if (!allocator)
		return;

	if (allocator->free_list) {
		struct cve_dle_t *ne = &allocator->free_list->list;
		struct cve_dle_t *e = NULL;

		do {
			e = ne;
			ne = cve_dle_remove(e);
			if (ne != e) {
				OS_FREE(e->container,
					sizeof(struct ia_node));
			}
		} while (ne != e);
		/* release the anchor node */
		OS_FREE(allocator->free_list, sizeof(struct ia_node));
		allocator->free_list = NULL;
	}

	OS_FREE(allocator, sizeof(*allocator));
	*pallocator = NULL;
}

#if defined _DEBUG  && defined RING3_VALIDATION && defined PRINT_IOVA
void cve_iova_print_free_list(cve_iova_allocator_handle_t _allocator)
{
	struct ia_allocator *allocator = (struct ia_allocator *)_allocator;

	printf("%s> allocator=%p: ", __func__, allocator);
	if (allocator->free_list) {
		struct ia_node *node = allocator->free_list;

		do {
			printf("%s> %x-%x, node: %p | ", __func__,
					node->start, node->end, node);
			node = cve_dle_next(node, list);
		} while (node != allocator->free_list);
		printf("\n");
	} else {
		printf("%s> empty list\n", __func__);
	}
}
#endif
