/********************************************
 * Copyright (C) 2019-2021 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/



#ifndef _LIN_MM_INTERNAL_H_
#define _LIN_MM_INTERNAL_H_

#ifdef RING3_VALIDATION
#include "linux_kernel_mock.h"
#include <stdint.h>
#include <stdint_ext.h>
#endif

#include "sph_device_regs.h"
#include "iova_allocator.h"

enum iova_partition_list {
	ICE_MEM_BASE_PARTITION = 0,
	MEM_PARTITION_LOW_4KB = ICE_MEM_BASE_PARTITION,
	MEM_PARTITION_LOW_32KB = ICE_MEM_BASE_PARTITION,
	MEM_PARTITION_LOW_32KB_HW,
	MEM_PARTITION_HIGH_32KB,
	MEM_PARTITION_HIGH_16MB,
	MEM_PARTITION_HIGH_32MB,
	MEM_PARTITION_HIGHER_32KB,
	MEM_PARTITION_HIGHER_16MB,
	MEM_PARTITION_HIGHER_32MB,
};

enum iova_page_sz_type {
	IOVA_PAGE_ALIGNMENT_LOW_32K = 0,
	IOVA_PAGE_ALIGNMENT_32K = 1,
	IOVA_PAGE_ALIGNMENT_16M = 2,
	IOVA_PAGE_ALIGNMENT_32M = 3,
	IOVA_PAGE_ALIGNMENT_MAX = 4
};


/* flags used to track the page table state */
enum page_table_flags {
	PAGES_ADDED_TO_PAGE_TABLE = BIT(0),
	PAGES_REMOVED_FROM_PAGE_TABLE = BIT(1),
};

struct ice_lin_mm_buf_config {
	/*
	 * holds the index of the llc policy in
	 * the AXI attribute table
	 */
	u32 llc_policy;
	/* permissions */
	u32 prot;
	/* partition from which the ICE VA is allocated */
	enum iova_partition_list partition_id;
};

struct ice_mmu_config {
	/* ICE PT Width[L2][in bits] within ICE VA width [10-4]*/
	u8 l2_width;
	/* ICE page shift [12-22]*/
	u8 page_shift;
	/* ICE VA start range */
	u64 va_start;
	/* ICE VA end range */
	u64 va_end;
	/* ICE Page Size*/
	u32 page_sz;
	/* PDE index for start VA */
	u32 pde_start_idx;
	/* PDE index for end VA */
	u32 pde_end_idx;
};

/* holds page table management data */
struct cve_lin_mm_domain {
	u8 id;
	/* DMA handle of the page directory */
	struct cve_dma_handle pgd_dma_handle;
	/* host virtual address of page directory */
	pt_entry_t *pgd_vaddr;
	/*
	 * a shadow L1 page that holds the virtual addresses of the L2 pages
	 * so that the host can reach them
	 */
	pt_entry_t **virtual_l1;
	/* virtual-address allocator object */
	cve_iova_allocator_handle_t iova_allocator[ICE_MEM_MAX_PARTITION];
	/* flags used to track the page table state */
	enum page_table_flags pt_state;
	/* MMU config, dynamic parameters for MMU configurations */
	struct ice_mmu_config mmu_config[ICE_MEM_MAX_PARTITION];
	u32 page_sz_reg_config_arr[ICE_PAGE_SZ_CONFIG_REG_COUNT];
};

/*
 * destroys a memory domain
 * inputs : domain - the cve domain
 * outputs:
 * returns:
 */
void lin_mm_domain_destroy(struct cve_lin_mm_domain *cve_domain);

/*
 * map a page in the page table of the given memory domain
 * inputs :
 *      adom - the cve domain
 *      ice_va - device's virtual address where the page will be mapped.
 *                 the offset into the page is cleared
 *      dma_addr - the address which the device sees.
 *                 the offset into the page is cleared by the function
 *      size - size, in bytes, of the memory to map
 *      buf_meta_data - pointer to a buffer's meta data information
 *
 * outputs:
 * returns: 0 on success, a negative error code on failure
 */
int lin_mm_map(struct cve_lin_mm_domain *adom,
		ice_va_t ice_va,
		cve_dma_addr_t dma_addr,
		size_t size_bytes,
		struct ice_lin_mm_buf_config *buf_meta_data);

/*
 * unmap a range of address in the device's page table
 * inputs :
 *      adom - the cve domain
 *      ice_va - base address of the range to be unmapped in device's
 *                  virtual address
 *      cve_pages_nr - number of pages to free
 *      partition_id - partition  id from where the VA ws allocated
 * outputs:
 * returns:
 */
void lin_mm_unmap(struct cve_lin_mm_domain *adom,
		ice_va_t ice_va,
		u32 cve_pages_nr,
		u8 partition_id);

void cve_page_table_dump(struct cve_lin_mm_domain *adom);

#endif /* _LIN_MM_INTERNAL_H_ */
