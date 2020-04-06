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

#ifndef RING3_VALIDATION
#include <linux/types.h>
#include <linux/io.h>
#else
#include <stdint.h>
#include <stdint_ext.h>
#include <string.h>
#endif

#include "os_interface.h"
#include "osmm_interface.h"
#include "cve_driver_internal.h"
#include "cve_linux_internal.h"
#include "project_device_interface.h"
#include "device_interface.h"

/* CONSTANTS */

/* CVE ADDRESS FIELDS:
 * |--- L1 SIZE ---|---L2 SIZE---|---CVE PAGE_SHIFT---|
 * L1 SIZE is constant 10 bits
 * L2 SIZE and ICE_PAGE_SHIFT are depending on CVE PAGE SIZE
 */
#define ICE_VA_L1_WIDTH 10
#define ICE_VA_L2_MIN_WIDTH 4
#define ICE_VA_L2_WIDTH(page_shift) \
	(ICE_DEFAULT_VA_WIDTH - ICE_VA_L1_WIDTH - page_shift)

/* CVE ADDRESS ACCESS SHIFT and MASKS */
#define ICE_L2PT_SHIFT(page_shift) (page_shift)
#define ICE_L1PT_SHIFT (ICE_DEFAULT_VA_WIDTH - ICE_VA_L1_WIDTH)
#define ICE_L1PT_MASK (~(BIT_ULL(ICE_L1PT_SHIFT) - 1))
#define ICE_L2PT_MASK(l2_width) ((BIT_ULL(l2_width) - 1))

/* NUMBER OF PD ENTRIES and PT ENTRIES*/
#define ICE_L1PT_PTES		(1U << ICE_VA_L1_WIDTH)
#define ICE_L2PT_PTES(l2_width) (1U << l2_width)

/* ACCESS to PADDR FIELD of LT2 */
#define ICE_PADDR_BITS_NR(ice_phy_addr_width)	(ice_phy_addr_width)
#define ICE_PADDR_SHIFT		12
#define ICE_PADDR_SHIFT_EXTENDED 15
#define ICE_PADDR_MASK \
	(BIT_ULL(ICE_DEFAULT_PA_WIDTH - ICE_DEFAULT_PA_SHIFT) - 1)

#define CVE_PROT_READ_BIT_SHIFT		31
#define CVE_PROT_WRITE_BIT_SHIFT	30
#define CVE_PROT_EXEC_BIT_SHIFT		29
#define ICE_PD_BIT_SHIFT		28

#define CVE_PROT_READ_BIT		BIT(CVE_PROT_READ_BIT_SHIFT)
#define CVE_PROT_WRITE_BIT		BIT(CVE_PROT_WRITE_BIT_SHIFT)
#define CVE_PROT_EXEC_BIT		BIT(CVE_PROT_EXEC_BIT_SHIFT)
#define ICE_PD_BIT			BIT(ICE_PD_BIT_SHIFT)

#define INVALID_PAGE		((cve_dma_addr_t)0)

#define TBL_DMA_ADDR(a) \
	((cve_dma_addr_t)((a) & ICE_PADDR_MASK) << ICE_DEFAULT_PA_SHIFT)

/* first entry in the page directory is not accessible to the driver */
#define ICE_VA_LOW_FIRST_PAGE (1)
#define ICE_VA_LOW_LAST_PAGE(end_addr, page_shift) (end_addr >> page_shift)

#define ICE_VA_FIRST_PAGE(start_addr, page_shift) \
	((start_addr) ? (start_addr >> page_shift) : 1)

#define ICE_VA_LAST_PAGE(end_addr, page_shift) (end_addr >> page_shift)
#define __mmu_config_35bit_va_page_32K(config) \
do { \
	config->l2_width = ICE_VA_L2_WIDTH(ICE_PAGE_SHIFT_32K);\
	config->page_shift = ICE_PAGE_SHIFT_32K; \
	config->va_start = ICE_VA_RANGE_LOW_32KB_START; \
	config->va_end = ICE_VA_RANGE_LOW_32KB_END; \
	config->page_sz = ICE_PAGE_SZ(ICE_PAGE_SHIFT_32K); \
	config->pde_start_idx = (ICE_VA_RANGE_LOW_32KB_START/ICE_PAGE_SZ_32M); \
	config->pde_end_idx = \
	((ICE_VA_RANGE_LOW_32KB_END - 1)/ICE_PAGE_SZ_32M); \
} while (0)

#define __mmu_config_35bit_va_page_32K_hw(config) \
do { \
	config->l2_width = ICE_VA_L2_WIDTH(ICE_PAGE_SHIFT_32K);\
	config->page_shift = ICE_PAGE_SHIFT_32K; \
	config->va_start = ICE_VA_RANGE_LOW_32KB_HW_START; \
	config->va_end = ICE_VA_RANGE_LOW_32KB_HW_END; \
	config->page_sz = ICE_PAGE_SZ(ICE_PAGE_SHIFT_32K); \
	config->pde_start_idx = \
	(ICE_VA_RANGE_LOW_32KB_HW_START/ICE_PAGE_SZ_32M); \
	config->pde_end_idx = \
	((ICE_VA_RANGE_LOW_32KB_HW_END - 1)/ICE_PAGE_SZ_32M); \
} while (0)


#define __mmu_config_32bit_va_page_4K(config) \
do { \
	config->l2_width = ICE_VA_L2_WIDTH(ICE_PAGE_SHIFT_4K);\
	config->page_shift = ICE_PAGE_SHIFT_4K; \
	config->va_start = ICE_VA_RANGE_LOW_4KB_START; \
	config->va_end = ICE_VA_RANGE_LOW_4KB_END; \
	config->page_sz = ICE_PAGE_SZ(ICE_PAGE_SHIFT_4K); \
	config->pde_start_idx = (ICE_VA_RANGE_LOW_4KB_START/ICE_PAGE_SZ_4M); \
	config->pde_end_idx = \
	((ICE_VA_RANGE_LOW_4KB_END - 1)/ICE_PAGE_SZ_4M); \
} while (0)

#define __mmu_config_35bit_va_page_32K_high(config) \
do { \
	config->l2_width = ICE_VA_L2_WIDTH(ICE_PAGE_SHIFT_32K);\
	config->page_shift = ICE_PAGE_SHIFT_32K; \
	config->va_start = ICE_VA_RANGE_HIGH_32KB_START; \
	config->va_end = ICE_VA_RANGE_HIGH_32KB_END; \
	config->page_sz = ICE_PAGE_SZ(ICE_PAGE_SHIFT_32K); \
	config->pde_start_idx = \
	(ICE_VA_RANGE_HIGH_32KB_START/ICE_PAGE_SZ_32M); \
	config->pde_end_idx = \
	((ICE_VA_RANGE_HIGH_32KB_END - 1)/ICE_PAGE_SZ_32M); \
} while (0)

#define __mmu_config_35bit_va_page_16M(config) \
do { \
	config->l2_width = ICE_VA_L2_MIN_WIDTH; \
	config->page_shift = ICE_PAGE_SHIFT_16M; \
	config->va_start = ICE_VA_RANGE_HIGH_16MB_START; \
	config->va_end = ICE_VA_RANGE_HIGH_16MB_END; \
	config->page_sz = ICE_PAGE_SZ(ICE_PAGE_SHIFT_16M); \
	config->pde_start_idx = \
	(ICE_VA_RANGE_HIGH_16MB_START/ICE_PAGE_SZ_32M); \
	config->pde_end_idx = \
	((ICE_VA_RANGE_HIGH_16MB_END -  1)/ICE_PAGE_SZ_32M); \
} while (0)

#define __mmu_config_35bit_va_page_32M(config) \
do { \
	config->l2_width = ICE_VA_L2_MIN_WIDTH;\
	config->page_shift = ICE_PAGE_SHIFT_32M; \
	config->va_start = ICE_VA_RANGE_HIGH_32MB_START; \
	config->va_end = ICE_VA_RANGE_HIGH_32MB_END; \
	config->page_sz = ICE_PAGE_SZ(ICE_PAGE_SHIFT_32M); \
	config->pde_start_idx = \
	(ICE_VA_RANGE_HIGH_32MB_START/ICE_PAGE_SZ_32M); \
	config->pde_end_idx = \
	((ICE_VA_RANGE_HIGH_32MB_END - 1)/ICE_PAGE_SZ_32M); \
} while (0)

#define __mmu_config_35bit_va_page_32K_BAR1(config) \
do { \
	config->l2_width = ICE_VA_L2_WIDTH(ICE_PAGE_SHIFT_32K);\
	config->page_shift = ICE_PAGE_SHIFT_32K; \
	config->va_start = ICE_VA_RANGE_LOW_IDC_BAR1_START; \
	config->va_end = ICE_VA_RANGE_LOW_IDC_BAR1_END; \
	config->page_sz = ICE_PAGE_SZ(ICE_PAGE_SHIFT_32K); \
	config->pde_start_idx = \
	(ICE_VA_RANGE_LOW_IDC_BAR1_START/ICE_PAGE_SZ_32M); \
	config->pde_end_idx = (ICE_VA_RANGE_LOW_IDC_BAR1_END/ICE_PAGE_SZ_32M); \
} while (0)


static void __do_mmu_config(struct cve_lin_mm_domain *domain,
		 u64 *sz_per_page_alignment,
		u64 *infer_buf_page_config);
static void __config_page_sz_reg_array(struct cve_lin_mm_domain *domain);
static void __config_page_sz_for_partition(struct cve_lin_mm_domain *domain,
		u8 partition_id);
static int __alloc_new_l2_page(struct cve_lin_mm_domain *cve_domain,
		struct ice_mmu_config *mmu_config, u32 l1_idx);
static void __dealloc_l2_page(struct cve_lin_mm_domain *cve_domain,
		u32 l1_idx);


/* MODULE VARIABLES */

/* MODULE FUNCTIONS */

/*
 * logs the contents of the page table of the given domain
 * inputs : adom - the memory domain
 * outputs:
 * returns:
 */

static void __dump_pt(struct cve_lin_mm_domain *adom,
		struct ice_mmu_config *mmu_config)
{
	u32 l1_idx;

	for (l1_idx = mmu_config->pde_start_idx;
			l1_idx <= mmu_config->pde_end_idx;
			l1_idx++) {
		u32 l2_idx;
		ice_va_t ice_va_hi = (cve_dma_addr_t)l1_idx << ICE_L1PT_SHIFT;

		if (adom->pgd_vaddr[l1_idx] == INVALID_PAGE)
			continue;

		cve_os_log(CVE_LOGLEVEL_INFO,
			"JobID=%d, l1: index=%u ICEVA=0x%llx value=%8.8x; PT2 page: IAVA=%p, PA=0x%llx\n",
			adom->id,
			l1_idx,
			ice_va_hi,
			adom->pgd_vaddr[l1_idx],
			adom->virtual_l1[l1_idx],
			TBL_DMA_ADDR(adom->pgd_vaddr[l1_idx]));

		for (l2_idx = 0;
				l2_idx < ICE_L2PT_PTES(mmu_config->l2_width);
				l2_idx++) {
			pt_entry_t *l2_pt_vaddr = adom->virtual_l1[l1_idx];
			ice_va_t __maybe_unused cve_vaddr = ice_va_hi +
				(l2_idx <<
				 ICE_L2PT_SHIFT(mmu_config->page_shift));

			if (l2_pt_vaddr[l2_idx] == INVALID_PAGE)
				continue;

			cve_os_log(CVE_LOGLEVEL_INFO,
				"\tJobID=%d, l2: index=%u ICEVA=0x%llx value=%8.8x PA=%llx prot=%c%c%c\n",
				adom->id,
				l2_idx,
				cve_vaddr,
				l2_pt_vaddr[l2_idx],
				TBL_DMA_ADDR(l2_pt_vaddr[l2_idx]),
				(l2_pt_vaddr[l2_idx]
					& CVE_PROT_READ_BIT) ? 'r' : '-',
				(l2_pt_vaddr[l2_idx]
					& CVE_PROT_WRITE_BIT) ? 'w' : '-',
				(l2_pt_vaddr[l2_idx]
					& CVE_PROT_EXEC_BIT) ? 'x' : '-');
		}
	}
}

void cve_page_table_dump(struct cve_lin_mm_domain *adom)
{
	struct ice_mmu_config hw_reserved_mmu_config;
	struct ice_mmu_config *mmu_config =
		&adom->mmu_config[ICE_MEM_BASE_PARTITION];
	u8 partition_id = ICE_MEM_BASE_PARTITION, dump_bar1_pt = 1;

	FUNC_ENTER();

	/*Dump the ICE BAR1 mapping also */
	mmu_config = &hw_reserved_mmu_config;
	__mmu_config_35bit_va_page_32K_BAR1(mmu_config);

	cve_os_log(CVE_LOGLEVEL_INFO,
			">>>>>>>>>>> begin IOMMU page table dump >>>>>>>>>>>\n");

	for (; partition_id < ICE_MEM_MAX_PARTITION; partition_id++) {
		mmu_config = &adom->mmu_config[partition_id];

		if (dump_bar1_pt && (mmu_config->pde_start_idx >
					hw_reserved_mmu_config.pde_start_idx)) {
			__dump_pt(adom, &hw_reserved_mmu_config);
			dump_bar1_pt = 0;
		}
		__dump_pt(adom, mmu_config);
	}

	cve_os_log(CVE_LOGLEVEL_INFO,
			"<<<<<<<<<< end IOMMU page table dump <<<<<<<<<<\n");
	FUNC_LEAVE();
}


/*
 * allocate and initialize a page in a page table
 * inputs :
 * outputs: out_pt_vaddr - holds the host virtual address of the page
 *          out_pt_dma_addr - holds the DMA address of the page
 * returns: 0 on success, a negative error value on failure
 */
static int alloc_page_table(pt_entry_t **out_pt_vaddr,
		struct cve_dma_handle *out_pt_dma_handle)
{
	u32 i;
	struct cve_device *dev = get_first_device();
	pt_entry_t *pt_vaddr = NULL;
	int ret;

	FUNC_ENTER();

	ret = OS_ALLOC_DMA_CONTIG(dev,
			PAGE_SIZE,
			1,
			(void **)&pt_vaddr,
			out_pt_dma_handle, 0);
	if (ret != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"OS_ALLOC_DMA_CONTIG_pages failed\n");
		goto out;
	}

	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"Page allocated: IAVA=0x%lx, PA=0x%llx\n",
		(uintptr_t)pt_vaddr,
		out_pt_dma_handle->mem_handle.dma_address);

	for (i = 0; i < ICE_L1PT_PTES; i++)
		pt_vaddr[i] = INVALID_PAGE;

	/* success */
	*out_pt_vaddr = pt_vaddr;
	ret = 0;
out:

	FUNC_LEAVE();
	return ret;
}

/*
 * free a page in a page table
 * inputs : pt - the page to free
 * outputs:
 * returns:
 */
static void free_page_table(pt_entry_t *pt_vaddr,
		struct cve_dma_handle *dma_handle)
{
	struct cve_device *dev = get_first_device();

	FUNC_ENTER();

	OS_FREE_DMA_CONTIG(dev,
			PAGE_SIZE,
			pt_vaddr,
			dma_handle, 0);

	FUNC_LEAVE();
}

/* Allocate and initialize a new L2 Page */
static int __alloc_new_l2_page(struct cve_lin_mm_domain *cve_domain,
		struct ice_mmu_config *mmu_config, u32 l1_idx)
{
	int retval = 0;
	struct cve_dma_handle pt_dma_handle;
	pt_entry_t *l2_pt_vaddr, l1_entry;
	cve_dma_addr_t l2_pt_dma_addr;
	int calculated_l2_width;
	u8 l2_borrowed_width;
	u32 start_l1 = l1_idx, end_l1 = l1_idx;

	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"Creating Page Table\n");
	retval = alloc_page_table(&l2_pt_vaddr,
			&pt_dma_handle);
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"alloc_page_table failed %d\n", retval);
		goto out;
	}
	l2_pt_dma_addr = pt_dma_handle.mem_handle.dma_address;
	ASSERT((l2_pt_vaddr) && (l2_pt_dma_addr != 0));

	/* Update PD entry */
	calculated_l2_width = ICE_VA_L2_WIDTH(mmu_config->page_shift);
	/* page size > 32MB not supported */
	ASSERT(calculated_l2_width >= 0);

	l2_borrowed_width = mmu_config->l2_width - calculated_l2_width;
	if (l2_borrowed_width > 0) {
		u32 end_mask = ((1 << l2_borrowed_width) - 1);
		u32 start_mask = ~end_mask;

		end_l1 = ((l1_idx & start_mask) + end_mask);
	}

	l1_entry = (l2_pt_dma_addr >> ICE_DEFAULT_PA_SHIFT) | ICE_PD_BIT;
	do {
		cve_domain->pgd_vaddr[start_l1] = l1_entry;
		/* keep the host virtual address of the new page */
		cve_domain->virtual_l1[start_l1] = l2_pt_vaddr;
		start_l1++;
	} while (start_l1 <= end_l1);

out:
	return retval;
}

static void __dealloc_l2_page(struct cve_lin_mm_domain *cve_domain,
		u32 l1_idx)
{
	pt_entry_t pde = cve_domain->pgd_vaddr[l1_idx];
	pt_entry_t *l2_pt_vaddr;
	struct cve_dma_handle dma_handle;

	if (pde == INVALID_PAGE)
		return;

	l2_pt_vaddr = cve_domain->virtual_l1[l1_idx];
	dma_handle.mem_handle.dma_address = TBL_DMA_ADDR(pde);
	dma_handle.mem_type = CVE_MEMORY_TYPE_KERNEL_CONTIG;
	free_page_table(l2_pt_vaddr, &dma_handle);
}

/*
 * map a page in the page table of the given memory domain
 * inputs : cve_domain - the memory domain
 *          iova - device's virtual address where the page will be
 *                 mapped.
 *                 the offset into the page is cleared
 *          dma_addr - the address which the device sees.
 *                     the offset into the page is cleared by the function
 *          prot - access permissions
 *          llc_policy - hold the index of the llc policy in
 *                       the AXI attribute table
 * outputs:
 * returns: 0 on success, a negative error code on failure
 */
static int l2_map_page(struct cve_lin_mm_domain *cve_domain,
		ice_va_t iova,
		cve_dma_addr_t dma_addr,
		struct ice_lin_mm_buf_config *buf_meta_data)
{
	int retval = -ENOMEM;
	struct ice_mmu_config *mmu_config =
		&cve_domain->mmu_config[buf_meta_data->partition_id];
	u8 page_shift = mmu_config->page_shift;
	u32 l1_idx = iova >> ICE_L1PT_SHIFT;
	pt_entry_t l1_entry = cve_domain->pgd_vaddr[l1_idx];
	pt_entry_t *l2_pt_vaddr;
	cve_dma_addr_t l2_pt_dma_addr;
	ice_va_t iova_start = iova;
	unsigned int l2_idx;
	pt_entry_t prot_bits = 0;

	FUNC_ENTER();

	if (l1_entry == INVALID_PAGE) {
		retval = __alloc_new_l2_page(cve_domain, mmu_config, l1_idx);
		if (retval != 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
				"alloc_page_table failed %d\n", retval);
			goto out;
		}
		l1_entry = cve_domain->pgd_vaddr[l1_idx];
	}

	l2_pt_vaddr = cve_domain->virtual_l1[l1_idx];
	l2_pt_dma_addr = TBL_DMA_ADDR(cve_domain->pgd_vaddr[l1_idx]);
	ASSERT((l2_pt_vaddr) && (l2_pt_dma_addr != 0));

	dma_addr = round_down_cve_pagesize(dma_addr, mmu_config->page_sz);

	l2_idx = ((iova_start >> page_shift) &
		       ICE_L2PT_MASK(mmu_config->l2_width));

	if (l2_pt_vaddr[l2_idx] != INVALID_PAGE) {
		cve_os_log(CVE_LOGLEVEL_DEBUG,
			   "double-mapping: pgtbl=<v=%p,d=%pad>, l2_pt=<v=%p,d=%pad> l2_idx %u\n",
			   cve_domain->pgd_vaddr,
			   &cve_domain->pgd_dma_handle.mem_handle.dma_address,
			   l2_pt_vaddr, &l2_pt_dma_addr, l2_idx);
		retval = -ICEDRV_KERROR_PT_DUPLICATE_ENTRY;
		goto out;
	}

	/* there are 3 bits for protection */
	if (buf_meta_data->prot & CVE_MM_PROT_READ)
		prot_bits |= CVE_PROT_READ_BIT;
	if (buf_meta_data->prot & CVE_MM_PROT_WRITE)
		prot_bits |= CVE_PROT_WRITE_BIT;

	/* Update PT entry */
	l2_pt_vaddr[l2_idx] = (dma_addr >> ICE_DEFAULT_L2_SHIFT) | prot_bits;

	retval = cve_pt_llc_update(&l2_pt_vaddr[l2_idx],
			buf_meta_data->llc_policy);
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"cve_project_ddr_addr_remapping failed %d\n",
			retval);
		goto out;
	}

	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"[PT] page mapped. ICEVA=0x%llx, PA=0x%llx. PD_Idx=%u, PT_Idx=%u, PT_Entry='0x%x', LLC_Policy=0x%x\n",
		iova, dma_addr, l1_idx, l2_idx,
		l2_pt_vaddr[l2_idx], buf_meta_data->llc_policy);

	retval = 0;
out:
	FUNC_LEAVE();
	return retval;
}

/*
 * unmap a a single page in the device's page table
 * inputs : cve_domain - the memory domain
 *          ice_va - base address of the range to be unmapped in device's
 *                      virtual address
 * outputs:
 * returns: 0 on success, a negative error value on failure
 */
static int l2_unmap_page(struct cve_lin_mm_domain *cve_domain,
	ice_va_t ice_va, u8 partition_id)
{
	int retval = -EINVAL;
	struct ice_mmu_config *mmu_config =
		&cve_domain->mmu_config[partition_id];
	u8 page_shift = mmu_config->page_shift;
	u32 l1_idx = ice_va >> ICE_L1PT_SHIFT;
	pt_entry_t *l2_pt_vaddr = cve_domain->virtual_l1[l1_idx];
	ice_va_t iova_start = ice_va;

	unsigned int l2_idx = ((iova_start >> page_shift) &
			ICE_L2PT_MASK(mmu_config->l2_width));
	FUNC_ENTER();

	cve_os_log(CVE_LOGLEVEL_DEBUG,
			"DOM:%u Unmapping Page. ICEVA=0x%llx. PD_Idx=%u, PT_Idx=%u, PT_Entry=0x%x\n",
			cve_domain->id,
			ice_va, l1_idx, l2_idx, l2_pt_vaddr[l2_idx]);

	if (cve_domain->pgd_vaddr[l1_idx] == INVALID_PAGE)
		goto out;

	l2_pt_vaddr[l2_idx] = INVALID_PAGE;

	retval = 0;
out:
	FUNC_LEAVE();
	return retval;
}

/* INTERFACE FUNCTIONS */

void lin_mm_unmap(struct cve_lin_mm_domain *adom,
		ice_va_t ice_va,
		u32 cve_pages_nr, u8 partition_id)
{
	u32 j;
	ice_va_t va = ice_va;
	struct ice_mmu_config *mmu_config = &adom->mmu_config[partition_id];

	FUNC_ENTER();
	for (j = 0; j < cve_pages_nr; j++) {
		int r = l2_unmap_page(adom, va, partition_id);

		ASSERT(r == 0);
		va += mmu_config->page_sz;
	}
	FUNC_LEAVE();
}

int lin_mm_map(struct cve_lin_mm_domain *adom,
		ice_va_t ice_va,
		cve_dma_addr_t dma_addr,
		size_t size_bytes,
		struct ice_lin_mm_buf_config *buf_meta_data)
{
	struct ice_mmu_config *mmu_config =
		&adom->mmu_config[buf_meta_data->partition_id];
	ice_va_t va_start = round_down(ice_va, mmu_config->page_sz);
	ice_va_t va_end = ALIGN(ice_va + size_bytes, mmu_config->page_sz);
	u32 cve_pages_nr = (va_end - va_start) >> mmu_config->page_shift;
	u32 mapped_pages = 0;
	ice_va_t va = va_start;
	cve_dma_addr_t da = dma_addr;
	int retval;
	u32 j;

	FUNC_ENTER();
	cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Mapping IOVA range 0x%llx--0x%llx, size=0x%lx at dma_addr 0x%llx\n",
			va_start, va_end, size_bytes,
			dma_addr);

	/* TODO HACK: Ideally IDC should also be page aligned.
	 * Currently coral doesnt return a page aligned address
	 */
	if ((ice_va != IDC_BAR1_COUNTERS_ADDRESS_START) &&
			dma_addr & (mmu_config->page_sz - 1)) {
		retval = -ICEDRV_KERROR_IOVA_PAGE_ALIGNMENT;
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"PA:0x%llx is not page aligned(expected:0x%x)\n",
				dma_addr, mmu_config->page_sz);
		goto out;
	}

	for (j = 0; j < cve_pages_nr; j++) {
		retval = l2_map_page(adom, va, da, buf_meta_data);
		if (retval < 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
				"l2_map_page failed %d\n", retval);
			goto rollback;
		}
		va += mmu_config->page_sz;
		da += mmu_config->page_sz;
		mapped_pages++;
	}
	retval = 0;
out:
	FUNC_LEAVE();
	return retval;
rollback:
	lin_mm_unmap(adom, va_start, mapped_pages, buf_meta_data->partition_id);
	goto out;
}

static void __configure_partition_sz(u64 *sz_per_page_alignment,
		u64 *infer_buf_page_config, u64 *partition_sz_list)
{
	u8 i = IOVA_PAGE_ALIGNMENT_32K;
	u32 max_active_infer;
	u64 sz, total_sz = 0, infer_sz = 1;

	/* Calculate total size requirement for buffer in network and infer*/
	for (; i < IOVA_PAGE_ALIGNMENT_MAX; i++) {

		sz_per_page_alignment[i] = round_up_cve_pagesize(
						sz_per_page_alignment[i],
						ICE_PAGE_SZ_256M);
		if (sz_per_page_alignment[i] == 0)
			sz_per_page_alignment[i] = ICE_PAGE_SZ_256M;

		if (infer_buf_page_config[i])
			infer_sz += infer_buf_page_config[i];

		total_sz += sz_per_page_alignment[i];
		cve_os_log(CVE_LOGLEVEL_DEBUG,
				"sz_per_page_alignment[%d]:%llu infer_buf_page_config[%d]:%llu TotalSz:0x%llx\n",
				i, sz_per_page_alignment[i],
				i, infer_buf_page_config[i], total_sz);
	}

	/* Divide the unused VA space among the partitions used for inference*/
	max_active_infer = ((ICE_VA_HIGH_PHY_SZ - total_sz)/infer_sz);

	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"Infer size requirement (Low, 32K, 16M, 32M) = (0x%llx, 0x%llx, 0x%llx, 0x%llx).MaxNumInfer=%d.\n)",
		infer_buf_page_config[IOVA_PAGE_ALIGNMENT_LOW_32K],
		infer_buf_page_config[IOVA_PAGE_ALIGNMENT_32K],
		infer_buf_page_config[IOVA_PAGE_ALIGNMENT_16M],
		infer_buf_page_config[IOVA_PAGE_ALIGNMENT_32M],
		max_active_infer);

	for (i = IOVA_PAGE_ALIGNMENT_32K; i < IOVA_PAGE_ALIGNMENT_MAX; i++) {
		sz = (sz_per_page_alignment[i] +
			(infer_buf_page_config[i] * max_active_infer));
		partition_sz_list[i] = round_up_cve_pagesize(sz,
						ICE_PAGE_SZ_256M);
		if (partition_sz_list[i] == 0)
			partition_sz_list[i] = ICE_PAGE_SZ_256M;

		cve_os_log(CVE_LOGLEVEL_DEBUG,
				"partition_sz_list[%d]:%llu MaxActiveInfer:%d\n",
				i, partition_sz_list[i], max_active_infer);
	}
}

static void __configure_extended_partition_sz(
		u64 *infer_buf_page_config, u64 *partition_sz_list)
{
	u8 i;
	u32 max_active_infer;
	u64 sz, infer_sz = 0;
	u64 sum = 0;

	for (i = IOVA_PAGE_ALIGNMENT_32K; i < IOVA_PAGE_ALIGNMENT_MAX; i++)
		infer_sz += infer_buf_page_config[i];

	if (!infer_sz) {
		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Infer has zero buff size requirement\n");

		memset(partition_sz_list, 0, IOVA_PAGE_ALIGNMENT_MAX *
			sizeof(u64));

		goto end;
	}

	/* Divide the unused VA space among the partitions used for inference*/
	max_active_infer = ((ICE_VA_HIGH_TOTAL_SZ - ICE_VA_HIGH_PHY_SZ) /
				infer_sz);

	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"Infer size requirement (Low, 32K, 16M, 32M) = (0x%llx, 0x%llx, 0x%llx, 0x%llx).MaxNumInfer=%d.\n)",
		infer_buf_page_config[IOVA_PAGE_ALIGNMENT_LOW_32K],
		infer_buf_page_config[IOVA_PAGE_ALIGNMENT_32K],
		infer_buf_page_config[IOVA_PAGE_ALIGNMENT_16M],
		infer_buf_page_config[IOVA_PAGE_ALIGNMENT_32M],
		max_active_infer);

	for (i = IOVA_PAGE_ALIGNMENT_32K; i < IOVA_PAGE_ALIGNMENT_MAX; i++) {

		sz = (infer_buf_page_config[i] * max_active_infer);

		partition_sz_list[i] = round_up_cve_pagesize(sz,
						ICE_PAGE_SZ_256M);
		sum += partition_sz_list[i];
	}

	ASSERT(sum <= (ICE_VA_HIGH_TOTAL_SZ - ICE_VA_HIGH_PHY_SZ));

end:
	return;
}

static void __do_mmu_config(struct cve_lin_mm_domain *domain,
		u64 *sz_per_page_alignment,
		u64 *infer_buf_page_config)
{
	u8 partition = ICE_MEM_BASE_PARTITION;
	struct ice_mmu_config *mmu_config;
	u64 start = 0, end = 0;
	u64 _sz_per_page_alignment[IOVA_PAGE_ALIGNMENT_MAX] = {0};

	__configure_partition_sz(sz_per_page_alignment, infer_buf_page_config,
			_sz_per_page_alignment);

	for (; partition < ICE_MEM_MAX_PARTITION; partition++) {
		mmu_config = &domain->mmu_config[partition];
		switch (partition) {
		case ICE_MEM_BASE_PARTITION:
#ifdef ICE_ENABLE_EXTENDED_VA_MODE
			__mmu_config_35bit_va_page_32K(mmu_config);
#else
			__mmu_config_32bit_va_page_4K(mmu_config);
#endif
			break;
		case MEM_PARTITION_LOW_32KB_HW:
			__mmu_config_35bit_va_page_32K_hw(mmu_config);
			break;
		case MEM_PARTITION_HIGH_32KB:
			__mmu_config_35bit_va_page_32K_high(mmu_config);
			start = ICE_VA_RANGE_HIGH_32KB_START;
			end = start +
				_sz_per_page_alignment[IOVA_PAGE_ALIGNMENT_32K];
			mmu_config->va_end = end;
			break;
		case MEM_PARTITION_HIGH_16MB:
			__mmu_config_35bit_va_page_16M(mmu_config);
			start = end;
			end = start +
				_sz_per_page_alignment[IOVA_PAGE_ALIGNMENT_16M];
			mmu_config->va_end = end;
			mmu_config->va_start = start;
			break;
		case MEM_PARTITION_HIGH_32MB:
			__mmu_config_35bit_va_page_32M(mmu_config);
			mmu_config->va_start = end;
			end = mmu_config->va_start +
				_sz_per_page_alignment[IOVA_PAGE_ALIGNMENT_32M];
			end = round_up_cve_pagesize(end, ICE_PAGE_SZ_256M);
			mmu_config->va_end = end;
			break;
		case MEM_PARTITION_HIGHER_32KB:
			__mmu_config_35bit_va_page_32K_high(mmu_config);
			mmu_config->va_start = end;
			mmu_config->va_end = end;
			break;
		case MEM_PARTITION_HIGHER_16MB:
			__mmu_config_35bit_va_page_16M(mmu_config);
			mmu_config->va_start = end;
			mmu_config->va_end = end;
			break;
		case MEM_PARTITION_HIGHER_32MB:
			__mmu_config_35bit_va_page_32M(mmu_config);
			mmu_config->va_start = end;
			mmu_config->va_end = end;
		}

		mmu_config->pde_start_idx =
			(mmu_config->va_start/ICE_PAGE_SZ_32M);
		mmu_config->pde_end_idx =
			((mmu_config->va_end - 1)/ICE_PAGE_SZ_32M);
		cve_os_log(CVE_LOGLEVEL_DEBUG,
				"pa_width:%d pa_shift:%d page_shift:%d va_width:%d, page_sz:%u VaStart:0x%llx VaEnd:0x%llx\n",
				ICE_DEFAULT_PA_WIDTH, ICE_DEFAULT_PA_SHIFT,
				mmu_config->page_shift, ICE_DEFAULT_VA_WIDTH,
				mmu_config->page_sz,
				mmu_config->va_start,
				mmu_config->va_end);
	}

}

static void __do_extended_mmu_config(struct cve_lin_mm_domain *domain,
		u64 *infer_buf_page_config)
{
	u8 partition = MEM_PARTITION_HIGHER_32KB;
	struct ice_mmu_config *mmu_config;
	u64 end = 0;
	u64 _sz_per_page_alignment[IOVA_PAGE_ALIGNMENT_MAX] = {0};

	__configure_extended_partition_sz(infer_buf_page_config,
			_sz_per_page_alignment);

	for (; partition < ICE_MEM_MAX_PARTITION; partition++) {
		mmu_config = &domain->mmu_config[partition];
		switch (partition) {
		case MEM_PARTITION_HIGHER_32KB:
			__mmu_config_35bit_va_page_32K_high(mmu_config);
			mmu_config->va_start = ICE_VA_RANGE_HIGHER_32KB_START;
			end = mmu_config->va_start +
				_sz_per_page_alignment[IOVA_PAGE_ALIGNMENT_32K];
			mmu_config->va_end = end;
			break;
		case MEM_PARTITION_HIGHER_16MB:
			__mmu_config_35bit_va_page_16M(mmu_config);
			mmu_config->va_start = end;
			end += _sz_per_page_alignment[IOVA_PAGE_ALIGNMENT_16M];
			mmu_config->va_end = end;
			break;
		case MEM_PARTITION_HIGHER_32MB:
			__mmu_config_35bit_va_page_32M(mmu_config);
			mmu_config->va_start = end;
			end += _sz_per_page_alignment[IOVA_PAGE_ALIGNMENT_32M];
			mmu_config->va_end = end;
			break;
		default:
			ASSERT(false);
		}

		mmu_config->pde_start_idx =
			(mmu_config->va_start/ICE_PAGE_SZ_32M);
		mmu_config->pde_end_idx =
			((mmu_config->va_end - 1)/ICE_PAGE_SZ_32M);
		cve_os_log(CVE_LOGLEVEL_DEBUG,
				"pa_width:%d pa_shift:%d page_shift:%d va_width:%d, page_sz:%u VaStart:0x%llx VaEnd:0x%llx\n",
				ICE_DEFAULT_PA_WIDTH, ICE_DEFAULT_PA_SHIFT,
				mmu_config->page_shift, ICE_DEFAULT_VA_WIDTH,
				mmu_config->page_sz,
				mmu_config->va_start,
				mmu_config->va_end);
	}

}

static int lin_mm_domain_init(u8 id, u64 *sz_per_page_alignment,
		u64 *infer_buf_page_config,
		struct cve_lin_mm_domain **out_cve_domain)
{
	struct cve_lin_mm_domain *cve_domain = NULL;
	struct ice_mmu_config *mmu_config = NULL;
	int retval;
	u64 va_start_page, va_end_page;
	u8 page_shift, index = 0;

	FUNC_ENTER();
	retval = OS_ALLOC_ZERO(sizeof(*cve_domain),
			(void **)&cve_domain);
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "allocate cve_domain failed\n");
		goto out;
	}

#ifdef STANDALONE_TESTING
	ASSERT(os_lock_init(&cve_domain->lock) == 0);
#endif
	cve_domain->id = id;
	mmu_config = &cve_domain->mmu_config[ICE_MEM_BASE_PARTITION];
	__do_mmu_config(cve_domain, sz_per_page_alignment,
			infer_buf_page_config);

	memset(cve_domain->page_sz_reg_config_arr, 0,
		ICE_PAGE_SZ_CONFIG_REG_COUNT *
		sizeof(cve_domain->page_sz_reg_config_arr[0]));

	__config_page_sz_reg_array(cve_domain);

	/*
	 * We always map the L1 page table (a single page as well as
	 * the L2 page tables).
	 */
	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"Creating Page Directory\n");
	retval = alloc_page_table(&cve_domain->pgd_vaddr,
			&cve_domain->pgd_dma_handle);
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"alloc_page_table failed %d\n", retval);
		goto out;
	}

	ASSERT((cve_domain->pgd_vaddr) &&
		(cve_domain->pgd_dma_handle.mem_handle.dma_address != 0));

	retval = OS_ALLOC_ZERO(PAGE_SIZE * 2,
			(void **)&cve_domain->virtual_l1);
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"OS_ALLOC_ZERO failed %d\n", retval);
		goto out;
	}

	for (; index < MEM_PARTITION_HIGHER_32KB; index++) {
		page_shift = mmu_config[index].page_shift;
		va_end_page = ICE_VA_LAST_PAGE(mmu_config[index].va_end,
				page_shift);
		va_start_page = ICE_VA_FIRST_PAGE(mmu_config[index].va_start,
				page_shift);


		/* Ensure that ranges starts/end on 32 MB (1 << 25) boundary:
		 * - each PD entry defines 4MB address space
		 * - each PAGE_SIZE MMU register define page size for 8 entries
		 */
		ASSERT(IS_ALIGNED(mmu_config[index].va_start,
					BIT(ICE_PAGE_SIZE_REG_SHIFT)));
		ASSERT(IS_ALIGNED((mmu_config[index].va_end),
					BIT(ICE_PAGE_SIZE_REG_SHIFT)));


		cve_os_log(CVE_LOGLEVEL_DEBUG,
				"[PT] Init iova allocator bottom=0x%llx top=0x%llx\n",
				va_start_page, va_end_page);
		retval = cve_iova_allocator_init(va_start_page, va_end_page,
				&cve_domain->iova_allocator[index]);
		if (retval != 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
					"cve_iova_allocator_init failed %d\n",
					retval);
			goto err_iova_init;
		}

	}

	*out_cve_domain = cve_domain;
	retval = 0;

	FUNC_LEAVE();
	return retval;

err_iova_init:
	{
		u32 i = 0;

		for (; i < index; i++)
			cve_iova_allocator_destroy(
					&cve_domain->iova_allocator[i]);
	}
out:
	if (retval < 0) {
		if (cve_domain) {
			if (cve_domain->pgd_vaddr) {
				free_page_table(cve_domain->pgd_vaddr,
					&cve_domain->pgd_dma_handle);
			}
			if (cve_domain->virtual_l1) {
				OS_FREE(cve_domain->virtual_l1,
				PAGE_SIZE * 2);
			}

			OS_FREE(cve_domain, sizeof(*cve_domain));
		}
	}
	FUNC_LEAVE();
	return retval;
}

/* Do not call if CreateInfer does not contain unique IFM/OFM */
static int lin_mm_domain_extend(u64 *infer_buf_page_config,
		struct cve_lin_mm_domain *cve_domain)
{
	struct ice_mmu_config *mmu_config = NULL;
	int retval;
	u64 va_start_page, va_end_page;
	u8 page_shift, index = 0;

	FUNC_ENTER();

	__do_extended_mmu_config(cve_domain, infer_buf_page_config);

	__config_page_sz_reg_array(cve_domain);

	mmu_config = &cve_domain->mmu_config[ICE_MEM_BASE_PARTITION];

	for (index = MEM_PARTITION_HIGHER_32KB; index < ICE_MEM_MAX_PARTITION;
		index++) {

		page_shift = mmu_config[index].page_shift;
		va_end_page = ICE_VA_LAST_PAGE(mmu_config[index].va_end,
				page_shift);
		va_start_page = ICE_VA_FIRST_PAGE(mmu_config[index].va_start,
				page_shift);


		/* Ensure that ranges starts/end on 32 MB (1 << 25) boundary:
		 * - each PD entry defines 4MB address space
		 * - each PAGE_SIZE MMU register define page size for 8 entries
		 */
		ASSERT(IS_ALIGNED(mmu_config[index].va_start,
					BIT(ICE_PAGE_SIZE_REG_SHIFT)));
		ASSERT(IS_ALIGNED((mmu_config[index].va_end),
					BIT(ICE_PAGE_SIZE_REG_SHIFT)));


		cve_os_log(CVE_LOGLEVEL_DEBUG,
				"[PT] Init iova allocator bottom=0x%llx top=0x%llx\n",
				va_start_page, va_end_page);
		retval = cve_iova_allocator_init(va_start_page, va_end_page,
				&cve_domain->iova_allocator[index]);
		if (retval != 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
					"cve_iova_allocator_init failed %d\n",
					retval);
			goto err_iova_init;
		}

	}

	retval = 0;

	FUNC_LEAVE();
	return retval;

err_iova_init:
	{
		u32 i = MEM_PARTITION_HIGHER_32KB;

		for (; i < index; i++)
			cve_iova_allocator_destroy(
					&cve_domain->iova_allocator[i]);
	}

	FUNC_LEAVE();
	return retval;
}

void lin_mm_domain_destroy(struct cve_lin_mm_domain *cve_domain)
{
	u32 l1_idx, index = 0;
	pt_entry_t *l2_pt_vaddr, *prev_l2_pt_vaddr = NULL;

	FUNC_ENTER();

	/* free all the pages in the page table */
	for (l1_idx = 0; l1_idx < ICE_L1PT_PTES; l1_idx++) {
		pt_entry_t pde = cve_domain->pgd_vaddr[l1_idx];

		if (pde == (pt_entry_t)INVALID_PAGE)
			continue;

		l2_pt_vaddr = cve_domain->virtual_l1[l1_idx];
		if (prev_l2_pt_vaddr == l2_pt_vaddr)
			continue;

		__dealloc_l2_page(cve_domain, l1_idx);

		prev_l2_pt_vaddr = l2_pt_vaddr;
	}

	free_page_table(cve_domain->pgd_vaddr,
			&cve_domain->pgd_dma_handle);

	OS_FREE(cve_domain->virtual_l1, PAGE_SIZE * 2);

	for (index = 0; index < ICE_MEM_MAX_PARTITION; index++) {
		cve_iova_allocator_destroy(
			&cve_domain->iova_allocator[index]);
	}

	OS_FREE(cve_domain, sizeof(*cve_domain));
	FUNC_LEAVE();
}

int cve_osmm_get_domain(u8 id, u64 *va_partition_config,
		u64 *infer_buf_page_config,
		os_domain_handle *out_hdomain)
{
	int retval = -ENOMEM;
	struct cve_lin_mm_domain *cve_domain = NULL;

	FUNC_ENTER();

	retval = lin_mm_domain_init(id, va_partition_config,
			infer_buf_page_config, &cve_domain);
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"lin_mm_domain_init failed %d\n", retval);
		goto out;
	}

	/* success */
	*out_hdomain = (os_domain_handle)cve_domain;
	retval = 0;
out:
	FUNC_LEAVE();
	return retval;
}

int cve_osmm_extend_domain(u64 *infer_buf_page_config,
		os_domain_handle hdomain)
{
	int retval = -ENOMEM;
	struct cve_lin_mm_domain *cve_domain =
		(struct cve_lin_mm_domain *)hdomain;

	FUNC_ENTER();

	retval = lin_mm_domain_extend(infer_buf_page_config, cve_domain);
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"lin_mm_domain_extend failed %d\n", retval);
		goto out;
	}

	retval = 0;
out:
	FUNC_LEAVE();
	return retval;
}

void cve_osmm_put_domain(os_domain_handle hdom)
{
	struct cve_lin_mm_domain *cve_domain = (struct cve_lin_mm_domain *)hdom;

	FUNC_ENTER();
	lin_mm_domain_destroy(cve_domain);
	FUNC_LEAVE();
}

u32 cve_osmm_get_domain_pd_base_addr(os_domain_handle hdom)
{
	struct cve_lin_mm_domain *cve_domain = (struct cve_lin_mm_domain *)hdom;

	cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Page Directory PA=0x%llx\n",
			cve_domain->pgd_dma_handle.mem_handle.dma_address);

	return (cve_domain->pgd_dma_handle.mem_handle.dma_address
			>> ICE_DEFAULT_PA_SHIFT);
}

static void __config_page_sz_reg_array(struct cve_lin_mm_domain *domain)
{
	u8 partition_id = ICE_MEM_BASE_PARTITION;

	for (; partition_id < ICE_MEM_MAX_PARTITION; partition_id++)
		__config_page_sz_for_partition(domain, partition_id);

}

static void __config_page_sz_for_partition(struct cve_lin_mm_domain *domain,
		u8 partition_id)
{
	struct ice_mmu_config *mmu_config = &domain->mmu_config[partition_id];
	u32 start_idx = 0, end_idx = 0, idx, reg_val, val;

	/* each 32 bit reg can be configured with 8 different page size
	 * i.e. 4 bits for each entry across 32 bits
	 */
#define PAGE_SZ_REG_ENTRY_COUNT 8
	start_idx = (mmu_config->va_start /
			(ICE_DEFAULT_PDE_VA_SPAN * PAGE_SZ_REG_ENTRY_COUNT));
	end_idx = (mmu_config->va_end /
			(ICE_DEFAULT_PDE_VA_SPAN * PAGE_SZ_REG_ENTRY_COUNT));


	/*Assumptions that partitions are aligned at 256MB boundary
	 * so each 32 bit value will have same page size
	 */
	val = ilog2(mmu_config->page_sz >> ICE_DEFAULT_PAGE_SHIFT);

	for (idx = start_idx; idx < end_idx; idx++) {
		reg_val = (val << 28) | (val << 24) | (val << 20) |
			(val << 16) | (val << 12) | (val << 8) |
			(val << 4) | val;
		domain->page_sz_reg_config_arr[idx] = reg_val;
	}
}

