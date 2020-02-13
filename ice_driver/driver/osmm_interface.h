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

#ifndef _OSMM_INTERFACE_H_
#define _OSMM_INTERFACE_H_

#ifdef RING3_VALIDATION
#include <stdint.h>
#include <stdint_ext.h>
#include "linux_kernel_mock.h"
#endif

#include "cve_driver_internal.h"
#include "lin_mm_internal.h"

typedef void *os_allocation_handle;
typedef void *os_domain_handle;

enum osmm_memory_type {
	OSMM_UNKNOWN_MEM_TYPE,
	OSMM_KERNEL_MEMORY,
	OSMM_USER_MEMORY,
	OSMM_SHARED_MEMORY,
	OSMM_INFER_MEMORY
};

/* cve specific data - dma handle & domain name */
struct cve_os_allocation {
	/* cyclic list element of cve_os_allocation */
	struct cve_dle_t list;
	/* the memory domain to which the allocation belongs */
	os_domain_handle domain;
	/* dma memory handle of this allocation */
	struct cve_dma_handle dma_handle;
	/* cve device index to which this allocation belongs */
	u32 cve_index;
	/* dma-buf attachment pointer*/
	struct dma_buf_attachment *dbuf_attach;
	/* Partition ID */
	enum iova_partition_list partition_id;
	/* Page Size recomendation, 0 means deafult*/
	u32 page_sz;
	/* Flag to force allocation from higher VA space i.e. 4GB above.
	 * 0 means default i.e. lower 4GB
	*/
	u8 alloc_higher_va;
};

int cve_osmm_inf_dma_buf_map(u64 inf_id,
		os_domain_handle *hdomain,
		u32 dma_domain_array_size,
		union allocation_address alloc_addr,
		enum osmm_memory_type mem_type,
		os_allocation_handle ntw_halloc,
		os_allocation_handle *inf_halloc);

void cve_osmm_inf_dma_buf_unmap(os_allocation_handle halloc);

/*
 * map a buffer in the device memory
 * inputs :
 *	hdomain - array of handle of the domain in which the mapping should
 *				be done
 *	dma_handle - array of device dma handle that includes the address where
 *		this allocation should be mapped and the allocation type.
 *		For USER allocation - dma_handle ignored and can be NULL.
 *	dma_domain_array_size - size of above arrays
 *		(data should arrive in pairs: domain & dma_handle)
 *	len - buffer's size in bytes
 *	alloc_addr - buffer's base address or fd in case of buffer sharing
 *	cve_addr - if different than CVE_INVALID_VIRTUAL_ADDR then
 *		the device address where the given buffer is to be mapped.
 *		must be page aligned
 *	prot - the access permissions of the buffer
 *	mem_type - os memory type (USER/KERNEL)
 *	iova_desc - IOVA descriptor defining the properties of the VA allocated
 * outputs: out_halloc - handle of the allocation
 * returns: 0 on success, a negative error code on failure
 */
int cve_osmm_dma_buf_map(os_domain_handle *hdomain,
		struct cve_dma_handle **dma_handle,
		u32 dma_domain_array_size,
		u64 size_bytes,
		union allocation_address alloc_addr,
		ice_va_t cve_addr,
		u32 prot,
		enum osmm_memory_type mem_type,
		struct ice_iova_desc *iova_desc,
		os_allocation_handle *out_halloc);

/*
 * unmap a buffer in the device memory
 * inputs :
 *	cve_dev - the structure that represents the cve device
 *	halloc - handle of the allocation
 * outputs:
 * returns:
 */
void cve_osmm_dma_buf_unmap(os_allocation_handle halloc,
		enum osmm_memory_type mem_type);

/*
 * return the device virtual address of the given allocation
 * inputs : halloc - handle of the allocation
 * outputs:
 * returns:  the device virtual address
 */
ice_va_t cve_osmm_alloc_get_iova(os_allocation_handle halloc);

/*
 * get a iommu domain
 * configure the ICE VA partitions dynamically based on the requested size per
 * page alignment
 * inputs : sz_per_page_alignment - an array with total size requirement
 *          per page alignment
 *          infer_buf_page_config - page config used by the infer buffers
 * outputs: out_hdomain - a handle to the domain
 * returns: 0 on success, a negative error code on failure
 */
int cve_osmm_get_domain(u8 id, u64 *sz_per_page_alignment,
		u64 *infer_buf_page_config,
		os_domain_handle *out_hdomain);

/* free a iommu domain
 * inputs : hdom - a handle to the domain
 * outputs:
 * returns:
 */
void cve_osmm_put_domain(os_domain_handle hdom);

/*
 * get the DMA base address of the domain's page table
 * inputs :
 * outputs:
 * returns: the address
 */
u32 cve_osmm_get_domain_pd_base_addr(os_domain_handle hdom);

/*
 * Perform cache operation for specific allocation.
 * if sync_dir == SYNC_TO_DEVICE:
 *	Flushes the caches lines containing the allocation data
 * if sync_dir == SYNC_TO_HOST:
 *	Invalidates the caches lines containing the allocation data
 * inputs:
 *		halloc - allocation
 *		cve_dev - pointer to cve device
 *		sync_dir - cache operation direction (to dev/to host)
 */
void cve_osmm_cache_allocation_op(os_allocation_handle halloc,
	struct cve_device *cve_dev,
	enum cve_cache_sync_direction sync_dir);

/*
 * Check if tlb invalidation is needed for specific CVE device.
 * clear the pages added flag
 * inputs:
 *	   hdomain - pointer to os domain structure
 * returns: is tlb invalidation needed
 */
u32 cve_osmm_is_need_tlb_invalidation(os_domain_handle hdomain);

/*
 * Clear all page table flags
 * inputs:
 *	   hdomain - pointer to os domain structure
 */
void cve_osmm_reset_all_pt_flags(os_domain_handle hdomain);

/*
 * Print the user buffer.
 * inputs:
 *		halloc - buffer allocation
 *		size_bytes - size of buffer
 *		buffer_addr - buffer address in user space
 *		buf_name - buffer_name
 */
void cve_osmm_print_user_buffer(os_allocation_handle halloc,
		u32 size_bytes,
		void *buffer_addr,
		const char *buf_name);

/**
 * cve_osmm_map_kva - Retrieve Kernel VA using DMA Buf APIs'
 *
 * This interface is used when memory is allocated using dma buf interface
 * used primarily for command buffer for which driver also needs write access
 * to do patching
 *
 * @alloc_hdl:     [in]  handle to the allocation structure for a surface
 * @va:            [out] va of the memory mapped in kernel space
 *
 */
int cve_osmm_map_kva(os_allocation_handle alloc_hdl, u64 *va);

int cve_osmm_unmap_kva(os_allocation_handle alloc_hdl, void *vaddr);

/*
 * return the page shift factor of the given allocation
 * inputs : halloc - handle of the allocation
 * outputs:
 * returns:  the page shift factor
 */
u8 ice_osmm_alloc_get_page_shift(os_allocation_handle halloc);

/*
 * return the page size of the given domain
 * inputs : domain handle
 *        : pointer to the page size array
 * outputs:
 * returns:  the page size
 */
void ice_osmm_domain_get_page_sz_list(os_domain_handle hdomain,
		u32 **page_sz_list);

void cve_osmm_print_page_table(os_domain_handle hdomain);

int cve_osmm_domain_copy(os_domain_handle *hdom_src,
		os_domain_handle *hdom_dst,
		u32 domain_array_size);

void cve_osmm_domain_destroy(os_domain_handle *hdom,
		u32 domain_array_size);

#endif /* _OS_MM_DMA_H_ */
