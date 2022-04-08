/********************************************
 * Copyright (C) 2019-2021 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/



#ifndef _MEMORY_MANAMGER_H_
#define _MEMORY_MANAMGER_H_

#ifdef RING3_VALIDATION
#include <stdint.h>
#include <stdint_ext.h>
#endif

#include "cve_driver.h"
#include "cve_driver_internal.h"
#include "cve_driver_internal_types.h"
#include "osmm_interface.h"

/*
 * remove all buffers in given buffer linked list
 * memory-context
 * inputs : hbuf_list - buffer linked list
 * outputs:
 * returns:
 */
void cve_mm_free_all_buffers(cve_mm_buffers_list_t hbuf_list);

/*
 * get the physical address of the page table
 * inputs :
 * context_id - the mm context
 * hdom - pointer to os domain handle for specific cve
 * outputs: out_page_table - the returned page table
 * returns: 0 on success, a negative error value on error
 */
int cve_mm_get_page_directory_base_addr(
		os_domain_handle hdom,
		u32 *out_dma_addr);

/*
 * invalidate the tlb if pages were added
 * inputs :
*      hdom - domain structure associated with the tlb
*      cve_dev - cve device associated with the tlb
 * outputs:
 * returns:
 */
void cve_mm_invalidate_tlb(os_domain_handle hdom,
		struct cve_device *cve_dev);

/*
 * reset the internal page table flags state
 * inputs :
 *	context - the mm context
 * outputs:
 * returns:
 */
void cve_mm_reset_page_table_flags(cve_mm_buffers_list_t hbuf_list);

int cve_mm_create_infer_buffer(
	u64 inf_id,
	void *inf_hdom,
	u32 domain_array_size,
	cve_mm_allocation_t buf_alloc,
	struct cve_inf_buffer *inf_buf);

void cve_mm_destroy_infer_buffer(
		u64 inf_id,
		struct cve_inf_buffer *inf_buf);

/*
 * create a buffer based on the given descriptor
 * inputs :
 *	hdom - array of handle of the domain in which the mapping should
 *				be done
 *	dma_domain_array_size - size of above arrays
 *	k_surface - the user surface descriptor (in kernel space)
 * outputs:
 *	out_alloc - pointer to structure that describes allocated user
 *				buffer
 * returns: 0 on success, a negative error value on error
 */
int cve_mm_create_buffer(
		os_domain_handle *hdom,
		u32 domain_array_size,
		struct cve_surface_descriptor *k_surface,
		cve_mm_allocation_t *out_alloc);

/*
 * destroy a buffer based on the given bufferid
 * inputs :
 *  context_id - context id associated with this buffer
 *	allocation - pointer to structure that describes allocated user
 *				buffer
 * outputs:
 * returns: 0 on success, a negative error value on error
 */
void cve_mm_destroy_buffer(
		cve_context_id_t context_id,
		cve_mm_allocation_t allocation);

/*
 * get the iova address which corresponds to the given buffer.
 * the iova address point to a beginning of a page, the offset should be added
 * to get to the exact location.
 * inputs :
 *	allocation - pointer to structure that describes allocated user
 *				buffer
 * outputs:
 *	out_iova - output iova address
 *	out_offset - output offset
 *	out_address - output buffer virtual address
 * returns: 0 on success, a negative error value on error
 */
int cve_mm_get_buffer_addresses(
		cve_mm_allocation_t allocation,
		ice_va_t *out_iova,
		u32 *out_offset,
		u64 *out_address);

/*
 * map kernel memory in all the device's page tables
 * these mappings are shared by all the memory domains
 * and MUST be kernel memory only!
 * inputs :
 *	hdom - pointer to memory domain
 *	vaddr -
 *	size_bytes -
 *	direction -
 *	permissions -
 *	cve_vaddr - the requested address in the device. if
 *			CVE_INVALID_VIRTUAL_ADDR then a newly allocated
 *			address is returned in this parameter
 *	dma_handle - the DMA handle of the allocation
 *	allocations_type - allocation type for unloading purposes
 *	surf -  pointer to surface descriptor
 * outputs:
 *	cve_vaddr - newly allocated of device address
 *	out_alloc_handle - handle to newly created allocation structure
 * returns:
 *	0 on success, a negative error value on error
 */
int cve_mm_create_kernel_mem_allocation(os_domain_handle hdom,
		void *vaddr,
		u32 size_bytes,
		enum cve_surface_direction direction,
		u32 permissions,
		ice_va_t *cve_vaddr,
		struct cve_dma_handle *dma_handle,
		struct cve_surface_descriptor *surf,
		cve_mm_allocation_t *out_alloc_handle);

/* cleanup resources that are kept in the memory manager for the
 * given allocation
 * inputs :
 *	halloc - handle to allocation to be removed
 * outputs:
 * returns:
 */
void cve_mm_reclaim_allocation(
		cve_mm_allocation_t halloc);

/* set dirty dram flag & source CVE for specific allocation
 * inputs :
 *	user_buf - handle to user buffer allocation
 *	cve_dev - pointer to cve device that changed this alloc
 * outputs:
 * returns:
 */
void cve_mm_set_dirty_dram(struct cve_ntw_buffer *user_buf,
	struct cve_device *cve_dev);

/* set dirty cache flag for specific allocation
 * inputs :
 *	user_buf - handle to user buffer allocation
 * outputs:
 * returns:
 */
void cve_mm_set_dirty_cache(cve_mm_allocation_t *halloc);

/*
 * Perform cache operation for specific allocation:
 * Flushes the caches lines containing the allocation data
 * inputs:
 *		halloc - allocation
 *		inf_id - inference id. Set to 0 for Networks.
 *		cve_dev - pointer to cve device
 */
void cve_mm_sync_mem_to_dev(cve_mm_allocation_t halloc,
	struct cve_device *cve_dev);

/*
 * Perform cache operation for specific allocation.
 * Invalidates the caches lines containing the allocation data
 * inputs:
 *		halloc - allocation
 *		inf_id - inference id. Set to 0 for Networks.
 */
int cve_mm_sync_mem_to_host(cve_mm_allocation_t halloc);

/*
 * Print buffer as seen by specific CVE and associated with bufferId.
 * inputs:
 *	halloc - pointer to structure that describes allocated user
 *			buffer
 *	buffer_addr - command buffer address in user space
 *	size_bytes - size of buffer
 *	buf_name - buffer name
 */
void cve_mm_print_user_buffer(cve_mm_allocation_t halloc,
		void *buffer_addr,
		u32 size_bytes,
		const char *buf_name);



/**
 * Map user surface to Kernel Virtual Space
 *
 * for surface allocated via dma_buf interface
 *
 * inputs :
 *	allocation - pointer to structure that describes allocated user
 *				buffer
 * returns: 0 on success, a negative error value on error
 */
int cve_mm_map_kva(cve_mm_allocation_t allocation);

/**
 * remove any mapping done for user surfaces allocated via dma buf interface
 *
 * inputs :
 *	allocation - pointer to structure that describes allocated user
 *				buffer
 * returns: 0 on success, a negative error value on error
 */
int cve_mm_unmap_kva(cve_mm_allocation_t allocation);


/*
* patch the surfaces of the given job
* inputs :
*	  buf_list - list of user buffers in current context
*	  patch_desc_list - list of patch points descriptors
*	  patch_list_sz - number of patch points
* outputs:
* returns: 0 on success, a negative error code on failure
*/
int ice_mm_process_patch_point(struct cve_ntw_buffer *buf_list,
		struct cve_patch_point_descriptor *patch_desc_list,
		u32 patch_list_sz, struct job_descriptor *job);

/*
* patch the counters of the given jobgroup
* inputs :
*	  buf_list - list of user buffers in current context
*	  job - job with all patching related information
*	  dev - to be used as reference of odd/even for counter patching
* outputs:
* returns: 0 on success, a negative error code on failure
*/
int ice_mm_patch_cntrs(struct cve_ntw_buffer *buf_list,
		struct job_descriptor *job,
		struct cve_device *dev);

/* post patch dump enable through sysfs */
void dump_patched_surf(struct ice_network *ntw);


/*
 * retrive the page size from domain
 * inputs :
 *	hdom - domain structure associated with the page table
 *	page_sz_list - pointer to hold the array contain page size config
 * returns:
 */
void ice_mm_get_page_sz_list(os_domain_handle hdom, u32 **page_sz_list);

void print_cur_page_table(os_domain_handle hdom);

cve_virtual_address_t ice_mm_get_iova(struct cve_ntw_buffer *buffer);

void ice_mm_domain_destroy(void *hdom_inf,
	u32 domain_array_size);

int ice_mm_process_inf_pp_arr(struct ice_infer *inf);
int ice_mm_patch_inf_pp_arr(struct ice_infer *inf);

void ice_mm_get_buf_info(cve_mm_allocation_t halloc,
	u64 *size_bytes, u32 *page_size, u8 *pid, u64 *fd);
void ice_mm_inc_user(cve_mm_allocation_t halloc);
void ice_mm_get_user(cve_mm_allocation_t halloc, u64 *count);

void ice_mm_transfer_shared_surface(
	struct cve_ntw_buffer *ntw_buf,
	struct cve_inf_buffer *inf_buf);

void ice_mm_use_extended_iceva(struct cve_ntw_buffer *ntw_buf);

#endif /* _MEMORY_MANAMGER_H_ */

