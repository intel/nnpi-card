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
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <stdint_ext.h>
#include "linux_kernel_mock.h"
#else
#include <linux/errno.h>
#include <linux/mm.h>
#endif

#include "os_interface.h"
#include "device_interface.h"
#include "memory_manager.h"
#include "doubly_linked_list.h"
#include "project_settings.h"
#include "iova_allocator.h"
#include "cve_device_group.h"
#include "cve_linux_internal.h"
#include "ice_debug.h"

/* DATA TYPES */

/* hold information about an allocation */
struct allocation_desc {
	/* base address */
	void *vaddr;
	/* file descriptor in case of buffer sharing */
	u64 fd;
	/* size */
	u64 size_bytes;
	/* direction */
	enum cve_surface_direction direction;
	/* dirty flags */
	int dirty_cache;
	int dirty_dram;
	struct cve_device *dirty_dram_src_cve;
	/* os specific allocation handle */
	os_allocation_handle halloc;
	/* flag to indicate if fd connected memory was mapped*/
	bool is_mapped;
	/* IOVA descriptor */
	struct ice_iova_desc iova_desc;
	/* Type of Memory i.e. Kernel/User/Shared/Infer */
	enum osmm_memory_type mem_type;
};

/* INTERNAL FUNCTIONS */
static int __get_patch_point_addr_and_val(
		struct allocation_desc *cb_alloc_desc,
		struct cve_patch_point_descriptor *k_patch_point,
		u64 **patch_address, u64 *ks_value);

static void __map_page_sz_to_partition(struct ice_iova_desc *iova_desc,
		struct cve_surface_descriptor *surf);

/* create a new allocation object for the given surface and map it to
 * the device's memory
 * inputs :
 *			hdomain - array of handle of the domain in which the
 *						mapping should be done
 *			dma_handle - array of the device physical address where
 *						this allocation should be mapped
 *			dma_domain_array_size - size of above arrays
 *						(data should arrive in pairs:
 *						domain & dma_handle)
 *			base_addr - allocation's base address
 *			size_bytes - allocation's size in bytes
 *			direction - allocation's direction
 *			cve_vaddr - the device virtual address where this
 *						allocation should be mapped
 *			prot - allocation's memory permission bits
 *			map_prefetch_page - a flag to indicate if additional
 *			page should be mapped
 *			alloc_type - hold allocation type
 *			surf - surface decriptor of buffer to be mapped
 * outputs: out_alloc - hold the newly created allocation object
 * returns: 0 on success, a negative error code on failure
 * note   : must be called with lock taken
 */
static int create_new_allocation(
		os_domain_handle * hdom,
		struct cve_dma_handle **dma_handle,
		u32 dma_domain_array_size,
		union allocation_address alloc_addr,
		u64 size_bytes,
		enum cve_surface_direction direction,
		u32 prot,
		ice_va_t cve_vaddr,
		enum osmm_memory_type alloc_type,
		struct cve_surface_descriptor *surf,
		struct allocation_desc **out_alloc)
{
	struct allocation_desc *alloc = NULL;
	u32 llc_policy = surf->llc_policy;
	struct ice_iova_desc *iova_desc = NULL;
	int retval = OS_ALLOC_ZERO(sizeof(*alloc),
			(void **)&alloc);

	if (retval < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"os_malloc_zero failed %d\n",
				retval);
		goto out;
	}

	iova_desc = &alloc->iova_desc;
	iova_desc->llc_policy = llc_policy;
	iova_desc->alloc_higher_va = surf->alloc_higher_va;
	__map_page_sz_to_partition(iova_desc, surf);

	retval = cve_osmm_dma_buf_map(
			hdom,
			dma_handle,
			dma_domain_array_size,
			size_bytes,
			alloc_addr,
			cve_vaddr,
			prot,
			alloc_type,
			iova_desc,
			&alloc->halloc);
	if (retval < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"osmm_dma_buf_map failed %d\n",
				retval);
		goto out;
	}

	if (alloc_type == OSMM_INFER_MEMORY) {
		/* Do nothing */
		/* Ensure Infer Buff is never patched with other surface */
	} else if (alloc_type == OSMM_SHARED_MEMORY) {
		/* Copy only FD */
		alloc->fd = alloc_addr.fd;
	}  else {
		/* If User/Kernel copy vaddr */
		alloc->vaddr = alloc_addr.vaddr;
	}

	alloc->size_bytes = size_bytes;
	alloc->direction = direction;
	alloc->mem_type = alloc_type;
	/* dirty cache/dram flags are currently for user buffs only */
	alloc->dirty_cache = 0;
	alloc->dirty_dram = 0;
	alloc->dirty_dram_src_cve = NULL;

	/* success */
	*out_alloc = alloc;
	retval = 0;
out:
	if ((retval < 0) && (alloc))
		OS_FREE(alloc, sizeof(*alloc));

	return retval;
}

/* INTERFACE FUNCTIONS */
/* cleanup resources that are kept in the memory manager for the
 * given allocation
 * inputs :
 *			alloc - the allocation to be removed
 * outputs:
 * returns:
 */
void cve_mm_reclaim_allocation(cve_mm_allocation_t halloc)
{
	struct allocation_desc *alloc = (struct allocation_desc *)halloc;

	if (alloc == NULL)
		return;

	cve_osmm_dma_buf_unmap(alloc->halloc, alloc->mem_type);

	OS_FREE(alloc, sizeof(*alloc));
}

void cve_mm_set_dirty_dram(struct cve_ntw_buffer *user_buf,
	struct cve_device *cve_dev)
{
	struct allocation_desc *alloc =
		(struct allocation_desc *)user_buf->ntw_buf_alloc;

	cve_os_dev_log(CVE_LOGLEVEL_DEBUG,
		cve_dev->dev_index,
		"[CACHE] Set Dirty DRAM Flag for buffer ID %llu\n",
		user_buf->buffer_id);

	alloc->dirty_dram = 1;
	alloc->dirty_dram_src_cve = cve_dev;
}

void cve_mm_set_dirty_cache(cve_mm_allocation_t *halloc)
{
	struct allocation_desc *alloc = (struct allocation_desc *)halloc;

	alloc->dirty_cache = 1;
}

void cve_mm_sync_mem_to_dev(cve_mm_allocation_t halloc,
	struct cve_device *cve_dev)
{
	struct allocation_desc *alloc = (struct allocation_desc *)halloc;

	if (alloc->dirty_cache) {
		cve_osmm_cache_allocation_op(alloc->halloc,
			cve_dev,
			SYNC_TO_DEVICE);
		alloc->dirty_cache = 0;
	}
}

int cve_mm_sync_mem_to_host(cve_mm_allocation_t halloc)
{
	struct allocation_desc *alloc = (struct allocation_desc *)halloc;
	int retval = CVE_DEFAULT_ERROR_CODE;

	if (alloc->dirty_dram) {
		if (alloc->dirty_dram_src_cve == NULL) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
					"Allocation with dirty DRAM, but src CVE not defined\n");
			goto out;
		}
		cve_osmm_cache_allocation_op(alloc->halloc,
			alloc->dirty_dram_src_cve,
			SYNC_TO_HOST);
		alloc->dirty_dram = 0;
		alloc->dirty_dram_src_cve = NULL;
	}

	/* success */
	retval = 0;

out:
	return retval;
}

void cve_mm_invalidate_tlb(os_domain_handle hdom,
	struct cve_device *cve_dev)
{
	/* if pages were added to the page table and the
	 * driver settings requires tlb invalidation.
	 * do tlb invalidation and clear the pages added flag.
	 */
	if (cve_osmm_is_need_tlb_invalidation(hdom))
		ice_di_tlb_invalidate_full(cve_dev);
}

void cve_mm_reset_page_table_flags(os_domain_handle hdom)
{
	cve_osmm_reset_all_pt_flags(hdom);
}


/* returns the partition_id to be used for VA mapping. Default is lower 4GB */
static void __map_page_sz_to_partition(struct ice_iova_desc *iova_desc,
		struct cve_surface_descriptor *surf)
{
	u32 page_sz = surf->page_sz;

	/* Only 1 partition for 32bit VA mode */
	if (ICE_DEFAULT_VA_WIDTH != ICE_VA_WIDTH_EXTENDED) {
		/* Large page size configuration only supported for
		 * 35bit IOVA
		 */
		iova_desc->page_sz = ICE_PAGE_SZ_4K;
		iova_desc->page_shift = ICE_PAGE_SHIFT_4K;
		iova_desc->partition_id = MEM_PARTITION_LOW_4KB;
		return;
	}

	if (page_sz)
		iova_desc->page_sz = page_sz;
	else
		iova_desc->page_sz = ICE_PAGE_SZ(ICE_DEFAULT_PAGE_SHIFT);

	if (iova_desc->page_sz == ICE_PAGE_SZ_32M) {
		iova_desc->partition_id = MEM_PARTITION_HIGH_32MB;
		iova_desc->page_shift = ICE_PAGE_SHIFT_32M;
	} else if (iova_desc->page_sz == ICE_PAGE_SZ_16M) {
		iova_desc->partition_id = MEM_PARTITION_HIGH_16MB;
		iova_desc->page_shift = ICE_PAGE_SHIFT_16M;
	} else if (iova_desc->page_sz == ICE_PAGE_SZ_32K) {
		if (iova_desc->alloc_higher_va) {
			iova_desc->partition_id = MEM_PARTITION_HIGH_32KB;
		} else {
			if (surf->map_in_hw_region) {
				iova_desc->partition_id =
					MEM_PARTITION_LOW_32KB_HW;
			} else {
				iova_desc->partition_id =
					MEM_PARTITION_LOW_32KB;
			}
		}
		iova_desc->page_shift = ICE_PAGE_SHIFT_32K;
	}
}

static int __get_patch_point_addr_and_val(
		struct allocation_desc *cb_alloc_desc,
		struct cve_patch_point_descriptor *k_patch_point,
		u64 **patch_address, u64 *ks_value)
{

	u64 *patch_addr;
	u64 val_at_addr;
	bool is_dma_buf = false;
	int retval = 0;

	is_dma_buf = (cb_alloc_desc->fd > 0) ? true : false;

	if (is_dma_buf) {
		uint8_t *base_va =
			(uint8_t *)(uintptr_t)(cb_alloc_desc->vaddr);

		patch_addr = (u64 *)(uintptr_t)
			(k_patch_point->byte_offset + base_va);
		val_at_addr = *patch_addr;

		cve_os_log(CVE_LOGLEVEL_DEBUG,
				"PatchBaseVA:%llu @PatchPointVA:%llu PatchPointVA:%llu @PatchValue:%llu\n",
				(u64)base_va, *((u64 *)base_va),
				(u64)(patch_addr), *patch_addr);

	} else {
		patch_addr = (u64 *)(uintptr_t)k_patch_point->patch_address;
		retval = cve_os_read_user_memory(
				patch_addr,
				sizeof(val_at_addr),
				&val_at_addr);
		if (retval < 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
					"os_read_user_memory failed %d\n",
					retval);
			goto out;
		}

	}
	*patch_address = patch_addr;
	*ks_value = val_at_addr;

	return 0;

out:
	return retval;
}

int ice_mm_domain_copy(os_domain_handle *hdom_src,
	void **hdom_inf,
	u32 domain_array_size)
{
	int retval = 0;

	retval = cve_osmm_domain_copy(hdom_src, hdom_inf,
		domain_array_size);
	if (retval < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"os_malloc_zero failed %d\n", retval);
	}

	return retval;
}

void ice_mm_domain_destroy(void *hdom_inf,
	u32 domain_array_size)
{
	cve_osmm_domain_destroy(hdom_inf,
		domain_array_size);
}

int cve_mm_create_kernel_mem_allocation(
		os_domain_handle hdom,
		void *vaddr,
		u32 size_bytes,
		enum cve_surface_direction direction,
		u32 permissions,
		ice_va_t *cve_vaddr,
		struct cve_dma_handle *dma_handle,
		struct cve_surface_descriptor *surf,
		cve_mm_allocation_t *out_alloc_handle)
{
	int retval = CVE_DEFAULT_ERROR_CODE;
	struct allocation_desc *palloc = NULL;
	union allocation_address alloc_addr;

	alloc_addr.vaddr = vaddr;

	cve_os_log(CVE_LOGLEVEL_DEBUG, "Start Kernel Allocation\n");
	/* Mapping prefetch buffer issue in FW is being handled outside
	 * the driver code Therefore we don't need to check if additional
	 * prefetch map is needed here.
	 */
	retval = create_new_allocation(
			&hdom,
			&dma_handle,
			1,
			alloc_addr,
			size_bytes,
			direction,
			permissions,
			*cve_vaddr,
			OSMM_KERNEL_MEMORY,
			surf,
			&palloc);
	if (retval < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"create_new_allocation failed %d\n", retval);
		goto out;
	}

	/* case cve_vaddr is dynamically allocated return it to caller */
	if (*cve_vaddr == CVE_INVALID_VIRTUAL_ADDR)
		*cve_vaddr = cve_osmm_alloc_get_iova(palloc->halloc);
	cve_os_log(CVE_LOGLEVEL_DEBUG,
			"End Kernel Allocation: IAVA=0x%lx size_bytes=0x%x, iova=0x%llx-0x%llx, direction=%s\n",
			(uintptr_t)vaddr,
			size_bytes,
			*cve_vaddr,
			*cve_vaddr + size_bytes,
			get_cve_surface_direction_str(direction));

	/* success */
	*out_alloc_handle = palloc;
	retval = 0;
out:

	return retval;
}

int cve_mm_get_page_directory_base_addr(
		os_domain_handle hdom,
		u32 *out_base_addr)
{
	int retval = CVE_DEFAULT_ERROR_CODE;

	if (!hdom) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"domain doesn't exist for this context\n");
		retval = -EINVAL;
		goto out;
	}

	*out_base_addr = cve_osmm_get_domain_pd_base_addr(hdom);

	/* success */
	retval = 0;
out:
	return retval;
}

void ice_mm_get_domain_by_cve_idx(
	void *hdom_inf,
	u32 dma_domain_array_size,
	struct cve_device *dev,
	os_domain_handle *os_hdom)
{
	ice_osmm_get_inf_ice_domain(hdom_inf,
		dma_domain_array_size, dev->dev_index, os_hdom);
}

int cve_mm_get_buffer_addresses(
	cve_mm_allocation_t allocation,
	ice_va_t *out_iova,
	u32 *out_offset,
	u64 *out_address)
{
	struct allocation_desc *alloc = (struct allocation_desc *)allocation;
	u64 base_address;
	int err = 0;

	/* get the host virtual address */
	base_address = (u64)(uintptr_t)alloc->vaddr;

	*out_iova = cve_osmm_alloc_get_iova(alloc->halloc);
	*out_offset = 0;
	*out_address = base_address;

	return err;
}

int cve_mm_create_infer_buffer(
	u64 inf_id,
	void *hdom_inf,
	u32 domain_array_size,
	cve_mm_allocation_t buf_alloc,
	struct cve_inf_buffer *inf_buf)
{
	int retval = 0;
	enum osmm_memory_type alloc_type;
	union allocation_address alloc_addr = {0};
	struct allocation_desc *inf_alloc;
	struct allocation_desc *ntw_alloc =
		(struct allocation_desc *)buf_alloc;

	retval = OS_ALLOC_ZERO(sizeof(*inf_alloc), (void **)&inf_alloc);
	if (retval < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"os_alloc_zero failed %d\n", retval);
		goto out;
	}

	/* if using buffer sharing, set the allocation flag type
	 * to shared and set the propriatery print
	 */
	if (!inf_buf->fd && !inf_buf->base_address) {
		retval = -EINVAL;
		ASSERT(false);
		goto free_mem;
	} else if (inf_buf->fd) {
		alloc_type = OSMM_SHARED_MEMORY;
		alloc_addr.fd = inf_buf->fd;
		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Buffer FD=%llu\n", alloc_addr.fd);
	} else {
		alloc_type = OSMM_USER_MEMORY;
		alloc_addr.vaddr = (void *)(uintptr_t)inf_buf->base_address;
		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Buffer IAVA=0x%lx\n", (uintptr_t)alloc_addr.vaddr);
	}

	retval = cve_osmm_inf_dma_buf_map(
			inf_id,
			hdom_inf,
			domain_array_size,
			alloc_addr,
			alloc_type,
			ntw_alloc->halloc,
			&inf_alloc->halloc);
	if (retval < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"create_new_allocation failed %d\n", retval);
		goto free_mem;
	}

	inf_buf->inf_buf_alloc = (cve_mm_allocation_t)inf_alloc;

	goto out;

free_mem:
	OS_FREE(inf_alloc, sizeof(*inf_alloc));
out:
	return retval;
}

void cve_mm_destroy_infer_buffer(
		u64 inf_id,
		struct cve_inf_buffer *inf_buf)
{
	struct allocation_desc *inf_alloc =
		(struct allocation_desc *)inf_buf->inf_buf_alloc;

	cve_osmm_inf_dma_buf_unmap(inf_alloc->halloc);
	OS_FREE(inf_alloc, sizeof(*inf_alloc));
}

int cve_mm_create_buffer(
	os_domain_handle *hdom,
	u32 domain_array_size,
	struct cve_surface_descriptor *k_surface,
	cve_mm_allocation_t *out_alloc)
{
	int retval = CVE_DEFAULT_ERROR_CODE;
	struct allocation_desc *alloc = NULL;
	enum osmm_memory_type alloc_type;
	union allocation_address alloc_addr = {0};
	u32 prot;

	if (!k_surface->fd &&
			(k_surface->base_address) &
			(PLAFTORM_CACHELINE_SZ - 1)) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"Expected alignment to 0x%x, given base_address=%llx size=0x%llx\n",
				PLAFTORM_CACHELINE_SZ,
				k_surface->base_address,
				k_surface->size_bytes);
		retval = ICEDRV_KERROR_SURF_DEV_CACHE_ALIGNMENT;
		goto out;
	}

	ASSERT((k_surface->direction & CVE_SURFACE_DIRECTION_IN) ||
			(k_surface->direction & CVE_SURFACE_DIRECTION_OUT));

	prot = (k_surface->direction & CVE_SURFACE_DIRECTION_IN) ?
			CVE_MM_PROT_READ : 0;
	prot |= (k_surface->direction & CVE_SURFACE_DIRECTION_OUT) ?
			CVE_MM_PROT_WRITE : 0;

	/* if using buffer sharing, set the allocation flag type
	 * to shared and set the propriatery print
	 */
	if (!k_surface->fd && !k_surface->base_address) {
		alloc_type = OSMM_INFER_MEMORY;
		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Buffer Infer. Size=0x%llx, Direction=%d, Prot=%d\n",
			k_surface->size_bytes,
			k_surface->direction,
			prot);
	} else if (k_surface->fd) {
		alloc_type = OSMM_SHARED_MEMORY;
		alloc_addr.fd = k_surface->fd;
		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Buffer FD=%llu. Size=0x%llx, Direction=%d, Prot=%d\n",
			alloc_addr.fd,
			k_surface->size_bytes,
			k_surface->direction,
			prot);
	}

	else {
		alloc_type = OSMM_USER_MEMORY;
		alloc_addr.vaddr = (void *)(uintptr_t)k_surface->base_address;
		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Buffer IAVA=0x%lx. Size=0x%llx, Direction=%s, Prot=%d\n",
			(uintptr_t)alloc_addr.vaddr,
			k_surface->size_bytes,
			get_cve_surface_direction_str(k_surface->direction),
			prot);
	}

	retval = create_new_allocation(
			hdom,
			NULL,
			domain_array_size,
			alloc_addr,
			k_surface->size_bytes,
			k_surface->direction,
			prot,
			CVE_INVALID_VIRTUAL_ADDR,
			alloc_type,
			k_surface,
			&alloc);
	if (retval < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"create_new_allocation failed %d\n", retval);
		goto out;
	}

	/* success */
	*out_alloc = alloc;

	retval = 0;
out:
	ASSERT((!alloc) || (retval == 0));
	return retval;
}

void cve_mm_destroy_buffer(
	cve_context_id_t context_id,
	cve_mm_allocation_t allocation)
{
	struct allocation_desc *alloc = (struct allocation_desc *)allocation;

	cve_mm_reclaim_allocation(alloc);

	/* May be further optimized:
	 * - for each context the time stamp indicating the "last run time"
	 * will be saved
	 * - for each device the time stamp indicating the "last reset time"
	 * will be saved
	 * if the "last reset time" > the "last run time"
	 * there is no need to invalidate the TLB
	 */
}

int cve_mm_map_kva(cve_mm_allocation_t halloc)
{
	struct allocation_desc *alloc = (struct allocation_desc *)halloc;
	int err = 0;
	u64 base_address;

	if (alloc->fd > 0 && alloc->is_mapped == false) {
		err = cve_osmm_map_kva(alloc->halloc, &base_address);
		if (err)
			return err;

		alloc->is_mapped = true;
		alloc->vaddr = (void *)base_address;
		cve_os_log(CVE_LOGLEVEL_DEBUG,
				"[MAP] Surface VA:%llu FD:%llu SZ:0x%llx\n",
				(u64)alloc->vaddr, alloc->fd,
				alloc->size_bytes);
	}

	return err;
}




int cve_mm_unmap_kva(cve_mm_allocation_t halloc)
{
	struct allocation_desc *alloc = (struct allocation_desc *)halloc;
	int err = 0;

	if (alloc->is_mapped) {
		err = cve_osmm_unmap_kva(alloc->halloc, alloc->vaddr);
		alloc->is_mapped = false;
		cve_os_log(CVE_LOGLEVEL_DEBUG,
				"Unamp Surface VA:%llu FD:%llu SZ:0x%llx\n",
				(u64)alloc->vaddr, alloc->fd,
				alloc->size_bytes);
	}

	return err;
}


void cve_mm_print_user_buffer(cve_mm_allocation_t halloc,
		void *buffer_addr,
		u32 size_bytes,
		const char *buf_name)
{
	struct allocation_desc *alloc = (struct allocation_desc *)halloc;
#ifdef __KERNEL__
#ifdef CONFIG_DYNAMIC_DEBUG
	DEFINE_DYNAMIC_DEBUG_METADATA(descriptor, "enable user buffer print");

	if (unlikely(descriptor.flags & _DPRINTK_FLAGS_PRINT))

#endif
#else
	if (print_debug)
#endif
	{
		cve_osmm_print_user_buffer(
				alloc->halloc,
				size_bytes,
				buffer_addr,
				buf_name);
	}
}

#ifdef _DEBUG
void print_cur_page_table(os_domain_handle hdom)
{
	cve_osmm_print_page_table(hdom);
}
#endif


static int __patch_inter_cb_offset(struct cve_ntw_buffer *buf_info,
	u32 *patch_address, s16 inter_cb_offset)
{
	u32  original_val;
	struct allocation_desc *alloc_desc;
	bool is_dma_buf = false;
	int ret = 0;

	alloc_desc = (struct allocation_desc *)buf_info->ntw_buf_alloc;
	is_dma_buf = (alloc_desc->fd > 0) ? true : false;

	if (is_dma_buf) {
		original_val = *(patch_address);
	} else {
		ret = cve_os_read_user_memory(patch_address, sizeof(u32),
			&original_val);
		if (ret < 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
				"os_read_user_memory_64 failed %d\n", ret);
			goto out;
		}
	}

	cve_os_log(CVE_LOGLEVEL_DEBUG,
			"buff ID: %llu patch_address:%p OrigVal: 0x%x\n",
			buf_info->buffer_id, patch_address, original_val);


	original_val &= 0xFFFF0000;
	cve_os_log(CVE_LOGLEVEL_DEBUG,
			"buff ID: %llu patch_address:%p OrigVal: 0x%x\n",
			buf_info->buffer_id, patch_address, original_val);

	original_val |= (inter_cb_offset & 0x0000FFFF);

	cve_os_log(CVE_LOGLEVEL_DEBUG,
			"buff ID: %llu patch_address:%p OrigVal: 0x%x Offset:%d\n",
			buf_info->buffer_id, patch_address, original_val,
			inter_cb_offset);

	if (is_dma_buf) {
		*patch_address = original_val;
	} else {
		ret = cve_os_write_user_memory(patch_address, sizeof(u32),
				&original_val);
		if (ret < 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
					"os_write_user_memory failed %d\n",
					ret);
			goto out;
		}
	}

	/*
	 * find the buffer that was patched and set the dirty
	 * cache bit for this buffer - for cache flush operation
	 */
	cve_mm_set_dirty_cache(buf_info->ntw_buf_alloc);


out:
	return ret;
}

static int __patch_surface(struct cve_ntw_buffer *buf_info,
	u64 *patch_address, u64 ks_value)
{
	struct allocation_desc *alloc_desc;
	bool is_dma_buf = false;
	int ret = 0;

	alloc_desc = (struct allocation_desc *)buf_info->ntw_buf_alloc;
	is_dma_buf = (alloc_desc->fd > 0) ? true : false;

	cve_os_log(CVE_LOGLEVEL_DEBUG,
		 "Patching BufferID=0x%llx with PatchValue=0x%llx at IAVA=0x%lx\n",
		 buf_info->buffer_id,
		 ks_value,
		 (uintptr_t)patch_address);

	if (is_dma_buf) {
		*patch_address = ks_value;
	} else {
		ret = cve_os_write_user_memory_64(patch_address,
				ks_value);
		if (ret < 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
				"os_write_user_memory_64 failed %d\n",
				ret);
			goto out;
		}
	}
out:
	return ret;
}

/* Common function to calculate VA for Surface and PP */
static void __calc_pp_va(ice_va_t va, u32 page_offset,
		struct cve_patch_point_descriptor *pp_desc,
		u64 *surf_ice_va) {

	u64 patch_value_64, mask, ice_va;

	ice_va = *(surf_ice_va);

	va += page_offset;
	patch_value_64 = va + pp_desc->byte_offset_from_base;

	/*If is_msb is true then use the 3 MSB bit of VA */
	if (pp_desc->is_msb)
		patch_value_64 >>= 32;

	if (pp_desc->bit_offset) {
		patch_value_64 >>= sizeof(cve_virtual_address_t) *
		BITS_PER_BYTE - pp_desc->num_bits;
		patch_value_64 <<= (u64)(pp_desc->bit_offset);
	} else {
		patch_value_64 &= BIT_ULL(pp_desc->num_bits) - 1;
	}
	mask = BIT_ULL(pp_desc->num_bits) - 1;
	mask <<= (u64)(pp_desc->bit_offset);

	ice_va &= ~mask;
	ice_va |= (mask & patch_value_64);

	*(surf_ice_va) = ice_va;
}

static void __calc_cntr_va(struct jobgroup_descriptor *jobgroup,
	struct cve_patch_point_descriptor *pp_desc,
	struct cve_device *dev,
	u64 *surf_ice_va)
{
	cve_virtual_address_t cve_start_address = 0;
	ice_va_t base_surf_va = 0;
	u32 increase_value;
	uint16_t j;

	/* BAR1 start address remains constant e.g. 0xFFFF0000.
	 * Add offset of a particular counter reg type to
	 * this start address e.g. COUNTER_INCREMENT register
	 * offset is 0x8.
	 * Increase value specifies the gap between two counters
	 * of same counter  register e.g offset of COUNTER_INCREMENT0
	 * is 0x8 and COUNTER_INCREMENT1 is 0x28 hence increase value
	 * becomes 0x20.
	 * Only counter value should be patched for COUNTER_NOTIFICATION
	 * register.
	 */
	cve_start_address = IDC_BAR1_COUNTERS_ADDRESS_START;
	increase_value = 32;

	/* Guaranteed that all required counters are mapped */
	j = jobgroup->network->cntr_info.cntr_id_map[pp_desc->cntr_id];
	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"CntrSwID=%u already Mapped to CntrHwID=%u. NtwID:0x%llx\n",
		pp_desc->cntr_id, j, jobgroup->network->network_id);

	if (pp_desc->patch_point_type ==
				ICE_PP_TYPE_CNTR_SET) {
		cve_start_address +=
			cfg_default.bar1_msg_evctice0_msgregaddr;
	} else if (pp_desc->patch_point_type ==
				ICE_PP_TYPE_CNTR_INC) {
		cve_start_address +=
			cfg_default.bar1_msg_evctincice0_msgregaddr;
	}

	if (pp_desc->patch_point_type == ICE_PP_TYPE_CNTR_NOTIFY)
		base_surf_va = (u32)j;
	else if (pp_desc->patch_point_type == ICE_PP_TYPE_CNTR_NOTIFY_ADDR) {
		base_surf_va = IDC_BAR1_COUNTERS_NOTI_ADDR;
		if (ice_is_soc())
			base_surf_va += (dev->dev_index % 2) ?
				IDC_BAR1_ICE_REGION_SPILL_SZ : 0;
	} else {
		base_surf_va = cve_start_address + (increase_value * j);
		if (ice_is_soc())
			base_surf_va += (dev->dev_index % 2) ?
				IDC_BAR1_ICE_REGION_SPILL_SZ : 0;
	}

	__calc_pp_va(base_surf_va, 0, pp_desc, surf_ice_va);
}

static void __calc_surf_va(struct allocation_desc *alloc_desc,
	struct cve_patch_point_descriptor *pp_desc, u64 *surf_ice_va)
{
	ice_va_t base_surf_va = 0;

	base_surf_va = cve_osmm_alloc_get_iova(alloc_desc->halloc);

	__calc_pp_va(base_surf_va, 0, pp_desc, surf_ice_va);

	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"New PatchValue calculated. BufferICEVA=0x%llx, IsMSB=%u, PatchValue=%llx\n",
		base_surf_va, pp_desc->is_msb, *surf_ice_va);

}

static int  __create_pp_mirror_image(
	struct cve_patch_point_descriptor *cur_pp_desc,
	struct job_descriptor *job,
	struct ice_pp_copy **out_pp)
{
	struct ice_pp_copy *pp = NULL;
	struct ice_network *ntw = job->jobgroup->network;
	int ret = 0;
	u32 sz = 0;

	/* allocate structure for the counter patch point mirror image */
	sz = (sizeof(*pp));
	/* TODO: Free this memory during DestroyNetwork */
	ret = OS_ALLOC_ZERO(sz, (void **)&pp);
	if (ret < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"Allocation for counter patch point failed %d. JobID=%lx\n",
			ret, (uintptr_t)job);
		goto out;
	}
	/* Mirroring is required to store counter patch point information */
	memcpy(&pp->pp_desc, cur_pp_desc, sizeof(*cur_pp_desc));

	if (cur_pp_desc->patch_point_type == ICE_PP_TYPE_SURFACE) {
		/* Add this PP desc to Ntw list */
		cve_dle_add_to_list_before(ntw->ntw_surf_pp_list, list, pp);
	} else {
		/* TODO: Move this PP desc to Ntw list */
		cve_dle_add_to_list_before(job->job_cntr_pp_list, list, pp);
	}

	*out_pp = pp;

out:
	return ret;
}

int ice_mm_patch_inf_pp_arr(struct ice_infer *inf)
{
	u32 i;
	int ret = 0;
	struct ice_pp_value *pp_value;

	if (inf->inf_pp_arr == NULL)
		goto out;

	for (i = 0; i < inf->ntw->ntw_surf_pp_count; i++) {

		/* IAVA and Value of PP is stored in this object */
		pp_value = &inf->inf_pp_arr[i];

		ret = __patch_surface(pp_value->ntw_buf,
				pp_value->pp_address, pp_value->pp_value);
		if (ret < 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
				"ERROR:%d __patch_surface() failed\n", ret);
			goto out;
		}
	}

out:
	return ret;
}

static int __process_inf_surf_pp(struct cve_patch_point_descriptor *cur_pp_desc,
		struct cve_ntw_buffer *ntw_buf,
		struct cve_inf_buffer *inf_buf,
		struct ice_pp_value *pp_value)
{
	int ret = 0;
	struct allocation_desc *alloc_desc, *cb_alloc_desc;
	u64  ks_value;
	u64 *patch_address = NULL;

	cb_alloc_desc = (struct allocation_desc *)ntw_buf->ntw_buf_alloc;
	alloc_desc = (struct allocation_desc *)inf_buf->inf_buf_alloc;

	ret = __get_patch_point_addr_and_val(cb_alloc_desc,
			cur_pp_desc, &patch_address, &ks_value);
	if (ret < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"Failed(%d) to read from patch point location\n",
				ret);
		goto out;
	}

	__calc_surf_va(alloc_desc, cur_pp_desc, &ks_value);

	pp_value->ntw_buf = ntw_buf;
	pp_value->pp_address = patch_address;
	pp_value->pp_value = ks_value;

out:
	return ret;
}

int ice_mm_process_inf_pp_arr(struct ice_infer *inf)
{
	u32 i;
	int ret = 0;
	struct ice_network *ntw = inf->ntw;
	struct ice_pp_copy *pp_copy = ntw->ntw_surf_pp_list;
	struct ice_pp_value *pp_value;
	struct cve_patch_point_descriptor *pp_desc;
	struct cve_ntw_buffer *ntw_buf, *ntw_buf_user;
	struct cve_inf_buffer *inf_buf;

	for (i = 0; i < ntw->ntw_surf_pp_count; i++) {

		/* PP desc for this iteration */
		pp_desc = &pp_copy->pp_desc;

		/* IAVA and Value of PP will be store in this object */
		pp_value = &inf->inf_pp_arr[i];

		/* Get CB buffer from Ntw list */
		ntw_buf = &ntw->buf_list[pp_desc->patching_buf_index];

		/* Get User buffer from Inf list*/
		ntw_buf_user = &ntw->buf_list[pp_desc->allocation_buf_index];
		inf_buf = &inf->buf_list[ntw_buf_user->index_in_inf];

		ret = __process_inf_surf_pp(pp_desc, ntw_buf, inf_buf,
				pp_value);
		if (ret < 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
				"__process_inf_surf_pp failed %d\n", ret);
			goto out;
		}

		pp_copy = cve_dle_next(pp_copy, list);
	}

out:
	return ret;
}

static int __process_surf_pp(struct cve_patch_point_descriptor *cur_pp_desc,
		struct cve_ntw_buffer *buf_list,
		struct job_descriptor *job)
{
	u32 buf_idx = 0;
	int ret = 0;
	struct cve_ntw_buffer *ad, *cb_buf_info;
	struct allocation_desc *alloc_desc, *cb_alloc_desc;
	u64  ks_value;
	u64 *patch_address = NULL;
	struct ice_pp_copy *surf_pp;

	buf_idx = cur_pp_desc->patching_buf_index;
	cb_buf_info = &buf_list[buf_idx];

	buf_idx = cur_pp_desc->allocation_buf_index;
	ad = &buf_list[buf_idx];

	cb_alloc_desc =
		(struct allocation_desc *)cb_buf_info->ntw_buf_alloc;
	alloc_desc = (struct allocation_desc *)ad->ntw_buf_alloc;

	ret = __get_patch_point_addr_and_val(cb_alloc_desc,
			cur_pp_desc, &patch_address, &ks_value);
	if (ret < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"Failed(%d) to read from patch point location\n",
				ret);
		goto out;
	}

	if (alloc_desc->mem_type == OSMM_INFER_MEMORY) {
		ret = __create_pp_mirror_image(cur_pp_desc, job, &surf_pp);
		if (ret < 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
				"Failed(%d) to create patch point copy\n",
				ret);
			goto out;
		}

		job->jobgroup->network->ntw_surf_pp_count++;

		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Creating PP copy for Infer Buffer. BufferIdx=%d, JobID=%lx",
			buf_idx, (uintptr_t)job);
#if 1
		goto out;
#endif
	}

	__calc_surf_va(alloc_desc, cur_pp_desc, &ks_value);

	ret = __patch_surface(cb_buf_info, patch_address, ks_value);
	if (ret < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"ERROR:%d __patch_surface() failed\n", ret);
		goto out;
	}

out:
	return ret;
}

static int __process_inter_cb_loop_pp(
		struct cve_patch_point_descriptor *cur_pp_desc,
		struct cve_ntw_buffer *buf_list,
		struct jobgroup_descriptor *jobgroup)
{
	u32 buf_idx = 0;
	int ret = 0;
	struct cve_ntw_buffer *cb_buf_info;
	struct allocation_desc *cb_alloc_desc;
	u64  ks_value;
	u64 *patch_address = NULL;

	buf_idx = cur_pp_desc->patching_buf_index;
	cb_buf_info = &buf_list[buf_idx];

	cb_alloc_desc =
		(struct allocation_desc *)cb_buf_info->ntw_buf_alloc;

	ret = __get_patch_point_addr_and_val(cb_alloc_desc,
			cur_pp_desc, &patch_address, &ks_value);
	if (ret < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"Failed(%d) to read from patch point location\n",
				ret);
		goto out;
	}

	ret = __patch_inter_cb_offset(cb_buf_info, (u32 *)patch_address,
			cur_pp_desc->inter_cb_offset);
	if (ret < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"ERROR:%d __patch_surface() failed\n", ret);
		goto out;
	}


out:
	return ret;
}

int ice_mm_process_patch_point(struct cve_ntw_buffer *buf_list,
		struct cve_patch_point_descriptor *patch_desc_list,
		u32 patch_list_sz, struct job_descriptor *job)
{
	u32 i = 0;
	int ret = 0;
	struct cve_patch_point_descriptor *cur_pp_desc;
	u32 cntr_pp_count = 0;
	enum ice_pp_type pp_type;
	struct jobgroup_descriptor *jobgroup = job->jobgroup;
	struct ice_pp_copy *pp;

	for (i = 0; i < patch_list_sz; ++i) {
		cur_pp_desc = &patch_desc_list[i];
		pp_type = patch_desc_list[i].patch_point_type;

		cve_os_log(CVE_LOGLEVEL_DEBUG,
			COLOR_YELLOW(
				"Processing Patch Point. PP_Idx=%d\n"
				),
			i);

		switch (pp_type) {
		case ICE_PP_TYPE_CNTR_SET:
		case ICE_PP_TYPE_CNTR_INC:
		case ICE_PP_TYPE_CNTR_NOTIFY:
		case ICE_PP_TYPE_CNTR_NOTIFY_ADDR:
			ret = __create_pp_mirror_image(cur_pp_desc, job, &pp);
			cntr_pp_count++;
			/* KMD is assuming that cntr_id will never be
			 * -1 here. Creating Bitmap of graph_ctr_id
			 *  that is used by this Jobgroup.
			 */
			jobgroup->cntr_bitmap |=
				(1 << cur_pp_desc->cntr_id);
			break;
		case ICE_PP_TYPE_SURFACE:
			ret = __process_surf_pp(cur_pp_desc, buf_list, job);
			break;
		case ICE_PP_TYPE_INTER_CB:
			ret = __process_inter_cb_loop_pp(cur_pp_desc,
					buf_list,
					jobgroup);
			break;
		default:
			ret = -ICEDRV_KERROR_PP_TYPE_EINVAL;
			cve_os_log(CVE_LOGLEVEL_ERROR,
					"ERROR:%d JG:%p Invalid PatchPoint Type:%d\n",
					ret, jobgroup, pp_type);
			break;
		}

		if (ret < 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
					"ERROR:%d JG:%p Index:%d Type:%d patching process failed\n",
					ret, jobgroup, i, pp_type);
			goto out;
		}
	}

out:
	return ret;
}

int ice_mm_patch_cntrs(struct cve_ntw_buffer *buf_list,
	struct job_descriptor *job,
	struct cve_device *dev)
{
	u32 buf_idx = 0;
	int ret = 0;
	struct ice_pp_copy *head_des;
	struct ice_pp_copy *next_des;
	struct cve_ntw_buffer *cb_buf_info;
	struct allocation_desc *cb_alloc_desc;
	u64  ks_value;
	u64 *patch_address = NULL;

	head_des = job->job_cntr_pp_list;
	next_des = head_des;

	/* This invalid case should have reached here */
	ASSERT(head_des != NULL);

	do {
		buf_idx = next_des->pp_desc.patching_buf_index;
		cb_buf_info = &buf_list[buf_idx];

		cb_alloc_desc =
			(struct allocation_desc *)cb_buf_info->ntw_buf_alloc;

		/* Gets PP address and current Value in that address */
		ret = __get_patch_point_addr_and_val(cb_alloc_desc,
		&next_des->pp_desc, &patch_address, &ks_value);
		if (ret < 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
				"Failed(%d) to read from patch point location\n",
				ret);
			goto out;
		}

		/* Calculate newValue for PP address */
		__calc_cntr_va(job->jobgroup, &next_des->pp_desc,
				dev, &ks_value);

		/* Perform patching. Patching done if newValue is different */
		ret = __patch_surface(cb_buf_info, patch_address, ks_value);
		if (ret < 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
				"ERROR:%d __patch_surface() failed\n", ret);
			goto out;
		}

		cve_mm_set_dirty_cache(cb_buf_info->ntw_buf_alloc);
		cve_mm_sync_mem_to_dev(cb_buf_info->ntw_buf_alloc, dev);

		next_des = cve_dle_next(next_des, list);
	} while (head_des != next_des);

out:
	return ret;
}

cve_virtual_address_t ice_mm_get_iova(struct cve_ntw_buffer *buffer)
{
	struct allocation_desc *alloc_desc;

	alloc_desc = (struct allocation_desc *)buffer->ntw_buf_alloc;

	return cve_osmm_alloc_get_iova(alloc_desc->halloc);
}

void ice_mm_get_page_sz_list(os_domain_handle hdom, u32 **page_sz_list)
{
	return ice_osmm_domain_get_page_sz_list(hdom, page_sz_list);
}
