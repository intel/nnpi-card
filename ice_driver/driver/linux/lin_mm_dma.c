/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/



#ifdef RING3_VALIDATION
#include "linux_kernel_mock.h"
#define GET_USER_PAGES_HAS_TSK (0)
#define GET_USER_PAGES_GUP_PARAM (0)
#else
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/dma-mapping.h>
#include <asm/current.h>
#include <linux/highmem.h>
#include <linux/version.h>
#include <linux/dma-buf.h>

#define GET_USER_PAGES_HAS_TSK (KERNEL_VERSION(4, 6, 0) <= LINUX_VERSION_CODE)
#define GET_USER_PAGES_GUP_PARAM \
	(KERNEL_VERSION(4, 10, 0) <= LINUX_VERSION_CODE)
#endif

#define INFER_MEM_ONLY(mem_type) \
	((mem_type) == OSMM_INFER_MEMORY)
#define USER_MEM_ONLY(mem_type) \
	((mem_type) == OSMM_USER_MEMORY)
#define SHARED_MEM_ONLY(mem_type) \
	((mem_type) == OSMM_SHARED_MEMORY)
#define USER_OR_SHARED_MEM(mem_type) \
	(USER_MEM_ONLY(mem_type) || SHARED_MEM_ONLY(mem_type))
#define KERNEL_MEM_ONLY(mem_type) \
	((mem_type) == OSMM_KERNEL_MEMORY)

#include <device_interface.h>
#include "project_settings.h"
#include "osmm_interface.h"
#include "cve_linux_internal.h"
#include "lin_mm_internal.h"
#include "ice_debug.h"
#include "doubly_linked_list.h"

/* DATA TYPES */

/* allocation descriptor */
struct lin_mm_allocation {
	/* size as per the surface requirement */
	u64 size_bytes;
	/* actual size allocated by the allocator */
	u64 actual_sz;
	/* guest virtual address */
	void *vaddr;
	/* file descriptor in case of buffer sharing */
	u64 fd;
	/* list of mem domain & dma per cve device */
	struct cve_os_allocation *per_cve;
	/* device virtual address */
	/*
	 * NOTE: cve_vaddr is identical per allocation to all
	 * cve devices, otherwise it's impossible to perform
	 * patching. read more info in cve_ds_handle_submit()
	 * function.
	 */
	ice_va_t cve_vaddr;
	/* list of all the page frames */
	struct page **pages;
	/* number of page frames */
	size_t os_pages_nr;
	/* ICE page shift */
	u8 page_shift;
	/* allocation type */
	enum osmm_memory_type mem_type;
	/* dma-buf pointer */
	struct dma_buf *dbuf;
	/* Page size alignment requirement */
	u32 page_sz;
	/* Holds meta data for a buffer
	 * LLC config, permission bits, partition id
	 */
	struct ice_lin_mm_buf_config buf_meta_data;
	/* number of ice page frames */
	size_t ice_pages_nr;
	os_domain_handle hdomain[MAX_CVE_DEVICES_NR];
	u32 dma_domain_array_size;
};


static u32 calc_alloc_cve_pages_nr(const struct lin_mm_allocation *alloc);

static int dma_buf_sharing_connect_to_buffer(
	struct device *dev,
	struct lin_mm_allocation *alloc,
	struct cve_os_allocation *cve_alloc_data);

static void dma_buf_sharing_disconnect_from_buffer(
	struct lin_mm_allocation *alloc,
	struct cve_os_allocation *cve_alloc_data);

void cve_osmm_print_page_table(os_domain_handle hdomain)
{
	struct cve_device_group *dg = cve_dg_get();

	if (!dg) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"null dg pointer (%d) !!\n", -EINVAL);
		return;
	}
	if (dg->dump_conf.pt_dump)
		cve_page_table_dump((struct cve_lin_mm_domain *)hdomain);
}

/*
 * InferDomain is destroyed during DestroyInfer
 */
void cve_osmm_domain_destroy(os_domain_handle *hdom,
		u32 domain_array_size)
{
	u32 i;

	for (i = 0; i < domain_array_size; i++) {
		struct cve_lin_mm_domain *dom =
			(struct cve_lin_mm_domain *)hdom[i];

		lin_mm_domain_destroy(dom);
	}
}

/* INTERNAL FUNCTIONS */

static enum dma_data_direction prot_2_dir(enum cve_memory_protection prot)
{
	enum dma_data_direction dir =
		(prot == CVE_MM_PROT_READ) ? DMA_TO_DEVICE :
		(prot == CVE_MM_PROT_WRITE) ? DMA_FROM_DEVICE :
		(prot == (CVE_MM_PROT_WRITE  | CVE_MM_PROT_READ)) ?
			DMA_BIDIRECTIONAL : DMA_NONE;
	ASSERT(dir != DMA_NONE);
	return dir;
}

/*
 * remove the mappings in device's page tables of all the pages
 * in the given allocation.
 * inputs : cve_vaddr - cve virtual address
 *          cve_pages_to_unmap - number of pages
 *          adom - pointer to cve domain
 * outputs:
 * returns:
 */
static void remove_from_device_page_table(ice_va_t cve_vaddr,
	u32 cve_pages_to_unmap,
	struct cve_lin_mm_domain *adom, u8 partition_id)
{
	FUNC_ENTER();

	ASSERT(cve_vaddr != 0);

	lin_mm_unmap(adom, cve_vaddr, cve_pages_to_unmap, partition_id);

	FUNC_LEAVE();
}

/*
 * get iova (page frame index) for an allocation
 * inputs : allocator - the allocation's iova allocator
 *                      cve_addr - the device-virtual address at which the
 *                                 allocation should be mapped
 *                      pages_nr - size of allocation
 * outputs: out_iova - will hold the allocated iova
 * returns: 0 on success, a negative error code on failure
 */
static int get_iova(cve_iova_allocator_handle_t allocator,
		struct ice_mmu_config *mmu_config,
		ice_va_t cve_addr,
		u32 cve_pages_nr,
		u32 *out_iova)
{
	u32 iova;
	int retval = CVE_DEFAULT_ERROR_CODE;

	FUNC_ENTER();

	if (cve_addr == CVE_INVALID_VIRTUAL_ADDR) {
		retval = cve_iova_alloc(allocator, cve_pages_nr, &iova);
		if (retval != 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
				"cve_iova_alloc failed %d\n", retval);
			goto out;
		}
	} else {
		iova = VADDR_TO_IOVA(cve_addr, mmu_config->page_shift);
		if (IOVA_TO_VADDR(iova, mmu_config->page_shift) != cve_addr) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
				"ICEVA not page aligned. ICEVA=0x%llx, PageShift=%d\n",
				cve_addr, mmu_config->page_shift);
			retval = -ICEDRV_KERROR_IOVA_PAGE_ALIGNMENT;
			goto out;
		}
#ifdef IDC_ENABLE
		/* We are not claiming iova region for counters as it is not
		 * in top 3 GB.
		 * TBD: Move counters IOVA region to driver maintained space
		 */
		if (cve_addr == IDC_BAR1_COUNTERS_ADDRESS_START) {
			*out_iova = iova;
			retval = 0;
			goto out;
		}
#endif
		retval = cve_iova_claim(allocator, iova, cve_pages_nr);
		if (retval != 0) {
			cve_os_log(CVE_LOGLEVEL_WARNING,
				"cve_iova_claim failed %d\n", retval);
			goto out;
		}
	}
	*out_iova = iova;

	retval = 0;
out:
	FUNC_LEAVE();
	return retval;
}

/*
 * calculate number of pages in the given allocation
 * inputs : alloc
 * outputs:
 * returns: number of pages in the allocation
 */
static u32 calc_alloc_os_pages_nr(const struct lin_mm_allocation *alloc)
{
	unsigned long start = (unsigned long)alloc->vaddr;
	unsigned long end = round_up_os_pagesize(start + alloc->size_bytes);
	u32 os_pages_nr =
		bytes_to_os_pages(end - round_down_os_pagesize(start));
	return os_pages_nr;
}

/*
 * calculate number of CVE pages in the given allocation
 * inputs : alloc
 * outputs:
 * returns: number of pages in the allocation
 */
static u32 calc_alloc_cve_pages_nr(const struct lin_mm_allocation *alloc)
{
	u64 end;
	u32 page_sz = ICE_PAGE_SZ(alloc->page_shift);
	u32 ice_pages_nr;

	end = round_up_cve_pagesize((alloc->actual_sz), page_sz);
	ice_pages_nr = bytes_to_cve_pages(end, alloc->page_shift);
	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"PagesCount=%d, PageSize=0x%x, AllocSize=0x%llx\n",
		ice_pages_nr, page_sz, alloc->actual_sz);
	return ice_pages_nr;
}

/*
 * map all the papges in the given allocation in the device's page tables
 * where allocation is physically contiguous, as is the case with kernel memory
 * that was allocated using kmalloc
 * inputs : alloc
 *          cve_alloc_data - pointer to cve specific alloc data (dma & domain)
 *          cve_vaddr - the device-virtual address at which the allocation
 *                      should be mapped (can be CVE_INVALID_VIRTUAL_ADDR)
 * outputs: cve_vaddr that was allocated.
 * returns: 0 on success, a negative error code on failure
 */
static int add_contig_to_device_page_table(struct lin_mm_allocation *alloc,
		struct cve_os_allocation *cve_alloc_data)
{
	u32 cve_pages_nr, page_sz;
	int retval;
	struct cve_lin_mm_domain *adom =
		(struct cve_lin_mm_domain *)cve_alloc_data->domain;

	FUNC_ENTER();

	alloc->actual_sz = alloc->size_bytes;
	alloc->os_pages_nr = calc_alloc_os_pages_nr(alloc);
	cve_pages_nr = calc_alloc_cve_pages_nr(alloc);
	page_sz = ICE_PAGE_SZ(alloc->page_shift);

	/* map all pages */
	retval = lin_mm_map(adom,
			alloc->cve_vaddr,
			cve_alloc_data->dma_handle.mem_handle.dma_address,
			cve_pages_nr * page_sz, &alloc->buf_meta_data);
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"lin_mm_map failed %d\n", retval);
		goto out;
	}

	retval = 0;
out:
	FUNC_LEAVE();
	return retval;

}

/*
 * unmap the given allocation from device memory.
 * the DMA layer guarantees that the memory is sync'ed before the cpu
 * accesses it.
 * inputs : cve_alloc_data - dma & domain data
 *          dir - dma data direction
 *          nents - number of entries to unregister
 * outputs:
 * returns:
 */
static void unmap_user_allocation(struct cve_os_allocation *cve_alloc_data,
	enum dma_data_direction dir,
	int nents)
{
	struct scatterlist *sglist =
		cve_alloc_data->dma_handle.mem_handle.sgt->sgl;
	struct cve_device *ice = get_first_device();

	FUNC_ENTER();

	dma_unmap_sg(to_cve_os_device(ice)->dev,
			sglist, nents,
			dir);

	FUNC_LEAVE();
}

/*
 * map the given allocation to device memory. the DMA layer
 * guarantees that the memory is sync'ed before the devices accesses it.
 * inputs : cve_alloc_data - dma & domain data
 *          dir - dma data direction
 *          nents - number of entries to register
 * outputs:
 * returns: 0 on success, a negative error code on failure
 */
static int map_user_allocation(struct cve_os_allocation *cve_alloc_data,
	enum dma_data_direction dir,
	int nents)
{
	int retval = CVE_DEFAULT_ERROR_CODE;
	struct cve_device *ice = get_first_device();
	struct scatterlist *sglist =
		cve_alloc_data->dma_handle.mem_handle.sgt->sgl;
	int r_nents;

	FUNC_ENTER();

	/* dma address of user memory are set by dma_map_sg */
	r_nents = dma_map_sg(to_cve_os_device(ice)->dev,
			sglist,
			nents,
			dir);
	if (r_nents != nents) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "dma_map_sg failed\n");
		unmap_user_allocation(cve_alloc_data,
			dir,
			r_nents);
		retval = -EFAULT;
		goto out;
	}

	/* success */
	retval = 0;
out:
	FUNC_LEAVE();
	return retval;
}

/*
 * add all the papges in the given allocation's scatter/gather list
 * to the device's page tables.
 * inputs : alloc
 *          cve_alloc_data - pointer to cve specific alloc data (dma & domain)
 *          cve_vaddr - the device-virtual address at which the allocation
 *                      should be mapped (can be CVE_INVALID_VIRTUAL_ADDR)
 * outputs: cve_vaddr that was allocated.
 * returns: number of entries in the allocation's scatter/gather list that were
 *          mapped
 */
static int add_sglist_to_device_page_table(struct lin_mm_allocation *alloc,
		struct cve_os_allocation *cve_alloc_data)
{
	u8 partition_id = alloc->buf_meta_data.partition_id;
	struct scatterlist *sglist =
		cve_alloc_data->dma_handle.mem_handle.sgt->sgl;
	int nents = cve_alloc_data->dma_handle.mem_handle.sgt->nents;
	struct cve_lin_mm_domain *adom =
		(struct cve_lin_mm_domain *)cve_alloc_data->domain;
	struct ice_mmu_config *mmu_config = &(adom->mmu_config[partition_id]);
	struct scatterlist *sg = NULL;
	u32 mapped_pages_nr = 0;
	int retval = CVE_DEFAULT_ERROR_CODE;
	u32 base_iova, iova;
	int i;
	u64 total_size_bytes = 0;

	FUNC_ENTER();

	iova = VADDR_TO_IOVA(alloc->cve_vaddr, mmu_config->page_shift);
	base_iova = iova;

	for_each_sg(sglist, sg, nents, i) {

		/* each segment in list is aligned to CVE page
		 * to calculate minimum num of CVE pages required
		 * sg->offset is OS page aligned
		 */
		u64 size_bytes = round_up_cve_pagesize(
				(sg->offset & (mmu_config->page_sz - 1)) +
				sg_dma_len(sg), mmu_config->page_sz);
		u32 size_cve_pages = bytes_to_cve_pages(size_bytes,
				mmu_config->page_shift);
		ice_va_t cva = IOVA_TO_VADDR(iova, mmu_config->page_shift);

		total_size_bytes += size_bytes;
		if (total_size_bytes >= alloc->size_bytes)
			size_bytes -= (total_size_bytes - alloc->size_bytes);

		retval = lin_mm_map(adom,
				cva,
				sg_dma_address(sg),
				size_bytes,
				&alloc->buf_meta_data);
		if (retval) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
				"lin_mm_map failed %d\n", retval);
			goto cleanup_error;
		}

		if (total_size_bytes >= alloc->size_bytes)
			break;

		iova += size_cve_pages;
		mapped_pages_nr += size_cve_pages;
	}

	/* success */
	retval = 0;
out:
	FUNC_LEAVE();
	return retval;

cleanup_error:
	lin_mm_unmap(adom,
			IOVA_TO_VADDR(base_iova, mmu_config->page_shift),
			mapped_pages_nr,
			alloc->buf_meta_data.partition_id);
	goto out;
}

/*
 * map all the papges in the given allocation in the device's page tables
 * where allocation is physically contiguous, as is the case with kernel memory
 * that was allocated using kmalloc
 * inputs : alloc
 *          cve_alloc_data - pointer to cve specific alloc data (dma & domain)
 *          cve_vaddr - the device-virtual address at which the allocation
 *                      should be mapped (can be CVE_INVALID_VIRTUAL_ADDR)
 * outputs: cve_vaddr that was allocated.
 * returns: 0 on success, a negative error code on failure
 */
static int add_to_device_page_table(struct lin_mm_allocation *alloc,
		struct cve_os_allocation *cve_alloc)
{
	return (cve_alloc->dma_handle.mem_type == CVE_MEMORY_TYPE_USER ||
		cve_alloc->dma_handle.mem_type == CVE_MEMORY_TYPE_KERNEL_SG) ||
		cve_alloc->dma_handle.mem_type ==
		CVE_MEMORY_TYPE_SHARED_BUFFER_SG ?
		add_sglist_to_device_page_table(alloc, cve_alloc) :
		add_contig_to_device_page_table(alloc, cve_alloc);
}

/*
 * pin the pages in the given allocation to memory
 * inputs : alloc
 * outputs: the allocation's 'sgt', 'pages' and 'npages' fields are updated
 * returns: 0 on success, a negative error code on failure
 */
static int pin_user_memory(struct lin_mm_allocation *alloc)
{
	unsigned long start;
	size_t array_size;
	int os_pages_nr;
	struct page **pages = NULL;
	long nr = 0;
	int ret = -ENOMEM;
	int is_writable =
		(alloc->buf_meta_data.prot & CVE_MM_PROT_WRITE) ? 1 : 0;
#if GET_USER_PAGES_GUP_PARAM
	unsigned int gup_flags;

	gup_flags = FOLL_WRITE;
	gup_flags |= (is_writable) ? 0 : FOLL_FORCE;
#endif
	FUNC_ENTER();

	start = (unsigned long)alloc->vaddr;
	os_pages_nr = calc_alloc_os_pages_nr(alloc);
	array_size = os_pages_nr * sizeof(struct page *);

	ret = OS_ALLOC_ZERO(array_size, (void **)&pages);
	if (ret != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"OS_ALLOC_ZERO failed %d\n", ret);
		goto error;
	}


	down_read(&current->mm->mmap_sem);

	/* TODO - check page permissions : must be non-executable
	 * (implies that the pages are mapped, which in turn implies that
	 * it's not kernel memory.
	 */

#if GET_USER_PAGES_HAS_TSK
	nr = get_user_pages(start & PAGE_MASK,
#else
	nr = get_user_pages(current,
			    current->mm,
			    start & OS_PAGE_MASK,
#endif
			    os_pages_nr,
#if GET_USER_PAGES_GUP_PARAM
			    gup_flags,
#else
			    is_writable,
			    0, /* force */
#endif
			    pages,
			    NULL);
	if (nr < os_pages_nr) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "get_user_pages failed\n");
		goto error_up_read;
	}

	up_read(&current->mm->mmap_sem);

	alloc->pages = pages;
	alloc->os_pages_nr = os_pages_nr;

out:
	FUNC_LEAVE();
	return ret;

error_up_read:
	up_read(&current->mm->mmap_sem);
error:
	while (nr > 0)
		put_page(pages[--nr]);

	if (pages)
		OS_FREE(pages, array_size);

	goto out;
}

/*
 * unpin the pages in the given allocation
 * inputs : alloc -
 * outputs: the allocation's 'sgt' field is reset
 * returns:
 */
static void unpin_user_memory(struct lin_mm_allocation *alloc)
{
	u32 array_size;
	int might_be_dirty;

	FUNC_ENTER();
	if (!alloc->vaddr || !USER_MEM_ONLY(alloc->mem_type)) {
		FUNC_LEAVE();
		return;
	}

	might_be_dirty = ((alloc->buf_meta_data.prot & CVE_MM_PROT_WRITE) != 0);

	while (alloc->os_pages_nr) {
		struct page *p = alloc->pages[--alloc->os_pages_nr];

		if (might_be_dirty)
			SetPageDirty(p);
		put_page(p);
	}

	array_size = calc_alloc_os_pages_nr(alloc) * sizeof(struct page *);
	OS_FREE(alloc->pages, array_size);

	FUNC_LEAVE();
}

/*
 * allocate sg for user pages
 * inputs : alloc - user allocation general data
 * outputs: the allocation's 'sgt'
 * returns: 0 on success, a negative error code on failure
 */
static int user_mem_alloc_sg(struct lin_mm_allocation *alloc,
	struct cve_os_allocation *cve_alloc_data)
{
	unsigned long start;
	struct sg_table *sgt = NULL;
	int ret = -ENOMEM;

	FUNC_ENTER();
	start = ((unsigned long)alloc->vaddr) & ~OS_PAGE_MASK;

	ret = OS_ALLOC_ZERO(sizeof(*sgt), (void **)&sgt);
	if (ret != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"OS_ALLOC_ZERO failed %d\n", ret);
		goto error;
	}

	ret = sg_alloc_table_from_pages(sgt,
			alloc->pages,
			alloc->os_pages_nr,
			start,
			alloc->size_bytes,
			GFP_KERNEL);
	if (ret < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"sg_alloc_table_from_pages failed\n");
		goto error;
	}

	cve_alloc_data->dma_handle.mem_type = CVE_MEMORY_TYPE_USER;
	cve_alloc_data->dma_handle.mem_handle.sgt = sgt;

out:
	FUNC_LEAVE();
	return ret;

error:
	OS_FREE(sgt, sizeof(*sgt));

	goto out;
}

/*
 * free sg allocation for user specific allocation
 * inputs : cve_alloc_data - cve specific allocation data
 * outputs: the allocation's 'sgt' field is reset
 * returns:
 */
static void user_mem_free_sg(struct cve_os_allocation *cve_alloc_data)
{
	struct sg_table *sgt = cve_alloc_data->dma_handle.mem_handle.sgt;

	FUNC_ENTER();

	if (sgt == NULL)
		return;

	sg_free_table(sgt);
	OS_FREE(sgt, sizeof(*sgt));
	cve_alloc_data->dma_handle.mem_handle.sgt = NULL;

	FUNC_LEAVE();
}

static int dma_buf_sharing_connect_to_buffer(
	struct device *dev,
	struct lin_mm_allocation *alloc,
	struct cve_os_allocation *cve_alloc_data)
{
	int retval = 0;
	struct dma_buf *dbuf = alloc->dbuf;
	struct dma_buf_attachment *dbuf_attach = NULL;
	struct sg_table *dbuf_sg_table = NULL;
	enum dma_data_direction direction =
		prot_2_dir(alloc->buf_meta_data.prot);

	FUNC_ENTER();

	dbuf_attach = dma_buf_attach(dbuf, dev);
	if (IS_ERR(dbuf_attach)) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"[buffer-sharing] error in dma_buf_attach\n");
		retval = PTR_ERR(dbuf_attach);
		goto out;
	}
	cve_alloc_data->dbuf_attach = dbuf_attach;

	dbuf_sg_table = dma_buf_map_attachment(dbuf_attach, direction);
	if (IS_ERR(dbuf_sg_table)) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"[buffer-sharing] error in dma_buf_map_attachment\n");
		retval = PTR_ERR(dbuf_sg_table);
		goto dma_buf_detach;
	}
	cve_alloc_data->dma_handle.mem_handle.sgt = dbuf_sg_table;

	cve_os_log(CVE_LOGLEVEL_DEBUG,
			"[buffer-sharing] mm_alloc:%p dma_buf:%p cve_alloc:%p\n",
			alloc, dbuf, cve_alloc_data);
out:
	FUNC_LEAVE();
	return retval;
dma_buf_detach:
	dma_buf_detach(dbuf, dbuf_attach);

	goto out;
}

static void dma_buf_sharing_disconnect_from_buffer(
	struct lin_mm_allocation *alloc,
	struct cve_os_allocation *cve_alloc_data)
{
	enum dma_data_direction dir = prot_2_dir(alloc->buf_meta_data.prot);
	struct dma_buf *dbuf = alloc->dbuf;
	struct dma_buf_attachment *dbuf_attach =
		cve_alloc_data->dbuf_attach;
	struct sg_table *dbuf_sg_table =
		cve_alloc_data->dma_handle.mem_handle.sgt;

	FUNC_ENTER();

	dma_buf_unmap_attachment(dbuf_attach, dbuf_sg_table, dir);

	dma_buf_detach(dbuf, dbuf_attach);

	FUNC_LEAVE();
}

static int ice_osmm_get_iceva(struct lin_mm_allocation *ntw_alloc,
		struct lin_mm_allocation *inf_alloc)
{
	u8 pid = ntw_alloc->buf_meta_data.partition_id;
	u32 i, j, base_iova = 0;
	u32 dma_domain_array_size = ntw_alloc->dma_domain_array_size;
	int retval = 0;
	os_domain_handle *hdomain = ntw_alloc->hdomain;

	/* allocate and update per cve per allocation data */
	for (i = 0; i < dma_domain_array_size; i++) {
		struct cve_lin_mm_domain *domain =
			(struct cve_lin_mm_domain *)hdomain[i];

		retval = get_iova(
			domain->iova_allocator[pid],
			&domain->mmu_config[pid],
			inf_alloc->cve_vaddr, ntw_alloc->ice_pages_nr,
			&base_iova);
		if (retval != 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
				"get_iova failed %d\n", retval);
			goto revert_iova;
		}
		inf_alloc->cve_vaddr = IOVA_TO_VADDR(base_iova,
						ntw_alloc->page_shift);
	}

	goto out;

revert_iova:
	for (j = 0; j < i; j++) {
		struct cve_lin_mm_domain *domain =
			(struct cve_lin_mm_domain *)hdomain[j];

		cve_iova_free(
			domain->iova_allocator[pid],
			VADDR_TO_IOVA(inf_alloc->cve_vaddr,
			ntw_alloc->page_shift),
			ntw_alloc->ice_pages_nr);
	}

out:
	return retval;
}

static int ice_osmm_release_iceva(struct lin_mm_allocation *alloc)
{
	u32 i;
	u8 pid = alloc->buf_meta_data.partition_id;
	int retval = 0;

	if (alloc->cve_vaddr == IDC_BAR1_COUNTERS_ADDRESS_START)
		goto out;

	for (i = 0; i < alloc->dma_domain_array_size; i++) {
		struct cve_lin_mm_domain *domain =
			(struct cve_lin_mm_domain *)alloc->hdomain[i];

		retval = cve_iova_free(
			domain->iova_allocator[pid],
			VADDR_TO_IOVA(alloc->cve_vaddr, alloc->page_shift),
			alloc->ice_pages_nr);
		if (retval != 0) {
			/* TODO: Clean way to release IOVA */
			cve_os_log(CVE_LOGLEVEL_ERROR,
				"cve_iova_free failed %d\n", retval);
		}
	}

out:
	alloc->cve_vaddr = 0;

	return retval;
}

static int ice_osmm_get_sgt(struct cve_dma_handle **dma_handle,
		union allocation_address alloc_addr,
		enum osmm_memory_type mem_type,
		struct lin_mm_allocation *alloc)
{
	u32 i, j;
	u32 dma_domain_array_size = alloc->dma_domain_array_size;
	int retval = 0;
	struct cve_os_allocation *cve_alloc_data = NULL;
	struct cve_os_allocation *cve_alloc_list = NULL;
	struct device *dev = NULL;
	struct cve_device *ice = get_first_device();
	os_domain_handle *hdomain = alloc->hdomain;

	if (USER_MEM_ONLY(mem_type)) {
		alloc->vaddr = alloc_addr.vaddr;
		/*
		 * kernel memory is always pinned, so no need to pin it.
		 * so this step is needed for user memory only
		 */
		retval = pin_user_memory(alloc);
		if (retval) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
				"pin_user_memory failed\n");
			goto out;
		}

	} else if (SHARED_MEM_ONLY(mem_type)) {
		/* get the shared dma-buf from handle */
		struct dma_buf *dbuf = NULL;

		alloc->fd = alloc_addr.fd;
		dbuf = dma_buf_get(alloc->fd);
		if (IS_ERR(dbuf)) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
				"[buffer-sharing] error in dma_buf_get\n");
			retval = PTR_ERR(dbuf);
			goto out;
		}

		alloc->dbuf = dbuf;
		cve_os_log(CVE_LOGLEVEL_DEBUG,
				"[buffer-sharing] mm_alloc_info:%p bufFd:%llu dma_buf:%p\n",
				alloc, alloc->fd, dbuf);
	}

	/* allocate and update per cve per allocation data */
	for (i = 0; i < dma_domain_array_size; i++) {
		struct sg_table *sgt = NULL;
		struct cve_lin_mm_domain *domain =
			(struct cve_lin_mm_domain *)hdomain[i];

		/* save CVE specific data in allocation struct */
		retval = OS_ALLOC_ZERO(
				sizeof(*cve_alloc_data),
				(void **)&cve_alloc_data);
		if (retval != 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
					"OS_ALLOC_ZERO (cve_alloc_data) failed %d\n",
					retval);
			goto undo_loop;
		}

		/* add dma_handle & os domain handle to cve_alloc_data */
		if (dma_handle != NULL) {
			cve_alloc_data->dma_handle.mem_handle =
				dma_handle[i]->mem_handle;
			cve_alloc_data->dma_handle.mem_type =
				dma_handle[i]->mem_type;
		}
		cve_alloc_data->domain = domain;

		if (USER_MEM_ONLY(mem_type)) {
			/*
			 * kernel memory is either allocated with
			 * dma_coherent_alloc for contig or allocated as
			 * scatter gather list and mapped to device so
			 * no need to map it to the device.
			 */
			retval = user_mem_alloc_sg(alloc, cve_alloc_data);
			if (retval) {
				cve_os_log(CVE_LOGLEVEL_ERROR,
					"user_mem_alloc_sg failed\n");
				OS_FREE(cve_alloc_data,
					sizeof(*cve_alloc_data));
				goto undo_loop;
			}
			sgt = cve_alloc_data->dma_handle.mem_handle.sgt;
			retval = map_user_allocation(cve_alloc_data,
					prot_2_dir(alloc->buf_meta_data.prot),
					sgt->nents);
			if (retval) {
				cve_os_log(CVE_LOGLEVEL_ERROR,
					"map_user_allocation failed\n");
				user_mem_free_sg(cve_alloc_data);
				OS_FREE(cve_alloc_data,
					sizeof(*cve_alloc_data));
				goto undo_loop;
			}
		}

		/* shared buffer memory (dma_buf) */
		else if (SHARED_MEM_ONLY(mem_type)) {
			cve_alloc_data->dma_handle.mem_type =
				CVE_MEMORY_TYPE_SHARED_BUFFER_SG;
			dev = to_cve_os_device(ice)->dev;

			retval = dma_buf_sharing_connect_to_buffer(
					dev, alloc, cve_alloc_data);
			if (retval) {
				cve_os_log(CVE_LOGLEVEL_ERROR,
					"[buffer-sharing] dma_buf_sharing_connect_to_buffer failed\n");
				OS_FREE(cve_alloc_data,
					sizeof(*cve_alloc_data));
				goto undo_loop;
			}

			sgt = cve_alloc_data->dma_handle.mem_handle.sgt;
			retval = map_user_allocation(cve_alloc_data,
					prot_2_dir(alloc->buf_meta_data.prot),
					sgt->nents);
			if (retval) {
				cve_os_log(CVE_LOGLEVEL_ERROR,
					"map_user_allocation failed\n");
				dma_buf_sharing_disconnect_from_buffer(alloc,
					cve_alloc_data);
				OS_FREE(cve_alloc_data,
					sizeof(*cve_alloc_data));
				goto undo_loop;
			}
		}

		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"SizeBytes=0x%llx IAVA=0x%lx fd=%llu Prot=%s Type=%s LLC_Policy=%u\n",
			alloc->size_bytes,
			(uintptr_t)alloc_addr.vaddr,
			alloc_addr.fd,
			get_cve_memory_protection_str(
				alloc->buf_meta_data.prot),
			get_osmm_memory_type_str(mem_type),
			alloc->buf_meta_data.llc_policy);

		cve_dle_add_to_list_before(cve_alloc_list,
				list, cve_alloc_data);
	}
	alloc->per_cve = cve_alloc_list;
	goto out;

undo_loop:
	/* TODO: Duplicate Code. try using ice_osmm_release_sgt() */
	for (j = 0; j < i; j++) {
		struct cve_os_allocation *cve_alloc =
			cve_alloc_list;

		cve_dle_remove_from_list(cve_alloc_list,
				list,
				cve_alloc);

		if (cve_alloc->dma_handle.mem_type == CVE_MEMORY_TYPE_USER) {
			unmap_user_allocation(cve_alloc,
				prot_2_dir(alloc->buf_meta_data.prot),
				cve_alloc->dma_handle.mem_handle.sgt->nents);
			cve_sync_sgt_to_llc(
				cve_alloc->dma_handle.mem_handle.sgt);
			user_mem_free_sg(cve_alloc);
		}

		if (cve_alloc->dma_handle.mem_type ==
			CVE_MEMORY_TYPE_SHARED_BUFFER_SG) {
			unmap_user_allocation(cve_alloc,
				prot_2_dir(alloc->buf_meta_data.prot),
				cve_alloc->dma_handle.mem_handle.sgt->nents);

			dma_buf_sharing_disconnect_from_buffer(alloc,
				cve_alloc);
			cve_os_log(CVE_LOGLEVEL_DEBUG,
				"[buffer-sharing] disconnected from shared buffer");
		}

		OS_FREE(cve_alloc, sizeof(*cve_alloc));
	}

	alloc->per_cve = NULL;

	if (USER_MEM_ONLY(alloc->mem_type))
		unpin_user_memory(alloc);
	/* in case of shared buffer disconnect from buffer */
	else if (SHARED_MEM_ONLY(alloc->mem_type))
		dma_buf_put(alloc->dbuf);

out:
	return retval;
}

static void ice_osmm_release_sgt(struct lin_mm_allocation *alloc)
{
	struct cve_os_allocation *cve_alloc_list = alloc->per_cve;
	enum dma_data_direction dir;

	dir = prot_2_dir(alloc->buf_meta_data.prot);

	/* allocate and update per cve per allocation data */
	while (cve_alloc_list) {

		struct cve_os_allocation *cve_alloc =
			cve_alloc_list;

		cve_dle_remove_from_list(cve_alloc_list,
				list,
				cve_alloc);

		if (cve_alloc->dma_handle.mem_type == CVE_MEMORY_TYPE_USER) {
			unmap_user_allocation(cve_alloc, dir,
				cve_alloc->dma_handle.mem_handle.sgt->nents);
			cve_sync_sgt_to_llc(
				cve_alloc->dma_handle.mem_handle.sgt);
			user_mem_free_sg(cve_alloc);
		}

		if (cve_alloc->dma_handle.mem_type ==
			CVE_MEMORY_TYPE_SHARED_BUFFER_SG) {
			unmap_user_allocation(cve_alloc, dir,
				cve_alloc->dma_handle.mem_handle.sgt->nents);

			dma_buf_sharing_disconnect_from_buffer(alloc,
				cve_alloc);
			cve_os_log(CVE_LOGLEVEL_DEBUG,
				"[buffer-sharing] disconnected from shared buffer");
		}

		OS_FREE(cve_alloc, sizeof(*cve_alloc));
	}
	alloc->per_cve = NULL;

	if (USER_MEM_ONLY(alloc->mem_type))
		unpin_user_memory(alloc);
	/* in case of shared buffer disconnect from buffer */
	else if (SHARED_MEM_ONLY(alloc->mem_type))
		dma_buf_put(alloc->dbuf);

	FUNC_LEAVE();
}

static int ice_osmm_set_pte(
		u32 dma_domain_array_size,
		struct lin_mm_allocation *alloc)
{
	u32 i, j;
	int retval = 0;
	struct cve_os_allocation *cve_alloc_data = NULL;
	struct cve_lin_mm_domain *domain;

	cve_alloc_data = alloc->per_cve;
	for (i = 0; i < dma_domain_array_size; i++) {

		/*
		 * NOTE: we should assume that all buffers mapped to exact
		 * the same address in all CVE devices, otherwise it's
		 * impossible to perform patching. read more info in
		 * cve_ds_handle_submit() function.
		 * therefore for first user memory allocation alloc->cve_addr
		 * is equal to CVE_INVALID_VIRTUAL_ADDR, we will call
		 * cve_iova_alloc, and alloc->cve_addr will got actual address
		 * for next loop (CVE) alloc->cve_addr will contain actual
		 * address and we will call cve_iova_claim for the same address
		 * on next CVE dev, and so on for all CVE devices in the system
		 * If cve_iova_claim fails then we should report failure.
		 */
		retval = add_to_device_page_table(alloc,
					cve_alloc_data);
		if (retval != 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
				"add_to_device_page_table failed\n");
			goto undo_loop;
		}

		/* mark the flag of "pages added"
		 * before submission of next job invalidation should occur
		 */
		domain = (struct cve_lin_mm_domain *)cve_alloc_data->domain;
		domain->pt_state |= PAGES_ADDED_TO_PAGE_TABLE;

		cve_alloc_data = cve_dle_next(cve_alloc_data, list);
	}

	goto out;

undo_loop:
	for (j = 0; j < i; j++) {
		domain = (struct cve_lin_mm_domain *)alloc->hdomain[i];

		remove_from_device_page_table(alloc->cve_vaddr,
			alloc->ice_pages_nr,
			domain,
			alloc->buf_meta_data.partition_id);

		domain->pt_state |= PAGES_REMOVED_FROM_PAGE_TABLE;
	}
out:
	return retval;
}

static void ice_osmm_unset_pte(struct lin_mm_allocation *alloc)
{
	u32 i;
	struct cve_lin_mm_domain *domain;

	for (i = 0; i < alloc->dma_domain_array_size; i++) {

		domain = (struct cve_lin_mm_domain *)alloc->hdomain[i];

		remove_from_device_page_table(alloc->cve_vaddr,
			alloc->ice_pages_nr,
			domain,
			alloc->buf_meta_data.partition_id);

		domain->pt_state |= PAGES_REMOVED_FROM_PAGE_TABLE;
	}
}

/* INTERFACE FUNCTIONS */

/*
 * Prepare sgl of InferBuffer.
 * Get PA of InferBuffer and modify corresponding PTE
 */
int cve_osmm_inf_dma_buf_map(u64 inf_id,
		os_domain_handle *hdomain,
		u32 dma_domain_array_size,
		union allocation_address alloc_addr,
		enum osmm_memory_type mem_type,
		os_allocation_handle ntw_halloc,
		os_allocation_handle *inf_halloc)
{
	struct lin_mm_allocation *inf_alloc = NULL;
	struct lin_mm_allocation *ntw_alloc;
	int retval = 0;

	ntw_alloc = (struct lin_mm_allocation *)ntw_halloc;

	FUNC_ENTER();

	/* device page size must be smaller than the OS page size */
	BUILD_BUG_ON(ICE_DEFAULT_PAGE_SZ < OS_PAGE_SIZE);

	/* TODO: De-allocation */
	retval = OS_ALLOC_ZERO(sizeof(*inf_alloc), (void **)&inf_alloc);
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "OS_ALLOC_ZERO failed\n");
		goto out;
	}

	inf_alloc->size_bytes = ntw_alloc->size_bytes;
	inf_alloc->actual_sz = ntw_alloc->actual_sz;
	inf_alloc->buf_meta_data = ntw_alloc->buf_meta_data;
	inf_alloc->mem_type = mem_type;
	inf_alloc->cve_vaddr = ntw_alloc->cve_vaddr;
	inf_alloc->page_sz = ntw_alloc->page_sz;
	inf_alloc->page_shift = ntw_alloc->page_shift;
	inf_alloc->ice_pages_nr = ntw_alloc->ice_pages_nr;
	memcpy(inf_alloc->hdomain, hdomain,
		dma_domain_array_size * sizeof(os_domain_handle));
	inf_alloc->dma_domain_array_size = ntw_alloc->dma_domain_array_size;

	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"Mapping InfBuf. Size=0x%llx, ActualSize=0x%llx, PageSz=0x%x NumPages=%ld, PID=%d. FD=0x%llx\n",
		inf_alloc->size_bytes, inf_alloc->actual_sz,
		inf_alloc->page_sz, inf_alloc->ice_pages_nr,
		ntw_alloc->buf_meta_data.partition_id, alloc_addr.fd);

	retval = ice_osmm_get_iceva(ntw_alloc, inf_alloc);
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"ice_osmm_get_iceva failed %d\n", retval);
		goto out;
	}

	retval = ice_osmm_get_sgt(NULL, alloc_addr, mem_type, inf_alloc);
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"ice_osmm_get_sgt failed %d\n", retval);
		ASSERT(false);
	}

	retval = ice_osmm_set_pte(dma_domain_array_size, inf_alloc);
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"ice_osmm_set_pte failed %d\n", retval);
		ASSERT(false);
	}

	*inf_halloc = (os_allocation_handle)inf_alloc;

out:
	FUNC_LEAVE();
	return retval;
}

/*
 * Release sgl of InferBuffer.  No need to modify PTE because
 * other InferRequests will still use them.
 */
void cve_osmm_inf_dma_buf_unmap(os_allocation_handle halloc)
{
	struct lin_mm_allocation *inf_alloc =
		(struct lin_mm_allocation *)halloc;

	ice_osmm_unset_pte(inf_alloc);

	ice_osmm_release_sgt(inf_alloc);

	ice_osmm_release_iceva(inf_alloc);

	OS_FREE(inf_alloc, sizeof(*inf_alloc));
}

int cve_osmm_dma_buf_map(os_domain_handle *hdomain,
		struct cve_dma_handle **dma_handle,
		u32 dma_domain_array_size,
		u64 size_bytes,
		union allocation_address alloc_addr,
		ice_va_t cve_addr,
		u32 prot,
		enum osmm_memory_type mem_type,
		struct ice_iova_desc *iova_desc,
		os_allocation_handle *out_halloc)
{
	struct lin_mm_allocation *alloc = NULL;
	int retval = 0;

	FUNC_ENTER();

	/* device page size must be smaller than the OS page size */
	BUILD_BUG_ON(ICE_DEFAULT_PAGE_SZ < OS_PAGE_SIZE);

	retval = OS_ALLOC_ZERO(sizeof(*alloc), (void **)&alloc);
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "OS_ALLOC_ZERO failed\n");
		goto out;
	}

	alloc->size_bytes = size_bytes;
	alloc->actual_sz = size_bytes;
	alloc->buf_meta_data.prot = prot;
	alloc->mem_type = mem_type;
	alloc->buf_meta_data.llc_policy = iova_desc->llc_policy;
	alloc->cve_vaddr = cve_addr;
	alloc->page_sz = iova_desc->page_sz;
	alloc->page_shift = iova_desc->page_shift;
	alloc->buf_meta_data.partition_id = iova_desc->partition_id;
	alloc->ice_pages_nr = calc_alloc_cve_pages_nr(alloc);
	memcpy(alloc->hdomain, hdomain,
		dma_domain_array_size * sizeof(os_domain_handle));
	alloc->dma_domain_array_size = dma_domain_array_size;

	if (INFER_MEM_ONLY(mem_type)) {
		*out_halloc = alloc;
		goto out;
	}

	retval = ice_osmm_get_iceva(alloc, alloc);
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"ice_osmm_get_iceva failed %d\n", retval);
		goto free_mem;
	}

	retval = ice_osmm_get_sgt(dma_handle, alloc_addr, mem_type, alloc);
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"ice_osmm_get_sgt failed %d\n", retval);
		goto release_iceva;
	}

	retval = ice_osmm_set_pte(dma_domain_array_size, alloc);
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"ice_osmm_set_pte failed %d\n", retval);
		goto release_sgt;
	}

	*out_halloc = alloc;
	goto out;

release_sgt:
	ice_osmm_release_sgt(alloc);
release_iceva:
	ice_osmm_release_iceva(alloc);
free_mem:
	OS_FREE(alloc, sizeof(*alloc));
out:
	FUNC_LEAVE();
	return retval;
}

void ice_osmm_dma_buf_transfer(os_allocation_handle *hdst,
	os_allocation_handle *hsrc)
{
	struct lin_mm_allocation **dst = (struct lin_mm_allocation **)hdst;
	struct lin_mm_allocation **src = (struct lin_mm_allocation **)hsrc;

	OS_FREE(*dst, sizeof(*dst));

	*dst = *src;
	*src = NULL;
}

void ice_osmm_use_extended_iceva(os_allocation_handle halloc)
{
	struct lin_mm_allocation *alloc = (struct lin_mm_allocation *)halloc;

	if (alloc->buf_meta_data.partition_id >= MEM_PARTITION_HIGH_32KB) {
		alloc->buf_meta_data.partition_id +=
			(MEM_PARTITION_HIGHER_32KB - MEM_PARTITION_HIGH_32KB);
	}
}

void cve_osmm_dma_buf_unmap(os_allocation_handle halloc,
		enum osmm_memory_type mem_type)
{
	struct lin_mm_allocation *ntw_alloc =
			(struct lin_mm_allocation *)halloc;

	FUNC_ENTER();

	cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Reclaiming allocation of %s memory\n",
			get_osmm_memory_type_str(ntw_alloc->mem_type));

	if (!INFER_MEM_ONLY(mem_type)) {

		ice_osmm_unset_pte(ntw_alloc);

		ice_osmm_release_sgt(ntw_alloc);

		ice_osmm_release_iceva(ntw_alloc);
	}

	OS_FREE(ntw_alloc, sizeof(*ntw_alloc));

	FUNC_LEAVE();
}

ice_va_t cve_osmm_alloc_get_iova(os_allocation_handle halloc)
{
	struct lin_mm_allocation *alloc = (struct lin_mm_allocation *)halloc;

	return alloc->cve_vaddr;
}

void cve_osmm_cache_allocation_op(os_allocation_handle halloc,
	struct cve_device *cve_dev,
	enum cve_cache_sync_direction sync_dir)
{
	struct lin_mm_allocation *alloc = (struct lin_mm_allocation *)halloc;
	struct cve_os_allocation *cve_alloc_data = NULL;

	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"Performing Cache operation for Network Buffers\n");

	if (!alloc->per_cve) {
		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Aborting Cache operation for this Buffer.\n");
		return;
	}

	/* TODO: need to optimize this */
	cve_alloc_data = cve_dle_lookup(alloc->per_cve,
						list,
						cve_index,
						cve_dev->dev_index);

	if (cve_alloc_data != NULL) {
		if (sync_dir == SYNC_TO_DEVICE) {
			cve_os_log(CVE_LOGLEVEL_DEBUG,
				"[CACHE] Flushing buffer, size = %lld\n",
				alloc->size_bytes);
			cve_os_sync_sg_memory_to_device(cve_dev,
				cve_alloc_data->dma_handle.mem_handle.sgt);
		} else {
			cve_os_log(CVE_LOGLEVEL_DEBUG,
				"[CACHE] Invalidating buffer, size = %lld\n",
				alloc->size_bytes);
			cve_os_sync_sg_memory_to_host(cve_dev,
				cve_alloc_data->dma_handle.mem_handle.sgt);
		}
	}
}

u32 cve_osmm_is_need_tlb_invalidation(os_domain_handle hdomain)
{
	u32 need_invalidation = 0;
	struct cve_lin_mm_domain *domain =
		(struct cve_lin_mm_domain *)hdomain;

	/* if pages were added to the page table and the
	 * driver settings requires tlb invalidation.
	 * do tlb invalidation and clear the pages added flag.
	 */
	if (domain->pt_state & PAGES_ADDED_TO_PAGE_TABLE) {
		if (g_driver_settings.flags &
				NEED_TLB_INVALIDATION_IF_PAGES_ADDED) {
			/* mark the invalidation flag */
			need_invalidation = 1;
			/* clear the page added flag */
			domain->pt_state &= ~PAGES_ADDED_TO_PAGE_TABLE;
		}
	}

	return need_invalidation;
}

void cve_osmm_reset_all_pt_flags(os_domain_handle hdomain)
{
	struct cve_lin_mm_domain *domain =
		(struct cve_lin_mm_domain *)hdomain;

	domain->pt_state = 0;
}

void cve_osmm_print_user_buffer(os_allocation_handle halloc,
		u32 size_bytes,
		void *buffer_addr,
		const char *buf_name)
{
	struct lin_mm_allocation *alloc = (struct lin_mm_allocation *)halloc;

	if ((alloc != NULL) &&
		(alloc->mem_type == OSMM_USER_MEMORY)) {

		cve_os_print_user_buffer((void **)alloc->pages,
				alloc->os_pages_nr,
				buffer_addr,
				size_bytes,
				buf_name);

	} else if ((alloc != NULL) &&
		(alloc->mem_type == OSMM_SHARED_MEMORY)) {

		cve_os_print_shared_buffer(buffer_addr,
				size_bytes, buf_name);

	} else {
		cve_os_log(CVE_LOGLEVEL_DEBUG,
				"Buffer %p is not user buffer and therefore won't be printed\n",
				buffer_addr);
	}
}

int cve_osmm_map_kva(os_allocation_handle alloc_hdl, u64 *va)
{
	int err = 0;
	struct lin_mm_allocation *mm_alloc_info =
		(struct lin_mm_allocation *)alloc_hdl;
	struct dma_buf *dbuf = mm_alloc_info->dbuf;
	void *vaddr;

	err = dma_buf_begin_cpu_access(dbuf, DMA_BIDIRECTIONAL);
	if (err) {
		pr_err("mm_alloc_info:%p dma_buf:%p failed(%d) to dma_buf_begin_cpu_access\n",
				mm_alloc_info, dbuf, err);
		goto err_begin_cpu_access;

	}

	vaddr = dma_buf_vmap(dbuf);
	if (!vaddr) {
		pr_err("mm_alloc_info:%p dma_buf:%p failed to vmap\n",
				mm_alloc_info, dbuf);
		err = -EACCES;
		goto err_buf_vmap;
	}
	cve_os_log(CVE_LOGLEVEL_DEBUG,
			"mm_alloc_info:%p dma_buf:%p VA:%llu @VA:%llu\n",
			mm_alloc_info, dbuf, (u64)vaddr, *((u64 *)(vaddr)));

	*va = (u64)vaddr;

	return err;

err_buf_vmap:
	dma_buf_end_cpu_access(dbuf, DMA_BIDIRECTIONAL);
err_begin_cpu_access:
	return err;
}

int cve_osmm_unmap_kva(os_allocation_handle alloc_hdl, void *vaddr)
{
	int err = 0;
	struct lin_mm_allocation *mm_alloc_info =
		(struct lin_mm_allocation *)alloc_hdl;
	struct dma_buf *dbuf = mm_alloc_info->dbuf;

	cve_os_log(CVE_LOGLEVEL_DEBUG,
			"mm_alloc_info:%p dma_buf:%p VA:%llu @VA:%llu\n",
			mm_alloc_info, dbuf, (u64)vaddr, *((u64 *)(vaddr)));

	dma_buf_vunmap(dbuf, vaddr);
	dma_buf_end_cpu_access(dbuf, DMA_BIDIRECTIONAL);

	return err;
}

u8 ice_osmm_alloc_get_page_shift(os_allocation_handle halloc)
{
	struct lin_mm_allocation *alloc = (struct lin_mm_allocation *)halloc;

	return alloc->page_shift;

}

void ice_osmm_domain_get_page_sz_list(os_domain_handle hdomain,
		u32 **page_sz_list)
{
	struct cve_lin_mm_domain *domain =
		(struct cve_lin_mm_domain *)hdomain;

	*page_sz_list = &domain->page_sz_reg_config_arr[0];
}

void ice_osmm_get_page_size(os_allocation_handle halloc,
	u32 *page_sz, u8 *pid)
{
	struct lin_mm_allocation *alloc = (struct lin_mm_allocation *)halloc;

	*page_sz = alloc->page_sz;
	*pid = alloc->buf_meta_data.partition_id;
}
