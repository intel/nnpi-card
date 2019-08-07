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
#include <string.h>
#include <linux_kernel_mock.h>
#endif

#include "dev_context.h"
#include "device_interface.h"
#include "cve_firmware.h"
#include "ice_debug.h"

/* hold per device per context data */
struct dev_context {
	/* link to the module's list of contexts */
	struct cve_dle_t list;
	/* os-specific domain handle for cve device */
	os_domain_handle hdom;
	/* list of mapped fw sections per cve device */
	struct cve_fw_mapped_sections *mapped_fw_sections;
	/* list of custom loaded fw sections per cve device */
	struct cve_fw_loaded_sections *loaded_cust_fw_sections;
	/* list of embedded command buffers subjobs per cve device  */
	cve_di_subjob_handle_t *embedded_cbs_subjobs;
	/* cve dump buffer allocation info */
	struct dev_alloc cve_dump_alloc;
	/* pointer to the device */
	struct cve_device *cve_dev;
	cve_mm_allocation_t bar1_alloc_handle;
};

/* INTERNAL FUNCTIONS */
static int cve_dev_map_base_package_fws(struct dev_context *context)
{
	int retval;

#ifndef NULL_DEVICE_RING0
	retval = cve_fw_map(context->cve_dev,
			context->hdom,
			&context->mapped_fw_sections,
			&context->embedded_cbs_subjobs);
#else
	retval = 0;
#endif
	return retval;
}

#ifdef IDC_ENABLE
int cve_bar1_map(struct cve_device *cve_dev,
		os_domain_handle hdom,
		cve_mm_allocation_t *out_alloc_handle)
{
	int retval;
	cve_mm_allocation_t alloc_handles;
	struct cve_dma_handle mapped_dma_handles;
	struct cve_os_device *os_dev = to_cve_os_device(cve_dev);
	u64 offset;
#ifdef RING3_VALIDATION
	u64 bar1;
#else
	dma_addr_t bar1;
#endif
	u32 permissions = BAR1_ICE_PERMISSION;
	u32 size_bytes = BAR1_ICE_SPACE;
	u32 cve_addr = IDC_BAR1_COUNTERS_ADDRESS_START;
	struct cve_surface_descriptor surf;
	ice_va_t va = 0;

	bar1 = os_dev->idc_dev.bar1_base_address;
	offset = ICE_BAR1_OFFSET(cve_dev->dev_index);

	mapped_dma_handles.mem_type = CVE_MEMORY_TYPE_KERNEL_CONTIG;
	mapped_dma_handles.mem_handle.dma_address =
			(u64)PAGE_ALIGN(bar1 + offset);

	memset(&surf, 0, sizeof(struct cve_surface_descriptor));
	surf.llc_policy = ICE_BAR1_LLC_CONFIG;
	va = cve_addr;

	cve_os_dev_log(CVE_LOGLEVEL_DEBUG,
		cve_dev->dev_index,
		COLOR_GREEN("Start Mapping BAR1. PA=0x%llx\n"),
		 mapped_dma_handles.mem_handle.dma_address);

	/* map the memory in cve address space */
	retval = cve_mm_create_kernel_mem_allocation(hdom,
			NULL,
			size_bytes,
			CVE_SURFACE_DIRECTION_IN | CVE_SURFACE_DIRECTION_OUT,
			permissions,
			&va,
			&mapped_dma_handles,
			&surf,
			&alloc_handles);
	if (retval < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"cve_mm_create_kernel_mem_allocation failed %d\n",
				retval);
		goto out;
	}

	cve_os_dev_log(CVE_LOGLEVEL_DEBUG,
		cve_dev->dev_index,
		COLOR_GREEN("Stop Mapping BAR1\n"));

	cve_addr = va;
	*out_alloc_handle = alloc_handles;
out:
	return retval;
}
#endif

static void cve_dev_fw_unload_and_unmap(cve_dev_context_handle_t hcontext)
{
	struct dev_context *context = (struct dev_context *)hcontext;

	cve_os_dev_log(CVE_LOGLEVEL_DEBUG,
			context->cve_dev->dev_index,
			"Unmap Base + Bank0/1 FW\n");
	cve_fw_unmap(context->cve_dev,
			context->mapped_fw_sections,
			context->embedded_cbs_subjobs);
	/* unload bank0/bank1 firmwares */
	cve_os_dev_log(CVE_LOGLEVEL_DEBUG,
			context->cve_dev->dev_index,
			"Unload Bank0/1 FW\n");
	cve_fw_unload(context->cve_dev,
			context->loaded_cust_fw_sections);
}

static int cve_dev_init_per_cve_ctx(struct dev_context *dev_ctx,
		struct cve_device *cve_dev)
{
	struct dev_context *nc = dev_ctx;
	int retval = cve_osmm_get_domain(cve_dev, &nc->hdom);
	cve_mm_allocation_t alloc_handle = NULL;
	struct cve_surface_descriptor surf;
	ice_va_t ice_vaddr = CVE_INVALID_VIRTUAL_ADDR;

	if (retval < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"osmm_get_domain failed %d\n", retval);
		goto out;
	}

	/* assign a device to device interface context */
	nc->cve_dev = cve_dev;

#ifdef IDC_ENABLE
		retval = cve_bar1_map(nc->cve_dev,
				nc->hdom,
				&nc->bar1_alloc_handle);
		if (retval != 0) {
			cve_os_log_default(CVE_LOGLEVEL_ERROR,
					"Failed to map bar1 %d\n",
					retval);
			goto failed_to_map_fw;
		}
#endif

	/* load the base package FWs. add fws to context */
	retval = cve_dev_map_base_package_fws(nc);
	if (retval != 0) {
		cve_os_log_default(CVE_LOGLEVEL_ERROR,
				"Failed to map base package %d\n",
				retval);
		goto failed_to_map_fw;
	}

	if (cve_dev->debug_control_buf.cve_dump_buffer != NULL) {
		memset(&surf, 0, sizeof(struct cve_surface_descriptor));
		retval = cve_mm_create_kernel_mem_allocation(nc->hdom,
				cve_dev->debug_control_buf.cve_dump_buffer,
				cve_dev->debug_control_buf.size_bytes,
				CVE_SURFACE_DIRECTION_INOUT,
				CVE_MM_PROT_READ | CVE_MM_PROT_WRITE,
				&ice_vaddr,
				&cve_dev->debug_control_buf.dump_dma_handle,
				&surf,
				&alloc_handle);
		if (retval != 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
				"cve_mm_create_kernel_mem_allocation failed (ice dump) %d\n",
				retval);
			goto failed_to_map_dump;
		}

		nc->cve_dump_alloc.alloc_handle = alloc_handle;
		cve_dev->debug_control_buf.ice_vaddr = ice_vaddr;
	}

	return 0;

failed_to_map_dump:
	cve_dev_fw_unload_and_unmap(nc);
failed_to_map_fw:
	cve_osmm_put_domain(nc->hdom);
out:
	return retval;
}

static void cve_dev_release_per_cve_ctx(struct dev_context *dev_ctx)
{
	struct dev_context *context = dev_ctx;
	struct cve_device *dev = context->cve_dev;

	if (context) {

		/* Block MMU if ICE is powered on */
		if ((dev->power_state == ICE_POWER_ON) ||
			(dev->power_state == ICE_POWER_OFF_INITIATED))
			ice_di_mmu_block_entrance(dev);

		cve_os_dev_log(CVE_LOGLEVEL_DEBUG,
				dev->dev_index,
				"Unload & Unmap FW\n");

		cve_dev_fw_unload_and_unmap(context);

		if (context->cve_dump_alloc.alloc_handle) {
			/*remove allocations of ICE_DUMP buffer */
			cve_os_dev_log(CVE_LOGLEVEL_DEBUG,
					dev->dev_index,
					"Reclaim ICE_DUMP buffer\n");
			cve_mm_reclaim_allocation(
				context->cve_dump_alloc.alloc_handle);
		}

		if (context->bar1_alloc_handle) {
			cve_os_dev_log(CVE_LOGLEVEL_DEBUG,
				dev->dev_index,
				"Reclaim BAR1 allocation\n");
			cve_mm_reclaim_allocation(
				context->bar1_alloc_handle);
		}
		cve_os_dev_log(CVE_LOGLEVEL_DEBUG,
				dev->dev_index,
				"Remove domain\n");
		cve_osmm_put_domain(context->hdom);
	}
}

static int cve_dev_fw_load_and_map_per_cve(cve_dev_context_handle_t hcontext,
		const u64 fw_image,
		const u64 fw_binmap,
		const u32 fw_binmap_size_bytes)
{
	int retval = CVE_DEFAULT_ERROR_CODE;
	struct dev_context *context = (struct dev_context *)hcontext;
	struct cve_fw_loaded_sections *fw_sec = NULL;
	struct cve_fw_loaded_sections *fw_sec_base = NULL;
	struct cve_fw_mapped_sections *fw_mapped = NULL;

	retval = OS_ALLOC_ZERO(sizeof(*fw_sec), (void **)&fw_sec);
	if (retval < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"os_malloc_zero failed %d\n", retval);
		goto out;
	}

	cve_os_dev_log(CVE_LOGLEVEL_DEBUG,
		context->cve_dev->dev_index,
		COLOR_GREEN("Start Firmware Load and Map on ICE-%d\n"),
		context->cve_dev->dev_index);

	/* load dynamic fw to memory */
	retval = cve_fw_load_binary(context->cve_dev,
			fw_image, fw_binmap,
			fw_binmap_size_bytes,
			fw_sec);
	if (retval != 0) {
		cve_os_log_default(CVE_LOGLEVEL_ERROR,
				"cve_fw_load_binary_context failure\n");
		goto out;
	}

	cve_os_dev_log(CVE_LOGLEVEL_DEBUG,
		context->cve_dev->dev_index,
		COLOR_GREEN("Firmware Loaded. FW_Type=%s, SectionsCount=%d\n"),
		get_fw_binary_type_str(fw_sec->fw_type),
		fw_sec->sections_nr);

	/* find mapped structure with dummy base fw */
	fw_mapped = cve_dle_lookup(context->mapped_fw_sections,
			list, cve_fw_loaded->fw_type, fw_sec->fw_type);
	if (!fw_mapped) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"FW_Type=%s can't be found in mapped fw list\n",
				get_fw_binary_type_str(fw_sec->fw_type));
		retval = -ICEDRV_KERROR_FW_INVAL_TYPE;
		goto out;
	}

	/* copy of base fw loaded section pointer for restoring incase error*/
	fw_sec_base = fw_mapped->cve_fw_loaded;

	cve_os_dev_log(CVE_LOGLEVEL_DEBUG,
		context->cve_dev->dev_index,
		"Cleaning the mapped Sections\n");
	/* clean mapped structure with dummy base fw */
	cve_mapped_fw_sections_cleanup(context->cve_dev, fw_mapped);

	cve_os_dev_log(CVE_LOGLEVEL_DEBUG,
		context->cve_dev->dev_index,
		"Mapping Sections\n");
	/* fill mapped structure with new fw and map the fw to device */
	retval = cve_fw_map_sections(context->cve_dev,
			context->hdom,
			fw_sec,
			fw_mapped);
	if (retval != 0) {
		int err = 0;

		cve_os_log(CVE_LOGLEVEL_WARNING,
			"cve_fw_map_sections failure,base fw to be restored\n");
		/* restore  old base fw */
		err = cve_fw_map_sections(context->cve_dev,
						context->hdom,
						fw_sec_base,
						fw_mapped);
		if (err != 0) {
			cve_os_log_default(CVE_LOGLEVEL_ERROR,
				"restoring of base fw failure\n");
		}
		goto out;
	}

	/* add new loaded dynamic fw to loaded_cust_fw_sections struct */
	cve_dle_add_to_list_after(context->loaded_cust_fw_sections,
		list,
		fw_sec);

	cve_os_dev_log(CVE_LOGLEVEL_DEBUG,
		context->cve_dev->dev_index,
		COLOR_GREEN("End Firmware Load and Map on ICE-%d\n"),
		context->cve_dev->dev_index);

	/* success */
	retval = 0;
out:
	if (retval != 0) {
		if (fw_sec) {
			cve_fw_sections_cleanup(context->cve_dev,
				fw_sec->sections,
				fw_sec->dma_handles,
				fw_sec->sections_nr);

			OS_FREE(fw_sec, sizeof(*fw_sec));
		}
	}

	return retval;
}


/* INTERFACE FUNCTIONS */
void cve_dev_close_all_contexts(cve_dev_context_handle_t hcontext_list)
{
	struct dev_context *dev_context_list =
		(struct dev_context *)hcontext_list;

	while (dev_context_list) {
		struct dev_context *dev_ctx = dev_context_list;

		cve_dle_remove_from_list(
				dev_context_list, list, dev_ctx);

		cve_os_log(CVE_LOGLEVEL_DEBUG,
				"Remove dev context for CVE %d\n",
				dev_ctx->cve_dev->dev_index);

		cve_dev_release_per_cve_ctx(dev_ctx);

		OS_FREE(dev_ctx, sizeof(*dev_ctx));
	}
}

int cve_dev_fw_load_and_map(cve_dev_context_handle_t hcontext_list,
		const u64 fw_image,
		const u64 fw_binmap,
		const u32 fw_binmap_size_bytes)
{
	struct dev_context *dev_context_list =
		(struct dev_context *) hcontext_list;
	struct dev_context *dev_ctx_item = dev_context_list;
	int retval = CVE_DEFAULT_ERROR_CODE;

	cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Start Firmware Load and Map on all ICEs\n");

	do {
		retval = cve_dev_fw_load_and_map_per_cve(dev_ctx_item,
			fw_image,
			fw_binmap,
			fw_binmap_size_bytes);
		if (retval < 0) {
			cve_os_dev_log(CVE_LOGLEVEL_ERROR,
				dev_ctx_item->cve_dev->dev_index,
				"cve_dev_fw_load_and_map_pre_cve failed %d\n",
				retval);
			goto out;
		}
		dev_ctx_item = cve_dle_next(dev_ctx_item, list);
	} while (dev_ctx_item != dev_context_list);

	cve_os_log(CVE_LOGLEVEL_DEBUG,
			"End Firmware Load and Map on all ICEs\n");

out:
	/* TODO: unload fw that was already loaded */

	return retval;
}

void cve_dev_restore_fws(struct cve_device *cve_dev,
		cve_dev_context_handle_t hcontext)
{
	struct dev_context *context = (struct dev_context *)hcontext;

	/* restore the FWs just before the reset */
	cve_fw_restore(cve_dev, context->mapped_fw_sections);
}

int cve_dev_open_all_contexts(cve_dev_context_handle_t *out_hctx_list)
{
	struct cve_device_group *cve_dg = g_cve_dev_group_list;
	struct dev_context *dev_context_list = NULL;
	int retval = CVE_DEFAULT_ERROR_CODE, i;
	struct cve_device *dev, *dev_head;
	struct dev_context *nc = NULL;

	/* Only 1 DG exist in new Driver. So not looping on it. */
	for (i = 0; i < MAX_NUM_ICEBO; i++) {
		dev_head = cve_dg->dev_info.icebo_list[i].dev_list;
		dev = dev_head;
		if (!dev_head)
			continue;

		do {
			retval = OS_ALLOC_ZERO(sizeof(struct dev_context),
					(void **)&nc);
			if (retval != 0) {
				cve_os_log(CVE_LOGLEVEL_ERROR,
						"os_malloc_failed %d\n",
						retval);
				goto out;
			}

			retval = cve_dev_init_per_cve_ctx(nc, dev);
			if (retval != 0) {
				cve_os_log_default(CVE_LOGLEVEL_ERROR,
						"cve_dev_init_per_cve_ctx failed %d\n",
						retval);
				OS_FREE(nc, sizeof(*nc));
				goto out;
			}

			/* Add the device context list */
			cve_dle_add_to_list_before(
					dev_context_list, list, nc);

			dev = cve_dle_next(dev, bo_list);

		} while (dev != dev_head);
	}
	/* If all devices are masked then Context Creation must fail */
	if (!dev_context_list) {
		cve_os_log_default(CVE_LOGLEVEL_ERROR,
				"No device available.\n");
		retval = -1;
		goto out;
	}

	/* success */
	*out_hctx_list = dev_context_list;

out:
	if (retval != 0)
		cve_dev_close_all_contexts(dev_context_list);
	return retval;
}

void cve_dev_context_get_by_cve_idx(cve_dev_context_handle_t hcontext_list,
	u32 dev_index, cve_dev_context_handle_t *out_hcontext)
{
	struct dev_context *dev_context_list =
		(struct dev_context *)hcontext_list;

	struct dev_context *dev_ctx_item =
		cve_dle_lookup(dev_context_list,
			list, cve_dev->dev_index,
			dev_index);

	ASSERT(dev_ctx_item);

	*out_hcontext = dev_ctx_item;
}

void cve_dev_get_emb_cb_list(cve_dev_context_handle_t hcontext,
		cve_di_subjob_handle_t **out_embedded_cbs_subjobs)
{
	struct dev_context *context = (struct dev_context *)hcontext;

	*out_embedded_cbs_subjobs = NULL;

	if (hcontext != NULL)
		*out_embedded_cbs_subjobs = context->embedded_cbs_subjobs;
}

void cve_dev_get_os_domain(cve_dev_context_handle_t hcontext,
		os_domain_handle *out_hdom)
{
	struct dev_context *context = (struct dev_context *)hcontext;

	*out_hdom = NULL;

	if (hcontext != NULL)
		*out_hdom = context->hdom;
}

void cve_dev_get_os_domain_arr(cve_dev_context_handle_t hcontext_list,
	u32 domain_array_size,
	os_domain_handle *out_hdom)
{
	u32 i = 0;
	struct dev_context *dev_context_list =
		(struct dev_context *) hcontext_list;
	struct dev_context *dev_ctx_item = dev_context_list;

	/* initialize array of os_domain_handle */
	do {
		cve_dev_get_os_domain(dev_ctx_item,
			&out_hdom[i]);

		i++;
		dev_ctx_item = cve_dle_next(dev_ctx_item, list);
	} while ((dev_ctx_item != dev_context_list) && (i < domain_array_size));

	/* if domain_array_size is less than actual devices in the system */
	ASSERT((dev_ctx_item == dev_context_list) && (i = domain_array_size));
}

void cve_dev_get_custom_fw_version_per_context(
	cve_dev_context_handle_t hcontext,
	enum fw_binary_type fwtype,
	Version *out_fw_version)
{
	struct dev_context *context = (struct dev_context *)hcontext;
	struct cve_fw_loaded_sections *loaded_fw_sections = NULL;
	Version zero_version = { {0, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 0} };

	/* look for the custom loaded section based on the FW type */
	loaded_fw_sections = cve_dle_lookup(
			context->loaded_cust_fw_sections,
			list, fw_type,
			fwtype);

	if (hcontext != NULL) {
		if (loaded_fw_sections != NULL)
			*out_fw_version = *loaded_fw_sections->fw_version;

		else {
			cve_os_log(CVE_LOGLEVEL_DEBUG,
					"Cannot find loaded section with FW_Type=%s\n",
					get_fw_binary_type_str(fwtype));
			*out_fw_version = zero_version;
		}
	}
}

void cve_di_reset_cve_dump(struct cve_device *dev, uint8_t dumpTrigger,
		struct di_cve_dump_buffer ice_dump_buf)
{
	cve_di_set_cve_dump_configuration_register(dev,
			ice_dump_buf);
	cve_di_set_cve_dump_control_register(dev, dumpTrigger, ice_dump_buf);
}

int cve_dev_alloc_and_map_cbdt(cve_dev_context_handle_t dev_ctx,
			struct fifo_descriptor *fifo_desc,
			u32 max_cbdt_entries)
{
	void *vaddr;
	u32 size_bytes;
	struct dev_context *nc;
	struct cve_device *dev;
	struct cve_surface_descriptor surf;
	int retval = CVE_DEFAULT_ERROR_CODE;
	ice_va_t ice_va = CVE_INVALID_VIRTUAL_ADDR;
	cve_mm_allocation_t fifo_alloc_handle = NULL;

	/* Adding space for Embedded CB */
	max_cbdt_entries += 1;

	nc = (struct dev_context *)dev_ctx;
	dev = nc->cve_dev;

	retval = OS_ALLOC_DMA_CONTIG(dev,
			sizeof(union CVE_SHARED_CB_DESCRIPTOR),
			max_cbdt_entries,
			&vaddr,
			&fifo_desc->fifo.cb_desc_dma_handle, 1);
	if (retval != 0) {
		cve_os_dev_log(CVE_LOGLEVEL_ERROR,
			dev->dev_index,
			"os_alloc_dma failed %d\n", retval);
		goto out;
	}

	size_bytes = max_cbdt_entries * sizeof(union CVE_SHARED_CB_DESCRIPTOR);
	memset(vaddr, 0, size_bytes);
	fifo_desc->fifo.cb_desc_vaddr = vaddr;
	fifo_desc->fifo.size_bytes = size_bytes;
	fifo_desc->fifo.entries = max_cbdt_entries;

	memset(&surf, 0, sizeof(struct cve_surface_descriptor));
	surf.llc_policy = CVE_FIFO_LLC_CONFIG;

	cve_os_dev_log(CVE_LOGLEVEL_DEBUG,
		nc->cve_dev->dev_index,
		"Start Mapping CBDT. PA=0x%llx\n",
		fifo_desc->fifo.cb_desc_dma_handle.mem_handle.dma_address);

	/* map the fifo in the shared domain */
	retval = cve_mm_create_kernel_mem_allocation(nc->hdom,
					fifo_desc->fifo.cb_desc_vaddr,
					fifo_desc->fifo.size_bytes,
					CVE_SURFACE_DIRECTION_INOUT,
					CVE_MM_PROT_READ | CVE_MM_PROT_WRITE,
					&ice_va,
					&fifo_desc->fifo.cb_desc_dma_handle,
					&surf,
					&fifo_alloc_handle);
	if (retval != 0) {
		cve_os_dev_log(CVE_LOGLEVEL_ERROR,
			dev->dev_index,
			"cve_mm_create_kernel_mem_allocation failed %d\n",
			retval);
		goto failed_map_fifo;
	}

	cve_os_dev_log(CVE_LOGLEVEL_DEBUG,
		nc->cve_dev->dev_index,
		"Stop Mapping CBDT. PA=0x%llx, ICEVA=0x%llx\n",
		fifo_desc->fifo.cb_desc_dma_handle.mem_handle.dma_address,
		ice_va);

	fifo_desc->fifo_alloc.alloc_handle = fifo_alloc_handle;
	fifo_desc->fifo_alloc.ice_vaddr = ice_va;

	return 0;

failed_map_fifo:
	/* free descriptors list */
	OS_FREE_DMA_CONTIG(dev,
			fifo_desc->fifo.size_bytes,
			fifo_desc->fifo.cb_desc_vaddr,
			&fifo_desc->fifo.cb_desc_dma_handle, 1);
out:
	return retval;
}

int cve_dev_dealloc_and_unmap_cbdt(cve_dev_context_handle_t dev_ctx,
			struct fifo_descriptor *fifo_desc)
{
	struct dev_context *nc;
	struct cve_device *dev;

	nc = (struct dev_context *)dev_ctx;
	dev = nc->cve_dev;

	cve_mm_reclaim_allocation(fifo_desc->fifo_alloc.alloc_handle);

	/* free descriptors list */
	OS_FREE_DMA_CONTIG(dev,
		fifo_desc->fifo.size_bytes,
		fifo_desc->fifo.cb_desc_vaddr,
		&fifo_desc->fifo.cb_desc_dma_handle, 1);

	return 0;
}



