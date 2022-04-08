/********************************************
 * Copyright (C) 2019-2021 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/



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
	/* list of embedded command buffers subjobs per cve device  */
	cve_di_subjob_handle_t *embedded_cbs_subjobs;
	/* cve dump buffer allocation info */
	struct dev_alloc cve_dump_alloc;
	/* pointer to the device */
	struct cve_device *cve_dev;
	cve_mm_allocation_t bar1_alloc_handle;
};

/* INTERNAL FUNCTIONS */

static int __map_base_package_fws(cve_dev_context_handle_t hcontext)
{
	int retval;
	struct dev_context *context = (struct dev_context *)hcontext;

#ifndef NULL_DEVICE_RING0
	retval = cve_fw_map(context->hdom,
			&context->mapped_fw_sections,
			&context->embedded_cbs_subjobs);
#else
	retval = 0;
#endif
	return retval;
}

void ice_map_dev_and_context(cve_dev_context_handle_t hcontext,
	struct cve_device *dev)
{
	struct dev_context *context = (struct dev_context *)hcontext;

	context->cve_dev = dev;
}

void ice_unmap_dev_and_context(cve_dev_context_handle_t hcontext)
{
	struct dev_context *context = (struct dev_context *)hcontext;

	context->cve_dev = NULL;
}

#ifdef IDC_ENABLE
void ice_unmap_bar1(cve_dev_context_handle_t hcontext)
{
	struct dev_context *dev_ctx = (struct dev_context *)hcontext;

	if (dev_ctx->bar1_alloc_handle) {
		cve_os_log(CVE_LOGLEVEL_DEBUG,
				"Reclaim BAR1 allocation\n");
		cve_mm_reclaim_allocation(dev_ctx->bar1_alloc_handle);
	}
}

int ice_map_bar1(struct cve_device *cve_dev,
		cve_dev_context_handle_t hcontext)
{
	int retval;
	cve_mm_allocation_t alloc_handles;
	struct dev_context *dev_ctx = (struct dev_context *)hcontext;
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

	ice_memset_s(&surf, sizeof(surf), 0,
			sizeof(struct cve_surface_descriptor));
	surf.llc_policy = ICE_BAR1_LLC_CONFIG;
	surf.map_in_hw_region = 1;
	va = cve_addr;

	cve_os_dev_log(CVE_LOGLEVEL_DEBUG,
		cve_dev->dev_index,
		COLOR_GREEN("Start Mapping BAR1. PA=0x%llx\n"),
		 mapped_dma_handles.mem_handle.dma_address);

	/* map the memory in cve address space */
	retval = cve_mm_create_kernel_mem_allocation(dev_ctx->hdom,
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
	dev_ctx->bar1_alloc_handle = alloc_handles;
out:
	return retval;
}
#endif

static void cve_dev_release_per_cve_ctx(struct dev_context *dev_ctx)
{
	struct dev_context *context = dev_ctx;

	if (context) {
		cve_os_log(CVE_LOGLEVEL_DEBUG,
				"Unload & Unmap FW\n");

		cve_fw_unmap(context->mapped_fw_sections,
			context->embedded_cbs_subjobs);

		if (context->cve_dump_alloc.alloc_handle) {
			/*remove allocations of ICE_DUMP buffer */
			cve_os_log(CVE_LOGLEVEL_DEBUG,
					"Reclaim ICE_DUMP buffer\n");
			cve_mm_reclaim_allocation(
				context->cve_dump_alloc.alloc_handle);
		}

		if (context->bar1_alloc_handle) {
			cve_os_log(CVE_LOGLEVEL_DEBUG,
				"Reclaim BAR1 allocation\n");
			cve_mm_reclaim_allocation(
				context->bar1_alloc_handle);
		}
		cve_os_log(CVE_LOGLEVEL_DEBUG,
				"Remove domain\n");
		cve_osmm_put_domain(context->hdom);
	}
}

static int __load_fw(const u64 fw_image,
		const u64 fw_binmap,
		const u32 fw_binmap_size_bytes,
		struct cve_fw_loaded_sections **out_fw_sec)
{
	int retval = CVE_DEFAULT_ERROR_CODE;
	struct cve_fw_loaded_sections *fw_sec = NULL;

	retval = OS_ALLOC_ZERO(sizeof(*fw_sec), (void **)&fw_sec);
	if (retval < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"os_malloc_zero failed %d\n", retval);
		goto exit;
	}

	cve_os_log(CVE_LOGLEVEL_DEBUG,
			COLOR_GREEN("Start Firmware Load and Map\n"));

	/* load dynamic fw to memory */
	retval = cve_fw_load_binary(fw_image, fw_binmap,
			fw_binmap_size_bytes,
			fw_sec);
	if (retval != 0) {
		cve_os_log_default(CVE_LOGLEVEL_ERROR,
				"cve_fw_load_binary_context failure\n");
		goto err_fw_load;
	}

	cve_os_log(CVE_LOGLEVEL_DEBUG,
		COLOR_GREEN("Firmware Loaded. FW_Type=%s, SectionsCount=%d\n"),
			get_fw_binary_type_str(fw_sec->fw_type),
			fw_sec->sections_nr);

	fw_sec->user_count = 0;
	fw_sec->last_used = trace_clock_global();
	*out_fw_sec = fw_sec;

	return retval;
err_fw_load:
	OS_FREE(fw_sec, sizeof(*fw_sec));
exit:
	return retval;
}


static int ice_map_fw_per_dev_ctx(cve_dev_context_handle_t hcontext,
		struct cve_fw_loaded_sections *load_fw_sec,
		enum fw_binary_type fw_type)
{
	int retval = CVE_DEFAULT_ERROR_CODE;
	struct dev_context *context = (struct dev_context *)hcontext;
	struct cve_fw_loaded_sections *fw_sec = load_fw_sec;
	struct cve_fw_loaded_sections *fw_sec_base = NULL;
	struct cve_fw_mapped_sections *fw_mapped = NULL;

	/* find mapped structure with dummy base fw */
	fw_mapped = cve_dle_lookup(context->mapped_fw_sections,
			list, cve_fw_loaded->fw_type, fw_type);
	if (!fw_mapped) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"FW_Type=%s can't be found in mapped fw list\n",
				get_fw_binary_type_str(fw_type));
		retval = -ICEDRV_KERROR_FW_INVAL_TYPE;
		goto out;
	}

	/* if loaded fw pointer is NULL, map base f/w */
	if (!load_fw_sec) {
		load_fw_sec = fw_mapped->base_fw_loaded;
		fw_sec = load_fw_sec;
	}

	/* copy of base fw loaded section pointer for restoring incase error*/
	fw_sec_base = fw_mapped->cve_fw_loaded;

	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"Cleaning the mapped Sections\n");
	/* clean mapped structure with dummy base fw */
	cve_mapped_fw_sections_cleanup(fw_mapped);

	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"Mapping Sections\n");
	/* fill mapped structure with new fw and map the fw to device */
	retval = cve_fw_map_sections(context->hdom,
			fw_sec,
			fw_mapped);
	if (retval != 0) {
		int err = 0;

		cve_os_log(CVE_LOGLEVEL_WARNING,
			"cve_fw_map_sections failure,base fw to be restored\n");
		/* restore  old base fw */
		err = cve_fw_map_sections(context->hdom,
						fw_sec_base,
						fw_mapped);
		if (err != 0) {
			cve_os_log_default(CVE_LOGLEVEL_ERROR,
				"restoring of base fw failure\n");
		}
		goto out;
	}

	/* success */
	retval = 0;
out:
	return retval;
}


/* INTERFACE FUNCTIONS */
void ice_fini_sw_dev_contexts(cve_dev_context_handle_t hcontext_list,
		struct cve_fw_loaded_sections *loaded_fw_sections_list)
{
	struct dev_context *dev_context_list =
		(struct dev_context *)hcontext_list;

	while (dev_context_list) {
		struct dev_context *dev_ctx = dev_context_list;

		cve_dle_remove_from_list(
				dev_context_list, list, dev_ctx);

		cve_os_log(CVE_LOGLEVEL_DEBUG,
				"Remove dev context\n");

		cve_dev_release_per_cve_ctx(dev_ctx);

		OS_FREE(dev_ctx, sizeof(*dev_ctx));
	}

       /* unload bank0/bank1 firmwares */
	cve_os_log(CVE_LOGLEVEL_DEBUG, "Unload Bank0/1 FW\n");
	cve_fw_unload(NULL, loaded_fw_sections_list);
}

int ice_dev_fw_load(const u64 fw_image,
		const u64 fw_binmap,
		const u32 fw_binmap_size_bytes,
		struct cve_fw_loaded_sections **out_fw_sec)
{
	int retval = CVE_DEFAULT_ERROR_CODE;

	cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Start Firmware Load and Map on all ICEs\n");

	retval = __load_fw(fw_image,
			fw_binmap,
			fw_binmap_size_bytes,
			out_fw_sec);
	if (retval < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"load_fw failed %d\n", retval);
		goto out;
	}

	cve_os_log(CVE_LOGLEVEL_DEBUG,
			"End Firmware Load and Map on all ICEs\n");

out:
	/* TODO: unload fw that was already loaded */

	return retval;
}

int ice_dev_fw_map(cve_dev_context_handle_t hcontext_list,
		struct cve_fw_loaded_sections *out_fw_sec,
		enum fw_binary_type fw_type)
{
	struct dev_context *dev_context_list =
		(struct dev_context *) hcontext_list;
	struct dev_context *dev_ctx_item = dev_context_list;
	int retval = CVE_DEFAULT_ERROR_CODE;

	cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Start Firmware Mapping on ICEs\n");

	do {
		retval = ice_map_fw_per_dev_ctx(dev_ctx_item,
			out_fw_sec, fw_type);
		if (retval < 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
				"ce_load_fw_per_dev_ctx failed %d\n",
				retval);
			goto out;
		}
		dev_ctx_item = cve_dle_next(dev_ctx_item, list);
	} while (dev_ctx_item != dev_context_list);

	cve_os_log(CVE_LOGLEVEL_DEBUG,
			"End Firmware Map on ICEs\n");

out:
	/* TODO: unload fw that was already loaded */

	return retval;
}


int cve_dev_fw_load_and_map(cve_dev_context_handle_t hcontext_list,
		const u64 fw_image,
		const u64 fw_binmap,
		const u32 fw_binmap_size_bytes,
		enum fw_binary_type fw_type,
		struct cve_fw_loaded_sections **out_fw_sec)
{
	struct dev_context *dev_context_list =
		(struct dev_context *) hcontext_list;
	struct dev_context *dev_ctx_item = dev_context_list;
	int retval = CVE_DEFAULT_ERROR_CODE;

	cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Start Firmware Load and Map on all ICEs\n");

	retval = __load_fw(fw_image,
			fw_binmap,
			fw_binmap_size_bytes,
			out_fw_sec);
	if (retval < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"load_fw failed %d\n", retval);
		goto out;
	}

	do {
		retval = ice_map_fw_per_dev_ctx(dev_ctx_item,
			*out_fw_sec, fw_type);
		if (retval < 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
				"ce_load_fw_per_dev_ctx failed %d\n",
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

void cve_dev_restore_tlc_fw(struct cve_device *cve_dev,
		cve_dev_context_handle_t hcontext)
{
	struct dev_context *context = (struct dev_context *)hcontext;

	/* restore the FWs just before the reset */
	cve_fw_restore_tlc(cve_dev, context->mapped_fw_sections);
}

void cve_dev_restore_ivp_fw(struct cve_device *cve_dev,
		cve_dev_context_handle_t hcontext)
{
	struct dev_context *context = (struct dev_context *)hcontext;

	/* restore the FWs just before the reset */
	cve_fw_restore_ivp(cve_dev, context->mapped_fw_sections);
}


int ice_init_sw_dev_contexts(u8 num_ice,
		u64 *va_partition_config,
		u64 *infer_buf_page_config,
		struct ice_pnetwork *pntw)
{
	struct dev_context *dev_context_list = NULL;
	int retval = CVE_DEFAULT_ERROR_CODE, i;
	struct dev_context *nc = NULL;

	/* Create domain equal to number of ICE requirements of the network*/
	for (i = 0; i < num_ice; i++) {
		retval = OS_ALLOC_ZERO(sizeof(struct dev_context),
				(void **)&nc);
		if (retval != 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
					"os_malloc_failed %d\n",
					retval);
			goto out;
		}

		retval = cve_osmm_get_domain(i,
				(uint64_t *)va_partition_config,
				(uint64_t *)infer_buf_page_config,
				&nc->hdom);
		if (retval < 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
					"osmm_get_domain failed %d\n",
					retval);
			OS_FREE(nc, sizeof(*nc));
			goto out;
		}

		/* load the base package FWs. add fws to context */
		retval = __map_base_package_fws(nc);
		if (retval != 0) {
			cve_os_log_default(CVE_LOGLEVEL_ERROR,
					"Failed to map base package %d\n",
					retval);
			cve_osmm_put_domain(nc->hdom);
			OS_FREE(nc, sizeof(*nc));
			goto out;
		}

		/* Add the device context list */
		cve_dle_add_to_list_before(
				dev_context_list, list, nc);

		pntw->dev_ctx[i] = nc;
	}

	/* success */
	pntw->dev_hctx_list = dev_context_list;

	return retval;

out:
	while (dev_context_list) {
		struct dev_context *dev_ctx = dev_context_list;

		cve_dle_remove_from_list(
				dev_context_list, list, dev_ctx);

		cve_os_log(CVE_LOGLEVEL_DEBUG,
				"Unmap Base + Bank0/1 FW\n");
		cve_fw_unmap(dev_ctx->mapped_fw_sections,
				dev_ctx->embedded_cbs_subjobs);

		cve_os_log(CVE_LOGLEVEL_DEBUG,
				"Remove dev context\n");
		cve_osmm_put_domain(dev_ctx->hdom);
		OS_FREE(dev_ctx, sizeof(*dev_ctx));
	}

	return retval;
}

int ice_extend_sw_dev_contexts(struct ice_pnetwork *pntw)
{
	u32 i;
	int retval = CVE_DEFAULT_ERROR_CODE;
	struct dev_context *nc = NULL;

	/* Create domain equal to number of ICE requirements of the network*/
	for (i = 0; i < pntw->num_ice; i++) {

		nc = pntw->dev_ctx[i];

		retval = cve_osmm_extend_domain(
				(uint64_t *)pntw->infer_buf_page_config,
				nc->hdom);
		if (retval < 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
					"osmm_get_domain failed %d\n",
					retval);
			goto out;
		}
	}

out:
	return retval;
}

void cve_dev_get_emb_cb_list(cve_dev_context_handle_t hcontext,
		cve_di_subjob_handle_t **out_embedded_cbs_subjobs)
{
	struct dev_context *context = (struct dev_context *)hcontext;

	*out_embedded_cbs_subjobs = NULL;

	if (hcontext != NULL)
		*out_embedded_cbs_subjobs = context->embedded_cbs_subjobs;
}

void cve_dev_get_os_domain_arr(cve_dev_context_handle_t hcontext_list,
	u32 domain_array_size,
	os_domain_handle *out_hdom)
{
	u32 i = 0;
	struct dev_context *dev_context_list =
		(struct dev_context *) hcontext_list;
	struct dev_context *dev_ctx_item = dev_context_list;

	ASSERT(dev_ctx_item);

	/* initialize array of os_domain_handle */
	do {
		out_hdom[i] = dev_ctx_item->hdom;

		i++;
		dev_ctx_item = cve_dle_next(dev_ctx_item, list);
	} while ((dev_ctx_item != dev_context_list) && (i < domain_array_size));

	/* if domain_array_size is less than actual devices in the system */
	ASSERT((dev_ctx_item == dev_context_list) && (i = domain_array_size));
}

void cve_dev_get_custom_fw_version_per_context(
	struct cve_fw_loaded_sections *loaded_fw_sections_list,
	enum fw_binary_type fwtype,
	Version *out_fw_version)
{
	struct cve_fw_loaded_sections *loaded_fw_section = NULL;
	Version zero_version = { {0, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 0} };

	/* look for the custom loaded section based on the FW type */
	loaded_fw_section = cve_dle_lookup(
			loaded_fw_sections_list,
			list, fw_type,
			fwtype);

	if (loaded_fw_section != NULL)
		*out_fw_version = *loaded_fw_section->fw_version;

	else {
		cve_os_log(CVE_LOGLEVEL_DEBUG,
				"Cannot find loaded section with FW_Type=%s\n",
				get_fw_binary_type_str(fwtype));
		*out_fw_version = zero_version;
	}
}

void cve_di_reset_cve_dump(struct cve_device *dev, uint8_t dumpTrigger,
		struct di_cve_dump_buffer *ice_dump_buf)
{
	/* Configure dump buffer address only before doorbell
	 * No communication with TLC on HPORT post doorbell
	 */
	if (dumpTrigger != cfg_default.ice_dump_now)
		cve_di_set_cve_dump_configuration_register(dev, ice_dump_buf);

	cve_di_set_cve_dump_control_register(dev, dumpTrigger, ice_dump_buf);
}

int cve_dev_alloc_and_map_cbdt(cve_dev_context_handle_t dev_ctx,
			struct fifo_descriptor *fifo_desc,
			u32 max_cbdt_entries)
{
	void *vaddr;
	u32 size_bytes;
	struct dev_context *nc;
	struct cve_device *dev = get_first_device();
	struct cve_surface_descriptor surf;
	int retval = CVE_DEFAULT_ERROR_CODE;
	ice_va_t ice_va = CVE_INVALID_VIRTUAL_ADDR;
	cve_mm_allocation_t fifo_alloc_handle = NULL;

	/* Adding space for Embedded CB */
	max_cbdt_entries += 1;

	nc = (struct dev_context *)dev_ctx;

	retval = OS_ALLOC_DMA_CONTIG(dev,
			sizeof(union CVE_SHARED_CB_DESCRIPTOR),
			max_cbdt_entries,
			&vaddr,
			&fifo_desc->fifo.cb_desc_dma_handle, 1);
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"os_alloc_dma failed %d\n", retval);
		goto out;
	}

	size_bytes = max_cbdt_entries * sizeof(union CVE_SHARED_CB_DESCRIPTOR);
	retval = ice_memset_s(vaddr, size_bytes, 0, size_bytes);
	if (retval < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"Safelib memset failed %d\n", retval);
		goto failed_map_fifo;
	}

	fifo_desc->fifo.cb_desc_vaddr = vaddr;
	fifo_desc->fifo.size_bytes = size_bytes;
	fifo_desc->fifo.entries = max_cbdt_entries;

	ice_memset_s(&surf, sizeof(surf), 0,
			sizeof(struct cve_surface_descriptor));
	surf.llc_policy = CVE_FIFO_LLC_CONFIG;

	cve_os_log(CVE_LOGLEVEL_DEBUG,
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
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"cve_mm_create_kernel_mem_allocation failed %d\n",
			retval);
		goto failed_map_fifo;
	}

	cve_os_log(CVE_LOGLEVEL_DEBUG,
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
	struct cve_device *dev = get_first_device();

	cve_mm_reclaim_allocation(fifo_desc->fifo_alloc.alloc_handle);

	/* free descriptors list */
	OS_FREE_DMA_CONTIG(dev,
		fifo_desc->fifo.size_bytes,
		fifo_desc->fifo.cb_desc_vaddr,
		&fifo_desc->fifo.cb_desc_dma_handle, 1);

	return 0;
}



