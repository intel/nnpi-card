/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/



#ifdef RING3_VALIDATION
#include <stdint.h>
#include <stdint_ext.h>
#include <string.h>
#include <linux_kernel_mock.h>
#else
#include <linux/types.h>
#include <linux/firmware.h>
#endif

#include "cve_firmware.h"
#include "os_interface.h"
#include "memory_manager.h"
#include "cve_driver_internal.h"
#include "device_interface.h"
#include "cve_linux_internal.h"
#include "version.h"
#include "ice_debug.h"
/* #include "coh_platform_interface.h" */

#ifdef RING3_VALIDATION

/** Debug version of RTL firmware */
#define	RTL_DEBUG_FW 1
/** Release version of RTL firmware */
#define	RTL_RELEASE_FW 2
/** Coral firmware */
#define	CORAL_FW 3

#endif

/* MODULE LEVEL VARIABLES */
#define BANK0_IVP_BASE_ADDR	0x00320000
#define BANK0_IVP_SIZE	0x9E0000	/* 9.875M */

#define BANK0_ASIP_BASE_ADDR	0x00e00000
#define BANK0_ASIP_SIZE	0x100000	/* 1M */

#define BANK1_IVP_BASE_ADDR	0x00d00000
#define BANK1_IVP_SIZE	0x100000	/* 1M */

#define BANK1_ASIP_BASE_ADDR	0x00f00000
#define BANK1_ASIP_SIZE	0x100000	/* 1M */


#define TLC_FW_BIN_NAME "/cve_image0_fw.bin"
#define TLC_FW_MAP_NAME "/cve_image0_map.bin"
#define IVP_FW_BIN_NAME "/cve_image1_fw.bin"
#define IVP_FW_MAP_NAME "/cve_image1_map.bin"
#define IVP_BANK0_FW_BIN_NAME "/cve_image2_fw.bin"
#define IVP_BANK0_FW_MAP_NAME "/cve_image2_map.bin"
#define IVP_BANK1_FW_BIN_NAME  "/cve_image3_fw.bin"
#define IVP_BANK1_FW_MAP_NAME  "/cve_image3_map.bin"
#define ASIP_FW_BIN_NAME "/cve_image4_fw.bin"
#define ASIP_FW_MAP_NAME "/cve_image4_map.bin"
#define ASIP_BANK0_FW_BIN_NAME "/cve_image5_fw.bin"
#define ASIP_BANK0_FW_MAP_NAME "/cve_image5_map.bin"
#define ASIP_BANK1_FW_BIN_NAME "/cve_image6_fw.bin"
#define ASIP_BANK1_FW_MAP_NAME "/cve_image6_map.bin"
#define LOAD_AND_CLEAR_CACHE_BIN_NAME "/cve_cb_1.bin"
#define LOAD_AND_CLEAR_CACHE_MAP_NAME "/cve_cb_1_map.bin"


#define TLC_FW_BIN (FW_PACK_DIR TLC_FW_BIN_NAME)
#define TLC_FW_MAP (FW_PACK_DIR TLC_FW_MAP_NAME)
#define IVP_FW_BIN (FW_PACK_DIR IVP_FW_BIN_NAME)
#define IVP_FW_MAP (FW_PACK_DIR IVP_FW_MAP_NAME)
#define ASIP_FW_BIN (FW_PACK_DIR ASIP_FW_BIN_NAME)
#define ASIP_FW_MAP (FW_PACK_DIR ASIP_FW_MAP_NAME)

#define IVP_BANK0_FW_BIN (FW_PACK_DIR IVP_BANK0_FW_BIN_NAME)
#define IVP_BANK0_FW_MAP (FW_PACK_DIR IVP_BANK0_FW_MAP_NAME)
#define IVP_BANK1_FW_BIN (FW_PACK_DIR IVP_BANK1_FW_BIN_NAME)
#define IVP_BANK1_FW_MAP (FW_PACK_DIR IVP_BANK1_FW_MAP_NAME)

#define ASIP_BANK0_FW_BIN (FW_PACK_DIR ASIP_BANK0_FW_BIN_NAME)
#define ASIP_BANK0_FW_MAP (FW_PACK_DIR ASIP_BANK0_FW_MAP_NAME)
#define ASIP_BANK1_FW_BIN (FW_PACK_DIR ASIP_BANK1_FW_BIN_NAME)
#define ASIP_BANK1_FW_MAP (FW_PACK_DIR ASIP_BANK1_FW_MAP_NAME)

#define LOAD_AND_CLEAR_CACHE_BIN (FW_PACK_DIR LOAD_AND_CLEAR_CACHE_BIN_NAME)
#define LOAD_AND_CLEAR_CACHE_MAP (FW_PACK_DIR LOAD_AND_CLEAR_CACHE_MAP_NAME)

/* init the global base FWs versions */
Version tlc_version;
Version ivp_version;
Version asip_version;

#ifndef NULL_DEVICE_RING0
static struct cve_fw_file fw_binaries_files[] =  {
		/* TLC */
		{
				TLC_FW_BIN,
				TLC_FW_MAP,
				CVE_FW_TLC_TYPE
		},
		/* IVP */
		{
				IVP_FW_BIN,
				IVP_FW_MAP,
				CVE_FW_IVP_MFW_TYPE
		},
		/* ASIP */
		{
				ASIP_FW_BIN,
				ASIP_FW_MAP,
				CVE_FW_ASIP_MFW_TYPE
		},
		/* IVP_BANK0 */
		{
				IVP_BANK0_FW_BIN,
				IVP_BANK0_FW_MAP,
				CVE_FW_IVP_BANK0_TYPE
		},
		/* IVP_BANK1 */
		{
				IVP_BANK1_FW_BIN,
				IVP_BANK1_FW_MAP,
				CVE_FW_IVP_BANK1_TYPE
		},
		/* ASIP_BANK0 */
		{
				ASIP_BANK0_FW_BIN,
				ASIP_BANK0_FW_MAP,
				CVE_FW_ASIP_BANK0_TYPE
		},
		/* ASIP_BANK1 */
		{
				ASIP_BANK1_FW_BIN,
				ASIP_BANK1_FW_MAP,
				CVE_FW_ASIP_BANK1_TYPE
		},
		/* Context switch CB */
		{
				LOAD_AND_CLEAR_CACHE_BIN,
				LOAD_AND_CLEAR_CACHE_MAP,
				CVE_FW_CB1_TYPE
		}
};
#endif
/* PRIVATE FUNCTIONS */
/**
 * Build Version struct from array of 6 sub versions
 * @params 6 * u32 - based on structs in ICVE_FIRMWARE_SECTION_DESCRIPTOR,
 * the first 6th u32 are the versions array
 * @return Version struct
 */
static void set_bin_ver_from_ver_arr(u32 ver_1,
		u32 ver_2,
		u32 ver_3,
		u32 ver_4,
		u32 ver_5,
		u32 ver_6,
		Version *out_fw_version)
{
	out_fw_version->component.product  = ver_1 >> 28;
	out_fw_version->component.major    = (ver_1 >> 24) & 0xF;
	out_fw_version->component.minor    = (ver_1 >> 16) & 0xFF;
	out_fw_version->component.patch    = ver_1 & 0xFFFF;
	out_fw_version->component.metadata = ver_2;
	out_fw_version->component.checksum = ver_3;
	out_fw_version->product.product    = ver_4 >> 28;
	out_fw_version->product.major      = (ver_4 >> 24) & 0xF;
	out_fw_version->product.minor      = (ver_4 >> 16) & 0xFF;
	out_fw_version->product.patch      = ver_4 & 0xFFFF;
	out_fw_version->product.metadata   = ver_5;
	out_fw_version->product.checksum   = ver_6;
}

static int cve_fw_load_firmware_from_kernel_mem(struct cve_device *cve_dev,
		u64 fw_image,
		u64 fw_binmap,
		u32 fw_binmap_size_bytes,
		u32 *out_sections_nr,
		struct cve_fw_section_descriptor **out_sections,
		struct cve_dma_handle **out_dma_handles,
		Version **out_fw_version)
{
	int retval = CVE_DEFAULT_ERROR_CODE;
	u32 sections_nr = 0;
	/* hold a pointer to the map file interface sections */
	struct ICVE_FIRMWARE_SECTION_DESCRIPTOR *sections = NULL;
	/* hold a pointer to the map file impl sections */
	struct cve_fw_section_descriptor *sections_impl = NULL;
	struct cve_dma_handle *dma_handles = NULL;
	Version *fw_version = NULL;
	u32 i, ignore_section = 0;

	/* read the sections info from the map file */
	sections_nr = fw_binmap_size_bytes /
			sizeof(struct ICVE_FIRMWARE_SECTION_DESCRIPTOR);
	retval = OS_ALLOC_ZERO(sizeof(*sections_impl) * sections_nr,
				(void **)&sections_impl);
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"OS_ALLOC_ZERO (sections_impl) failed %d\n",
				retval);
		goto out;
	}
	retval = OS_ALLOC_ZERO(sizeof(*dma_handles) * sections_nr,
			(void **)&dma_handles);
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"OS_ALLOC_ZERO (dma_handles) failed %d\n",
				retval);
		goto out;
	}

	retval = OS_ALLOC_ZERO(sizeof(*fw_version),
				(void **)&fw_version);
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"OS_ALLOC_ZERO (fw_version) failed %d\n",
				retval);
		goto out;
	}

	sections = (struct ICVE_FIRMWARE_SECTION_DESCRIPTOR *)
			(uintptr_t)fw_binmap;

	/* read the sections */
	retval = -ENOMEM;
	for (i = 0; i < sections_nr; i++) {
		struct ICVE_FIRMWARE_SECTION_DESCRIPTOR *s = &sections[i];

		/* Copy the FWs map file to an internal structure */
		sections_impl[i].cve_addr = sections[i].cve_addr;
		sections_impl[i].permissions = sections[i].permissions;
		sections_impl[i].size_bytes = sections[i].size_bytes;

		/*TODO HACK: ignore sections smaller than 16 bytes so that we
		 * ignore marker sections which are not page alignment
		 * Currently TLC marker is 8 bytes
		 */
		if (sections[i].size_bytes <= 16) {
			ignore_section++;
			continue;
		}

		/* Allocate DMA'able memory and get its kernel virt address */
		retval = OS_ALLOC_DMA_SG(cve_dev,
				s->size_bytes,
				1,
				&dma_handles[i],
				true);
		if (retval != 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
					"OS_ALLOC_DMA_SG failed: %d\n",
					retval);
			goto out;
		}

		/* Copy the content of the FW buffer to just
		 * allocated DMA'able memory
		 */
		cve_os_dma_copy_from_buffer(&dma_handles[i],
				(void *)(uintptr_t)
				(fw_image + s->offset_in_file),
				s->size_bytes);

		/* Flush CPU caches, if needed */
		if (!(s->permissions & CVE_MM_PROT_WRITE)) {
			cve_os_sync_sg_memory_to_device(cve_dev,
					dma_handles[i].mem_handle.sgt);
		}

		cve_os_dev_log(CVE_LOGLEVEL_DEBUG,
				cve_dev->dev_index,
				"Loading Firmware Section. SectionID=%i, PA=0x%llx, ICEVA=0x%x, Perm=%s, Size=0x%x, Offset=0x%x\n",
				i,
#ifdef RING3_VALIDATION
				dma_handles[i].mem_handle.dma_address,
#else
				dma_handles[i].mem_handle.sgt->sgl->dma_address,
#endif
				sections[i].cve_addr,
				get_cve_memory_protection_str(
					sections[i].permissions),
				sections[i].size_bytes,
				sections[i].offset_in_file);
	}

	set_bin_ver_from_ver_arr(sections->version[0],
				sections->version[1],
				sections->version[2],
				sections->version[3],
				sections->version[4],
				sections->version[5],
				fw_version);

	/* success */
	*out_sections_nr = (sections_nr - ignore_section);
	*out_sections = sections_impl;
	*out_dma_handles = dma_handles;
	*out_fw_version = fw_version;

	retval = 0;

out:
	if (retval != 0) {
		cve_fw_sections_cleanup(NULL, sections_impl,
			dma_handles,
			sections_nr);

		if (fw_version)
			OS_FREE(fw_version, sizeof(*fw_version));
	}

	return retval;
}
/**
 * Copies the content of section from the user allocated buffer
 * to DMA'able memory
 * @param fw_image - user allocated buffer
 * @param dma_handle - DMA'able memory
 * @param section - FW section descriptor
 * @return 0 on success
 */
static int cve_fw_copy_from_user_mem(void __user *fw_image,
		struct cve_dma_handle *dma_handle,
		struct ICVE_FIRMWARE_SECTION_DESCRIPTOR *section)
{
	void *vaddr;
	int retval;

	/* Map the dma handle*/
	vaddr = cve_os_vmap_dma_handle(dma_handle);
	if (!vaddr) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"failed to vmap\n");
		retval = -ENOMEM;
		goto failed_to_vmap;
	}

	/* Copy the content of the FW buffer to DMA'able memory */
	retval = cve_os_read_user_memory(fw_image + section->offset_in_file,
			section->size_bytes,
			(void *)(uintptr_t)
			vaddr);
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"cve_os_read_user_memory failed: %d\n",
				retval);
		goto failed_to_read;
	}

	/* Unmap the dma handle*/
	cve_os_vunmap_dma_handle(vaddr);

	return 0;

failed_to_read:
	cve_os_vunmap_dma_handle(vaddr);
failed_to_vmap:
	return retval;

}

static int cve_fw_load_firmware_from_user_mem(u64 fw_image,
		u64 fw_binmap,
		u32 fw_binmap_size_bytes,
		u32 *out_sections_nr,
		struct cve_fw_section_descriptor **out_sections,
		struct cve_dma_handle **out_dma_handles,
		Version **out_fw_version)
{
	int retval = CVE_DEFAULT_ERROR_CODE;
	u32 sections_nr = 0;
	struct cve_device *dev = get_first_device();
	/* hold a pointer to the map file interface sections */
	struct ICVE_FIRMWARE_SECTION_DESCRIPTOR *sections = NULL;
	/* hold a pointer to the map file impl sections */
	struct cve_fw_section_descriptor *sections_impl = NULL;
	struct cve_dma_handle *dma_handles = NULL;
	Version *fw_version = NULL;
	u32 i;

	/* read the sections info from the map file */
	sections_nr = fw_binmap_size_bytes /
			sizeof(struct ICVE_FIRMWARE_SECTION_DESCRIPTOR);
	retval = OS_ALLOC_ZERO(sizeof(*sections_impl) * sections_nr,
				(void **)&sections_impl);
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"OS_ALLOC_ZERO (sections_impl) failed %d\n",
				retval);
		goto out;
	}
	retval = OS_ALLOC_ZERO(sizeof(*dma_handles) * sections_nr,
			(void **)&dma_handles);
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"OS_ALLOC_ZERO (dma_handles) failed %d\n",
				retval);
		goto out;
	}

	/* copy to kernel space */
	retval = OS_ALLOC_ZERO(sizeof(*sections) * sections_nr,
				(void **)&sections);
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"OS_ALLOC_ZERO (sections) failed %d\n",
				retval);
		goto out;
	}

	/* fw_version allocation */
	retval = OS_ALLOC_ZERO(sizeof(*fw_version),
					(void **)&fw_version);
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"OS_ALLOC_ZERO (fw_version) failed %d\n",
				retval);
		goto out;
	}

	retval = cve_os_read_user_memory((void *)(uintptr_t)fw_binmap,
			sizeof(*sections) * sections_nr,
			sections);
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"cve_os_read_user_memory failed: %d\n",
				retval);
		goto out;
	}

	/* read the sections */
	retval = -ENOMEM;
	for (i = 0; i < sections_nr; i++) {
		struct ICVE_FIRMWARE_SECTION_DESCRIPTOR *s = &sections[i];

		/* Copy the FWs map file to an internal structure */
		sections_impl[i].cve_addr = sections[i].cve_addr;
		sections_impl[i].permissions = sections[i].permissions;
		sections_impl[i].size_bytes = sections[i].size_bytes;

		/* The test with non page aligned IOVA address crashes on [SI]
		 * To avoid the crash, error check is performed here.
		 * TODO: analyse the crash after removing this sanity
		 * check from here.
		 */
		if (!IS_ADDR_ALIGNED(sections_impl[i].cve_addr)) {
			cve_os_log(CVE_LOGLEVEL_WARNING,
			"ice_addr not page aligned 0x%x\n",
				sections_impl[i].cve_addr);
			retval = -ICEDRV_KERROR_IOVA_PAGE_ALIGNMENT;
			goto out;
		}

		/* Allocate DMA'able memory and get its kernel virt address */
		retval = OS_ALLOC_DMA_SG(dev,
				s->size_bytes,
				1,
				&dma_handles[i],
				true);
		if (retval != 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
					"OS_ALLOC_DMA_SG failed: %d\n",
					retval);
			goto out;
		}

		retval = cve_fw_copy_from_user_mem((void *)(uintptr_t)
				(fw_image),
				&dma_handles[i],
				s);
		if (retval != 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
					"Failed to copy: %d\n",
					retval);
			goto out;
		}

		/* Flush CPU caches, if needed */
		if (!(s->permissions & CVE_MM_PROT_WRITE)) {
			cve_os_sync_sg_memory_to_device(dev,
					dma_handles[i].mem_handle.sgt);
		}

		cve_os_log(CVE_LOGLEVEL_DEBUG,
				"Loading Firmware Section. SectionID=%i, PA=0x%llx, ICEVA=0x%x, Perm=%s, Size=0x%x, Offset=0x%x\n",
				i,
#ifdef RING3_VALIDATION
				dma_handles[i].mem_handle.dma_address,
#else
				dma_handles[i].mem_handle.sgt->sgl->dma_address,
#endif
				sections[i].cve_addr,
				get_cve_memory_protection_str(
					sections[i].permissions),
				sections[i].size_bytes,
				sections[i].offset_in_file);
	}

	set_bin_ver_from_ver_arr(sections->version[0],
			sections->version[1],
			sections->version[2],
			sections->version[3],
			sections->version[4],
			sections->version[5],
			fw_version);

	/* success */
	*out_sections_nr = sections_nr;
	*out_sections = sections_impl;
	*out_dma_handles = dma_handles;
	*out_fw_version = fw_version;
	retval = 0;

out:
	OS_FREE(sections, sizeof(*sections) * sections_nr);

	if (retval != 0) {
		cve_fw_sections_cleanup(NULL, sections_impl,
			dma_handles,
			sections_nr);

		if (fw_version)
			OS_FREE(fw_version, sizeof(*fw_version));
	}

	return retval;
}

/*
 * read section cve addresses and detect customer fw type
 * inputs : the fw section descriptor
 * outputs: out_fw_type firmware type
 * returns: 0 on success, a negative error code on failure
 */
static int cve_fw_get_cust_fw_type(
		struct cve_fw_section_descriptor *section,
		enum fw_binary_type *out_fw_type)
{
	int retval = CVE_DEFAULT_ERROR_CODE;
	enum fw_binary_type fw_type;

	/* Sanity check for cve_addr and size_bytes to handle integer overflow
	 * cve_addr <= MAX(BANK0/1 IVP/ASIP address) i.e. BANK1_ASIP_BASE_ADDR
	 * size_bytes <= MAX(BANK0/1 IVP/ASIP size) i.e. BANK0_IVP_SIZE
	 */
	if (!((section->cve_addr <= BANK1_ASIP_BASE_ADDR) &&
		(section->size_bytes <= BANK0_IVP_SIZE))) {
		retval = -ICEDRV_KERROR_FW_PERM;
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"ERROR:%d invalid cve_addr address, cve_addr = 0x%x or invalid size, size_bytes = 0x%x\n",
				retval, section->cve_addr, section->size_bytes);
		goto out;
	}

	/*fw_image sanity check*/
	if ((section->cve_addr >= BANK0_IVP_BASE_ADDR) &&
			(section->cve_addr + section->size_bytes <
			BANK0_IVP_BASE_ADDR + BANK0_IVP_SIZE)) {
		fw_type = CVE_FW_IVP_BANK0_TYPE;
	} else if ((section->cve_addr >= BANK0_ASIP_BASE_ADDR) &&
			(section->cve_addr + section->size_bytes <
			BANK0_ASIP_BASE_ADDR + BANK0_ASIP_SIZE)) {
		fw_type =  CVE_FW_ASIP_BANK0_TYPE;
	} else if ((section->cve_addr >= BANK1_IVP_BASE_ADDR) &&
			(section->cve_addr + section->size_bytes <
			BANK1_IVP_BASE_ADDR + BANK1_IVP_SIZE)) {
		fw_type =  CVE_FW_IVP_BANK1_TYPE;
	} else if ((section->cve_addr >= BANK1_ASIP_BASE_ADDR) &&
			(section->cve_addr + section->size_bytes <
			BANK1_ASIP_BASE_ADDR + BANK1_ASIP_SIZE)) {
		fw_type =  CVE_FW_ASIP_BANK1_TYPE;
	} else{
		retval = -ICEDRV_KERROR_FW_PERM;
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"ERROR:%d invalid cve_addr address ,cve_addr = 0x%x\n",
				retval, section->cve_addr);
		goto out;
	}

	/* success */
	retval = 0;
	*out_fw_type = fw_type;
out:
	return retval;
}

/**
 * Copies the content of section from dma handle to dma handle
 * @param from_dma_handle - the dma handle the data to be copied from
 * @param to_dma_handle - the dma handle the data to be copied to
 * @param section - FW section descriptor
 * @return 0 on success
 */
static int cve_fw_copy_from_kern_mem(struct cve_dma_handle *from_dma_handle,
		struct cve_dma_handle *to_dma_handle,
		struct cve_fw_section_descriptor *section)
{
	void *vaddr;
	int retval;

	/* Map the dma handle*/
	vaddr = cve_os_vmap_dma_handle(from_dma_handle);
	if (!vaddr) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"failed to vmap\n");
		retval = -ENOMEM;
		goto failed_to_vmap;
	}

	/* Copy the content of the FW buffer to DMA'able memory */
	retval = cve_os_dma_copy_from_buffer(to_dma_handle,
			vaddr,
			section->size_bytes);
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"cve_os_dma_copy_from_buffer failed: %d\n",
				retval);
		goto failed_to_read;
	}

	/* Unmap the dma handle*/
	cve_os_vunmap_dma_handle(vaddr);

	return 0;

failed_to_read:
	cve_os_vunmap_dma_handle(vaddr);
failed_to_vmap:
	return retval;

}

/* !!!!!!!!!!!!! Should return status !!!!!!!!!!!!!*/
static void restore_fw_sections(struct cve_device *cve_dev,
		struct cve_fw_mapped_sections *mapped_fw)
{
	u32  j;
	struct cve_fw_loaded_sections *fw_sec = mapped_fw->cve_fw_loaded;

	for (j = 0; j < fw_sec->sections_nr; ++j) {
		struct cve_fw_section_descriptor *s = &fw_sec->sections[j];
		struct cve_dma_handle *dma_handle = &mapped_fw->dma_handles[j];

		if (s->permissions & CVE_MM_PROT_WRITE)	{
			cve_os_dev_log(CVE_LOGLEVEL_DEBUG,
				cve_dev->dev_index,
				"Restoring Firmware Section. ICEVA=0x%x, Size=0x%x\n",
				s->cve_addr,
				s->size_bytes);

			cve_fw_copy_from_kern_mem(&fw_sec->dma_handles[j],
					dma_handle,
					s);

			/* sync the dma data to device */
			cve_os_sync_sg_memory_to_device(cve_dev,
					dma_handle->mem_handle.sgt);
		}
	}
}

/* UTILITY FUNCTIONS */
/*
 * load a firmware binary to a given memory context for specified device
 * inputs : cve_device *cve_dev - device handle
 *          cve_fw_file *fw_ld_files - the firmware binary/map information
 * outputs:	cve_fw_loaded_sections *fw_sec - the firmware binary sections
 * returns: 0 on success, a negative error code on failure
 */
#ifndef NULL_DEVICE_RING0
static int cve_fw_load_binary_files(
		struct cve_device *cve_dev,
		const struct cve_fw_file *fw_ld_file,
		struct cve_fw_loaded_sections *out_fw_loaded)
{
	u32 sections_nr = 0;
	struct cve_fw_section_descriptor *sections = NULL;
	struct cve_dma_handle *dma_handles = NULL;
	Version *fw_version = NULL;

	/* load the binary into system memory */
	int retval = cve_fw_load_firmware_via_files(cve_dev,
			(const char *)&fw_ld_file->binary_file_name,
			(const char *)&fw_ld_file->map_file_name,
			&sections_nr,
			&sections,
			&dma_handles,
			&fw_version);
	if (retval < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"cve_os_load_firmware_via_files failed %d\n",
				retval);
		goto out;
	}

	/* success */
	out_fw_loaded->sections_nr = sections_nr;
	out_fw_loaded->sections = sections;
	out_fw_loaded->dma_handles = dma_handles;
	out_fw_loaded->fw_version = fw_version;
	retval = 0;
out:
	if (retval != 0) {
		/*
		 * Note: fw allocations will be reclaimed as part of the
		 * shared domain removal. Therefore there is no need to
		 * reclaim it here.
		 */
		cve_fw_sections_cleanup(NULL, sections,
			dma_handles,
			sections_nr);
	}

	return retval;
}
#endif
/*
 * Detect fw_type and check if fw_type is constant between all sections
 * inputs : cve_section_descriptor *sections - fw sections
 *          u32 sections_nr - number of fw sections
 * outputs: fw_binary_type *out_fw_type - detected fw_type
 * returns: 0 on success, a negative error code on failure
 */
static int cve_fw_type_section_detect(
		struct cve_fw_section_descriptor *sections,
		u32 sections_nr,
		enum fw_binary_type *out_fw_type)
{
	enum fw_binary_type fw_type = CVE_FW_TYPE_INVALID;
	enum fw_binary_type new_fw_type = CVE_FW_TYPE_INVALID;
	int retval = CVE_DEFAULT_ERROR_CODE;
	u32 i = 0;

	for (i = 0; i < sections_nr; i++) {
		struct cve_fw_section_descriptor *s = &sections[i];

		retval = cve_fw_get_cust_fw_type(s, &fw_type);
		if (retval != 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
					"cve_fw_get_cust_fw_type failure %d\n",
					retval);
			goto out;
		}
		if (new_fw_type == CVE_FW_TYPE_INVALID) {
			new_fw_type = fw_type;
		} else if (new_fw_type != fw_type) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
					"FW type is NOT constant between all FW sections, prev fw_type: %d, curr fw_type: %d\n",
					new_fw_type, fw_type);
			retval = -ICEDRV_KERROR_FW_INVAL_TYPE;
			goto out;
		}
	}

	/* success */
	*out_fw_type = fw_type;
	retval = 0;

out:
	return retval;
}

int cve_fw_map_sections(
		const os_domain_handle hdom,
		struct cve_fw_loaded_sections *fw_loaded_sec,
		struct cve_fw_mapped_sections *out_fw_mapped_sec)
{
	int retval;
	u32 i;
	u32 mapped_sections_nr = 0;
	u32 sections_nr = fw_loaded_sec->sections_nr;
	struct cve_device *dev = get_first_device();
	struct cve_fw_section_descriptor *sections = fw_loaded_sec->sections;
	struct cve_dma_handle *dma_handles = fw_loaded_sec->dma_handles;
	struct cve_dma_handle *mapped_dma_handles = NULL;
	cve_mm_allocation_t *alloc_handles = NULL;
	struct cve_surface_descriptor surf;
	ice_va_t va = 0;

	memset(&surf, 0, sizeof(struct cve_surface_descriptor));

	/* allocate dma addr array in fw mapped structure */
	retval = OS_ALLOC_ZERO(
			sizeof(*mapped_dma_handles) * sections_nr,
			(void **)&mapped_dma_handles);
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"OS_ALLOC_ZERO (dma_handles) failed %d\n",
				retval);
		goto out;
	}

	/* allocate alloc_handles array in fw mapped structure */
	retval = OS_ALLOC_ZERO(
			sizeof(*alloc_handles) * sections_nr,
			(void **)&alloc_handles);
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"OS_ALLOC_ZERO (alloc_handles) failed %d\n",
				retval);
		goto out;
	}

	cve_os_log(CVE_LOGLEVEL_DEBUG,
		COLOR_GREEN(
			"Mapping Firmware. FW_Type=%s, SectionsCount=%d\n"
			),
		get_fw_binary_type_str(fw_loaded_sec->fw_type),
		sections_nr);

	/* map the sections in device page tables */
	for (i = 0; i < sections_nr; i++) {
		struct cve_fw_section_descriptor *s = &sections[i];
		u32 permissions = s->permissions;

		/*
		 * create SG DMA list for writable sections of FW,
		 * copy pointer of SG DMA list for readble sections
		 */
		if (!(permissions & CVE_MM_PROT_WRITE)) {
			mapped_dma_handles[i] = dma_handles[i];
		} else {
			/* Allocate DMA'able memory. Writable section has
			 * two dma handles:
			 * - loaded
			 * - mapped
			 * Data from loaded to mapped will be copied after
			 * CVE reset - on FW restore
			 */
			retval = OS_ALLOC_DMA_SG(dev,
					s->size_bytes,
					1,
					&mapped_dma_handles[i],
					false);
			if (retval != 0) {
				cve_os_log(CVE_LOGLEVEL_ERROR,
						"OS_ALLOC_DMA_SG failed: %d\n",
						retval);
				goto out;
			}

		}

		/* hold the number of mapped sections - for err handling */
		mapped_sections_nr++;

		if (cve_debug_get(DEBUG_TENS_EN)) {
			/* enabling write permissions for all FW sections */
			permissions = (s->permissions | CVE_MM_PROT_WRITE);
			cve_os_log(CVE_LOGLEVEL_DEBUG,
					"changing permissions for FW sections\n");
		}

		cve_os_log(CVE_LOGLEVEL_DEBUG,
			COLOR_YELLOW(
				"Start Mapping Firmware Section. FW_Type=%s, Section=%d, ICEVA=0x%x, Size=0x%x, Perm=%s\n"
				),
			get_fw_binary_type_str(fw_loaded_sec->fw_type),
			i,
			s->cve_addr,
			s->size_bytes,
			get_cve_memory_protection_str(s->permissions));

		/* map the memory in cve address space */
		surf.llc_policy = CVE_FW_LLC_CONFIG;
		surf.map_in_hw_region = 1;
		va = s->cve_addr;
		retval = cve_mm_create_kernel_mem_allocation(hdom,
				NULL,
				s->size_bytes,
				CVE_SURFACE_DIRECTION_IN,
				permissions,
				&va,
				&mapped_dma_handles[i],
				&surf,
				&(alloc_handles[i]));
		if (retval < 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
					"cve_mm_create_kernel_mem_allocation failed %d\n",
					retval);
			goto out;
		}
		s->cve_addr = (u32)va;

		cve_os_log(CVE_LOGLEVEL_DEBUG,
				COLOR_YELLOW(
					"Stop Mapping Firmware Section. FW_Type=%s, Section=%d\n"
					),
				get_fw_binary_type_str(fw_loaded_sec->fw_type),
				i);
	}

	/* success */
	out_fw_mapped_sec->cve_fw_loaded = fw_loaded_sec;
	out_fw_mapped_sec->dma_handles = mapped_dma_handles;
	out_fw_mapped_sec->alloc_handles = alloc_handles;
	retval = 0;
out:
	if (retval != 0) {
		/*
		 * Note: fw allocations will be reclaimed as part of the
		 * shared domain removal. Therefore there is no need to
		 * reclaim it here.
		 */
		for (i = 0; i < mapped_sections_nr; i++) {
			struct cve_fw_section_descriptor *s = &sections[i];

			if (alloc_handles && alloc_handles[i]) {
				/*remove allocations of the FW */
				cve_os_log(CVE_LOGLEVEL_DEBUG,
					"reclaiming allocation of FW sec %d\n",
					i);
				cve_mm_reclaim_allocation(alloc_handles[i]);
			}

			if ((s->permissions & CVE_MM_PROT_WRITE) ==
				CVE_MM_PROT_WRITE) {
				OS_FREE_DMA_SG(dev,
						s->size_bytes,
						&mapped_dma_handles[i]);
			}
		}
		if (mapped_dma_handles)
			OS_FREE(mapped_dma_handles,
				sizeof(*mapped_dma_handles) * sections_nr);
		if (alloc_handles)
			OS_FREE(alloc_handles,
				sizeof(*alloc_handles) * sections_nr);
	}

	return retval;
}

int cve_fw_load_binary(const u64 fw_image,
		const u64 fw_binmap,
		const u32 fw_binmap_size_bytes,
		struct cve_fw_loaded_sections *out_fw_sec)
{
	u32 sections_nr = 0;
	struct cve_fw_section_descriptor *sections = NULL;
	struct cve_dma_handle *dma_handles = NULL;
	Version *fw_version = NULL;
	enum fw_binary_type fw_type = CVE_FW_TYPE_INVALID;

	/* read input sections from memory */
	int retval = cve_fw_load_firmware_from_user_mem(fw_image,
			fw_binmap,
			fw_binmap_size_bytes,
			&sections_nr,
			&sections,
			&dma_handles,
			&fw_version);
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"cve_os_load_firmware_via_mem failed\n");
		goto out;
	}

	/* detect and check if fw_type is constant between all sections */
	retval = cve_fw_type_section_detect(sections,
				sections_nr,
				&fw_type);
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"cve_fw_type_section_detect failure %d\n",
				retval);
		goto out;
	}

	/* success */
	out_fw_sec->sections_nr = sections_nr;
	out_fw_sec->sections = sections;
	out_fw_sec->dma_handles = dma_handles;
	out_fw_sec->fw_type = fw_type;
	out_fw_sec->fw_version = fw_version;

	retval = 0;
out:
	if (retval != 0) {
		cve_fw_sections_cleanup(NULL, sections,
			dma_handles,
			sections_nr);
		if (fw_version)
			OS_FREE(fw_version, sizeof(*fw_version));
	}

	return retval;
}

/*
 * created embedded command buffer from corresponding fw loaded section
 * inputs : cve_fw_loaded_sections *emb_cb_section - fw loaded section that
 *            contains embedded command buffer
 *          cve_fw_file *fw_ld_files - the firmware binary/map information
 * outputs: cve_di_subjob_handle_t *subjobs_embedded_cbs - pointer to created
 *            embedded command buffer subjob
 * returns: 0 on success, a negative error code on failure
 */
static int cve_fw_create_emb_cb(struct cve_fw_loaded_sections *emb_cb_section,
	cve_di_subjob_handle_t *subjobs_embedded_cbs)
{
	int retval = CVE_DEFAULT_ERROR_CODE;
	u32 j;
	u16 commands_nr;
	struct cve_fw_section_descriptor *section = NULL;
	cve_di_subjob_handle_t *sub_job;
	void *vaddr;

	ASSERT(emb_cb_section && IS_EMBEDDED_CB_FW(emb_cb_section->fw_type));

	j = GET_CB_INDEX(emb_cb_section->fw_type);
	sub_job = &subjobs_embedded_cbs[j];

	/* for command buffer we only allow one section */
	if (emb_cb_section->sections_nr != 1) {
		retval = -ICEDRV_KERROR_FW_INVAL_ECB;
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"Embedded CB should have only 1 section\n");
		goto out;
	}

	section = &emb_cb_section->sections[0];

	commands_nr = section->size_bytes >> TLC_COMMAND_SIZE_SHIFT;

	vaddr = cve_os_vmap_dma_handle(&emb_cb_section->dma_handles[0]);

	if (!vaddr) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"failed to vmap\n");
		retval = -ICEDRV_KERROR_FW_ECB_MAPPING;
		goto out;
	}
	retval = cve_di_create_subjob(
			section->cve_addr,
			(uintptr_t)vaddr,
			commands_nr,
			1,
			sub_job);
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"Could not create subjob %d\n",
				retval);
		goto failed_to_create_subjob;
	}

	cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Embedded SubJob Created. CVE addrs: 0x%x\n",
			section->cve_addr);

	/* success */
	return 0;

failed_to_create_subjob:
	cve_os_vunmap_dma_handle(vaddr);
out:
	return retval;
}

/*
 * cleans up a firmware mapped sections data structures allocations
 * inputs : cve_fw_loaded_sections *mapped_fw_sec - the firmware binary sections
 * outputs:
 * returns:
 */
void cve_mapped_fw_sections_cleanup(
		struct cve_fw_mapped_sections *mapped_fw_sec)
{
	u32 i;
	struct cve_fw_loaded_sections *fw_sec = mapped_fw_sec->cve_fw_loaded;
	struct cve_fw_section_descriptor *s = NULL;
	struct cve_device *dev = get_first_device();

	for (i = 0; i < fw_sec->sections_nr; i++) {
		if (!fw_sec->sections)
			continue;

		s = &fw_sec->sections[i];

		if (mapped_fw_sec->alloc_handles) {
			/*remove allocations of the FW */
			cve_os_log(CVE_LOGLEVEL_DEBUG,
					"Reclaiming allocation of Section=%d\n",
					i);
			cve_mm_reclaim_allocation(
				mapped_fw_sec->alloc_handles[i]);
		}

		if ((s->permissions & CVE_MM_PROT_WRITE) == CVE_MM_PROT_WRITE) {
			struct cve_dma_handle *dma_handle_list =
				mapped_fw_sec->dma_handles;
			cve_os_log(CVE_LOGLEVEL_DEBUG,
					"This is WRITE section. Releasing DMA memory.\n");
			if (dma_handle_list &&
				dma_handle_list[i].mem_handle.sgt) {
				OS_FREE_DMA_SG(dev,
					s->size_bytes,
					&dma_handle_list[i]);
			}
		}
	}

	cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Removing DMA handle of this firmware\n");
	if (mapped_fw_sec->dma_handles)
		OS_FREE(mapped_fw_sec->dma_handles,
				sizeof(*mapped_fw_sec->dma_handles) *
					fw_sec->sections_nr);
	if (mapped_fw_sec->alloc_handles)
		OS_FREE(mapped_fw_sec->alloc_handles,
			sizeof(cve_mm_allocation_t) * fw_sec->sections_nr);
}

/* API FUNCTIONS */
#ifndef RING3_VALIDATION
void ice_fw_update_path(const char *path)
{
	u32 i;
	char fw_dir[MAX_NAME_LEN];

	strncpy(fw_dir, path, MAX_NAME_LEN-1);

	for (i = 0; i < ARRAY_SIZE(fw_binaries_files); i++) {
		strncpy(fw_binaries_files[i].binary_file_name,
				fw_dir, MAX_NAME_LEN-1);
		strncpy(fw_binaries_files[i].map_file_name,
				fw_dir, MAX_NAME_LEN-1);
		fw_binaries_files[i].binary_file_name[MAX_NAME_LEN-1] = 0;
		fw_binaries_files[i].map_file_name[MAX_NAME_LEN-1] = 0;
	}

	strcat(fw_binaries_files[0].binary_file_name, TLC_FW_BIN_NAME);
	strcat(fw_binaries_files[0].map_file_name, TLC_FW_MAP_NAME);
	strcat(fw_binaries_files[1].binary_file_name, IVP_FW_BIN_NAME);
	strcat(fw_binaries_files[1].map_file_name, IVP_FW_MAP_NAME);
	strcat(fw_binaries_files[2].binary_file_name, ASIP_FW_BIN_NAME);
	strcat(fw_binaries_files[2].map_file_name, ASIP_FW_MAP_NAME);
	strcat(fw_binaries_files[3].binary_file_name, IVP_BANK0_FW_BIN_NAME);
	strcat(fw_binaries_files[3].map_file_name, IVP_BANK0_FW_MAP_NAME);
	strcat(fw_binaries_files[4].binary_file_name, IVP_BANK1_FW_BIN_NAME);
	strcat(fw_binaries_files[4].map_file_name, IVP_BANK1_FW_MAP_NAME);
	strcat(fw_binaries_files[5].binary_file_name, ASIP_BANK0_FW_BIN_NAME);
	strcat(fw_binaries_files[5].map_file_name, ASIP_BANK0_FW_MAP_NAME);
	strcat(fw_binaries_files[6].binary_file_name, ASIP_BANK1_FW_BIN_NAME);
	strcat(fw_binaries_files[6].map_file_name, ASIP_BANK1_FW_MAP_NAME);
	strcat(fw_binaries_files[7].binary_file_name,
				LOAD_AND_CLEAR_CACHE_BIN_NAME);
	strcat(fw_binaries_files[7].map_file_name,
				LOAD_AND_CLEAR_CACHE_MAP_NAME);

}
#endif

int cve_fw_load(struct cve_device *cve_dev)
{
	int retval = CVE_DEFAULT_ERROR_CODE;
#ifndef NULL_DEVICE_RING0
	u32 i;
	struct cve_fw_loaded_sections *loaded_fw_list = NULL;

	cve_os_dev_log(CVE_LOGLEVEL_DEBUG,
			cve_dev->dev_index,
			"Load Firmwares on device\n");

	for (i = 0; i < ARRAY_SIZE(fw_binaries_files); i++) {
		struct cve_fw_loaded_sections *loaded_fw = NULL;

		cve_os_dev_log(CVE_LOGLEVEL_DEBUG,
			cve_dev->dev_index,
			COLOR_GREEN(
				"Loading Firmware. ID=%i, Type=%s, BinaryFile=%s, MapFile=%s\n"
				),
			i,
			get_fw_binary_type_str(fw_binaries_files[i].fw_type),
			fw_binaries_files[i].binary_file_name,
			fw_binaries_files[i].map_file_name);

		/* create a new context entry */
		retval = OS_ALLOC_ZERO(
				sizeof(*loaded_fw),
				(void **)&loaded_fw);
		if (retval != 0)
			goto out;

		/* detect fw type */
		loaded_fw->fw_type = fw_binaries_files[i].fw_type;

		retval = cve_fw_load_binary_files(cve_dev,
				&fw_binaries_files[i],
				loaded_fw);
		if (retval < 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
					"load_fw_binary failed %d\n", retval);
			OS_FREE(loaded_fw, sizeof(*loaded_fw));
			goto out;
		}

		/* check the FW type and fill the proper global FW version */
		if (loaded_fw->fw_type == CVE_FW_TLC_TYPE)
			tlc_version = *loaded_fw->fw_version;

		else if (loaded_fw->fw_type == CVE_FW_IVP_MFW_TYPE)
			ivp_version = *loaded_fw->fw_version;

		else if (loaded_fw->fw_type == CVE_FW_ASIP_MFW_TYPE)
			asip_version = *loaded_fw->fw_version;

		/* add the new context to the list */
		cve_dle_add_to_list_after(loaded_fw_list, list, loaded_fw);
	}

	cve_dev->fw_loaded_list = loaded_fw_list;
	/* success */
	retval = 0;
out:
	/* cleanup on error */
	if (retval != 0) {
		/* cleanup fw binaries */
		cve_fw_unload(cve_dev, loaded_fw_list);
	}
#else
	retval = 0;
#endif
	return retval;
}

int cve_fw_map(os_domain_handle hdom,
		struct cve_fw_mapped_sections **out_head,
		cve_di_subjob_handle_t **out_embedded_cbs_subjobs)
{
	int retval = CVE_DEFAULT_ERROR_CODE;
	struct cve_device *dev = get_first_device();
	struct cve_fw_loaded_sections *fw_loaded_head = NULL;
	struct cve_fw_loaded_sections *fw_loaded_curr = NULL;
	struct cve_fw_mapped_sections *fw_mapped_head = NULL;
	cve_di_subjob_handle_t *subjobs_embedded_cbs = NULL;

	fw_loaded_head = dev->fw_loaded_list;
	fw_loaded_curr = fw_loaded_head;

	if (!fw_loaded_head) {
		retval = -ICEDRV_KERROR_FW_NOENT;
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"ERROR:%d Base Loaded FW list not found in CVE device!\n",
				retval);
		goto out;
	}

	cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Start Firmwares Mapping on device\n");

	/* go over all base firmwares and map them to device memory */
	do {
		struct cve_fw_mapped_sections *fw_mapped = NULL;

		/* create a new fw mapped entry */
		retval = OS_ALLOC_ZERO(
				sizeof(*fw_mapped),
				(void **)&fw_mapped);
		if (retval != 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
				   "Failed to allocate memory for fw mapped section!\n");
			goto out;
		}

		/* map current firmware binary to device memory */
		retval = cve_fw_map_sections(hdom,
				fw_loaded_curr,
				fw_mapped);
		if (retval < 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
					"cve_fw_map_sections failed %d\n",
					retval);
			OS_FREE(fw_mapped, sizeof(*fw_mapped));
			goto out;
		}

		/* add fw mapped section to the list */
		cve_dle_add_to_list_after(fw_mapped_head, list, fw_mapped);

		/* create a subjob for the embedded cb */
		if (IS_EMBEDDED_CB_FW(fw_loaded_curr->fw_type)) {
			/* allocate memory for embedded cbs */
			retval = OS_ALLOC_ZERO(
				sizeof(*subjobs_embedded_cbs)*
					CVE_FW_CB_TYPE_MAX,
				(void **)&subjobs_embedded_cbs);
			if (retval != 0) {
				cve_os_log(CVE_LOGLEVEL_ERROR,
						"Failed to allocate memory for embedded cbs!\n");
				goto out;
			}
			retval = cve_fw_create_emb_cb(fw_loaded_curr,
				subjobs_embedded_cbs);
			if (retval != 0) {
				cve_os_log(CVE_LOGLEVEL_ERROR,
						"cve_fw_create_emb_cb failed %d\n",
						retval);
				goto out;
			}
		}
		fw_loaded_curr = cve_dle_next(fw_loaded_curr, list);
	} while (fw_loaded_curr != fw_loaded_head);

	cve_os_log(CVE_LOGLEVEL_DEBUG,
			"End Firmwares Mapping on device\n");

	*out_head = fw_mapped_head;
	*out_embedded_cbs_subjobs = subjobs_embedded_cbs;

	/* success */
	retval = 0;
out:
	/* cleanup on error */
	if (retval != 0) {
		/* cleanup fw binaries */
		cve_fw_unmap(fw_mapped_head, subjobs_embedded_cbs);
	}

	return retval;
}

void cve_fw_unload(struct cve_device *ice,
		struct cve_fw_loaded_sections *loaded_fw_sections_list)
{
#ifndef NULL_DEVICE_RING0
	/* unload context fws */
	while (loaded_fw_sections_list) {
		struct cve_fw_loaded_sections *loaded_fw_section =
			loaded_fw_sections_list;

		cve_dle_remove_from_list(loaded_fw_sections_list,
				list, loaded_fw_section);
		cve_fw_sections_cleanup(ice, loaded_fw_section->sections,
			loaded_fw_section->dma_handles,
			loaded_fw_section->sections_nr);
		OS_FREE(loaded_fw_section->fw_version,
			sizeof(*loaded_fw_section->fw_version));
		OS_FREE(loaded_fw_section, sizeof(*loaded_fw_section));
	}
#endif
}

void cve_fw_unmap(struct cve_fw_mapped_sections *fw_mapped_list,
		cve_di_subjob_handle_t *embedded_cbs_subjobs)
{
	while (fw_mapped_list) {
		struct cve_fw_mapped_sections *fw_mapped = fw_mapped_list;

		cve_dle_remove_from_list(fw_mapped_list,
				list,
				fw_mapped);
		cve_os_log(CVE_LOGLEVEL_DEBUG,
				"Mapped FW section cleanup\n");
		cve_mapped_fw_sections_cleanup(fw_mapped);
		OS_FREE(fw_mapped, sizeof(*fw_mapped));
	}

	/* cleanup embedded cbs subjobs */
	if (embedded_cbs_subjobs) {
		u32 i;
		void *vaddr;

		for (i = 0; i < CVE_FW_CB_TYPE_MAX; i++) {
			vaddr = cve_di_get_sub_job_kaddr
					(&embedded_cbs_subjobs[i]);
			cve_os_vunmap_dma_handle(vaddr);
			cve_di_sub_job_handle_destroy(&embedded_cbs_subjobs[i]);
		}

		OS_FREE(embedded_cbs_subjobs,
				sizeof(*embedded_cbs_subjobs)*
				CVE_FW_CB_TYPE_MAX);
	}
}

#define HW_STEP_A 0/* A step */
#define HW_STEP_B 1/* B step */
#define HW_STEP_C 2/* C step */

int cve_fw_init(void)
{
#ifdef RING3_VALIDATION
	u32 i;
	int retval = CVE_DEFAULT_ERROR_CODE;

	/* WORKAROUND for WW27 release...
	 * check if there's environment variable
	 * CVE_FW_DIR_PATH defined and get FW binary from there
	 * SHOULD BE DELETED when there's a permanent solution
	 */
#include <stdlib.h>
	char *fw_dir_path = getenv("CVE_FW_DIR_PATH");
	char *fw_selection = getenv("ICE_FW_SELECT");
	char *coral_mode = getenv("CORAL_PERF_MODE");
	char *workspace = getenv("WORKSPACE");
	char fw_dir[MAX_NAME_LEN];
	unsigned char stepping = 0;

	if (getenv("ENABLE_C_STEP") != NULL) {
		stepping = HW_STEP_C;
		cve_os_log(CVE_LOGLEVEL_INFO, "C STEP ENABLED\n");
	} else if (getenv("ENABLE_B_STEP") != NULL) {
		stepping = HW_STEP_B;
		cve_os_log(CVE_LOGLEVEL_INFO, "B STEP ENABLED\n");
	} else {
		stepping = HW_STEP_A;
		cve_os_log(CVE_LOGLEVEL_INFO, "A STEP ENABLED\n");
	}

	/* Check if the worst case scenario length is not exceeding
	 * MAX_NAME_LEN
	 */
	if (strnlen(workspace, MAX_NAME_LEN) + strlen(FW_PACK_DIR_BASE)
		+ strlen(RTL_A_STEP_FW_BASE_PACKAGE_DIR)
		+ strlen("/rtl/release") > MAX_NAME_LEN - 1) {

		cve_os_log(CVE_LOGLEVEL_ERROR,
			"workspace is too long(%d), should be under %d\n",
			strnlen(workspace, MAX_NAME_LEN),
			MAX_NAME_LEN - 1 - strlen(FW_PACK_DIR_BASE)
			- strlen(RTL_A_STEP_FW_BASE_PACKAGE_DIR)
			- strlen("/rtl/release"));
		goto out;
	}

	if (fw_dir_path || fw_selection || stepping) {
		if (fw_selection) {

			if (workspace == NULL) {
				cve_os_log(CVE_LOGLEVEL_ERROR,
					"WORKSPACE env variable is not set");
				ASSERT(workspace == NULL);
			}
			strcpy(fw_dir, workspace);
			strcat(fw_dir, FW_PACK_DIR_BASE);

			if (stepping == HW_STEP_C)
				strcat(fw_dir, RTL_C_STEP_FW_BASE_PACKAGE_DIR);
			else if (stepping == HW_STEP_B)
				strcat(fw_dir, RTL_B_STEP_FW_BASE_PACKAGE_DIR);
			else
				strcat(fw_dir, RTL_A_STEP_FW_BASE_PACKAGE_DIR);

			if (strcmp(fw_selection, xstr(RTL_DEBUG_FW)) == 0) {
				strcat(fw_dir, "/rtl/debug");
			} else if (strcmp(fw_selection,
						xstr(RTL_RELEASE_FW)) == 0) {
				strcat(fw_dir, "/rtl/release");
			} else if (strcmp(fw_selection, xstr(CORAL_FW)) == 0) {
				strcat(fw_dir, "/coral");
			} else {
				strcat(fw_dir, "/rtl/release");
			}
			fw_dir_path = fw_dir;
		} else if (stepping) {
			strcpy(fw_dir, workspace);
			strcat(fw_dir, FW_PACK_DIR_BASE);
			if (stepping == HW_STEP_C)
				strcat(fw_dir, RTL_C_STEP_FW_BASE_PACKAGE_DIR);
			else
				strcat(fw_dir, RTL_B_STEP_FW_BASE_PACKAGE_DIR);

			strcat(fw_dir, "/rtl/release");
			fw_dir_path = fw_dir;
		}
		if (coral_mode && (strcmp(coral_mode, xstr(PERF_MODE)) == 0)) {
			strcpy(fw_dir, workspace);
			strcat(fw_dir, FW_PACK_DIR_BASE);
			if (stepping == HW_STEP_C)
				strcat(fw_dir, RTL_C_STEP_FW_BASE_PACKAGE_DIR);
			else if (stepping == HW_STEP_B)
				strcat(fw_dir, RTL_B_STEP_FW_BASE_PACKAGE_DIR);
			else
				strcat(fw_dir, RTL_A_STEP_FW_BASE_PACKAGE_DIR);
			strcat(fw_dir, "/rtl/release");

			fw_dir_path = fw_dir;

			if (fw_selection &&
			(strcmp(fw_selection, xstr(RTL_RELEASE_FW)) != 0)) {
				cve_os_log(CVE_LOGLEVEL_WARNING,
		"Default FW is selected because of perf mode selection\n");
			}
		}
		/* Override current firmware values */
		if (strlen(fw_dir_path) > MAX_NAME_LEN) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
				"CVE_FW_DIR_PATH is too long (%s), should be under 1024\n",
				strlen(fw_dir_path));
			goto out;
		}

		if (ARRAY_SIZE(fw_binaries_files) != 8) {
			retval = CVE_DEFAULT_ERROR_CODE;
			cve_os_log(CVE_LOGLEVEL_ERROR,
					"mismatch number of fw files (%d != 8)\n",
					ARRAY_SIZE(fw_binaries_files));
			goto out;
		}

		for (i = 0; i < ARRAY_SIZE(fw_binaries_files); i++) {
			strncpy(fw_binaries_files[i].binary_file_name,
				fw_dir_path, MAX_NAME_LEN-1);
			strncpy(fw_binaries_files[i].map_file_name,
				fw_dir_path, MAX_NAME_LEN-1);
fw_binaries_files[i].binary_file_name[MAX_NAME_LEN-1] = 0;
			fw_binaries_files[i].map_file_name[MAX_NAME_LEN-1] = 0;

		}
		cve_os_log(CVE_LOGLEVEL_DEBUG,
				"fw_dir_path %s\n", fw_dir_path);

		strcat(fw_binaries_files[0].binary_file_name,
				TLC_FW_BIN_NAME);
		strcat(fw_binaries_files[0].map_file_name,
				TLC_FW_MAP_NAME);
		strcat(fw_binaries_files[1].binary_file_name,
				IVP_FW_BIN_NAME);
		strcat(fw_binaries_files[1].map_file_name,
				IVP_FW_MAP_NAME);
		strcat(fw_binaries_files[2].binary_file_name,
				ASIP_FW_BIN_NAME);
		strcat(fw_binaries_files[2].map_file_name,
				ASIP_FW_MAP_NAME);
		strcat(fw_binaries_files[3].binary_file_name,
				IVP_BANK0_FW_BIN_NAME);
		strcat(fw_binaries_files[3].map_file_name,
				IVP_BANK0_FW_MAP_NAME);
		strcat(fw_binaries_files[4].binary_file_name,
				IVP_BANK1_FW_BIN_NAME);
		strcat(fw_binaries_files[4].map_file_name,
				IVP_BANK1_FW_MAP_NAME);
		strcat(fw_binaries_files[5].binary_file_name,
				ASIP_BANK0_FW_BIN_NAME);
		strcat(fw_binaries_files[5].map_file_name,
				ASIP_BANK0_FW_MAP_NAME);
		strcat(fw_binaries_files[6].binary_file_name,
				ASIP_BANK1_FW_BIN_NAME);
		strcat(fw_binaries_files[6].map_file_name,
				ASIP_BANK1_FW_MAP_NAME);
		strcat(fw_binaries_files[7].binary_file_name,
				LOAD_AND_CLEAR_CACHE_BIN_NAME);
		strcat(fw_binaries_files[7].map_file_name,
				LOAD_AND_CLEAR_CACHE_MAP_NAME);

	}

	/* success */
	retval = 0;
out:
	return retval;
#else
	return 0;
#endif
}

void cve_fw_restore(struct cve_device *cve_dev,
		struct cve_fw_mapped_sections *head)
{
	struct cve_fw_mapped_sections *mapped_fw = NULL;

	/* restoring dynamic FW bin */
	if (head) {
		mapped_fw = head;
		do {
			restore_fw_sections(cve_dev, mapped_fw);
			mapped_fw = cve_dle_next(mapped_fw, list);
		} while (head != mapped_fw);
	}
}

/*
 * reclaim firmware loading sections & dma handles
 * inputs : cve_section_descriptor *sections_lst - list of fw sections
 *          struct cve_dma_handle *dma_handles_lst - list of dma handles
 *          u32 list_items_nr - number of items in the list
 * outputs:
 * returns:
 */
void cve_fw_sections_cleanup(struct cve_device *ice,
		struct cve_fw_section_descriptor *sections_lst,
		struct cve_dma_handle *dma_handles_lst,
		u32 list_items_nr)
{
	u32 i;
	struct cve_device *dev = get_first_device();

	if (ice)
		dev = ice;

	if (sections_lst) {
		struct cve_fw_section_descriptor *s = NULL;
		struct cve_dma_handle *fw_dma_handle = NULL;

		if (dma_handles_lst) {
			for (i = 0; i < list_items_nr; i++) {
				s = &sections_lst[i];

				fw_dma_handle = &dma_handles_lst[i];

				cve_os_log(CVE_LOGLEVEL_DEBUG,
					"FW_LOADING: Unload SectionID: %i. DMA sgt: %p, CVE addr: 0x%x, perm: %d, size bytes: 0x%x\n",
					i,
					fw_dma_handle->mem_handle.sgt,
					s->cve_addr,
					s->permissions,
					s->size_bytes);

				if (fw_dma_handle->mem_handle.sgt) {
					cve_sync_sgt_to_llc(
						fw_dma_handle->mem_handle.sgt);

					OS_FREE_DMA_SG(dev,
						s->size_bytes,
						fw_dma_handle);
				}

			}
			OS_FREE(dma_handles_lst,
					sizeof(*dma_handles_lst) *
					list_items_nr);
		}
		OS_FREE(sections_lst,
				sizeof(*sections_lst) * list_items_nr);
	}
}

int cve_fw_load_firmware_via_files(struct cve_device *cve_dev,
		const char *fw_file_name,
		const char *map_file_name,
		u32 *out_sections_nr,
		struct cve_fw_section_descriptor **out_sections,
		struct cve_dma_handle **out_dma_handles,
		Version **out_fw_version)
{
	int retval = CVE_DEFAULT_ERROR_CODE;
	u32 sections_nr = 0;
	struct cve_fw_section_descriptor *sections = NULL;
	struct cve_dma_handle *dma_handles = NULL;
	Version *fw_version = NULL;
	const struct firmware *map = NULL;
	const struct firmware *fw = NULL;
	struct device *dev = to_cve_os_device(cve_dev)->dev;

	/* load the map file */
	retval = request_firmware(&map,
			map_file_name,
			dev);
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"request_firmware failed for map %d\n", retval);
		goto out;
	}

	/* load the firmware binary */
	retval = request_firmware(&fw,
			fw_file_name,
			dev);

	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"request_firmware failed for fw %d\n", retval);
		goto out;
	}

	retval = cve_fw_load_firmware_from_kernel_mem(cve_dev,
			(uintptr_t)fw->data,
			(uintptr_t)map->data,
			(uintptr_t)map->size,
			&sections_nr,
			&sections,
			&dma_handles,
			&fw_version);
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"cve_os_load_firmware_via_mem failed for fw %d\n",
				retval);
		goto out;
	}

	/* success */
	*out_sections_nr = sections_nr;
	*out_sections = sections;
	*out_dma_handles = dma_handles;
	*out_fw_version = fw_version;
	retval = 0;

out:
	if (map)
		release_firmware(map);
	if (fw)
		release_firmware(fw);

	return retval;
}

