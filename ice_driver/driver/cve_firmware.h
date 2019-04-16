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

#ifndef _CVE_FIRMWARE_H_
#define _CVE_FIRMWARE_H_

#ifndef RING3_VALIDATION
#include <linux/types.h>
#else
#include <stdint.h>
#include <stdint_ext.h>
#endif

#include "cve_fw_map_interface.h"
#include "cve_fw_structs.h"
#include "cve_driver_internal_types.h"
#include "doubly_linked_list.h"
#include "memory_manager.h"

#define MAX_NAME_LEN 1024

/* describes a firmware loading binary file path */
struct cve_fw_file {
	/* binary file name */
	char binary_file_name[MAX_NAME_LEN];
	/* map file name */
	char map_file_name[MAX_NAME_LEN];
	/* Specify the binary type */
	enum fw_binary_type fw_type;
};

/*
 * map firmware binary to device memory.
 * inputs : cve_device *cve_dev - pointer for device
 *          hdom - handle to os domain structure
 *          cve_fw_loaded_sections *fw_loaded_sec - fw loaded sections
 * outputs: cve_fw_mapped_sections *out_fw_mapped_sec - fw mapped sections
 * returns: 0 on success, a negative error code on failure
 */
int cve_fw_map_sections(
		struct cve_device *cve_dev,
		const os_domain_handle hdom,
		struct cve_fw_loaded_sections *fw_loaded_sec,
		struct cve_fw_mapped_sections *out_fw_mapped_sec);

/*
 * load dynamic firmware binary to context memory
 * inputs : u64 fw_image - fw image address
 * u64 fw_binmap - fw map file addr
 * u32 fw_binmap_size_bytes - map size
 * outputs: cve_fw_loaded_sections *fw_sec - the firmware binary sections
 * returns: 0 on success, a negative error code on failure
 */
int cve_fw_load_binary(struct cve_device *cve_dev,
		const u64 fw_image,
		const u64 fw_binmap,
		const u32 fw_binmap_size_bytes,
		struct cve_fw_loaded_sections *out_fw_sec);

/*
 * cleans up a firmware mapped sections data structures allocations
 * inputs : cve_fw_loaded_sections *mapped_fw_sec - the firmware binary sections
 * outputs:
 * returns:
 */
void cve_mapped_fw_sections_cleanup(struct cve_device *cve_dev,
		struct cve_fw_mapped_sections *mapped_fw_sec);

/*
 * Initialize the FW module, no cleanup is required.
 * This function should be called once.
 * inputs :
 * outputs:
 * returns: 0 on success, a negative error code on failure
 */
int cve_fw_init(void);

/*
 * load the firmware binaries of the base package to
 * a given memory for specific cve device.
 * inputs :cve_dev - cve device
 * returns: 0 on success, a negative error code on failure
 */
int cve_fw_load(struct cve_device *cve_dev);

/*
 * map the loaded firmware sections of the base package to
 * specific cve device.
 * inputs :
 *	os_domain_handle hdom - pointer to cve's os domain struct
 * outputs: out_head - list of the firmwares that were loaded
 *	out_embedded_cbs_subjobs - array of subjobs that were
 *	initialized. The array size will be CVE_FW_CB_TYPE_MAX.
 * returns: 0 on success, a negative error code on failure
 */
int cve_fw_map(struct cve_device *cve_dev,
		os_domain_handle hdom,
		struct cve_fw_mapped_sections **out_head,
		cve_di_subjob_handle_t **out_embedded_cbs_subjobs);
/*
 * restore all the firmwares that were loaded at initialization time
 * inputs :
 *	cve_dev - the cve device
 *	head - a list of dynamic FW per context
 * outputs:
 * returns:
 */
void cve_fw_restore(struct cve_device *cve_dev,
		struct cve_fw_mapped_sections *head);

/*
 * unload all the firmware binaries that were loaded to specific
 * cve device
 * inputs :cve_dev - CVE device handle
 *         cve_fw_loaded_sections *fw_loaded_list - fw loaded list handle
 * outputs:
 * returns:
 */
void cve_fw_unload(struct cve_device *cve_dev,
		struct cve_fw_loaded_sections *fw_loaded_list);

/*
 * unmap all the firmware sections that were mapped to this context
 * inputs :cve_device *cve_dev - cve device handle
 *         cve_fw_mapped_sections *fw_mapped_sec - fw mapped list to
 *           specific context for specific device
 *         cve_di_subjob_handle_t *embedded_cbs_subjobs - array of embedded
 *           subjobs of the specific context for specific device
 * outputs:
 * returns:
 */
void cve_fw_unmap(struct cve_device *cve_dev,
		struct cve_fw_mapped_sections *fw_mapped_sec,
		cve_di_subjob_handle_t *embedded_cbs_subjobs);
/*
 * reclaim firmware loading sections & dma handles
 * inputs : cve_section_descriptor *sections_lst - list of fw sections
 *          struct cve_dma_handle *dma_handles_lst - list of dma handles
 *          u32 list_items_nr - number of items in the list
 * outputs:
 * returns:
 */
void cve_fw_sections_cleanup(struct cve_device *cve_dev,
	struct cve_fw_section_descriptor *sections_lst,
	struct cve_dma_handle *dma_handles_lst,
	u32 list_items_nr);


int cve_fw_load_firmware_via_files(struct cve_device *cve_dev,
		const char *fw_file_name,
		const char *map_file_name,
		u32 *out_sections_nr,
		struct cve_fw_section_descriptor **out_sections,
		struct cve_dma_handle **out_dma_handles,
		Version **out_fw_version);
#endif /* _CVE_FIRMWARE_H_ */
