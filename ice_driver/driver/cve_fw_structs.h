/********************************************
 * Copyright (C) 2019-2021 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/



#ifndef _CVE_FW_STRUCTS_H_
#define _CVE_FW_STRUCTS_H_

#ifndef RING3_VALIDATION
#include <linux/types.h>
#include "os_interface_impl.h"
#else
#include <stdint.h>
#include <stdint_ext.h>
#include "os_interface_stub.h"
#endif
#include "cve_fw_map_interface.h"
#include "doubly_linked_list.h"
#include "version.h"
#include "cve_driver_internal_types.h"

enum fw_binary_type {
	/* TLC, IVP & ASIP FWs */
	CVE_FW_TYPE_INVALID = 0,
	CVE_FW_TYPE_START,
	CVE_FW_TLC_TYPE = CVE_FW_TYPE_START,
	CVE_FW_IVP_MFW_TYPE,
	CVE_FW_ASIP_MFW_TYPE,
	CVE_FW_IVP_BANK0_TYPE,
	CVE_FW_IVP_BANK1_TYPE,
	CVE_FW_ASIP_BANK0_TYPE,
	CVE_FW_ASIP_BANK1_TYPE,
	CVE_FW_END_TYPES,
	/* Embedded CBs */
	CVE_FW_CB_TYPE_START = CVE_FW_END_TYPES,
	CVE_FW_CB1_TYPE = CVE_FW_CB_TYPE_START,
	/* comment out the below line
	 * to add additional embedded CB.
	 * CVE_FW_CB2_TYPE,
	 */
	CVE_FW_CB_TYPE_END
};

struct cve_fw_section_descriptor {
	/* the address where the working copy starts
	 * in device virtual address space
	 */
	u32 cve_addr;
	/* size of section in bytes*/
	u32 size_bytes;
	/* permission attributes */
	u32 permissions;
};

/*
 * Describes firmware sections that were loaded to memory
 * Each "cve_fw_loaded_sections" describes one fw type
 * (according to fw_binary_type enumerator)
 */
struct ice_fw_owner_info {
	/* pointer to the network using this f/w copy */
	void *user;
	/* pointer to the f/w structure managing this f/w copy */
	void *owner_fw;
	/* linked list of all networks using this f/w */
	struct cve_dle_t owner_list;
};

#define __MD5_MAX_SZ 16
struct cve_fw_loaded_sections {
	struct cve_dle_t list;
	/* firmware sections */
	u32 sections_nr;
	struct cve_fw_section_descriptor *sections;
	/* DMA data of the sections */
	struct cve_dma_handle *dma_handles;
	/* firmware type*/
	enum fw_binary_type fw_type;
	Version *fw_version;
	/* md5 sum of the image	 */
	u8 md5[__MD5_MAX_SZ];
	char md5_str[(__MD5_MAX_SZ * 2) + 1];
	u32 user_count;
	/* latest time stamp when this node was used by a network */
	u64 last_used;
	u8 cached_mem_used;
	struct ice_fw_owner_info *owners;
};

/*
 * Describes firmware sections that were mapped to device.
 * Each "cve_fw_mapped_sections" describes one fw type
 * (according to fw_binary_type enumerator)
 */
struct cve_fw_mapped_sections {
	struct cve_dle_t list;
	/* structure that describes corresponding fw loaded in memory */
	struct cve_fw_loaded_sections *cve_fw_loaded;
	/* structure that describes base fw loaded in memory */
	struct cve_fw_loaded_sections *base_fw_loaded;
	/* array of DMA handles
	 * The DMA handle can be either the same as the one inside the
	 * cve_fw_loaded_sections->dma_handles if the section is marked
	 * as "READ ONLY", or point to a new DMA handle if the
	 * section is marked with "WRITE" attribute.
	 */
	struct cve_dma_handle *dma_handles;
	/* array of allocation handles (corresponding to dma handles) */
	cve_mm_allocation_t *alloc_handles;
};

/* macros for fw structions */
#define IS_EMBEDDED_CB_FW(fw_type) \
	(fw_type >= CVE_FW_CB_TYPE_START && \
				fw_type < CVE_FW_CB_TYPE_END)
/* index to a context switch command buffer */
#define GET_CB_INDEX(fw_type) (fw_type - CVE_FW_CB_TYPE_START)
/* number of supported embedded CBs */
#define CVE_FW_CB_TYPE_MAX (CVE_FW_CB_TYPE_END - CVE_FW_CB_TYPE_START)

#endif /* _CVE_FW_STRUCTS_H_ */
