/********************************************
 * Copyright (C) 2019-2021 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/



#ifndef _DEVICE_CONTEXT_H_
#define _DEVICE_CONTEXT_H_

#ifdef RING3_VALIDATION
#include <stdint.h>
#include <stdint_ext.h>
#else
#include <linux/types.h>
#endif
#include "osmm_interface.h"
#include "cve_linux_internal.h"

/*
 * allocate a list of dev contexts according to num of ICE requested by the
 * network
 * inputs :
 * outputs:
 *	out_hctx_list -  will hold a handle to the list of dev contexts per
 *                   cve device
 * returns: 0 on success, a negative error code on failure
 */
int ice_init_sw_dev_contexts(u8 num_ice,
		u64 *va_partition_config,
		u64 *infer_buf_page_config,
		struct ice_pnetwork *pntw);
/*
 * free all the resources that were taken by the dev contexts (per cve
 * context)
 * inputs : hcontext_list - pointer to the list of dev contexts
 * loaded_cust_fw_sections - list of custome fws
 * outputs:
 * returns:
 */
void ice_fini_sw_dev_contexts(cve_dev_context_handle_t hcontext_list,
		struct cve_fw_loaded_sections *loaded_fw_sections_list);

/*
 * get array of CVE domains in current context
 * inputs : hcontext_list - device context list
 *          domain_array_size - size of domain array
 *          (should be equal to number of CVEs in the system)
 * outputs: out_hdom - array of CVE domains
 * returns:
 */
void cve_dev_get_os_domain_arr(cve_dev_context_handle_t hcontext_list,
	u32 domain_array_size,
	os_domain_handle *out_hdom);

/*
 * restore fws sections
 * inputs :
 *	cve_dev - cve device
 *	hcontext - device context
 * outputs:
 * returns: None
 */
void cve_dev_restore_fws(struct cve_device *cve_dev,
		cve_dev_context_handle_t hcontext);

void cve_dev_restore_tlc_fw(struct cve_device *cve_dev,
		cve_dev_context_handle_t hcontext);

void cve_dev_restore_ivp_fw(struct cve_device *cve_dev,
		cve_dev_context_handle_t hcontext);

/*
 * loads & map dynamic fw
 * inputs : hcontext - memory context
 *	fw_image - FW addr
 *	fw_binmap - FW map file for FW sections
 *	fw_binmap_size_bytes FW size
 * outputs:
 * returns: the address of the table
 */
int cve_dev_fw_load_and_map(cve_dev_context_handle_t hcontext,
		const u64 fw_image,
		const u64 fw_binmap,
		const u32 fw_binmap_size_bytes,
		enum fw_binary_type fw_type,
		struct cve_fw_loaded_sections **out_fw_sec);

int ice_dev_fw_load(const u64 fw_image,
		const u64 fw_binmap,
		const u32 fw_binmap_size_bytes,
		struct cve_fw_loaded_sections **out_fw_sec);

int ice_dev_fw_map(cve_dev_context_handle_t hcontext,
		struct cve_fw_loaded_sections *out_fw_sec,
		enum fw_binary_type fw_type);

void cve_dev_get_emb_cb_list(cve_dev_context_handle_t hcontext,
		cve_di_subjob_handle_t **out_embedded_cbs_subjobs);

void cve_dev_get_custom_fw_version_per_context(
	struct cve_fw_loaded_sections *loaded_fw_sections_list,
	enum fw_binary_type fw_type,
	Version *out_fw_version);

void cve_di_reset_cve_dump(struct cve_device *dev,  uint8_t dumpTrigger,
		struct di_cve_dump_buffer *ice_dump_buf);

void ice_map_dev_and_context(cve_dev_context_handle_t dev_ctx,
	struct cve_device *dev);
void ice_unmap_dev_and_context(cve_dev_context_handle_t dev_ctx);

void ice_unmap_bar1(cve_dev_context_handle_t dev_ctx);

int ice_map_bar1(struct cve_device *ice,
		cve_dev_context_handle_t dev_ctx);

/*
 * Allocate and map CBDT memory for given Device and Context
 *
 * input: dev_ctx - device context
 * input: max_cbdt_entries - Number of CBDT entries to be created
 * output: fifo_desc- fifo details
 */
int cve_dev_alloc_and_map_cbdt(cve_dev_context_handle_t dev_ctx,
			struct fifo_descriptor *fifo_desc,
			u32 max_cbdt_entries);

/*
 * Unmap and deallocate CBDT memory from given Device and Context
 *
 * input: dev_ctx - device context
 * input: fifo_desc- fifo details
 */
int cve_dev_dealloc_and_unmap_cbdt(cve_dev_context_handle_t dev_ctx,
			struct fifo_descriptor *fifo_desc);

int ice_extend_sw_dev_contexts(struct ice_pnetwork *pntw);

#endif /* _DEVICE_CONTEXT_H_ */
