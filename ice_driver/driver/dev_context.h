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

#ifndef _DEVICE_CONTEXT_H_
#define _DEVICE_CONTEXT_H_

#ifdef RING3_VALIDATION
#include <stdint.h>
#include <stdint_ext.h>
#else
#include <linux/types.h>
#endif
#include "osmm_interface.h"
#ifdef NEXT_E2E
#include "cve_linux_internal.h"
#endif

/*
 * allocated a list of dev contexts per cve device according to num
 * of cve devices in the system
 * inputs :
 * outputs:
 *	out_hctx_list -  will hold a handle to the list of dev contexts per
 *                   cve device
 * returns: 0 on success, a negative error code on failure
 */
int cve_dev_open_all_contexts(cve_dev_context_handle_t *out_hctx_list);

/*
 * free all the resources that were taken by the dev contexts (per cve
 * context)
 * inputs : hcontext_list - pointer to the list of dev contexts
 * outputs:
 * returns:
 */
void cve_dev_close_all_contexts(cve_dev_context_handle_t hcontext_list);

/*
 * get device context according to provided CVE device index
 * inputs : hcontext_list - device context list
 *          dev_index - CVE device index
 *          out_hcontext - pointer to device context
 * outputs:
 * returns:
 */
void cve_dev_context_get_by_cve_idx(cve_dev_context_handle_t hcontext_list,
	u32 dev_index, cve_dev_context_handle_t *out_hcontext);

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
		const u32 fw_binmap_size_bytes);

/*
 * Set Device FIFO pointer to the given FIFO.
 * Set FIFO size and address into appropriate registers
 * and marks FIFO as empty.
 *
 * input: dev - CVE device to be set
 * input: fifo_desc - FIFO to be used
 */
void cve_dev_reset_fifo(struct cve_device *dev,
			struct fifo_descriptor *fifo_desc);

void cve_dev_get_emb_cb_list(cve_dev_context_handle_t hcontext,
		cve_di_subjob_handle_t **out_embedded_cbs_subjobs);

void cve_dev_get_os_domain(cve_dev_context_handle_t hcontext,
		os_domain_handle *out_hdom);

void cve_dev_get_custom_fw_version_per_context(
	cve_dev_context_handle_t hcontext,
	enum fw_binary_type fw_type,
	Version *out_fw_version);

void cve_di_reset_cve_dump(struct cve_device *dev,  uint8_t dumpTrigger,
		struct di_cve_dump_buffer ice_dump_buf);

#ifdef NEXT_E2E
int cve_bar1_map(struct cve_device *cve_dev,
		os_domain_handle hdom,
		struct cve_dma_handle *out_dma_handle,
		cve_mm_allocation_t *out_alloc_handle);
#endif

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

#endif /* _DEVICE_CONTEXT_H_ */
