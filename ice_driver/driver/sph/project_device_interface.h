/*
 * NNP-I Linux Driver
 * Copyright (c) 2019, Intel Corporation.
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

#ifndef _DEVICE_INTERFACE_INTERNAL_H_
#define _DEVICE_INTERFACE_INTERNAL_H_

#ifdef RING3_VALIDATION
#include <stdint.h>
#include <stdint_ext.h>
#endif

#include "cve_linux_internal.h"
#include "cve_driver_internal.h"

#define LLC_FREQ_MSR 0x620
#define LLC_MASK 0xFFFF8080
#define max_llc_ratio(a) ((a) & 0x7F)
#define min_llc_ratio(a) (((a) >> 8) & 0x7F)

struct hw_revision_t {
	u16	major_rev;
	u16	minor_rev;
};

extern struct kobject *icedrv_kobj;
int is_wd_error(u32 status);
void get_hw_revision(struct cve_device *cve_dev,
				struct hw_revision_t *hw_rev);
int do_reset_device(struct cve_device *cve_dev, uint8_t idc_reset);
void cve_print_mmio_regs(struct cve_device *cve_dev);
void store_ecc_err_count(struct cve_device *cve_dev);
int init_platform_data(struct cve_device *cve_dev);
void cleanup_platform_data(struct cve_device *cve_dev);
int project_hook_enable_msi_interrupt(struct cve_os_device *os_dev);
int icedrv_sysfs_init(void);
int hw_config_sysfs_init(struct cve_device *ice_dev);
void hw_config_sysfs_term(struct cve_device *ice_dev);
void icedrv_sysfs_term(void);

/* Init cve_dump register in the device
 * inputs: os_dev - os device handle;
 * return: 0 on success, a negative error code on failure
 */
int project_hook_init_cve_dump_buffer(struct cve_device *dev);

/* free cve_dump register in the device
 * inputs: os_dev - os device handle;
 */
void project_hook_free_cve_dump_buffer(struct cve_device *dev);

#ifdef DEBUG_TENSILICA_ENABLE
inline void cve_decouple_debugger_reset(void);
#endif
#define project_hook_device_init(cve_dev)
#define project_hook_device_release(cve_dev)
#define project_hook_read_mmio_register(cve_dev)
#define project_hook_write_mmio_register(cve_dev)
#define project_hook_interrupt_handler_entry(cve_dev)
#define project_hook_interrupt_dpc_handler_entry(cve_dev)
#define project_hook_interrupt_dpc_handler_exit(cve_dev, status)

void project_hook_interrupt_handler_exit(struct cve_device *cve_dev,
		u32 status);
void project_hook_dispatch_new_job(struct cve_device *cve_dev,
					struct ice_network *ntw);
void ice_di_update_page_sz(struct cve_device *cve_dev, u32 *page_sz_array);
int cve_pt_llc_update(pt_entry_t *pt_entry, u32 llc_policy);

void cve_di_set_cve_dump_control_register(struct cve_device *cve_dev,
		uint8_t dumpTrigger, struct di_cve_dump_buffer ice_dump_buf);
void cve_di_set_cve_dump_configuration_register(
		struct cve_device *cve_dev,
		struct di_cve_dump_buffer ice_dump_buf);
int cve_sync_sgt_to_llc(struct sg_table *sgt);

void ice_di_disable_clk_squashing(struct cve_device *dev);

int set_ice_freq(void *ice_freq_config);

int configure_ice_frequency(struct cve_device *dev);

#define __no_op_return_success 0

#ifdef RING3_VALIDATION
#define init_icedrv_sysfs() __no_op_return_success
#define term_icedrv_sysfs() __no_op_stub
#define init_icedrv_hw_config(dev) __no_op_return_success
#define term_icedrv_hw_config(dev) __no_op_stub
#else
#define init_icedrv_sysfs() icedrv_sysfs_init()
#define term_icedrv_sysfs() icedrv_sysfs_term()
#define init_icedrv_hw_config(dev) hw_config_sysfs_init(dev)
#define term_icedrv_hw_config(dev) hw_config_sysfs_term(dev)
#endif

int ice_di_get_core_blob_sz(void);

#if ICEDRV_ENABLE_HSLE_FLOW
#define __rdy_max_usleep (30000)
#define __rdy_min_usleep (10000)
#define __rdy_bit_max_trial (800)
#else
#define __rdy_max_usleep (3000)
#define __rdy_min_usleep (1000)
#define __rdy_bit_max_trial (8)
#endif /*ICEDRV_ENABLE_HSLE_FLOW*/

#define __wait_for_ice_rdy(dev, value, mask, offset) \
do {\
	int32_t count = __rdy_bit_max_trial;\
	while (count) {\
		value = cve_os_read_idc_mmio(dev, offset); \
		if ((value & mask) == mask)\
			break;\
		count--;\
		usleep_range(__rdy_min_usleep, __rdy_max_usleep);\
	} \
} while (0)


#endif /* _DEVICE_INTERFACE_INTERNAL_H_ */
