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

#ifndef _DEVICE_INTERFACE_INTERNAL_COMMON_H_
#define _DEVICE_INTERFACE_INTERNAL_COMMON_H_

#ifdef RING3_VALIDATION
#include <stdint.h>
#include <stdint_ext.h>
#endif

#include "os_interface.h"
#include "project_device_interface.h"

/* general purpose register #13 assigned for CVE driver.
 * it uses for validate reset done.
 * the pin is connected in same wire with CVE cores so in case of reset
 * GP #13 register should back to his default value
 */
#define ICE_MMIO_GP_RESET_REG_ADDR_OFFSET (4 * 13)

#define ICE_MMIO_GP_RESET_REG_TEST_VAL     0xCAFED00D
#define ICE_INTR_STS_SINGLE_ECC_ERR \
	MMIO_HUB_MEM_INTERRUPT_STATUS_DSRAM_SINGLE_ERR_INTERRUPT_MASK

/* Update network's shared read error if exists */
static inline void is_shared_read_error(struct ice_network *ntw,
					struct cve_device *dev, int bo_id)
{
	AXI_SHARED_READ_STATUS_T err_reg;
	u32 offset;

	offset = ICEDC_ICEBO_OFFSET(bo_id) +
			cfg_default.axi_shared_read_status_offset;
	err_reg.val = cve_os_read_idc_mmio(dev, offset);

	if (err_reg.field.error_flag) {
		ntw->shared_read_err_status = err_reg.field.error_flag;
		err_reg.field.error_flag = 0;
		cve_os_write_idc_mmio(dev, offset, err_reg.val);
		cve_os_dev_log_default(CVE_LOGLEVEL_ERROR,
			dev->dev_index,
			"Error: NtwID:0x%llx, shared_read_status value:%x\n",
			ntw->network_id, err_reg.val);
	}

}


static inline int is_dsram_single_err(u32 status)
{
	return ((status &
		cfg_default.mmio_dsram_single_err_intr_mask)
			!= 0);
}

static inline int is_dsram_double_err(u32 status)
{
	return ((status &
		cfg_default.mmio_dsram_double_err_intr_mask)
			!= 0);
}

static inline int is_sram_parity_err(u32 status)
{
	return ((status &
		cfg_default.mmio_sram_parity_err_intr_mask)
			!= 0);
}

static inline int is_dsram_unmapped_addr(u32 status)
{
	return ((status &
		cfg_default.mmio_dsram_unmapped_addr_intr_mask)
			!= 0);
}

static inline int is_dsram_error(u32 status)
{
	return ((status &
		(cfg_default.mmio_dsram_single_err_intr_mask |
		cfg_default.mmio_dsram_double_err_intr_mask |
		cfg_default.mmio_sram_parity_err_intr_mask |
		cfg_default.mmio_dsram_unmapped_addr_intr_mask))
			!= 0);
}

static inline int is_tlc_bp_interrupt(u32 status)
{
	return ((status &
			cfg_default.mmio_intr_status_tlc_reserved_mask) != 0);
}

static inline int is_tlc_panic(u32 status)
{
	return ((status &
			cfg_default.mmio_intr_status_tlc_panic_mask)
			!= 0);
}

static inline int is_ice_dump_completed(u32 status)
{
	return ((status &
			cfg_default.mmio_intr_status_dump_completed_mask)
			!= 0);
}

static inline u32 unset_ice_dump_status(u32 status)
{
	return (status &
		(~cfg_default.mmio_intr_status_dump_completed_mask));
}

static inline int is_cb_complete(u32 status)
{
	return ((status &
			cfg_default.mmio_intr_status_tlc_cb_completed_mask)
			!= 0);
}

static inline int is_que_empty(u32 status)
{
	return ((status &
			cfg_default.mmio_intr_status_tlc_fifo_empty_mask)
			!= 0);
}

static inline int is_tlc_error(u32 status)
{
	return ((status &
			cfg_default.mmio_intr_status_tlc_err_mask)
			!= 0);
}

static inline int is_mmu_error(u32 status)
{
	return ((status &
			cfg_default.mmio_intr_status_mmu_err_mask)
			!= 0);
}

static inline int is_page_fault_error(u32 status)
{
	return ((status &
	(cfg_default.mmio_intr_status_mmu_page_no_write_perm_mask |
	cfg_default.mmio_intr_status_mmu_page_no_read_perm_mask |
	cfg_default.mmio_intr_status_mmu_page_no_exe_perm_mask |
	cfg_default.mmio_intr_status_mmu_page_none_perm_mask))
	!= 0);
}

static inline int is_bus_error(u32 status)
{
	return ((status &
		cfg_default.mmio_intr_status_mmu_soc_bus_err_mask)
		!= 0);
}

static inline int is_butress_error(u32 status)
{
	/* Is this mask enough? */
	/* Old value = 0xfe000000, New value = 0x01000000 */
	return ((status &
		cfg_default.mmio_intr_status_btrs_wd_intr_mask)
			!= 0);
}

static inline int is_cve_error(u32 status)
{
	return (is_tlc_error(status) ||
			is_mmu_error(status) ||
			is_page_fault_error(status) ||
			is_bus_error(status) ||
			is_wd_error(status) ||
			is_ice_dump_completed(status) ||
			is_tlc_panic(status) ||
			is_dsram_error(status)
	);
}

static inline u32 is_single_ecc_err(u32 status)
{
	return (status & cfg_default.mmio_dsram_single_err_intr_mask);
}

static inline u32 unset_sram_parity_err(u32 status)
{
	return (status & ~cfg_default.mmio_sram_parity_err_intr_mask);
}

static inline u32 unset_single_ecc_err(u32 status)
{
	return (status & ~cfg_default.mmio_dsram_single_err_intr_mask);
}

#endif /*_DEVICE_INTERFACE_INTERNAL_COMMON_H_*/
