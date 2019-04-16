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
	#include <stdint.h>
	#include <stdint_ext.h>
	#include "coral.h"
#else /* Ring0 platforms (Simics, FPGA and Sil) */
	#include <linux/types.h>
	#include <linux/reset.h>
	#include <linux/delay.h>
	#include <linux/log2.h>
	#ifdef FPGA
		#include <linux/bitops.h>
		#define DELAY_AFTER_RESET_SEC 1
		#define MMIO_BAR2_RESET_OFFSET 0x0
		#define MMIO_BAR2_RESET_REG_DEFAULT_VAL 0xFFFFFFFF
		#define GLOBAL_RESET_BIT 0
		#define HW_RESET_BIT 4
		#define SW_RESET_BIT 8

		enum fpga_reset_type {
			GLOBAL_RESET,
			HW_RESET,
			SW_RESET
		};
	#endif
	#include "ice_sw_counters.h"
#endif

#include <mmio_hub_regs.h>
#include <ice_mmu_inner_regs.h>
#include <cve_delphi_cfg_regs.h>
#include <cve_dse_regs.h>
#include <idc_regs_regs.h>
#include "device_interface_internal.h"
#include "cve_linux_internal.h"
/* #include "coh_dtf_log.h"*/
/* #include "coh_platform_interface.h"*/
#include "tlc_hi_regs.h"
#include "TLC_command_formats_values_no_ifdef.h"
#include "ice_trace.h"
#include "cve_dump.h"

#define ICE_CORE_BLOB_SIZE sizeof(cveCoreBlob_t)
#define CVE_DUMP_BLOB_NR 1


#ifdef DEBUG_TENSILICA_ENABLE
#include <mmio_semaphore_regs.h>

#define CVE_SEM_HW_GENERAL_REG \
	(CVE_SEMAPHORE_BASE + CVE_SEMAPHORE_MMIO_CVE_SEM_GENERAL_MMOFFSET)

/* In CVE2.0 debug module reset (DReset)can be
 * decoupled from CVE functional reset (Breset)
 * to enable decoupling of Dreset and Breset ,
 * CVE_SEM_HW_GENERAL_REG should be set  0x7
 * by decoupling the resets , tensilica debugger
 * will not need to reconnect upon CVE reset
 */
inline void cve_decouple_debugger_reset(struct cve_device *cve_dev)
{
	cve_os_write_mmio_32(cve_dev, CVE_SEM_HW_GENERAL_REG, 0x07);
}

#endif

/* this variable will be updated in init_hw_revision */
static struct hw_revision_t hw_rev_value;
static int hw_rev_initialized;

void get_hw_revision(struct cve_device *cve_dev, struct hw_revision_t *hw_rev)
{
	u32 hw_rev_mmio_val;

	if (!hw_rev_initialized) {
		hw_rev_mmio_val = cve_os_read_mmio_32(cve_dev,
				CVE_MMIO_HUB_HW_REVISION_MMOFFSET);
		hw_rev_value.major_rev =
			hw_rev_mmio_val &
			MMIO_HUB_MEM_HW_REVISION_MAJOR_REV_MASK;
		hw_rev_value.minor_rev =
			(hw_rev_mmio_val &
			MMIO_HUB_MEM_HW_REVISION_MINOR_REV_MASK)>>16;
		hw_rev_initialized = 1;
	}

	hw_rev->major_rev = hw_rev_value.major_rev;
	hw_rev->minor_rev = hw_rev_value.minor_rev;
}

int is_wd_error(u32 status)
{
	if (!enable_wdt_debugfs)
		return 0;
	return ((status &
	MMIO_HUB_MEM_INTERRUPT_STATUS_INTERNAL_CVE_WATCHDOG_INTERRUPT_MASK)
	!= 0);
}

static void configure_dtf(struct cve_device *cve_dev)
{
#ifdef FPGA
	union MMIO_HUB_MEM_DTF_CONTROL_t dtf_control;

	/* Set control register in cve top */
	dtf_control.val = 0;
	dtf_control.field.DTF_VTUNE_MODE = 1;
	dtf_control.field.DTF_ON = 1;
	cve_os_write_mmio_32(cve_dev,
			CVE_MMIO_HUB_DTF_CONTROL_MMOFFSET,
			dtf_control.val);
#endif
}

static void configure_llc(struct cve_device *cve_dev)
{

	/* changing the AXI default bits (20-23) in page table entry
	 * to be 24-27, value should be 0x6DA658
	 */
	union ICE_MMU_INNER_MEM_AXI_TABLE_PT_INDEX_BITS_t axi_pt_bits;
	u32 llc_bit = CVE_LLC_BIT_SHIFT;

	axi_pt_bits.val =
	(llc_bit <<
	 ICE_MMU_INNER_MEM_AXI_TABLE_PT_INDEX_BITS_TABLE_INDEX_BIT0_LSB) |
	((llc_bit + 1) <<
	 ICE_MMU_INNER_MEM_AXI_TABLE_PT_INDEX_BITS_TABLE_INDEX_BIT1_LSB) |
	((llc_bit + 2) <<
	 ICE_MMU_INNER_MEM_AXI_TABLE_PT_INDEX_BITS_TABLE_INDEX_BIT2_LSB) |
	((llc_bit + 3) <<
	 ICE_MMU_INNER_MEM_AXI_TABLE_PT_INDEX_BITS_TABLE_INDEX_BIT3_LSB);
	cve_os_write_mmio_32(cve_dev,
			ICE_MMU_BASE + ICE_MMU_AXI_TABLE_PT_INDEX_BITS_MMOFFSET,
			axi_pt_bits.val);

	/* Disabling because during HSLE bringup it was recommended
	 * to let these registers have default value
	 */
#if 0
	/* set the attribute table */
	cve_os_write_mmio_32(cve_dev,
		ICE_MMU_BASE + ICE_MMU_AXI_ATTRIBUTES_TABLE_MMOFFSET,
		AXI_ATTRIBUTE_TABLE_0);
	cve_os_write_mmio_32(cve_dev,
		ICE_MMU_BASE + ICE_MMU_AXI_ATTRIBUTES_TABLE_MMOFFSET + 4,
		AXI_ATTRIBUTE_TABLE_1);
	cve_os_write_mmio_32(cve_dev,
		ICE_MMU_BASE + ICE_MMU_AXI_ATTRIBUTES_TABLE_MMOFFSET + 8,
		AXI_ATTRIBUTE_TABLE_2);
	cve_os_write_mmio_32(cve_dev,
		ICE_MMU_BASE + ICE_MMU_AXI_ATTRIBUTES_TABLE_MMOFFSET + 12,
		AXI_ATTRIBUTE_TABLE_3);
#endif

	/* set tensilica cores default configuration */
	cve_os_write_mmio_32(cve_dev,
			ICE_MMU_BASE + ICE_MMU_TLC_AXI_ATTRIBUTES_MMOFFSET,
			CVE_TLC_LLC_CONFIG);
	cve_os_write_mmio_32(cve_dev,
			ICE_MMU_BASE + ICE_MMU_ASIP_AXI_ATTRIBUTES_MMOFFSET,
			CVE_ASIP_LLC_CONFIG);
	cve_os_write_mmio_32(cve_dev,
			ICE_MMU_BASE + ICE_MMU_DSP_AXI_ATTRIBUTES_MMOFFSET,
			CVE_DSP_LLC_CONFIG);

	/* set the page walk */
	cve_os_write_mmio_32(cve_dev,
		ICE_MMU_BASE + ICE_MMU_PAGE_WALK_AXI_ATTRIBUTES_MMOFFSET,
		CVE_PAGE_WALK_AXI_ATTRIBUTES);

}

/* return "0" if managed to set GP#13 register to "test" value */
static int set_gp_reg_to_test_val(struct cve_device *cve_dev)
{
	u32 reg_val;

	cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Setting GP#13 reg to test value %x\n",
			ICE_MMIO_GP_RESET_REG_TEST_VAL);

	cve_os_write_mmio_32(cve_dev,
			ICE_MMIO_GP_RESET_REG_ADDR,
			ICE_MMIO_GP_RESET_REG_TEST_VAL);

	reg_val = cve_os_read_mmio_32(cve_dev, ICE_MMIO_GP_RESET_REG_ADDR);
	if (reg_val != ICE_MMIO_GP_RESET_REG_TEST_VAL)
		cve_os_log(CVE_LOGLEVEL_ERROR,
			   "GP#13 write 0x%08x read 0x%08x\n",
			   ICE_MMIO_GP_RESET_REG_TEST_VAL, reg_val);

	if (reg_val != ICE_MMIO_GP_RESET_REG_TEST_VAL)
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"Error, unable to set GP#13 reg to test value %x\n",
				ICE_MMIO_GP_RESET_REG_TEST_VAL);

	return (reg_val != ICE_MMIO_GP_RESET_REG_TEST_VAL);
}

/* return "0" if GP#13 back to his default value */
static int get_gp_reg_val_reset_done(struct cve_device *cve_dev)
{
	u32 reg_val;
	int timeout;

	cve_os_log(CVE_LOGLEVEL_DEBUG,
		   "Checking GP#13 reg back to default value after reset\n");

	for (timeout = 0; timeout < 10; timeout++) {
		reg_val = cve_os_read_mmio_32(cve_dev,
					      ICE_MMIO_GP_RESET_REG_ADDR);
		if (reg_val == MMIO_HUB_MEM_GENERAL_PURPOSE_REGS_RESET) {
			cve_os_log(CVE_LOGLEVEL_DEBUG,
				   "GP#13 ready after %d cycles\n",
				   timeout);
			return 0;
		}
		udelay(1);
	}

	cve_os_log(CVE_LOGLEVEL_ERROR,
		   "GP#13 expected 0x%08x read 0x%08x\n",
		   MMIO_HUB_MEM_GENERAL_PURPOSE_REGS_RESET, reg_val);

	return 1;
}


/* No FPGA Reset for now. BAR2 is for Counter */
#ifdef FPGA_NO
/*
 * CVE2 FPGA has 3 reset types:
 * 1. Global reset - resets the fabric together with CVE.
 * 2. CVE HW reset - resets entire CVE block design
 * 3. CVE SW reset - resets entire CVE block design except of semaphore logic
 *
 * For keeping Tensilica cores break points, it's required to use the CVE SW
 * reset so semaphore logic area will not reset (although semaphore is not
 * used in COH)
 * the purpose of using ~(BIT(x)) is to reset bit in place x on default
 * register value.
 */

static void do_fpga_reset(struct cve_device *cve_dev, u8 reset_type)
{
	switch (reset_type) {
	case GLOBAL_RESET:
	{
		cve_os_log(CVE_LOGLEVEL_DEBUG,
				"Performing Global reset...\n");
		cve_os_write_mmio_32_bar2(cve_dev, MMIO_BAR2_RESET_OFFSET,
				MMIO_BAR2_RESET_REG_DEFAULT_VAL);
		ssleep(DELAY_AFTER_RESET_SEC);
		cve_os_write_mmio_32_bar2(cve_dev, MMIO_BAR2_RESET_OFFSET,
				MMIO_BAR2_RESET_REG_DEFAULT_VAL &
				~(BIT(GLOBAL_RESET_BIT)));
	}
	break;
	case HW_RESET:
	{
		cve_os_log(CVE_LOGLEVEL_DEBUG,
				"Performing HW reset...\n");
		cve_os_write_mmio_32_bar2(cve_dev, MMIO_BAR2_RESET_OFFSET,
				MMIO_BAR2_RESET_REG_DEFAULT_VAL &
				~(BIT(HW_RESET_BIT)));
		ssleep(DELAY_AFTER_RESET_SEC);
		cve_os_write_mmio_32_bar2(cve_dev, MMIO_BAR2_RESET_OFFSET,
				MMIO_BAR2_RESET_REG_DEFAULT_VAL);
	}
	break;
	case SW_RESET:
	{
		cve_os_log(CVE_LOGLEVEL_DEBUG,
				"Performing SW reset...\n");
		/* TODO: the first MMIO write (0x8) is WA due to a RTL bug.
		 * it will removed after RTL but will fix.
		 */
		cve_os_write_mmio_32_bar2(cve_dev, 0x8,
				MMIO_BAR2_RESET_REG_DEFAULT_VAL);
		cve_os_write_mmio_32_bar2(cve_dev, MMIO_BAR2_RESET_OFFSET,
				MMIO_BAR2_RESET_REG_DEFAULT_VAL &
				~(BIT(SW_RESET_BIT)));
		ssleep(DELAY_AFTER_RESET_SEC);
		cve_os_write_mmio_32_bar2(cve_dev, MMIO_BAR2_RESET_OFFSET,
				MMIO_BAR2_RESET_REG_DEFAULT_VAL);
	}
	break;
	default:
	{
		cve_os_log(CVE_LOGLEVEL_ERROR, "Invalid Reset type\n");
	}
	break;
	}
	ssleep(DELAY_AFTER_RESET_SEC);
	cve_os_log(CVE_LOGLEVEL_DEBUG, "Reset done\n");
}
#endif

int do_reset_device(struct cve_device *cve_dev, uint8_t idc_reset)
{
	int retval = 0;
	uint64_t value, mask, notify_ice_mask;

	/*cve_save_dtf_regs(cve_dev);*/

	mask = (1 << cve_dev->dev_index) << 4;

	value = mask;
	notify_ice_mask = value;

	if (idc_reset) {

		cve_os_dev_log(CVE_LOGLEVEL_DEBUG,
			cve_dev->dev_index,
			"Performing IDC Reset\n");
		retval = set_gp_reg_to_test_val(cve_dev);

		/* SW WA for STEP A */
		ice_di_disable_clk_squashing(cve_dev);

		cve_os_write_idc_mmio(cve_dev,
			IDC_REGS_IDC_MMIO_BAR0_MEM_ICERST_MMOFFSET, value);

		/* Check if ICEs are Ready */
		/* Driver is not yet sure how long to wait for ICERDY */
		while (1) {
			value = cve_os_read_idc_mmio(cve_dev,
				IDC_REGS_IDC_MMIO_BAR0_MEM_ICERDY_MMOFFSET);
			if ((value & mask) == mask)
				break;
			usleep_range(100, 500);
		}

		if ((value & mask) != mask) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
				"Initialization of ICE-%d failed\n",
				cve_dev->dev_index);
			return -1;
		}

/* This piece of code was never active. It was there
 * in CVE to support Platform Driver.
 */
#if 0
#ifdef RING3_VALIDATION
#elif defined(FPGA_NO)
		do_fpga_reset(cve_dev, SW_RESET);
#else		/* Simics and Sil */
		/* Look */
		retval |= reset_control_reset(to_cve_os_device(cve_dev)->rstc);
#endif
#endif
		cve_os_log(CVE_LOGLEVEL_DEBUG, "After call to reset device\n");

		/* TBD: Enable following line while working on Reset flow */
		/* retval |= get_gp_reg_val_reset_done(cve_dev); */
		get_gp_reg_val_reset_done(cve_dev);

	} else {

		cve_os_dev_log(CVE_LOGLEVEL_DEBUG,
			cve_dev->dev_index,
			"Not performing IDC Reset\n");
	}

	value = cve_os_read_idc_mmio(cve_dev,
		IDC_REGS_IDC_MMIO_BAR0_MEM_ICERDY_MMOFFSET);

	/* Enable Inter Core Communication notifications messages to the
	 * ICEs which are power enabled
	 */
	cve_os_write_idc_mmio(cve_dev,
		IDC_REGS_IDC_MMIO_BAR0_MEM_ICENOTE_MMOFFSET,
		value | notify_ice_mask);

	/*cve_restore_dtf_regs(cve_dev);*/

#ifndef NULL_DEVICE_RING0
	ice_restore_trace_hw_regs(cve_dev);
#endif

	configure_dtf(cve_dev);

	/* configure the LLC after reset */
	configure_llc(cve_dev);

	return retval;
}

void store_ecc_err_count(struct cve_device *cve_dev)
{
#ifndef RING3_VALIDATION
	uint32_t serr, derr, parity_err;
	union MMIO_HUB_MEM_UNMAPPED_ERR_ID_t unmapped_err;

	serr = cve_os_read_mmio_32_force_print(cve_dev,
			CVE_MMIO_HUB_ECC_SERRCOUNT_MMOFFSET);

	derr = cve_os_read_mmio_32_force_print(cve_dev,
			CVE_MMIO_HUB_ECC_DERRCOUNT_MMOFFSET);

	parity_err = cve_os_read_mmio_32_force_print(cve_dev,
			CVE_MMIO_HUB_PARITY_ERRCOUNT_MMOFFSET);

	unmapped_err.val = cve_os_read_mmio_32_force_print(cve_dev,
			CVE_MMIO_HUB_UNMAPPED_ERR_ID_MMOFFSET);

	if (cve_dev->hswc_infer) {
		ice_swc_counter_add(cve_dev->hswc_infer,
		ICEDRV_SWC_INFER_DEVICE_COUNTER_ECC_SERRCOUNT, serr);

		ice_swc_counter_add(cve_dev->hswc_infer,
		ICEDRV_SWC_INFER_DEVICE_COUNTER_ECC_DERRCOUNT, derr);

		ice_swc_counter_add(cve_dev->hswc_infer,
		ICEDRV_SWC_INFER_DEVICE_COUNTER_PARITY_ERRCOUNT, parity_err);

		ice_swc_counter_set(cve_dev->hswc_infer,
			ICEDRV_SWC_INFER_DEVICE_COUNTER_UNMAPPED_ERR_ID,
			unmapped_err.field.TID_ERR);
	}
#else
	cve_os_read_mmio_32_force_print(cve_dev,
			CVE_MMIO_HUB_ECC_SERRCOUNT_MMOFFSET);
	cve_os_read_mmio_32_force_print(cve_dev,
			CVE_MMIO_HUB_ECC_DERRCOUNT_MMOFFSET);
	cve_os_read_mmio_32_force_print(cve_dev,
			CVE_MMIO_HUB_PARITY_ERRCOUNT_MMOFFSET);
	cve_os_read_mmio_32_force_print(cve_dev,
			CVE_MMIO_HUB_UNMAPPED_ERR_ID_MMOFFSET);
#endif
}

void cve_print_mmio_regs(struct cve_device *cve_dev)
{
	int i;

	cve_os_read_mmio_32_force_print(cve_dev,
			ICE_MMU_BASE + ICE_MMU_MMU_FAULT_DETAILS_MMOFFSET);
	cve_os_read_mmio_32_force_print(cve_dev,
			ICE_MMU_BASE + ICE_MMU_FAULT_LINEAR_ADDRESS_MMOFFSET);
	cve_os_read_mmio_32_force_print(cve_dev,
			ICE_MMU_BASE + ICE_MMU_FAULT_PHYSICAL_ADDRESS_MMOFFSET);
	cve_os_read_mmio_32_force_print(cve_dev,
			ICE_MMU_BASE + ICE_MMU_MMU_CHICKEN_BITS_MMOFFSET);
	cve_os_read_mmio_32_force_print(cve_dev,
			CVE_MMIO_HUB_CBB_ERROR_CODE_MMOFFSET);
	cve_os_read_mmio_32_force_print(cve_dev,
			CVE_MMIO_HUB_CBB_ERROR_INFO_MMOFFSET);
	cve_os_read_mmio_32_force_print(cve_dev,
			CVE_MMIO_HUB_TLC_INFO_MMOFFSET);
	for (i = 0; i < 16; i++)
		cve_os_read_mmio_32_force_print(cve_dev,
			CVE_MMIO_HUB_GENERAL_PURPOSE_REGS_MMOFFSET + 4*i);
}

int init_platform_data(struct cve_device *cve_dev)
{
	return 0;
}

void cleanup_platform_data(struct cve_device *cve_dev)
{

}

void project_hook_interrupt_handler_exit(struct cve_device *cve_dev,
		u32 status, bool is_last_cb)
{
	union MMIO_HUB_MEM_CVE_CONFIG_t cve_config;

	if (enable_wdt_debugfs) {
		/* Disable WDT in CVE2 */
		cve_config.val = cve_os_read_mmio_32(cve_dev,
				CVE_MMIO_HUB_CVE_CONFIG_MMOFFSET);
		cve_config.val = cve_config.val &
			~MMIO_HUB_MEM_CVE_CONFIG_CVE_WATCHDOG_ENABLE_MASK;

		cve_os_write_mmio_32(cve_dev,
				CVE_MMIO_HUB_CVE_CONFIG_MMOFFSET,
				cve_config.val);
	}
}

void project_hook_dispatch_new_job(struct cve_device *cve_dev,
						struct ice_network *ntw)
{
	union MMIO_HUB_MEM_CVE_WATCHDOG_INIT_t wdt_init;

	/* Configure CVE HW watchdog: */
	enable_wdt_debugfs = cve_debug_get(DEBUG_WD_EN);

	/* Disable WD if debugger is used*/
	if (unlikely(cve_debug_get(DEBUG_TENS_EN)))
		enable_wdt_debugfs = 0;

	/* Disable WD if ice debugger is used*/
	if (unlikely(ntw->reserve_resource & ICE_SET_BREAK_POINT))
		enable_wdt_debugfs = 0;


	if (enable_wdt_debugfs) {
		/* Set watchdog expiration period.
		 *
		 * For now, set WDT to Maximum (~8sec) until we get final
		 * numbers from arch team.
		 * Silicon: 500Mhz * 8s =~ 0xF0000000
		 * FPGA: 5Mhz * 8s = 0x2625A00
		 */
#ifdef FPGA
		wdt_init.val = 0xF0000000;
#else
		wdt_init.val = 0xF0000000;
#endif
		cve_os_write_mmio_32(cve_dev,
				CVE_MMIO_HUB_CVE_WATCHDOG_INIT_MMOFFSET,
				wdt_init.val);

		/* Enable WDT in CVE2 */
		cve_os_read_modify_write_mmio_32(cve_dev,
			CVE_MMIO_HUB_CVE_CONFIG_MMOFFSET,
			MMIO_HUB_MEM_CVE_CONFIG_CVE_WATCHDOG_ENABLE_MASK);

		/* Pet WDT in driver side (To make sure WDT is activated
		 * in case TLC is dead)
		 */
		cve_os_write_mmio_32(cve_dev,
			CVE_MMIO_HUB_TLC_WR_PULSE_MMOFFSET,
			MMIO_HUB_MEM_TLC_WR_PULSE_CVE_WATCHDOG_PETTING_MASK);
	}
}

void ice_di_update_page_sz(struct cve_device *cve_dev, u32 *page_sz_array)
{
	/* 4 bit configuration for one PDE and we have 1024 PDE
	 * for each 32 bit register 8 PDE page size can be configured,
	 * so in total it has 128 32 bit regsiters to configure 1024 unique
	 * page size entries
	 */
	int i;

	for (i = 0; i < ICE_PAGE_SZ_CONFIG_REG_COUNT; i++) {
		cve_os_write_mmio_32(cve_dev,
				(ICE_MMU_BASE +
				 ICE_MMU_PAGE_SIZES_MMOFFSET + (i * 4)),
				page_sz_array[i]);
		cve_os_dev_log(CVE_LOGLEVEL_DEBUG,
				cve_dev->dev_index,
				"PAGE_SZ_CONFIG_REG Index=%d, Value=0x%x\n",
				i, page_sz_array[i]);
	}

}

int cve_pt_llc_update(pt_entry_t *pt_entry, u32 llc_policy)
{
	int ret = 0;
#ifndef DISABLE_LLC

	/* Invalid policy, return failure */
	if (llc_policy >= CVE_LLC_MAX_POLICY_NR) {
		ret = -ICEDRV_KERROR_PT_INVAL_LLC_POLICY;
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"Invalid llc_policy %d, can't set policy in page entry\n",
				llc_policy);
		goto out;
	}

	*pt_entry |= llc_policy << CVE_LLC_BIT_SHIFT;

out:
#endif
	return ret;
}

void cve_di_set_cve_dump_control_register(struct cve_device *cve_dev,
		uint8_t dumpTrigger, struct di_cve_dump_buffer ice_dump_buf)
{
	union TLC_HI_MEM_TLC_DUMP_CONTROL_REG_t reg;
	u32 offset_bytes = CVE_TLC_HI_BASE +
			CVE_TLC_HI_TLC_DUMP_CONTROL_REG_MMOFFSET;

	if (ice_dump_buf.is_allowed_tlc_dump) {
		/* validate that we are 32bit aligned */
		ASSERT(((offset_bytes >> 2) << 2) == offset_bytes);

		reg.val = 0;
		if (ice_dump_buf.is_allowed_tlc_dump)
			reg.field.dumpTrigger = dumpTrigger;
		else
			reg.field.dumpTrigger = DUMP_CVE_NEVER;

		cve_os_write_mmio_32(cve_dev, offset_bytes, reg.val);
	}
}

void cve_di_set_cve_dump_configuration_register(
		struct cve_device *cve_dev,
		struct di_cve_dump_buffer ice_dump_buf)
{
	union TLC_HI_MEM_TLC_DUMP_BUFFER_CONFIG_REG_t reg;
	u32 offset_bytes = CVE_TLC_HI_BASE +
			CVE_TLC_HI_TLC_DUMP_BUFFER_CONFIG_REG_MMOFFSET;

	if (ice_dump_buf.is_allowed_tlc_dump) {
		/* validate that we are 32bit aligned */
		ASSERT(((offset_bytes >> 2) << 2) == offset_bytes);

		reg.val = ice_dump_buf.ice_vaddr;
		/* 0 means one dump is allowed */
		reg.field.maxDumpCount = 0;
		cve_os_write_mmio_32(cve_dev, offset_bytes, reg.val);
	}
}

int project_hook_init_cve_dump_buffer(struct cve_device *dev)
{
	int retval = CVE_DEFAULT_ERROR_CODE;
	u32 dump_size_aligned = ALIGN(
			ICE_CORE_BLOB_SIZE * CVE_DUMP_BLOB_NR,
			PLAFTORM_CACHELINE_SZ);
	if (dev == NULL)
		goto out; /* invalid device */

	/* Init debug_control_buf */
	retval = OS_ALLOC_DMA_CONTIG(dev,
			dump_size_aligned,
			CVE_DUMP_BLOB_NR,
			&(dev->debug_control_buf.cve_dump_buffer),
			&dev->debug_control_buf.dump_dma_handle, 1);
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
		  "os_alloc_dma failed (%d) for cve_dump init, hence disabling this feature\n",
		  retval);
		dev->debug_control_buf.is_allowed_tlc_dump = 0;
		goto out;

	}

	memset(dev->debug_control_buf.cve_dump_buffer,
				0, dump_size_aligned);

	dev->debug_control_buf.is_allowed_tlc_dump = 1;
	dev->debug_control_buf.size_bytes = dump_size_aligned;
	dev->debug_control_buf.is_cve_dump_on_error  = 0;

	retval = cve_os_init_wait_que(&dev->debug_control_buf.dump_wqs_que);
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"os_init_wait_que failed %d\n", retval);
		goto release_alloc;
	}

	return retval;

release_alloc:
	project_hook_free_cve_dump_buffer(dev);
out:
	return retval;
}

void project_hook_free_cve_dump_buffer(struct cve_device *dev)
{
	if (dev == NULL)
		return;

	/* free debug_control_buf */
	OS_FREE_DMA_CONTIG(dev,
		dev->debug_control_buf.size_bytes,
		dev->debug_control_buf.cve_dump_buffer,
		&dev->debug_control_buf.dump_dma_handle, 1);

	memset(&dev->debug_control_buf,
				0, sizeof(dev->debug_control_buf));
}

int ice_di_get_core_blob_sz(void)
{
	return ICE_CORE_BLOB_SIZE;
}


void ice_di_disable_clk_squashing_step_a(struct cve_device *dev)
{
	u32 offset, count = 10;
	u64 read_val, write_val = 0, mask = 0;
	u8 bo_id = (dev->dev_index / 2);

	offset = (ICEDC_ICEBO_OFFSET(bo_id) + ICEBO_GPSB_OFFSET
			+ ICEDC_ICEBO_CLK_GATE_CTL_OFFSET);


	read_val = cve_os_read_idc_mmio(dev, offset);
	mask = (1ULL << ICEDC_ICEBO_CLK_GATE_CTL_DISABLE_SQUASH_BIT_SHIFT);
	write_val = (read_val | mask);
	cve_os_write_idc_mmio(dev, offset, write_val);
	cve_os_log(CVE_LOGLEVEL_DEBUG,
			"ICEDC_ICEBO_CLK_GATE_CTL_OFFSET(0x%x): Read:0x%llx Write:0x%llx\n",
			offset, read_val, write_val);

	/* Check if ICEs are Ready */
	/* Driver is not yet sure how long to wait for ICERDY */
	while (count) {
		read_val = cve_os_read_idc_mmio(dev, offset);
		if ((read_val & mask) == mask)
			break;
		usleep_range(100, 500);

		/*TODO HACK: trace to track if reg value is correctly set */
		cve_os_log(CVE_LOGLEVEL_INFO,
			"ICEDC_ICEBO_CLK_GATE_CTL_OFFSET(0x%x): Read:0x%llx Write:0x%llx\n",
			offset, read_val, write_val);
		count--;
	}
}
