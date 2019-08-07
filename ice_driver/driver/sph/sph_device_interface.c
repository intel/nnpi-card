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
#endif

#include "ice_sw_counters.h"
#include "device_interface_internal.h"
#include "cve_linux_internal.h"
/* #include "coh_dtf_log.h"*/
/* #include "coh_platform_interface.h"*/
#include "ice_trace.h"
#include "project_device_interface.h"
#include "sph_device_regs.h"

#define CVE_DUMP_BLOB_NR 1

#ifdef DEBUG_TENSILICA_ENABLE

/* In CVE2.0 debug module reset (DReset)can be
 * decoupled from CVE functional reset (Breset)
 * to enable decoupling of Dreset and Breset ,
 * CVE_SEM_HW_GENERAL_REG should be set  0x7
 * by decoupling the resets , tensilica debugger
 * will not need to reconnect upon CVE reset
 */
inline void cve_decouple_debugger_reset(struct cve_device *cve_dev)
{
	cve_os_write_mmio_32(cve_dev,
		(cfg_default.ice_sem_base +
		cfg_default.ice_sem_mmio_general_offset), 0x07);
}

#endif

#ifndef RING3_VALIDATION
static struct kobject *hwconfig_kobj;
static struct kobject *llcfreq_kobj;

static ssize_t show_ice_freqinfo(struct kobject *kobj,
		struct kobj_attribute *attr,
		char *buf);

static ssize_t show_ice_freq(struct kobject *kobj,
		struct kobj_attribute *attr,
		char *buf);

static ssize_t store_ice_freq(struct kobject *kobj,
		struct kobj_attribute *attr,
		const char *buf, size_t count);

static ssize_t show_llc_freqinfo(struct kobject *kobj,
		struct kobj_attribute *attr,
		char *buf);

static ssize_t show_llc_freq(struct kobject *kobj,
		struct kobj_attribute *attr,
		char *buf);

static ssize_t store_llc_freq(struct kobject *kobj,
		struct kobj_attribute *attr,
		const char *buf, size_t count);

static struct kobj_attribute icefreqinfo_attr =
__ATTR(freqinfo, 0444, show_ice_freqinfo, NULL);

static struct kobj_attribute icefreq_attr =
__ATTR(freq, 0664, show_ice_freq, store_ice_freq);

static struct kobj_attribute llcfreqinfo_attr =
__ATTR(freqinfo, 0444, show_llc_freqinfo, NULL);

static struct kobj_attribute llcfreq_min_attr =
__ATTR(min, 0664, show_llc_freq, store_llc_freq);

static struct kobj_attribute llcfreq_max_attr =
__ATTR(max, 0664, show_llc_freq, store_llc_freq);

static struct attribute *ice_freq_attrs[] = {
	&icefreqinfo_attr.attr,
	&icefreq_attr.attr,
	NULL,	/* need to NULL terminate the list of attributes */
};

static struct attribute *llc_freq_attrs[] = {
	&llcfreqinfo_attr.attr,
	&llcfreq_min_attr.attr,
	&llcfreq_max_attr.attr,
	NULL,	/* need to NULL terminate the list of attributes */
};

static struct attribute_group freq_attr_group = {
		.attrs = ice_freq_attrs,
};

static struct attribute_group llc_attr_group = {
		.name = "freq",
		.attrs = llc_freq_attrs,
};

#endif

/* this variable will be updated in init_hw_revision */
void get_hw_revision(struct cve_device *cve_dev,
				struct hw_revision_t *hw_rev)
{
	u32 hw_rev_mmio_val;
	static struct hw_revision_t hw_rev_value;
	static int hw_rev_initialized;

	if (!hw_rev_initialized) {
		if (cfg_default.mmio_hw_revision_offset == INVALID_OFFSET) {
			hw_rev->major_rev = 0;
			hw_rev->minor_rev = 0;
			return;
		}
		hw_rev_mmio_val = cve_os_read_mmio_32(cve_dev,
				cfg_default.mmio_hw_revision_offset);
		hw_rev_value.major_rev = hw_rev_mmio_val &
			cfg_default.mmio_hw_revision_major_rev_mask;
		hw_rev_value.minor_rev = (hw_rev_mmio_val &
			cfg_default.mmio_hw_revision_minor_rev_mask)>>16;
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
	cfg_default.mmio_wd_intr_mask)
	!= 0);
}

static void configure_axi_max_inflight(struct cve_device *cve_dev)
{
	union cve_dse_mem_axi_max_inflight_t axi_inflight;

	axi_inflight.val = 0;
	axi_inflight.field.AXI_MAX_WRITE_INFLIGHT =
		AXI_MAX_INFLIGHT_WRITE_TRANSACTION;
	axi_inflight.field.AXI_MAX_READ_INFLIGHT =
		AXI_MAX_INFLIGHT_READ_TRANSACTION;

	cve_os_write_mmio_32(cve_dev,
		cfg_default.ice_dse_base +
		cfg_default.ice_axi_max_inflight_offset,
		axi_inflight.val);
}

static void configure_dtf(struct cve_device *cve_dev)
{
#ifdef FPGA
	if (ice_get_b_step_enable_flag()) {
		union mmio_hub_mem_dtf_control_t_b_step dtf_control;

		/* Set control register in cve top */
		dtf_control.val = 0;
		dtf_control.field.DTF_VTUNE_MODE = 1;
		dtf_control.field.DTF_ON = 1;
		cve_os_write_mmio_32(cve_dev,
			cfg_default.mmio_dtf_ctrl_offset,
			dtf_control.val);
	} else {
		union mmio_hub_mem_dtf_control_t_a_step dtf_control;

		/* Set control register in cve top */
		dtf_control.val = 0;
		dtf_control.field.DTF_VTUNE_MODE = 1;
		dtf_control.field.DTF_ON = 1;
		cve_os_write_mmio_32(cve_dev,
			cfg_default.mmio_dtf_ctrl_offset,
			dtf_control.val);
	}
#endif
}

static void configure_llc(struct cve_device *cve_dev)
{

	/* changing the AXI default bits (20-23) in page table entry
	 * to be 24-27, value should be 0x6DA658
	 */
	union ice_mmu_inner_mem_axi_table_pt_index_bits_t axi_pt_bits;
	u32 llc_bit = CVE_LLC_BIT_SHIFT;

	axi_pt_bits.val =
	(llc_bit <<
	 cfg_default.mmu_pt_idx_bits_table_bit0_lsb) |
	((llc_bit + 1) <<
	 cfg_default.mmu_pt_idx_bits_table_bit1_lsb) |
	((llc_bit + 2) <<
	 cfg_default.mmu_pt_idx_bits_table_bit2_lsb) |
	((llc_bit + 3) <<
	 cfg_default.mmu_pt_idx_bits_table_bit3_lsb);
	cve_os_write_mmio_32(cve_dev,
		cfg_default.mmu_base +
		cfg_default.mmu_axi_tbl_pt_idx_bits_offset,
		axi_pt_bits.val);

	/* Disabling because during HSLE bringup it was recommended
	 * to let these registers have default value
	 */
#if 0
	/* set the attribute table */
	cve_os_write_mmio_32(cve_dev,
	cfg_default.mmu_base + ICE_MMU_AXI_ATTRIBUTES_TABLE_MMOFFSET,
	AXI_ATTRIBUTE_TABLE_0);
	cve_os_write_mmio_32(cve_dev,
	cfg_default.mmu_base + ICE_MMU_AXI_ATTRIBUTES_TABLE_MMOFFSET + 4,
	AXI_ATTRIBUTE_TABLE_1);
	cve_os_write_mmio_32(cve_dev,
	cfg_default.mmu_base + ICE_MMU_AXI_ATTRIBUTES_TABLE_MMOFFSET + 8,
	AXI_ATTRIBUTE_TABLE_2);
	cve_os_write_mmio_32(cve_dev,
	cfg_default.mmu_base + ICE_MMU_AXI_ATTRIBUTES_TABLE_MMOFFSET + 12,
	AXI_ATTRIBUTE_TABLE_3);
#endif

	/* set tensilica cores default configuration */
	cve_os_write_mmio_32(cve_dev,
		cfg_default.mmu_base + cfg_default.mmu_tlc_axi_attri_offset,
		CVE_TLC_LLC_CONFIG);
	cve_os_write_mmio_32(cve_dev,
		cfg_default.mmu_base + cfg_default.mmu_asip_axi_attri_offset,
		CVE_ASIP_LLC_CONFIG);
	cve_os_write_mmio_32(cve_dev,
		cfg_default.mmu_base + cfg_default.mmu_dsp_axi_attri_offset,
		CVE_DSP_LLC_CONFIG);

	/* set the page walk */
	cve_os_write_mmio_32(cve_dev,
		cfg_default.mmu_base +
		cfg_default.mmu_page_walk_axi_attri_offset,
		CVE_PAGE_WALK_AXI_ATTRIBUTES);

}

int configure_ice_frequency(struct cve_device *dev)
{
	int ret = 0;
	struct ice_hw_config_ice_freq freq_config;

	freq_config.ice_num = dev->dev_index;
	freq_config.ice_freq = dev->frequency;

	ret = set_ice_freq((void *)&freq_config);

	return ret;
}

/* return "0" if managed to set GP#13 register to "test" value */
static int set_gp_reg_to_test_val(struct cve_device *cve_dev)
{
	u32 reg_val;

	cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Setting GP#13 reg to test value %x\n",
			ICE_MMIO_GP_RESET_REG_TEST_VAL);

	cve_os_write_mmio_32(cve_dev,
			(cfg_default.mmio_gp_regs_offset +
			 ICE_MMIO_GP_RESET_REG_ADDR_OFFSET),
			ICE_MMIO_GP_RESET_REG_TEST_VAL);

	reg_val = cve_os_read_mmio_32(cve_dev,
			(cfg_default.mmio_gp_regs_offset +
			 ICE_MMIO_GP_RESET_REG_ADDR_OFFSET));
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
		(cfg_default.mmio_gp_regs_offset +
				ICE_MMIO_GP_RESET_REG_ADDR_OFFSET));
		if (reg_val == cfg_default.mmio_hub_mem_gp_regs_reset) {
			cve_os_log(CVE_LOGLEVEL_DEBUG,
				   "GP#13 ready after %d cycles\n",
				   timeout);
			return 0;
		}
		udelay(1);
	}

	cve_os_log(CVE_LOGLEVEL_ERROR,
		   "GP#13 expected 0x%08x read 0x%08x\n",
		   cfg_default.mmio_hub_mem_gp_regs_reset, reg_val);

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
			cfg_default.bar0_mem_icerst_offset, value);

		/* Check if ICEs are Ready */
		/* Driver is not yet sure how long to wait for ICERDY */
		__wait_for_ice_rdy(cve_dev, value, mask,
					cfg_default.bar0_mem_icerdy_offset);
		if ((value & mask) != mask) {
			cve_os_log_default(CVE_LOGLEVEL_ERROR,
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
		cfg_default.bar0_mem_icerdy_offset);

	/* Enable Inter Core Communication notifications messages to the
	 * ICEs which are power enabled
	 */
	cve_os_write_idc_mmio(cve_dev,
		cfg_default.bar0_mem_icenote_offset, value | notify_ice_mask);

	/*cve_restore_dtf_regs(cve_dev);*/

#ifndef NULL_DEVICE_RING0
	ice_restore_trace_hw_regs(cve_dev);
#endif

	/* TODO: This is SW workaround for HW bug. To be removed.
	 * https://jira.devtools.intel.com/browse/ICE-14586
	 */
	configure_axi_max_inflight(cve_dev);

	configure_dtf(cve_dev);

	/* configure the LLC after reset */
	configure_llc(cve_dev);

	/* configure default ICE frequency */
	retval = configure_ice_frequency(cve_dev);
	return retval;
}

void store_ecc_err_count(struct cve_device *cve_dev)
{
#ifndef RING3_VALIDATION
	uint32_t serr, derr, parity_err;
	union mmio_hub_mem_unmapped_err_id_t unmapped_err;

	serr = cve_os_read_mmio_32_force_print(cve_dev,
			cfg_default.mmio_ecc_serrcount_offset);

	derr = cve_os_read_mmio_32_force_print(cve_dev,
			cfg_default.mmio_ecc_derrcount_offset);

	parity_err = cve_os_read_mmio_32_force_print(cve_dev,
			cfg_default.mmio_parity_errcount_offset);

	unmapped_err.val = cve_os_read_mmio_32_force_print(cve_dev,
			cfg_default.mmio_unmapped_err_id_offset);

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
			cfg_default.mmio_ecc_serrcount_offset);
	cve_os_read_mmio_32_force_print(cve_dev,
			cfg_default.mmio_ecc_derrcount_offset);
	cve_os_read_mmio_32_force_print(cve_dev,
			cfg_default.mmio_parity_errcount_offset);
	cve_os_read_mmio_32_force_print(cve_dev,
			cfg_default.mmio_unmapped_err_id_offset);
#endif
}

void cve_print_mmio_regs(struct cve_device *cve_dev)
{
	int i;

	cve_os_read_mmio_32_force_print(cve_dev,
			cfg_default.mmu_base +
			cfg_default.mmu_fault_details_offset);
	cve_os_read_mmio_32_force_print(cve_dev,
			cfg_default.mmu_base +
			cfg_default.mmu_fault_linear_addr_offset);
	cve_os_read_mmio_32_force_print(cve_dev,
			cfg_default.mmu_base +
			cfg_default.mmu_fault_physical_addr_offset);
	cve_os_read_mmio_32_force_print(cve_dev,
			cfg_default.mmu_base +
			cfg_default.mmu_chicken_bits_offset);
	cve_os_read_mmio_32_force_print(cve_dev,
			cfg_default.mmio_cbb_err_code_offset);
	cve_os_read_mmio_32_force_print(cve_dev,
			cfg_default.mmio_cbb_error_info_offset);
	cve_os_read_mmio_32_force_print(cve_dev,
			cfg_default.mmio_tlc_info_offset);
	for (i = 0; i < 16; i++)
		cve_os_read_mmio_32_force_print(cve_dev,
			cfg_default.mmio_gp_regs_offset + 4*i);
}

int init_platform_data(struct cve_device *cve_dev)
{
	return 0;
}

void cleanup_platform_data(struct cve_device *cve_dev)
{

}

int set_ice_freq(void *ice_freq_config)
{
	int retval = 0;
	struct cve_device *dev;
	u32 offset;
	u64 value;

	/* the ice value is in range of 0-11 so obtained thread num
	 * is in range of 4 - 15
	 */

	struct ice_hw_config_ice_freq *freq_config =
			(struct ice_hw_config_ice_freq *)ice_freq_config;

	uint32_t ice_index = freq_config->ice_num;
	uint32_t pcu_cr_thread_num = ice_index + 4;
	struct cve_device_group *device_group = g_cve_dev_group_list;

	dev = cve_device_get(ice_index);
	dev->frequency = freq_config->ice_freq;

	retval = cve_os_lock(&device_group->poweroff_dev_list_lock,
			CVE_INTERRUPTIBLE);
	if (retval != 0) {
		cve_os_log_default(CVE_LOGLEVEL_ERROR,
			"cve_os_lock error\n");

		return retval;
	}

	if ((dev->power_state == ICE_POWER_ON) ||
			(dev->power_state == ICE_POWER_OFF_INITIATED)) {

		offset = PCU_CR_THREAD_P_REQ_BASE + (8 * pcu_cr_thread_num);
		value = (freq_config->ice_freq / ICE_FREQ_DIVIDER_FACTOR);

		/* As of now we are setting energy efficency , pstate
		 * offset to 0 value as this is a write only register
		 */
		value = value << ICE_FREQ_SHIFT;
		cve_os_dev_log(CVE_LOGLEVEL_DEBUG, ice_index,
			"Setting ice frequency to: %u Mhz ( offset: 0x%x)\n",
			freq_config->ice_freq, offset);
		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"PCU_CR_THREAD%u_P_REQ offset(0x%x) Write 0x%llx\n",
			pcu_cr_thread_num, offset, value);

		cve_os_write_idc_mmio(dev, offset, value);
	} else {
		cve_os_dev_log_default(CVE_LOGLEVEL_INFO, ice_index,
			"ICE is not powered ON, Reg write will be done after Power ON\n");
		goto out;
	}

out:
	cve_os_unlock(&device_group->poweroff_dev_list_lock);

	return retval;
}

void project_hook_interrupt_handler_exit(struct cve_device *cve_dev,
		u32 status)
{
	union mmio_hub_mem_cve_config_t cve_config;

	if (enable_wdt_debugfs) {
		/* Disable WDT in CVE2 */
		cve_config.val = cve_os_read_mmio_32(cve_dev,
				cfg_default.mmio_cve_config_offset);
		cve_config.val = cve_config.val &
			~cfg_default.mmio_wd_enable_mask;

		cve_os_write_mmio_32(cve_dev,
				cfg_default.mmio_cve_config_offset,
				cve_config.val);
	}
}

void project_hook_dispatch_new_job(struct cve_device *cve_dev,
						struct ice_network *ntw)
{
	union mmio_hub_mem_cve_watchdog_init_t wdt_init;

	/* Configure CVE HW watchdog: */
	enable_wdt_debugfs = cve_debug_get(DEBUG_WD_EN);

	/* Disable WD if debugger is used*/
	if (unlikely(cve_debug_get(DEBUG_TENS_EN)))
		enable_wdt_debugfs = 0;

	/* Disable WD if ice debugger is used*/
	if (unlikely(ntw->ntw_enable_bp))
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
				cfg_default.mmio_wd_init_offset,
				wdt_init.val);

		/* Enable WDT in CVE2 */
		cve_os_read_modify_write_mmio_32(cve_dev,
			cfg_default.mmio_cve_config_offset,
			cfg_default.mmio_wd_enable_mask);

		/* Pet WDT in driver side (To make sure WDT is activated
		 * in case TLC is dead)
		 */
		cve_os_write_mmio_32(cve_dev,
			cfg_default.mmio_tlc_pulse_offset,
			cfg_default.mmio_tlc_wd_petting_mask);
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
				(cfg_default.mmu_base +
				 cfg_default.mmu_page_sizes_offset + (i * 4)),
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
	union tlc_hi_mem_tlc_dump_control_reg_t reg;
	u32 offset_bytes = cfg_default.ice_tlc_hi_base +
			cfg_default.ice_tlc_hi_dump_control_offset;

	if (ice_dump_buf.is_allowed_tlc_dump) {
		/* validate that we are 32bit aligned */
		ASSERT(((offset_bytes >> 2) << 2) == offset_bytes);

		reg.val = 0;
		if (ice_dump_buf.is_allowed_tlc_dump)
			reg.field.dumpTrigger = dumpTrigger;
		else
			reg.field.dumpTrigger = cfg_default.ice_dump_never;

		cve_os_write_mmio_32(cve_dev, offset_bytes, reg.val);
	}
}

void cve_di_set_cve_dump_configuration_register(
		struct cve_device *cve_dev,
		struct di_cve_dump_buffer ice_dump_buf)
{
	union tlc_hi_mem_tlc_dump_buffer_config_reg_t reg;
	u32 offset_bytes = cfg_default.ice_tlc_hi_base +
			cfg_default.ice_tlc_hi_dump_buf_offset;

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
			sizeof(CVECOREBLOB_T) * CVE_DUMP_BLOB_NR,
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
	return sizeof(CVECOREBLOB_T);
}


void ice_di_disable_clk_squashing(struct cve_device *dev)
{
	u32 offset, count = 10;
	u64 read_val, write_val = 0, mask = 0;
	u8 bo_id = (dev->dev_index / 2);

	if (ice_get_b_step_enable_flag())
		return;

	offset = (ICEDC_ICEBO_OFFSET(bo_id) + ICEBO_GPSB_OFFSET
			+ cfg_default.gpsb_x1_regs_clk_gate_ctl_offset);


	read_val = cve_os_read_idc_mmio(dev, offset);
	mask = (1ULL << cfg_default.mem_clk_gate_ctl_dont_squash_iceclk_lsb);
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

#ifndef RING3_VALIDATION
static ssize_t show_ice_freqinfo(struct kobject *kobj,
				struct kobj_attribute *attr,
				char *buf)
{
	int ret = 0;

	ret = sprintf((buf + ret),
		"freq value has to be in the range of 200-800 MHz, multiple of 25\n");
	return ret;
}


static ssize_t show_ice_freq(struct kobject *kobj,
				struct kobj_attribute *attr,
				char *buf)
{
	cve_os_log_default(CVE_LOGLEVEL_INFO, "Not Implemented");

	return 0;
}

static ssize_t store_ice_freq(struct kobject *kobj,
				struct kobj_attribute *attr,
				const char *buf, size_t count)
{
	char *freqset_s;
	u32 dev_index;
	u32 freq_to_set;
	struct ice_hw_config_ice_freq freq_conf;
	int ret = 0;

	ret = sscanf(kobj->name, "ice%d", &dev_index);
	if (ret < 1) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "failed getting ice id %s\n",
						kobj->name);
		return -EFAULT;
	}
	if (dev_index >= NUM_ICE_UNIT) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "wrong ice id %d\n", dev_index);
		return -EFAULT;
	}
	freqset_s = (char *)buf;
	freqset_s = strim(freqset_s);

	if (freqset_s == NULL)
		return -EFAULT;

	ret = kstrtoint(freqset_s, 10, &freq_to_set);
	if (ret < 0)
		return ret;

	if (freq_to_set < MIN_ICE_FREQ_PARAM ||
			freq_to_set > MAX_ICE_FREQ_PARAM ||
				freq_to_set % ICE_FREQ_DIVIDER_FACTOR != 0) {
		cve_os_log_default(CVE_LOGLEVEL_ERROR,
			"ice freq required has to be in range of 200-800, multiple of 25\n");
		return -EINVAL;
	}
	if (ret < 0)
		return ret;

	cve_os_log(CVE_LOGLEVEL_DEBUG, "freq: %d\n", freq_to_set);
	freq_conf.ice_num = dev_index;
	freq_conf.ice_freq = freq_to_set;
	cve_os_log(CVE_LOGLEVEL_DEBUG, "freq: %d\n", freq_conf.ice_freq);
	cve_os_log(CVE_LOGLEVEL_DEBUG, "ice: %d\n", freq_conf.ice_num);
	ret = set_ice_freq((void *)&freq_conf);
	if (ret < 0)
		return ret;
	return count;
}

static ssize_t show_llc_freqinfo(struct kobject *kobj,
				struct kobj_attribute *attr,
				char *buf)
{
	int ret = 0;

	ret = sprintf((buf + ret),
		"freq value has to be in the range of 400-2600 MHz, multiple of 100\n");
	return ret;
}


static ssize_t show_llc_freq(struct kobject *kobj,
				struct kobj_attribute *attr,
				char *buf)
{
	int ret = 0;
	u32 val_low, freq_high, freq_low;
	u64 freq;

	freq = get_llc_freq();
	val_low = freq & 0xFFFFFFFF;

	/*min ratio - 8-14
	 *max ratio - 0-6
	 */

	freq_high = max_llc_ratio(val_low);
	freq_low = min_llc_ratio(val_low);

	ret += sprintf((buf + ret), "LLC Freq Min: %u MHz, Max: %u MHz\n",
		(freq_low * 100),
		(freq_high * 100));

	return ret;
}

static ssize_t store_llc_freq(struct kobject *kobj,
				struct kobj_attribute *attr,
				const char *buf, size_t count)
{
	char *freqset_s;
	u32 freq_to_set;
	struct ice_hw_config_llc_freq freq_conf;
	int ret = 0;

	freqset_s = (char *)buf;
	freqset_s = strim(freqset_s);

	if (freqset_s == NULL)
		return -EFAULT;

	ret = kstrtoint(freqset_s, 10, &freq_to_set);
	if (ret < 0)
		return ret;

	if (freq_to_set < MIN_LLC_FREQ_PARAM ||
			freq_to_set > MAX_LLC_FREQ_PARAM ||
				freq_to_set % LLC_FREQ_DIVIDER_FACTOR != 0) {

		cve_os_log_default(CVE_LOGLEVEL_ERROR,
			"llc freq required has to be in range of 400-2600, multiple of 100\n");
		return -EINVAL;
	}

	if (strcmp(attr->attr.name, "min") == 0) {
		freq_conf.llc_freq_min = freq_to_set;
		freq_conf.llc_freq_max = 0;
		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Min freq to set: %u\n", freq_to_set);
	} else {
		freq_conf.llc_freq_min = 0;
		freq_conf.llc_freq_max = freq_to_set;
		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Max freq to set: %u\n", freq_to_set);
	}
	ret = set_llc_freq((void *)&freq_conf);
	if (ret)
		return -EINVAL;
	return count;
}

static int ice_hw_config_freq_sysfs_init(struct cve_device *ice_dev)
{
	int ret;
	/* Create the freq files associated with ice<n> config kobject */
	ret = sysfs_create_group(ice_dev->ice_config_kobj, &freq_attr_group);
	if (ret) {
		cve_os_dev_log(CVE_LOGLEVEL_ERROR, ice_dev->dev_index,
				"freq sysfs group creation failed\n");
	}
	return ret;
}

static int ice_hw_config_llc_sysfs_init(void)
{
	int ret;
	/* Create the freq files associated with ice<n> config kobject */
	ret = sysfs_create_group(llcfreq_kobj, &llc_attr_group);
	if (ret) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"llc sysfs group creation failed\n");
	}

	return ret;
}

static void ice_hw_config_freq_sysfs_term(struct cve_device *ice_dev)
{
	/* Remove the filter files associated with ice<n> config kobject */
	sysfs_remove_group(ice_dev->ice_config_kobj, &freq_attr_group);
}

void icedrv_sysfs_term(void)
{

	FUNC_ENTER();

	if (icedrv_kobj) {
		kobject_put(icedrv_kobj);
		icedrv_kobj = NULL;
		cve_os_log(CVE_LOGLEVEL_DEBUG,
					"icedrv sysfs  deleted\n");
	}

	FUNC_LEAVE();
}

int icedrv_sysfs_init(void)
{

	int ret = 0;

	FUNC_ENTER()
	if (icedrv_kobj)
		goto out;
	icedrv_kobj = kobject_create_and_add("icedrv", kernel_kobj);
	if (!icedrv_kobj) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
					"icedrv kobj creation failed\n");
		ret = -ENOMEM;
		goto out;
	}
out:
	FUNC_LEAVE()
	return ret;
}

int hw_config_sysfs_init(struct cve_device *ice_dev)
{

	int ret = 0;
	struct cve_os_device *os_dev;
	char name[10]

	FUNC_ENTER();
	os_dev = to_cve_os_device(ice_dev);
	/* create base subdir once */
	if (!icedrv_kobj) {
		cve_os_dev_log(CVE_LOGLEVEL_ERROR, ice_dev->dev_index,
					"icedrv kobj doesn't exist\n");
		ret = -ENOMEM;
		goto out;
	}

	if (hwconfig_kobj)
		goto ice_sysfs;

	hwconfig_kobj = kobject_create_and_add("hwconfig", icedrv_kobj);
	if (!hwconfig_kobj) {
		cve_os_dev_log(CVE_LOGLEVEL_ERROR, ice_dev->dev_index,
					"hwconfig kobj creation failed\n");
		ret = -ENOMEM;
		goto out;
	}
ice_sysfs:
	ice_dev->ice_config_kobj = NULL;
	snprintf(name, sizeof(name), "ice%d", ice_dev->dev_index);
	ice_dev->ice_config_kobj = kobject_create_and_add(name, hwconfig_kobj);
	if (!ice_dev->ice_config_kobj) {
		cve_os_dev_log(CVE_LOGLEVEL_ERROR, ice_dev->dev_index,
				"ice%d kobj creation failed\n",
				ice_dev->dev_index);
		ret = -ENOMEM;
		goto hwconfig_kobj_free;
	}
	ret = ice_hw_config_freq_sysfs_init(ice_dev);
	if (ret) {
		cve_os_dev_log(CVE_LOGLEVEL_ERROR, ice_dev->dev_index,
				"ice_trace_dso_sysfs_init failed\n");
		goto freq_sysfs_free;
	} else {
		if (llcfreq_kobj)
			goto out;
		llcfreq_kobj = kobject_create_and_add("llc", hwconfig_kobj);
		if (!llcfreq_kobj) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
						"llc kobj creation failed\n");
			ret = -ENOMEM;
			goto freq_sysfs_free;
		}
		ret = ice_hw_config_llc_sysfs_init();
		goto out;
	}

freq_sysfs_free:
	ice_hw_config_freq_sysfs_term(ice_dev);
	kobject_put(ice_dev->ice_config_kobj);
	ice_dev->ice_config_kobj = NULL;
hwconfig_kobj_free:
	kobject_put(hwconfig_kobj);
	hwconfig_kobj = NULL;
out:
	FUNC_LEAVE();
	return ret;
}

void hw_config_sysfs_term(struct cve_device *ice_dev)
{
	FUNC_ENTER();

	if (ice_dev->ice_config_kobj) {
		kobject_put(ice_dev->ice_config_kobj);
		ice_dev->ice_config_kobj = NULL;
		cve_os_dev_log(CVE_LOGLEVEL_DEBUG, ice_dev->dev_index,
					"ice config kobj deleted\n");
	}

	if (llcfreq_kobj) {
		kobject_put(llcfreq_kobj);
		llcfreq_kobj = NULL;
		cve_os_log(CVE_LOGLEVEL_DEBUG,
					"llc freq kobj deleted\n");
	}

	if (hwconfig_kobj) {
		kobject_put(hwconfig_kobj);
		hwconfig_kobj = NULL;
		cve_os_dev_log(CVE_LOGLEVEL_DEBUG, ice_dev->dev_index,
					"hw_config kobj deleted\n");
	}

	FUNC_LEAVE();
}

#endif
