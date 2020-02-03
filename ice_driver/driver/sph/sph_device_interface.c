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
#define LLC_PMON_RESET 0x100
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

/* kobject for sw_debug  */
static struct kobject *swdebug_kobj;


struct llcpmoninfo_details {
	u32 index;
	const u32 config_val0;
	const u32 config_val1;
	const char *name;
	const char *desc;

};

#define __LLCPMONINFO(_index, _config_val0, _config_val1, _pmon_name, _desc) { \
	.index = _index, \
	.config_val0 = _config_val0, \
	.config_val1 = _config_val1, \
	.name = __stringify(_pmon_name), \
	.desc = _desc, \
}

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

static ssize_t show_llcpmoninfo(struct kobject *kobj,
		struct kobj_attribute *attr,
		char *buf);

static ssize_t show_llcpmon(struct kobject *kobj,
		struct kobj_attribute *attr,
		char *buf);

static ssize_t show_llcpmonconfig(struct kobject *kobj,
		struct kobj_attribute *attr,
		char *buf);

static ssize_t store_llcpmon(struct kobject *kobj,
		struct kobj_attribute *attr,
		const char *buf, size_t count);


/* show and store function for debug_dump */

static ssize_t show_cbdump(struct kobject *kobj,
		struct kobj_attribute *attr,
		char *buf);

static ssize_t store_cbdump(struct kobject *kobj,
		struct kobj_attribute *attr,
		const char *buf, size_t count);

static ssize_t show_ptdump(struct kobject *kobj,
		struct kobj_attribute *attr,
		char *buf);

static ssize_t store_ptdump(struct kobject *kobj,
		struct kobj_attribute *attr,
		const char *buf, size_t count);

static ssize_t show_postpatchsurfdump(struct kobject *kobj,
		struct kobj_attribute *attr,
		char *buf);

static ssize_t store_postpatchsurfdump(struct kobject *kobj,
		struct kobj_attribute *attr,
		const char *buf, size_t count);

static ssize_t show_icereset(struct kobject *kobj,
		struct kobj_attribute *attr,
		char *buf);

static ssize_t store_icereset(struct kobject *kobj,
		struct kobj_attribute *attr,
		const char *buf, size_t count);

static ssize_t show_llcconfig(struct kobject *kobj,
		struct kobj_attribute *attr,
		char *buf);

static ssize_t store_llcconfig(struct kobject *kobj,
		struct kobj_attribute *attr,
		const char *buf, size_t count);

static ssize_t show_pagesizeconfig(struct kobject *kobj,
		struct kobj_attribute *attr,
		char *buf);

static ssize_t store_pagesizeconfig(struct kobject *kobj,
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

static struct kobj_attribute llcpmoninfo_attr =
__ATTR(llcpmon_info, 0444, show_llcpmoninfo, NULL);

static struct kobj_attribute llcpmon_config_attr =
__ATTR(llcpmon_config, 0664, show_llcpmonconfig, store_llcpmon);

static struct kobj_attribute llcpmon_read_attr =
__ATTR(llcpmon_counters, 0444, show_llcpmon, NULL);


/* attribute registration for debug_dump*/

static struct kobj_attribute cb_dump_attr =
__ATTR(cb_dump, 0664, show_cbdump, store_cbdump);

static struct kobj_attribute pt_dump_attr =
__ATTR(pt_dump, 0664, show_ptdump, store_ptdump);

static struct kobj_attribute post_patch_surf_dump_attr =
__ATTR(pp_surf_dump, 0664, show_postpatchsurfdump, store_postpatchsurfdump);

static struct kobj_attribute ice_reset_attr =
__ATTR(ice_reset, 0664, show_icereset, store_icereset);

static struct kobj_attribute llc_config_attr =
__ATTR(llc_config, 0664, show_llcconfig, store_llcconfig);

static struct kobj_attribute page_size_config_attr =
__ATTR(page_size_config, 0664, show_pagesizeconfig, store_pagesizeconfig);

static struct attribute *debug_attrs[] = {
	&cb_dump_attr.attr,
	&pt_dump_attr.attr,
	&post_patch_surf_dump_attr.attr,
	&ice_reset_attr.attr,
	&llc_config_attr.attr,
	&page_size_config_attr.attr,
	NULL,	/* need to NULL terminate the list of attributes */
};

static struct attribute_group debug_attr_group = {
		.attrs = debug_attrs,
};



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

static struct attribute *llcpmon_attrs[] = {
	&llcpmoninfo_attr.attr,
	NULL,   /* need to NULL terminate the list of attributes */
};

static struct attribute *llcpmon_control_attrs[] = {
	&llcpmon_config_attr.attr,
	&llcpmon_read_attr.attr,
	NULL,   /* need to NULL terminate the list of attributes */
};

static struct attribute_group llcpmon_attr_group = {
	.attrs = llcpmon_attrs,
};

static struct attribute_group llcpmon_control_attr_group = {
	.attrs = llcpmon_control_attrs,
};

static int llc_pmon_config_sysfs(u32 pmonindex, struct icebo_desc *bo,
						bool pmon_0_1);


const u64 pre_defined_llc_pmon_cfg0[MAX_LLCPMON_PREDEF_CONFIG] = {
		0x0, /*To disable LLC PMON */
		0x17663B88, /*LLC PMON HIT of ICE0 in BO */
		0x27663B88, /*LLC PMON MISS of ICE0 in BO */
		0x37663B88, /*LLC PMON HIT + MISS of ICE0 in BO */
		0x17663B98, /*LLC PMON ICEBO HIT */
};

const u64 pre_defined_llc_pmon_cfg1[MAX_LLCPMON_PREDEF_CONFIG] = {
		0x0, /*To disable LLC PMON */
		0x17663B90, /*LLC PMON HIT of ICE0 in BO */
		0x27663B90, /*LLC PMON MISS of ICE0 in BO */
		0x37663B90, /*LLC PMON HIT + MISS of ICE0 in BO */
		0x27663B98, /*LLC PMON ICEBO MISS */
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
	if (ice_get_a_step_enable_flag()) {
		union mmio_hub_mem_dtf_control_t_a_step dtf_control;

		/* Set control register in cve top */
		dtf_control.val = 0;
		dtf_control.field.DTF_VTUNE_MODE = 1;
		dtf_control.field.DTF_ON = 1;
		cve_os_write_mmio_32(cve_dev,
			cfg_default.mmio_dtf_ctrl_offset,
			dtf_control.val);

	} else if (ice_get_b_step_enable_flag()) {

		union mmio_hub_mem_dtf_control_t_b_step dtf_control;

		/* Set control register in cve top */
		dtf_control.val = 0;
		dtf_control.field.DTF_VTUNE_MODE = 1;
		dtf_control.field.DTF_ON = 1;
		cve_os_write_mmio_32(cve_dev,
			cfg_default.mmio_dtf_ctrl_offset,
			dtf_control.val);

	} else {
		union mmio_hub_mem_dtf_control_t_c_step dtf_control;

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
	struct cve_device_group *dg = cve_dg_get();
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

	if (dg->dump_conf.llc_config)
		cve_os_dev_log_default(CVE_LOGLEVEL_INFO,
			cve_dev->dev_index,
			"AXI_TABLE_PT_INDEX_REG  Offset=0x%x, Value=0x%x\n",
			(cfg_default.mmu_base +
			 cfg_default.mmu_axi_tbl_pt_idx_bits_offset),
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

	if (dg->dump_conf.llc_config == 1)
		cve_os_dev_log_default(CVE_LOGLEVEL_INFO,
			cve_dev->dev_index,
			"TLC_LLC_CONFIG  Offset=0x%x,Value=0x%x\n ASIP_LLC_CONFIG Offset=0x%x,Value=0x%x\n DSP_LLC_CONFIG  Offset=0x%x,Value=0x%x\n ICE_PAGE_WALK_AXI_ATTRIBUTES  Offset=0x%x,Value=0x%x\n",
			(cfg_default.mmu_base +
				cfg_default.mmu_tlc_axi_attri_offset),
			CVE_TLC_LLC_CONFIG,
			(cfg_default.mmu_base +
				cfg_default.mmu_asip_axi_attri_offset),
			CVE_ASIP_LLC_CONFIG,
			(cfg_default.mmu_base +
			    cfg_default.mmu_dsp_axi_attri_offset),
			CVE_DSP_LLC_CONFIG,
			(cfg_default.mmu_base +
				cfg_default.mmu_page_walk_axi_attri_offset),
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
	u32 err;
	int retval = 0;
	uint64_t value, mask, notify_ice_mask;
	struct cve_device_group *dg = cve_dg_get();

	err = ice_di_is_shared_read_error(cve_dev);
	if (err) {
		cve_os_dev_log_default(CVE_LOGLEVEL_INFO,
			cve_dev->dev_index,
			"shared_read_status value:%x\n",
			err);
	}

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
		ice_di_configure_clk_squashing(cve_dev, true);

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
		/* SW WA for STEP A */
		ice_di_configure_clk_squashing(cve_dev, false);

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

	if (dg->dump_conf.ice_reset)
		cve_os_dev_log_default(CVE_LOGLEVEL_INFO,
			cve_dev->dev_index,
			"ICE_RESET is done\n");

	/* configure the LLC after reset */
	configure_llc(cve_dev);

	/* configure default ICE frequency */
	configure_ice_frequency(cve_dev);

	return retval;
}

#define __max_u32 0xFFFFFFFF

/* if diff from max is < error val then counter needs to wrapped to
 * avoid overflow. so only add a extra difference from max allowed
 * after resetting the counter
 */
#define __handle_counter_wrap(hswc, cnt, cnt_wrap, val) \
do { \
	u32 temp; \
\
	temp = __max_u32 - ice_swc_counter_get(hswc, cnt); \
	if (temp < val) { \
		ice_swc_counter_set(hswc, cnt, 0); \
		ice_swc_counter_inc(hswc, cnt_wrap); \
		val = val - temp; \
	} \
\
	ice_swc_counter_add(hswc, cnt, val); \
} while (0)

#define __set_persistant_secc_counter(hswc, secc_err) \
	__handle_counter_wrap(hswc,\
			ICEDRV_SWC_DEVICE_COUNTER_ECC_SERRCOUNT, \
			ICEDRV_SWC_DEVICE_COUNTER_ECC_SERRCOUNT_WRAP, \
			secc_err)

#define __set_persistant_decc_counter(hswc, decc_err) \
	__handle_counter_wrap(hswc,\
			ICEDRV_SWC_DEVICE_COUNTER_ECC_DERRCOUNT, \
			ICEDRV_SWC_DEVICE_COUNTER_ECC_DERRCOUNT_WRAP, \
			decc_err)


void store_ecc_err_count(struct cve_device *cve_dev)
{
#ifndef RING3_VALIDATION

	uint32_t serr, derr, parity_err;
	union mmio_hub_mem_unmapped_err_id_t unmapped_err;

	serr = cve_os_read_mmio_32_force_print(cve_dev,
			cfg_default.mmio_ecc_serrcount_offset);
	ice_swc_counter_add(cve_dev->hswc_infer,
			ICEDRV_SWC_INFER_DEVICE_COUNTER_ECC_SERRCOUNT,
			serr);


	__set_persistant_secc_counter(cve_dev->hswc, serr);

	derr = cve_os_read_mmio_32_force_print(cve_dev,
			cfg_default.mmio_ecc_derrcount_offset);
	ice_swc_counter_add(cve_dev->hswc,
			ICEDRV_SWC_DEVICE_COUNTER_ECC_DERRCOUNT, derr);

	__set_persistant_decc_counter(cve_dev->hswc, derr);

	parity_err = cve_os_read_mmio_32_force_print(cve_dev,
			cfg_default.mmio_parity_errcount_offset);
	ice_swc_counter_add(cve_dev->hswc_infer,
			ICEDRV_SWC_INFER_DEVICE_COUNTER_PARITY_ERRCOUNT,
			parity_err);

	unmapped_err.val = cve_os_read_mmio_32_force_print(cve_dev,
			cfg_default.mmio_unmapped_err_id_offset);
	ice_swc_counter_set(cve_dev->hswc_infer,
			ICEDRV_SWC_INFER_DEVICE_COUNTER_UNMAPPED_ERR_ID,
			unmapped_err.field.TID_ERR);
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

static void __dump_mmu_fault_info(struct cve_device *ice)
{
	union ice_mmu_fault_info_t mmu_reg;
	u32 val[3];

	mmu_reg.val = cve_os_read_mmio_32(ice,
			cfg_default.mmu_base +
			cfg_default.mmu_fault_details_offset);
	val[0] = cve_os_read_mmio_32(ice,
			cfg_default.mmu_base +
			cfg_default.mmu_fault_linear_addr_offset);
	val[1] = cve_os_read_mmio_32(ice,
			cfg_default.mmu_base +
			cfg_default.mmu_fault_physical_addr_offset);
	val[2] = cve_os_read_mmio_32(ice,
			cfg_default.mmu_base +
			cfg_default.mmu_chicken_bits_offset);

	cve_os_log_default(CVE_LOGLEVEL_ERROR,
			"ICE%d MMU FaultDetail:0x%x[Src:%d{T:0,I:2,D:3,C:4} isRead:%d isL1:%d] FaultVA:0x%x FaultPA:0x%x ChickenBit:0x%x\n",
			ice->dev_index,
			mmu_reg.val,
			mmu_reg.mmu_fault_detail.ORIGINATOR,
			mmu_reg.mmu_fault_detail.RW_N,
			mmu_reg.mmu_fault_detail.L1,
			val[0], val[1], val[2]);
}

static void __dump_tlc_err_reg(struct cve_device *ice)
{
	union tlc_error_handling_reg_t tlc_err;
	u32 val[2];

	tlc_err.val = cve_os_read_mmio_32(ice,
			cfg_default.mmio_cbb_err_code_offset);
	val[0] = cve_os_read_mmio_32(ice,
			cfg_default.mmio_cbb_error_info_offset);
	val[1] = cve_os_read_mmio_32(ice,
			cfg_default.mmio_tlc_info_offset);
	cve_os_log_default(CVE_LOGLEVEL_ERROR,
			"ICE%d CbbErrCode:0x%x[Type:0x%x Category:0x%x Cbb:0x%x] CbbErrInfo:0x%x TlcInfo:0x%x\n",
			ice->dev_index, tlc_err.val,
			tlc_err.cbb_err_code.err_type,
			tlc_err.cbb_err_code.err_category,
			tlc_err.cbb_err_code.cbb_id,
			val[0], val[1]);
}

static void __dump_gp_reg(struct cve_device *ice)
{
	int i;
	u32 val[4];

	for (i = 0; i < ICE_MAX_GP_REG; i = i + 4) {
		val[0] = cve_os_read_mmio_32(ice,
				cfg_default.mmio_gp_regs_offset + i * 4);
		val[1] = cve_os_read_mmio_32(ice,
				cfg_default.mmio_gp_regs_offset +
				((i + 1) * 4));
		val[2] = cve_os_read_mmio_32(ice,
				cfg_default.mmio_gp_regs_offset +
				((i + 2) * 4));
		val[3] = cve_os_read_mmio_32(ice,
				cfg_default.mmio_gp_regs_offset +
				((i + 3) * 4));
		cve_os_log_default(CVE_LOGLEVEL_ERROR,
				"ICE%d GP%d:0x%x GP%d:0x%x GP%d:0x%x GP%d:0x%x\n",
				ice->dev_index, i, val[0],
				(i + 1), val[1], (i + 2), val[2],
				(i + 3), val[3]);
	}
}

void ice_dump_hw_err_info(struct cve_device *ice)
{
	__dump_mmu_fault_info(ice);
	__dump_tlc_err_reg(ice);
	__dump_gp_reg(ice);
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
	u32 max_freq_allowed;


	/* the ice value is in range of 0-11 so obtained thread num
	 * is in range of 4 - 15
	 */

	struct ice_hw_config_ice_freq *freq_config =
			(struct ice_hw_config_ice_freq *)ice_freq_config;

	uint32_t ice_index = freq_config->ice_num;
	uint32_t pcu_cr_thread_num = ice_index + 4;
	struct cve_device_group *device_group = g_cve_dev_group_list;

	dev = cve_device_get(ice_index);
	/* Check if this device is valid, might be NULL in case its masked */
	if (!dev) {
		retval = -ICEDRV_KERROR_ICE_NODEV;
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"Error:%d ICE%d does not exist\n",
				retval, ice_index);

		return retval;
	}

	max_freq_allowed = get_ice_max_freq();
	if ((freq_config->ice_freq < MIN_ICE_FREQ_PARAM) ||
	   (freq_config->ice_freq > max_freq_allowed ||
	   (freq_config->ice_freq % ICE_FREQ_DIVIDER_FACTOR != 0))) {
		retval = -ICEDRV_KERROR_INVAL_ICE_FREQ;
		cve_os_log_default(CVE_LOGLEVEL_ERROR,
		"ERROR:%d ice freq param should be in range of %d-%d , multiple of 25 ( freq:%u)\n",
			retval, MIN_ICE_FREQ_PARAM, max_freq_allowed,
			freq_config->ice_freq);

		return retval;
	}

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

void project_hook_interrupt_handler_exit(struct cve_device *cve_dev)
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
	struct cve_device_group __maybe_unused *dg = cve_dg_get();

	for (i = 0; i < ICE_PAGE_SZ_CONFIG_REG_COUNT; i++) {
		cve_os_write_mmio_32(cve_dev,
				(cfg_default.mmu_base +
				 cfg_default.mmu_page_sizes_offset + (i * 4)),
				page_sz_array[i]);
		cve_os_dev_log(dg->dump_conf.page_size_config ?
			    CVE_LOGLEVEL_INFO : CVE_LOGLEVEL_DEBUG,
				cve_dev->dev_index,
				"PAGE_SZ_CONFIG_REG Index=%d, offset=0x%x, Value=0x%x\n",
				i, (cfg_default.mmu_base +
				 cfg_default.mmu_page_sizes_offset + (i * 4)),
				page_sz_array[i]);
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
	u32 offset_bytes;

	if (dumpTrigger == cfg_default.ice_dump_now)
		offset_bytes = cfg_default.ice_tlc_low_base +
			cfg_default.ice_tlc_hi_dump_control_offset;
	else
		offset_bytes = cfg_default.ice_tlc_hi_base +
			cfg_default.ice_tlc_hi_dump_buf_offset;

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


void ice_di_configure_clk_squashing(struct cve_device *dev, bool disable)
{
	u32 offset, count = 10;
	u32 read_val, write_val = 0, mask = 0;
	u8 bo_id = (dev->dev_index / 2);

	if (!ice_get_a_step_enable_flag())
		return;

	offset = (ICEDC_ICEBO_OFFSET(bo_id) + ICEBO_GPSB_OFFSET
			+ cfg_default.gpsb_x1_regs_clk_gate_ctl_offset);


	read_val = cve_os_read_idc_mmio(dev, offset);
	mask = (1 << cfg_default.mem_clk_gate_ctl_dont_squash_iceclk_lsb);
	if (disable)
		write_val = (read_val | mask);
	else
		write_val = (read_val & ~mask);

	cve_os_write_idc_mmio(dev, offset, write_val);
	cve_os_log(CVE_LOGLEVEL_DEBUG,
			"ICEDC_ICEBO_CLK_GATE_CTL_OFFSET(0x%x): Read:0x%x Write:0x%x disable:%d\n",
			offset, read_val, write_val, disable);

	/* Check if register write is successful */
	while (count) {
		read_val = cve_os_read_idc_mmio(dev, offset);
		if (disable) {
			if ((read_val & mask) == mask)
				break;
		} else {
			if ((read_val | ~mask) == ~mask)
				break;
		}
		usleep_range(100, 110);

		/*TODO HACK: trace to track if reg value is correctly set */
		cve_os_log(CVE_LOGLEVEL_INFO,
			"ICEDC_ICEBO_CLK_GATE_CTL_OFFSET(0x%x): Read:0x%x Write:0x%x\n",
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
		"freq value has to be in the range of %d-%d MHz, multiple of 25\n",
		MIN_ICE_FREQ_PARAM, get_ice_max_freq());
	return ret;
}


static ssize_t show_ice_freq(struct kobject *kobj,
				struct kobj_attribute *attr,
				char *buf)
{
	cve_os_log_default(CVE_LOGLEVEL_INFO, "Not Implemented");

	return 0;
}

static ssize_t store_cbdump(struct kobject *kobj,
		struct kobj_attribute *attr,
		const char *buf, size_t count)
{
	int ret = 0, val;
	struct cve_device_group *dg = cve_dg_get();

	if (!dg) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"null dg pointer (%d) !!\n", -EINVAL);
		return -EINVAL;
	}

	ret = kstrtoint(buf, 10, &val);
	if (ret < 0)
		return ret;

	dg->dump_conf.cb_dump = (u8)val;

	return count;
}

static ssize_t show_cbdump(struct kobject *kobj,
				struct kobj_attribute *attr, char *buf)
{
	struct cve_device_group *dg = cve_dg_get();

	if (!dg) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"null dg pointer (%d) !!\n", -EINVAL);
		return -EINVAL;
	}
	return sprintf(buf, "%d\n", dg->dump_conf.cb_dump);
}

static ssize_t store_ptdump(struct kobject *kobj,
		struct kobj_attribute *attr,
		const char *buf, size_t count)
{
	int ret = 0, val;
	struct cve_device_group *dg = cve_dg_get();

	if (!dg) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"null dg pointer (%d) !!\n", -EINVAL);
		return -EINVAL;
	}

	ret = kstrtoint(buf, 10, &val);
	if (ret < 0)
		return ret;

	dg->dump_conf.pt_dump = (u8)val;

	return count;
}

static ssize_t show_ptdump(struct kobject *kobj,
				struct kobj_attribute *attr, char *buf)
{
	struct cve_device_group *dg = cve_dg_get();

	if (!dg) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"null dg pointer (%d) !!\n", -EINVAL);
		return -EINVAL;
	}
	return sprintf(buf, "%d\n", dg->dump_conf.pt_dump);
}

static ssize_t store_postpatchsurfdump(struct kobject *kobj,
		struct kobj_attribute *attr,
		const char *buf, size_t count)
{
	int ret = 0, val;

	struct cve_device_group *dg = cve_dg_get();

	if (!dg) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"null dg pointer (%d) !!\n", -EINVAL);
		return -EINVAL;
	}

	ret = kstrtoint(buf, 10, &val);
	if (ret < 0)
		return ret;

	dg->dump_conf.post_patch_surf_dump = (u8) val;

	return count;
}

static ssize_t show_postpatchsurfdump(struct kobject *kobj,
				struct kobj_attribute *attr, char *buf)
{
	struct cve_device_group *dg = cve_dg_get();

	if (!dg) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"null dg pointer (%d) !!\n", -EINVAL);
		return -EINVAL;
	}
	return sprintf(buf, "%d\n", dg->dump_conf.post_patch_surf_dump);
}

static ssize_t store_icereset(struct kobject *kobj,
		struct kobj_attribute *attr,
		const char *buf, size_t count)
{
	int ret = 0, val;

	struct cve_device_group *dg = cve_dg_get();

	if (!dg) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"null dg pointer (%d) !!\n", -EINVAL);
		return -EINVAL;
	}

	ret = kstrtoint(buf, 10, &val);
	if (ret < 0)
		return ret;

	dg->dump_conf.ice_reset = (u8) val;

	return count;
}

static ssize_t show_icereset(struct kobject *kobj,
				struct kobj_attribute *attr, char *buf)
{
	struct cve_device_group *dg = cve_dg_get();

	if (!dg) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"null dg pointer (%d) !!\n", -EINVAL);
		return -EINVAL;
	}
	return sprintf(buf, "%d\n", dg->dump_conf.ice_reset);
}

static ssize_t store_llcconfig(struct kobject *kobj,
		struct kobj_attribute *attr,
		const char *buf, size_t count)
{
	int ret = 0, val;
	struct cve_device_group *dg = cve_dg_get();

	if (!dg) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"null dg pointer (%d) !!\n", -EINVAL);
		return -EINVAL;
	}

	ret = kstrtoint(buf, 10, &val);
	if (ret < 0)
		return ret;

	dg->dump_conf.llc_config = (u8)val;

	return count;
}

static ssize_t show_llcconfig(struct kobject *kobj,
				struct kobj_attribute *attr, char *buf)
{
	struct cve_device_group *dg = cve_dg_get();

	if (!dg) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"null dg pointer (%d) !!\n", -EINVAL);
		return -EINVAL;
	}
	return sprintf(buf, "%d\n", dg->dump_conf.llc_config);
}

static ssize_t store_pagesizeconfig(struct kobject *kobj,
		struct kobj_attribute *attr,
		const char *buf, size_t count)
{
	int ret = 0, val;
	struct cve_device_group *dg = cve_dg_get();

	if (!dg) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"null dg pointer (%d) !!\n", -EINVAL);
		return -EINVAL;
	}

	ret = kstrtoint(buf, 10, &val);
	if (ret < 0)
		return ret;

	dg->dump_conf.page_size_config = (u8) val;

	return count;
}

static ssize_t show_pagesizeconfig(struct kobject *kobj,
		struct kobj_attribute *attr,
		char *buf)
{
	struct cve_device_group *dg = cve_dg_get();

	if (!dg) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"null dg pointer (%d) !!\n", -EINVAL);
		return -EINVAL;
	}
	return sprintf(buf, "%d\n", dg->dump_conf.page_size_config);
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
		"freq value has to be in the range of %d-%d MHz, multiple of 100\n",
		MIN_LLC_FREQ_PARAM, get_llc_max_freq());
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
	u32 max_freq_allowed;

	max_freq_allowed = get_llc_max_freq();
	freqset_s = (char *)buf;
	freqset_s = strim(freqset_s);

	if (freqset_s == NULL)
		return -EFAULT;

	ret = kstrtoint(freqset_s, 10, &freq_to_set);
	if (ret < 0)
		return ret;

	if (freq_to_set < MIN_LLC_FREQ_PARAM ||
			freq_to_set > max_freq_allowed ||
				freq_to_set % LLC_FREQ_DIVIDER_FACTOR != 0) {

		cve_os_log_default(CVE_LOGLEVEL_ERROR,
			"llc freq required has to be in range of %d-%d, multiple of 100\n",
			MIN_LLC_FREQ_PARAM, max_freq_allowed);
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
static int icebo_hw_config_llc_pmoninfo_sysfs_init(void)
{
	int ret;
	/*Create the pmoninfo file in hwconfig kobject */
	ret = sysfs_create_group(hwconfig_kobj, &llcpmon_attr_group);
	if (ret) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"llc pmon info sysfs group creation failed\n");
	}

	return ret;
}

static void icebo_hw_config_llc_pmoninfo_sysfs_term(void)
{
	/*Remove the pmoninfo file in hwconfig kobject */
	sysfs_remove_group(hwconfig_kobj, &llcpmon_attr_group);
}

static int icebo_hw_config_llc_pmon_sysfs_init(struct icebo_desc *bo)
{
	int ret;
	/*Create the icebo pmon file in hwconfig kobject */
	ret = sysfs_create_group(bo->icebo_kobj, &llcpmon_control_attr_group);
	if (ret) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"llc pmon info sysfs group creation failed\n");
	}

	return ret;
}

static void icebo_hw_config_llc_pmon_sysfs_term(struct icebo_desc *bo)
{
	/*Remove the pmoninfo file in hwconfig kobject */
	sysfs_remove_group(bo->icebo_kobj, &llcpmon_control_attr_group);
}

static void ice_hw_config_freq_sysfs_term(struct cve_device *ice_dev)
{
	/* Remove the filter files associated with ice<n> config kobject */
	sysfs_remove_group(ice_dev->ice_config_kobj, &freq_attr_group);
}

static void ice_hw_config_llc_sysfs_term(void)
{
	/* Remove the filter files associated with ice<n> config kobject */
	sysfs_remove_group(llcfreq_kobj, &llc_attr_group);
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

static int debug_dump_init(void)
{
	int ret;

	/* Create files for dump  */
	ret = sysfs_create_group(swdebug_kobj, &debug_attr_group);
	if (ret) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"debug_attr_group group creation failed\n");
	}
	return ret;
}

/*  function for debug print    */

int sw_debug_sysfs_init(void)
{
	int ret;

	FUNC_ENTER();
	/* create base subdir once */
	if (!icedrv_kobj) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"icedrv kobj doesn't exist\n");
		ret = -ENOMEM;
		goto out;
	}

	if (swdebug_kobj)
		goto dump_init;

	swdebug_kobj = kobject_create_and_add("swdebug", icedrv_kobj);
	if (!swdebug_kobj) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
					"swdebug kobj creation failed\n");
		ret = -ENOMEM;
		goto out;
	}

dump_init:
	ret = debug_dump_init();
	if (ret) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"debug_dump_init failed\n");
		goto swdebug_kobj_free;
	}
	goto out;

swdebug_kobj_free:
	kobject_put(swdebug_kobj);
	swdebug_kobj = NULL;

out:
	FUNC_LEAVE();
	return ret;
}

void sw_debug_sysfs_term(void)
{
	FUNC_ENTER();

	if (swdebug_kobj) {
		kobject_put(swdebug_kobj);
		swdebug_kobj = NULL;
		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"sw debug kobj deleted\n");
	}
	FUNC_LEAVE();
}

int hw_config_sysfs_init(struct cve_device *ice_dev)
{

	int ret = 0;
	struct cve_os_device *os_dev;
	struct cve_device_group *dg = g_cve_dev_group_list;
	struct icebo_desc *bo =
		&dg->dev_info.icebo_list[ice_dev->dev_index / 2];
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
		goto icebo_sysfs;

	hwconfig_kobj = kobject_create_and_add("hwconfig", icedrv_kobj);
	if (!hwconfig_kobj) {
		cve_os_dev_log(CVE_LOGLEVEL_ERROR, ice_dev->dev_index,
					"hwconfig kobj creation failed\n");
		ret = -ENOMEM;
		goto out;
	}
icebo_sysfs:
	if (bo->icebo_kobj)
		goto ice_sysfs;
	snprintf(name, sizeof(name), "icebo%d", bo->bo_id);
	bo->icebo_kobj = kobject_create_and_add(name, hwconfig_kobj);
	if (!bo->icebo_kobj) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"icebo%d kobj creation failed\n",
				bo->bo_id);
		ret = -ENOMEM;
		goto hwconfig_kobj_free;

	}
	ret = icebo_hw_config_llc_pmon_sysfs_init(bo);
	if (ret) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"icebo_hw_config_llc_pmon_sysfs_init failed\n");
		ret = -ENOMEM;
		goto icebo_kobj_free;

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
		goto icebo_sysfs_free;
	}
	ret = ice_hw_config_freq_sysfs_init(ice_dev);
	if (ret) {
		cve_os_dev_log(CVE_LOGLEVEL_ERROR, ice_dev->dev_index,
				"ice_hw_config_freq_sysfs_init failed\n");
		goto freq_kobj_free;
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
		if (ret) {
		cve_os_dev_log(CVE_LOGLEVEL_ERROR, ice_dev->dev_index,
				"ice_hw_config_llc_sysfs_init failed\n");
			goto llcfreq_kobj_free;
		}
		ret = icebo_hw_config_llc_pmoninfo_sysfs_init();
		if (ret) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
					"icebo_hw_config_llc_pmoninfo_sysfs_init failed\n");
			ret = -ENOMEM;
			goto llcfreq_sysfs_free;
		}
		goto out;
	}

	icebo_hw_config_llc_pmoninfo_sysfs_term();
llcfreq_sysfs_free:
	ice_hw_config_llc_sysfs_term();
llcfreq_kobj_free:
	kobject_put(llcfreq_kobj);
	llcfreq_kobj = NULL;
freq_sysfs_free:
	ice_hw_config_freq_sysfs_term(ice_dev);
freq_kobj_free:
	kobject_put(ice_dev->ice_config_kobj);
	ice_dev->ice_config_kobj = NULL;
icebo_sysfs_free:
	icebo_hw_config_llc_pmon_sysfs_term(bo);
icebo_kobj_free:
	kobject_put(bo->icebo_kobj);
	bo->icebo_kobj = NULL;
hwconfig_kobj_free:
	kobject_put(hwconfig_kobj);
	hwconfig_kobj = NULL;
out:
	FUNC_LEAVE();
	return ret;
}

void hw_config_sysfs_term(struct cve_device *ice_dev)
{
	struct cve_device_group *dg = g_cve_dev_group_list;
	struct icebo_desc *bo =
		&dg->dev_info.icebo_list[ice_dev->dev_index / 2];

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

	if (bo->icebo_kobj) {
		/*Resetting PMON registers before removing sysfs entries*/
		llc_pmon_config_sysfs(0, bo, true);
		kobject_put(bo->icebo_kobj);
		bo->icebo_kobj = NULL;
		cve_os_log(CVE_LOGLEVEL_DEBUG,
				"icebo%d kobj deleted\n", bo->bo_id);
	}

	if (hwconfig_kobj) {
		kobject_put(hwconfig_kobj);
		hwconfig_kobj = NULL;
		cve_os_dev_log(CVE_LOGLEVEL_DEBUG, ice_dev->dev_index,
					"hw_config kobj deleted\n");
	}

	FUNC_LEAVE();
}

static ssize_t show_llcpmoninfo(struct kobject *kobj,
			struct kobj_attribute *attr, char *buf)
{
	int ret = 0;
	u32 i;
	u32 size;
	struct llcpmoninfo_details llcpmon_arr[] = {
	__LLCPMONINFO(0, pre_defined_llc_pmon_cfg0[1],
		pre_defined_llc_pmon_cfg1[1], LLC_PMON_HIT_PER_ICE,
		"LLC HIT count of ICE0 in counter0 and ICE1 in counter1"),
	__LLCPMONINFO(1, pre_defined_llc_pmon_cfg0[2],
		pre_defined_llc_pmon_cfg1[2], LLC_PMON_MISS_PER_ICE,
		"LLC MISS count of ICE0 in counter0 and ICE1 in counter1"),
	__LLCPMONINFO(2, pre_defined_llc_pmon_cfg0[3],
		pre_defined_llc_pmon_cfg1[3], LLC_PMON_TRAFFIC_PER_ICE,
		"LLC HIT+MISS count of ICE0 in counter0 and ICE1 in counter1"),
	__LLCPMONINFO(3, pre_defined_llc_pmon_cfg0[4],
		pre_defined_llc_pmon_cfg1[4], LLC_PMON_HIT_MISS_OF_BO,
		"LLC HIT count of BO in counter0 and MISS count in counter1"),
	};

	size = sizeof(llcpmon_arr) / sizeof(struct llcpmoninfo_details);

	ret = sprintf((buf + ret),
		"-1, LLC_PMON_DISABLE_CONFIG, \"Disable LLC PMON configuration\"\n");
	for (i = 0; i < size; i++) {
		ret += sprintf((buf + ret), "%d, 0x%x, 0x%x, %s, \"%s\"\n",
		llcpmon_arr[i].index,
		llcpmon_arr[i].config_val0,
		llcpmon_arr[i].config_val1,
		llcpmon_arr[i].name,
		llcpmon_arr[i].desc);
	}
	ret += sprintf((buf + ret),
		"4, PMON_0_USER_CONFIG, PMON_1_USER_CONFIG, USER_DEFINED_CONFIG, \"User defined configiuration values of PMON 0,1\"\n");
	ret += sprintf((buf + ret),
		"5, PMON_2_USER_CONFIG, PMON_3_USER_CONFIG, USER_DEFINED_CONFIG, \"User defined configiuration values of PMON 2,3\"\n");

	return ret;
}

static ssize_t show_llcpmonconfig(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	int ret = 0;
	u8 bo_id;
	struct cve_device_group *dg = cve_dg_get();
	struct icebo_desc *bo;
	struct cve_device *dev;

	ret = sscanf(kobj->name, "icebo%hhd", &bo_id);
	if (ret < 1) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "failed getting ice bo id %s\n",
				kobj->name);
		return -EFAULT;
	}

	if (bo_id > MAX_NUM_ICEBO) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "wrong ice bo id %d\n", bo_id);
		return -EFAULT;
	}

	bo = &dg->dev_info.icebo_list[bo_id];
	if (bo == NULL) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "ICEBO%d doesn't exist\n",
							bo_id);
		return -EFAULT;
	}

	dev = bo->dev_list;
	if (dev == NULL) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"No device exists in the ICEBO%d\n",
							bo_id);
		return -EFAULT;
	}

	ret += sprintf((buf + ret),
		"BO:%hhd LLC PMON Config\nPMON0:0x%llx PMON1:0x%llx PMON2:0x%llx PMON3:0x%llx\n",
		bo_id,
		bo->llc_pmon_cfg.pmon0_cfg,
		bo->llc_pmon_cfg.pmon1_cfg,
		bo->llc_pmon_cfg.pmon2_cfg,
		bo->llc_pmon_cfg.pmon3_cfg);

	return ret;
}

static ssize_t show_llcpmon(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	int ret = 0;
	u8 bo_id;
	u32 offset;
	u64 cntr_value[4];
	struct cve_device_group *dg = cve_dg_get();
	struct icebo_desc *bo;
	struct cve_device *dev;

	ret = sscanf(kobj->name, "icebo%hhd", &bo_id);
	if (ret < 1) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "failed getting ice bo id %s\n",
				kobj->name);
		return -EFAULT;
	}

	if (bo_id > MAX_NUM_ICEBO) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "wrong ice BO id %d\n", bo_id);
		return -EFAULT;
	}

	bo = &dg->dev_info.icebo_list[bo_id];
	if (bo == NULL) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "ICEBO%d doesn't exist\n",
							bo_id);
		return -EFAULT;
	}

	dev = bo->dev_list;
	if (dev == NULL) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"No device exists in the ICEBO%d\n",
							bo_id);
		return -EFAULT;
	}

	offset = ICEDC_ICEBO_OFFSET(bo_id) +
		cfg_default.a2i_icebo_pmon_counter_0_offset;
	cntr_value[0] = cve_os_read_idc_mmio(dev, offset);

	offset = ICEDC_ICEBO_OFFSET(bo_id) +
		cfg_default.a2i_icebo_pmon_counter_1_offset;
	cntr_value[1] = cve_os_read_idc_mmio(dev, offset);

	offset = ICEDC_ICEBO_OFFSET(bo_id) +
		cfg_default.a2i_icebo_pmon_counter_2_offset;
	cntr_value[2] = cve_os_read_idc_mmio(dev, offset);

	offset = ICEDC_ICEBO_OFFSET(bo_id) +
		cfg_default.a2i_icebo_pmon_counter_3_offset;
	cntr_value[3] = cve_os_read_idc_mmio(dev, offset);

	ret += sprintf((buf + ret),
		"BO:%hhd LLC PMON Counters\nCOUNTER0:0x%llx COUNTER1:0x%llx COUNTER2:0x%llx COUNTER3:0x%llx\n",
		bo_id,
		cntr_value[0],
		cntr_value[1],
		cntr_value[2],
		cntr_value[3]);

	return ret;
}


static ssize_t store_llcpmon(struct kobject *kobj,
		struct kobj_attribute *attr,
		const char *buf, size_t count)
{
	u8 bo_id;
	int ret = 0;
	char *llcpmon_s, *pmonindex_s;
	int tmp_pmonindex;
	u32 pmonindex;
	char *user_config;
	char *user_cfg0_s, *user_cfg1_s;
	u64 user_cfg0 = 0, user_cfg1 = 0;
	struct cve_device_group *dg = cve_dg_get();
	struct icebo_desc *bo;
	struct cve_device *dev;
	bool pmon_0_1 = true;

	FUNC_ENTER();
	ret = sscanf(kobj->name, "icebo%hhd", &bo_id);
	if (ret < 1) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "failed getting ice bo id %s\n",
				kobj->name);
		return -EFAULT;
	}

	if (bo_id > MAX_NUM_ICEBO) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "wrong ice bo id %d\n", bo_id);
		return -EFAULT;
	}

	bo = &dg->dev_info.icebo_list[bo_id];
	if (bo == NULL) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "ICEBO%d doesn't exist\n",
					bo_id);
		return -EFAULT;
	}

	llcpmon_s = (char *)buf;
	llcpmon_s = strim(llcpmon_s);

	if (llcpmon_s == NULL)
		return -EFAULT;

	user_config = strchr(buf, ':');

	if (user_config == NULL) {
		ret = kstrtoint(llcpmon_s, 10, &tmp_pmonindex);
		if (ret < 0)
			return ret;
		if (tmp_pmonindex == MAX_LLCPMON_CONFIG - 3 ||
				tmp_pmonindex == MAX_LLCPMON_CONFIG - 2) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
				"Need to configure pmon user config hex values\n");
			return -EINVAL;
		}
	} else {
		pmonindex_s = strsep((char **)&llcpmon_s, ":");
		if (pmonindex_s == NULL)
			return -EINVAL;

		pmonindex_s = strim(pmonindex_s);
		ret = kstrtoint(pmonindex_s, 0, &tmp_pmonindex);
		if (ret < 0)
			return ret;

		if (tmp_pmonindex > MAX_LLCPMON_CONFIG - 2)
			return -EINVAL;

		if (tmp_pmonindex < MAX_LLCPMON_CONFIG - 3) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
				"Providing the config index is sufficient\n");
			return -EINVAL;
		}
		pmonindex = tmp_pmonindex + 1;
		user_cfg0_s = strsep((char **)&llcpmon_s, ",");

		if (user_cfg0_s == NULL)
			return -EINVAL;

		user_cfg0_s = strim(user_cfg0_s);

		user_cfg1_s = strsep((char **)&llcpmon_s, ",");

		if (user_cfg1_s == NULL)
			return -EINVAL;

		user_cfg1_s = strim(user_cfg1_s);

		ret = kstrtoull(user_cfg0_s, 16, &user_cfg0);
		if (ret < 0)
			return ret;

		ret = kstrtoull(user_cfg1_s, 16, &user_cfg1);
		if (ret < 0)
			return ret;
	}

	cve_os_log(CVE_LOGLEVEL_DEBUG, "index:%d\n", tmp_pmonindex);
	ret = cve_os_lock(&g_cve_driver_biglock, CVE_INTERRUPTIBLE);
	if (ret != 0)
		return -ERESTARTSYS;
	bo->llc_pmon_cfg.disable_llc_pmon = false;
	if (tmp_pmonindex < 0) {
		/*for PMON disable*/
		pmonindex = 0;
		ret = llc_pmon_config_sysfs(pmonindex, bo, pmon_0_1);
	} else if (tmp_pmonindex < MAX_LLCPMON_CONFIG - 3) {
		/* for all pre-define PMON config*/
		pmonindex = tmp_pmonindex + 1;
		ret = llc_pmon_config_sysfs(pmonindex, bo, pmon_0_1);
	} else {
		pmonindex = tmp_pmonindex + 1;
		dev = bo->dev_list;
		if (tmp_pmonindex == MAX_LLCPMON_CONFIG - 2) {
			pmon_0_1 = false;
			bo->llc_pmon_cfg.pmon2_cfg = user_cfg0;
			bo->llc_pmon_cfg.pmon3_cfg = user_cfg1;
			cve_os_log_default(CVE_LOGLEVEL_INFO,
				"llc pmon user config request icebo%d pmon2:0x%llx pmon3:0x%llx\n",
				bo->bo_id, bo->llc_pmon_cfg.pmon2_cfg,
						bo->llc_pmon_cfg.pmon3_cfg);
		} else {
			bo->llc_pmon_cfg.pmon0_cfg = user_cfg0;
			bo->llc_pmon_cfg.pmon1_cfg = user_cfg1;
			cve_os_log_default(CVE_LOGLEVEL_INFO,
				"llc pmon user config request icebo%d pmon0:0x%llx pmon1:0x%llx\n",
				bo->bo_id, bo->llc_pmon_cfg.pmon0_cfg,
						bo->llc_pmon_cfg.pmon1_cfg);
		}
		ice_di_start_llc_pmon(dev, pmon_0_1);
	}
	cve_os_unlock(&g_cve_driver_biglock);

	if (ret < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "llc pmon config failed\n");
		return ret;
	}

	FUNC_LEAVE();
	return count;
}

static int llc_pmon_config_sysfs(u32 pmonindex, struct icebo_desc *bo,
							bool pmon_0_1)
{
	int ret = 0;
	u32 offset;
	struct cve_device *dev;

	FUNC_ENTER();
	switch (pmonindex) {
	/*Disable LLC PMON */
	case 0:
		bo->llc_pmon_cfg.pmon0_cfg = 0x0;
		bo->llc_pmon_cfg.pmon1_cfg = 0x0;
		bo->llc_pmon_cfg.pmon2_cfg = 0x0;
		bo->llc_pmon_cfg.pmon3_cfg = 0x0;
		bo->llc_pmon_cfg.disable_llc_pmon = true;
		dev = bo->dev_list;
		offset = ICEDC_ICEBO_OFFSET(bo->bo_id) +
				cfg_default.a2i_icebo_pmon_global_offset;
		cve_os_write_idc_mmio(dev, offset, 0x0);
		cve_os_write_idc_mmio(dev, offset, LLC_PMON_RESET);
		cve_os_log_default(CVE_LOGLEVEL_INFO,
				"disbaling llc pmon for icebo%d\n", bo->bo_id);
		break;
	/*Pre Defined configurations of PMON0 and PMON1*/
	case 1 ... (MAX_LLCPMON_CONFIG - 2):
		bo->llc_pmon_cfg.pmon0_cfg =
				pre_defined_llc_pmon_cfg0[pmonindex];
		bo->llc_pmon_cfg.pmon1_cfg =
				pre_defined_llc_pmon_cfg1[pmonindex];
		dev = bo->dev_list;
		ice_di_start_llc_pmon(dev, pmon_0_1);
		cve_os_log(CVE_LOGLEVEL_DEBUG,
		"llc pmon config request icebo%d pmon0:0x%llx pmon1:0x%llx\n",
			bo->bo_id, bo->llc_pmon_cfg.pmon0_cfg,
					bo->llc_pmon_cfg.pmon1_cfg);
		break;
	default:
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"unsupported llc pmon index\n");
		ret = -EINVAL;
		goto out;
	}
out:
	FUNC_LEAVE();
	return ret;
}

int __init_ice_iccp(struct cve_device *dev)
{
	struct cve_device_group *p = g_cve_dev_group_list;
	struct icebo_desc *bo = &p->dev_info.icebo_list[dev->dev_index / 2];
	u8 bo_id = (dev->dev_index / 2);
	u32 config2_offset, config3_offset;
	union mem_iccp_config2_t config2;
	union mem_iccp_config3_t config3;

	if (bo->iccp_init_done == true)
		goto out;

	config2_offset = (ICEDC_ICEBO_OFFSET(bo_id) + ICEBO_GPSB_OFFSET
			+ cfg_default.gpsb_x1_regs_iccp_config2_offset);
	config3_offset = (ICEDC_ICEBO_OFFSET(bo_id) + ICEBO_GPSB_OFFSET
			+ cfg_default.gpsb_x1_regs_iccp_config3_offset);
	config2.val = cve_os_read_idc_mmio(dev, config2_offset);
	config2.field.RESET_CDYN = ice_get_reset_cdyn_val();
	config2.field.INITIAL_CDYN = ice_get_initial_cdyn_val();
	cve_os_write_idc_mmio(dev, config2_offset, config2.val);
	config3.val = cve_os_read_idc_mmio(dev, config3_offset);
	config3.field.BLOCKED_CDYN = ice_get_blocked_cdyn_val();
	cve_os_write_idc_mmio(dev, config3_offset, config3.val);
	bo->iccp_init_done = true;
out:
	return 0;
}

void __term_ice_iccp(struct cve_device *dev)
{
	/* place holder */
}

#endif

void ice_di_start_llc_pmon(struct cve_device *dev, bool pmon_0_1)
{
	u32 offset;
	u32 bo_id = (dev->dev_index >> 1);
	struct cve_device_group *dg = g_cve_dev_group_list;
	ICEBO_PMON_GLOBAL_T reg;
	u32 cfg0_value, cfg1_value;

	reg.val = 0;
	/* MEM_A2I_ICEBAR_ICEBO_PMON_GLOBAL_MMOFFSET */
	/* Stops all counters but doesnot reset them */
	offset = ICEDC_ICEBO_OFFSET(bo_id) +
			cfg_default.a2i_icebo_pmon_global_offset;
	reg.val = cve_os_read_idc_mmio(dev, offset);
	cve_os_write_idc_mmio(dev, offset, 0x0);

	/*Read LLC PMON counters before re-configuring*/
	ice_di_read_llc_pmon(dev);

	if (pmon_0_1) {
		cfg0_value =
			dg->dev_info.icebo_list[bo_id].llc_pmon_cfg.pmon0_cfg;
		cfg1_value =
			dg->dev_info.icebo_list[bo_id].llc_pmon_cfg.pmon1_cfg;
		/* MEM_A2I_ICEBAR_ICEBO_PMON_EVENT_0_MMOFFSET */
		offset = ICEDC_ICEBO_OFFSET(bo_id) +
			cfg_default.a2i_icebo_pmon_event_0_offset;
		cve_os_write_idc_mmio(dev, offset, cfg0_value);

		/* MEM_A2I_ICEBAR_ICEBO_PMON_EVENT_1_MMOFFSET */
		offset = ICEDC_ICEBO_OFFSET(bo_id) +
			cfg_default.a2i_icebo_pmon_event_1_offset;

		cve_os_write_idc_mmio(dev, offset, cfg1_value);

		reg.field.enable_counter_0 = 1;
		reg.field.enable_counter_1 = 1;
	} else {
		cfg0_value =
			dg->dev_info.icebo_list[bo_id].llc_pmon_cfg.pmon2_cfg;
		cfg1_value =
			dg->dev_info.icebo_list[bo_id].llc_pmon_cfg.pmon3_cfg;
		/* MEM_A2I_ICEBAR_ICEBO_PMON_EVENT_2_MMOFFSET */
		offset = ICEDC_ICEBO_OFFSET(bo_id) +
			cfg_default.a2i_icebo_pmon_event_2_offset;
		cve_os_write_idc_mmio(dev, offset, cfg0_value);

		/* MEM_A2I_ICEBAR_ICEBO_PMON_EVENT_3_MMOFFSET */
		offset = ICEDC_ICEBO_OFFSET(bo_id) +
			cfg_default.a2i_icebo_pmon_event_3_offset;

		cve_os_write_idc_mmio(dev, offset, cfg1_value);


		reg.field.enable_counter_2 = 1;
		reg.field.enable_counter_3 = 1;
	}
	reg.field.reset_pmon = 0;
	/* MEM_A2I_ICEBAR_ICEBO_PMON_STATUS_MMOFFSET */
	/* Cleans up any sticky overflow bits */
	offset = ICEDC_ICEBO_OFFSET(bo_id) +
			cfg_default.a2i_icebo_pmon_status_offset;
	cve_os_write_idc_mmio(dev, offset, 0x0);

	/* MEM_A2I_ICEBAR_ICEBO_PMON_GLOBAL_MMOFFSET */
	/* Reset all counter and start required counters*/
	offset = ICEDC_ICEBO_OFFSET(bo_id) +
			cfg_default.a2i_icebo_pmon_global_offset;
	cve_os_write_idc_mmio(dev, offset, LLC_PMON_RESET);
	cve_os_write_idc_mmio(dev, offset, reg.val);

	cve_os_dev_log(CVE_LOGLEVEL_DEBUG,
		dev->dev_index,
		"LLC PMON reset done for ICE_BO:%u", bo_id);
}

void ice_di_read_llc_pmon(struct cve_device *dev)
{
	u32 offset;
	u64 __maybe_unused pmon_cntr[4];
	u32 bo_id = (dev->dev_index >> 1);

	/* MEM_A2I_ICEBAR_ICEBO_PMON_COUNTER_0_MMOFFSET */
	offset = ICEDC_ICEBO_OFFSET(bo_id) +
			cfg_default.a2i_icebo_pmon_counter_0_offset;
	pmon_cntr[0] = cve_os_read_idc_mmio(dev, offset);

	/* MEM_A2I_ICEBAR_ICEBO_PMON_COUNTER_1_MMOFFSET */
	offset = ICEDC_ICEBO_OFFSET(bo_id) +
			cfg_default.a2i_icebo_pmon_counter_1_offset;
	pmon_cntr[1] = cve_os_read_idc_mmio(dev, offset);

	/* MEM_A2I_ICEBAR_ICEBO_PMON_COUNTER_2_MMOFFSET */
	offset = ICEDC_ICEBO_OFFSET(bo_id) +
			cfg_default.a2i_icebo_pmon_counter_2_offset;
	pmon_cntr[2] = cve_os_read_idc_mmio(dev, offset);

	/* MEM_A2I_ICEBAR_ICEBO_PMON_COUNTER_3_MMOFFSET */
	offset = ICEDC_ICEBO_OFFSET(bo_id) +
			cfg_default.a2i_icebo_pmon_counter_3_offset;
	pmon_cntr[3] = cve_os_read_idc_mmio(dev, offset);

	cve_os_dev_log(CVE_LOGLEVEL_DEBUG, dev->dev_index,
			"llc pmon counter values of BO:%u Counter0:0x%llx Counter1:0x%llx Counter2:0x%llx Counter3:0x%llx",
				bo_id, pmon_cntr[0], pmon_cntr[1],
				pmon_cntr[2], pmon_cntr[3]);
}

u32 __get_ice_max_freq(void)
{
	struct cve_device_group *dg;

	dg = cve_dg_get();

	return dg->ice_max_freq;
}

void __store_ice_max_freq(void)
{
	struct cve_device_group *dg;
	u64 freq;
	u32 val;

	freq = get_ice_freq();
	val = freq & 0xFFFFFFFF;
	dg = cve_dg_get();
	dg->ice_max_freq = (max_ice_ratio(val) * 25);
}

u32 __get_llc_max_freq(void)
{
	struct cve_device_group *dg;

	dg = cve_dg_get();

	return dg->llc_max_freq;
}

void __store_llc_max_freq(void)
{
	struct cve_device_group *dg;
	u64 freq;
	u32 val_low;

	freq = get_llc_freq();
	val_low = freq & 0xFFFFFFFF;
	dg = cve_dg_get();
	dg->llc_max_freq = (max_llc_ratio(val_low) * 100);
}

int __restore_llc_max_freq(void)
{
	struct ice_hw_config_llc_freq freq_conf;
	struct cve_device_group *dg;
	int ret = 0;

	dg = cve_dg_get();
	freq_conf.llc_freq_min = 0;
	freq_conf.llc_freq_max = dg->llc_max_freq;
	cve_os_log(CVE_LOGLEVEL_INFO,
		"Setting Max LLC freq to:%u\n", freq_conf.llc_freq_max);

	ret = set_llc_freq((void *)&freq_conf);

	return ret;
}
