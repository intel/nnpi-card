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

#include "ice_debug.h"
#include "cve_device.h"
#include "cve_driver.h"
#include "osmm_interface.h"
#include "device_interface.h"
#include "project_device_interface.h"

const char *get_cve_jobs_group_status_str(uint32_t status)
{
	switch (status) {

	case CVE_JOBSGROUPSTATUS_PENDING:
		return "JOBSGROUPSTATUS_PENDING";
	case CVE_JOBSGROUPSTATUS_DISPATCHED:
		return "JOBSGROUPSTATUS_DISPATCHED";
	case CVE_JOBSGROUPSTATUS_COMPLETED:
		return "JOBSGROUPSTATUS_COMPLETED";
	case CVE_JOBSGROUPSTATUS_ABORTED:
		return "JOBSGROUPSTATUS_ABORTED";
	case CVE_JOBSGROUPSTATUS_NORESOURCE:
		return "CVE_JOBSGROUPSTATUS_NORESOURCE";
	case CVE_JOBSGROUPSTATUS_ERROR:
		return "CVE_JOBSGROUPSTATUS_ERROR";
	default:
		return "Unknown";
	}
}

const char *get_osmm_memory_type_str(uint32_t type)
{
	switch (type) {

	case OSMM_KERNEL_MEMORY:
		return "KERNEL_MEMORY";
	case OSMM_USER_MEMORY:
		return "USER_MEMORY";
	case OSMM_SHARED_MEMORY:
		return "SHARED_MEMORY";
	default:
		return "Unknown";
	}
}

const char *get_cve_memory_protection_str(uint32_t prot)
{
	switch (prot) {

	case CVE_MM_PROT_READ:
		return "R";
	case CVE_MM_PROT_WRITE:
		return "W";
	case (CVE_MM_PROT_READ | CVE_MM_PROT_WRITE):
		return "RW";
	case CVE_MM_PROT_EXEC:
		return "X";
	case (CVE_MM_PROT_READ | CVE_MM_PROT_EXEC):
		return "RX";
	default:
		return "Unknown";
	}
}

const char *get_cve_surface_direction_str(uint32_t dir)
{
	switch (dir) {

	case CVE_SURFACE_DIRECTION_IN:
		return "IN";
	case CVE_SURFACE_DIRECTION_OUT:
		return "OUT";
	case CVE_SURFACE_DIRECTION_INOUT:
		return "INOUT";
	default:
		return "Unknown";
	}
}

const char *get_fw_binary_type_str(uint32_t type)
{
	switch (type) {

	case CVE_FW_TLC_TYPE:
		return "TLC";
	case CVE_FW_IVP_MFW_TYPE:
		return "IVP_MFW";
	case CVE_FW_ASIP_MFW_TYPE:
		return "ASIP_MFW";
	case CVE_FW_IVP_BANK0_TYPE:
		return "IVP_BANK0";
	case CVE_FW_IVP_BANK1_TYPE:
		return "IVP_BANK1";
	case CVE_FW_ASIP_BANK0_TYPE:
		return "ASIP_BANK0";
	case CVE_FW_ASIP_BANK1_TYPE:
		return "ASIP_BANK1";
	case CVE_FW_CB_TYPE_START:
		return "EMB_CB";
	default:
		return "Unknown";
	}
}

const char *get_idc_regs_str(uint32_t offset)
{
	if (offset == cfg_default.bar0_mem_idcspare_offset)
		return "IDC_ICE_DBG_INDICATION_REG";
	if (offset == cfg_default.bar0_mem_idcintst_offset)
		return "IDC_INTR_STATUS_LOW_REG";
	if (offset == cfg_default.bar0_mem_idcintst_offset + 4)
		return "IDC_INTR_STATUS_HIGH_REG";
	if (offset == cfg_default.bar0_mem_iceintst_offset)
		return "ICE_INTR_STATUS_LOW_REG";
	if (offset == cfg_default.bar0_mem_iceintst_offset + 4)
		return "ICE_INTR_STATUS_HIGH_REG";
	if (offset == cfg_default.bar0_mem_icepool0_offset)
		return "ICEPOOL0_REG";
	if (offset == cfg_default.bar0_mem_icepool1_offset)
		return "ICEPOOL1_REG";
	if (offset == cfg_default.bar0_mem_icepool2_offset)
		return "ICEPOOL2_REG";
	if (offset == cfg_default.bar0_mem_icepool3_offset)
		return "ICEPOOL3_REG";
	if (offset == cfg_default.bar0_mem_icepool4_offset)
		return "ICEPOOL4_REG";
	if (offset == cfg_default.bar0_mem_icepool5_offset)
		return "ICEPOOL5_REG";
	if (offset == cfg_default.bar0_mem_icenota0_offset)
		return "NOTFICATION_ADDR0_REG";
	if (offset == cfg_default.bar0_mem_icenota1_offset)
		return "NOTFICATION_ADDR1_REG";
	if (offset == cfg_default.bar0_mem_icenota2_offset)
		return "NOTFICATION_ADDR2_REG";
	if (offset == cfg_default.bar0_mem_icenota3_offset)
		return "NOTFICATION_ADDR3_REG";
	if (offset == cfg_default.bar0_mem_evctprot0_offset)
		return "CNTR_0_ACCESS_CONTROL_REG";
	if (offset == cfg_default.bar0_mem_evctprot1_offset)
		return "CNTR_1_ACCESS_CONTROL_REG";
	if (offset == cfg_default.bar0_mem_evctprot2_offset)
		return "CNTR_2_ACCESS_CONTROL_REG";
	if (offset == cfg_default.bar0_mem_evctprot3_offset)
		return "CNTR_3_ACCESS_CONTROL_REG";
	if (offset == cfg_default.bar0_mem_evctprot4_offset)
		return "CNTR_4_ACCESS_CONTROL_REG";
	if (offset == cfg_default.bar0_mem_evctprot5_offset)
		return "CNTR_5_ACCESS_CONTROL_REG";
	if (offset == cfg_default.bar0_mem_evctprot6_offset)
		return "CNTR_6_ACCESS_CONTROL_REG";
	if (offset == cfg_default.bar0_mem_evctprot7_offset)
		return "CNTR_7_ACCESS_CONTROL_REG";
	if (offset == cfg_default.bar0_mem_evctprot8_offset)
		return "CNTR_8_ACCESS_CONTROL_REG";
	if (offset == cfg_default.bar0_mem_evctprot9_offset)
		return "CNTR_9_ACCESS_CONTROL_REG";
	if (offset == cfg_default.bar0_mem_evctprot10_offset)
		return "CNTR_10_ACCESS_CONTROL_REG";
	if (offset == cfg_default.bar0_mem_evctprot11_offset)
		return "CNTR_11_ACCESS_CONTROL_REG";
	if (offset == cfg_default.bar0_mem_evctprot12_offset)
		return "CNTR_12_ACCESS_CONTROL_REG";
	if (offset == cfg_default.bar0_mem_evctprot13_offset)
		return "CNTR_13_ACCESS_CONTROL_REG";
	if (offset == cfg_default.bar0_mem_evctprot14_offset)
		return "CNTR_14_ACCESS_CONTROL_REG";
	if (offset == cfg_default.bar0_mem_evctprot15_offset)
		return "CNTR_15_ACCESS_CONTROL_REG";
	if (offset == cfg_default.bar0_mem_evctprot16_offset)
		return "CNTR_16_ACCESS_CONTROL_REG";
	if (offset == cfg_default.bar0_mem_evctprot17_offset)
		return "CNTR_17_ACCESS_CONTROL_REG";
	if (offset == cfg_default.bar0_mem_evctprot18_offset)
		return "CNTR_18_ACCESS_CONTROL_REG";
	if (offset == cfg_default.bar0_mem_evctprot19_offset)
		return "CNTR_19_ACCESS_CONTROL_REG";
	if (offset == cfg_default.bar0_mem_evctprot20_offset)
		return "CNTR_20_ACCESS_CONTROL_REG";
	if (offset == cfg_default.bar0_mem_evctprot21_offset)
		return "CNTR_21_ACCESS_CONTROL_REG";
	if (offset == cfg_default.bar0_mem_evctprot22_offset)
		return "CNTR_22_ACCESS_CONTROL_REG";
	if (offset == cfg_default.bar0_mem_evctprot23_offset)
		return "CNTR_23_ACCESS_CONTROL_REG";
	if (offset == cfg_default.bar0_mem_evctprot24_offset)
		return "CNTR_24_ACCESS_CONTROL_REG";
	if (offset == cfg_default.bar0_mem_evctprot25_offset)
		return "CNTR_25_ACCESS_CONTROL_REG";
	if (offset == cfg_default.bar0_mem_evctprot26_offset)
		return "CNTR_26_ACCESS_CONTROL_REG";
	if (offset == cfg_default.bar0_mem_evctprot27_offset)
		return "CNTR_27_ACCESS_CONTROL_REG";
	if (offset == cfg_default.bar0_mem_evctprot28_offset)
		return "CNTR_28_ACCESS_CONTROL_REG";
	if (offset == cfg_default.bar0_mem_evctprot29_offset)
		return "CNTR_29_ACCESS_CONTROL_REG";
	if (offset == cfg_default.bar0_mem_evctprot30_offset)
		return "CNTR_30_ACCESS_CONTROL_REG";
	if (offset == cfg_default.bar0_mem_evctprot31_offset)
		return "CNTR_31_ACCESS_CONTROL_REG";
	if (offset == cfg_default.bar0_mem_icerst_offset)
		return "ICE_RESET_REG";
	if (offset == cfg_default.bar0_mem_icerdy_offset)
		return "ICE_READY_REG";
	if (offset == cfg_default.bar0_mem_icenote_offset)
		return "ICE_NOTIFY_REG";
	if (offset == cfg_default.bar0_mem_iceinten_offset)
		return "ICE_INTR_ENABLE_REG";
	if (offset == cfg_default.bar0_mem_iceinten_offset + 4)
		return "ICE_ERR_INTR_ENABLE_REG";
	if (offset == cfg_default.bar0_mem_idcinten_offset)
		return "IDC_INTR_ENABLE_LOW_REG";
	if (offset == cfg_default.bar0_mem_idcinten_offset + 4)
		return "IDC_INTR_ENABLE_HIGH_REG";
	if (offset == cfg_default.bar0_mem_icepe_offset)
		return "ICE_POWER_ENABLE_REG";
	if (offset == cfg_default.bar0_mem_icemasksts_offset)
		return "ICE_MASK_REG";
	else
		return "Unknown";
}
const char *get_other_regs_str(uint32_t offset)
{
	if (offset == INVALID_OFFSET)
		return "Register offset does not exist";
	if (offset == cfg_default.mmio_hw_revision_offset)
		return "HW_REVISION_REG";
	else
		return "Unknown";
}
const char *get_regs_str(uint32_t offset)
{

	if (offset == cfg_default.mmu_base +
				cfg_default.mmu_axi_tbl_pt_idx_bits_offset)
		return "AXI_TABLE_PT_INDEX_REG";
	if (offset == cfg_default.mmu_base +
				cfg_default.mmu_tlc_axi_attri_offset)
		return "TLC_AXI_ATTRIBUTES_REG";
	if (offset == cfg_default.mmu_base +
				cfg_default.mmu_asip_axi_attri_offset)
		return "ASIP_AXI_ATTRIBUTES_REG";
	if (offset == cfg_default.mmu_base +
				cfg_default.mmu_dsp_axi_attri_offset)
		return "DSP_AXI_ATTRIBUTES_REG";
	if (offset == cfg_default.mmu_base +
				cfg_default.mmu_page_walk_axi_attri_offset)
		return "PAGE_WALK_AXI_ATTRIBUTES_REG";
	if (offset == cfg_default.mmio_dtf_ctrl_offset)
		return "DTF_CONTROL_REG";
	if (offset == cfg_default.mmio_pre_idle_delay_cnt_offset)
		return "PRE_IDLE_DELAY_COUNT_REG";
	if (offset == cfg_default.mmio_cve_config_offset)
		return "ICE_CONFIG_REG";
	if (offset == cfg_default.ice_prog_cores_ctrl_offset)
		return "PROG_CORES_CONTROL_REG";
	if (offset == cfg_default.mmio_dpcg_control)
		return "DPCG_CONTROL_REG";
#ifdef _DEBUG
	if (offset == cfg_default.ice_dbg_cbbid_base +
			cfg_default.ice_dbg_cbbid_cfg_offset + (1 * 4))
		return "ICE_DEBUG_CFG_REG";
#endif
	if (offset == cfg_default.mmio_cb_doorbell_offset)
		return "CB_DOORBELL_REG";
	if (offset == cfg_default.mmio_intr_mask_offset)
		return "INTERRUPT_MASK_REG";
	if (offset == cfg_default.mmio_tlc_pulse_offset)
		return "TLC_WR_PULSE_REG";
	if (offset == cfg_default.mmio_intr_status_offset)
		return "INTERRUPT_STATUS_REG";
	if (offset == cfg_default.mmu_atu0_base +
			cfg_default.ice_mmu_1_system_map_mem_invalidate_offset)
		return "MMU_ATU0_MEM_INVALIDATE_REG";
	if (offset == cfg_default.mmu_atu1_base +
			cfg_default.ice_mmu_1_system_map_mem_invalidate_offset)
		return "MMU_ATU1_MEM_INVALIDATE_REG";
	if (offset == cfg_default.mmu_atu2_base +
			cfg_default.ice_mmu_1_system_map_mem_invalidate_offset)
		return "MMU_ATU2_MEM_INVALIDATE_REG";
	if (offset == cfg_default.mmu_atu3_base +
			cfg_default.ice_mmu_1_system_map_mem_invalidate_offset)
		return "MMU_ATU3_MEM_INVALIDATE_REG";
	if (offset == cfg_default.mmu_atu0_base +
		       cfg_default.ice_mmu_1_system_map_mem_pt_base_addr_offset)
		return "MMU_ATU0_PT_BASE_ADDR_REG";
	if (offset == cfg_default.mmu_atu1_base +
		       cfg_default.ice_mmu_1_system_map_mem_pt_base_addr_offset)
		return "MMU_ATU1_PT_BASE_ADDR_REG";
	if (offset == cfg_default.mmu_atu2_base +
		       cfg_default.ice_mmu_1_system_map_mem_pt_base_addr_offset)
		return "MMU_ATU2_PT_BASE_ADDR_REG";
	if (offset == cfg_default.mmu_atu3_base +
		       cfg_default.ice_mmu_1_system_map_mem_pt_base_addr_offset)
		return "MMU_ATU3_PT_BASE_ADDR_REG";
	if (offset == cfg_default.ice_tlc_hi_base +
				cfg_default.ice_tlc_hi_dump_buf_offset)
		return "TLC_DUMP_CONFIG";
	if (offset == cfg_default.ice_tlc_hi_base +
			cfg_default.ice_tlc_hi_tlc_control_ucmd_reg_offset)
		return "TLC_HI_GENERATE_CONTROL_UCMD_REG";
	if (offset == cfg_default.ice_tlc_hi_base +
			cfg_default.ice_tlc_hi_tlc_debug_reg_offset)
		return "TLC_HI_DEBUG_REG";
	if (offset == cfg_default.ice_tlc_hi_base +
			cfg_default.ice_tlc_hi_dump_control_offset)
		return "TLC_DUMP_CONTROL_REG";
	if (offset == cfg_default.mmio_cbd_base_addr_offset)
		return "CB_DESC_BASE_ADDR_REG";
	if (offset == cfg_default.mmio_cbd_entries_nr_offset)
		return "CB_DESC_ENTRIES_NR_REG";
	if (offset == cfg_default.mmu_base + cfg_default.mmu_cfg_offset)
		return "MMU_CONFIG_REG";
	if (offset == cfg_default.mmio_wd_init_offset)
		return "ICE_WATCHDOG_INIT_REG";
	if (offset == cfg_default.mmu_base +
				cfg_default.mmu_fault_details_offset)
		return "MMU_FAULT_DETAILS_REG";
	if (offset == cfg_default.mmu_base +
				cfg_default.mmu_fault_linear_addr_offset)
		return "MMU_FAULT_LINEAR_ADDR_REG";
	if (offset == cfg_default.mmu_base +
				cfg_default.mmu_fault_physical_addr_offset)
		return "MMU_FAULT_PHYSICAL_ADDR_REG";
	if (offset == cfg_default.mmu_base +
				cfg_default.mmu_chicken_bits_offset)
		return "MMU_CHICKEN_BITS_REG";
	if (offset == cfg_default.mmio_cbb_err_code_offset)
		return "CBB_ERROR_CODE_REG";
	if (offset == cfg_default.mmio_cbb_error_info_offset)
		return "CBB_ERROR_INFO_REG";
	if (offset == cfg_default.mmio_tlc_info_offset)
		return "TLC_INFO_REG";
	if (offset >= cfg_default.mmio_gp_regs_offset &&
			offset <=
		(cfg_default.mmio_gp_regs_offset + (4 * ICE_MAX_GP_REG)))
		return "GENERAL_PURPOSE_REG";
	if (offset >= (cfg_default.mmu_base + cfg_default.mmu_page_sizes_offset)
		&& offset <= (cfg_default.mmu_base +
			cfg_default.mmu_page_sizes_offset + 4 * 127))
		return "PAGE_SIZE_CONFIG_REG";
	if (offset == cfg_default.ice_sem_base +
			cfg_default.ice_sem_mmio_demon_enable_offset)
		return "SEMAPHORE_DEMON_ENABLE_REG";
	if (offset == cfg_default.ice_sem_base +
			cfg_default.ice_sem_mmio_demon_control_offset)
		return "SEMAPHORE_DEMON_CONTROL_REG";
	if (offset >= (cfg_default.ice_sem_base +
		cfg_default.ice_sem_mmio_demon_table_offset) &&
		offset <= (cfg_default.ice_sem_base +
			 cfg_default.ice_sem_mmio_demon_table_offset + 4 * 31))
		return "SEMAPHORE_DEMON_TABLE_REG";
	if (offset == cfg_default.mmio_ecc_serrcount_offset)
		return "ECC_SERRCOUNT_REG";
	if (offset == cfg_default.mmio_ecc_derrcount_offset)
		return "ECC_DERRCOUNT_REG";
	if (offset == cfg_default.mmio_parity_errcount_offset)
		return "PARITY_ERRCOUNT_REG";
	if (offset == cfg_default.mmio_unmapped_err_id_offset)
		return "UNMAPPED_ERR_ID_REG";
	if (offset >= PCU_CR_THREAD_P_REQ_BASE &&
			offset <= (PCU_CR_THREAD_P_REQ_BASE + 8 * 15))
		return "PCU_CR_THREAD_P_REQ_REG";

	return get_other_regs_str(offset);
}
