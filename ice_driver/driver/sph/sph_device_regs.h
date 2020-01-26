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


#ifndef _SPH_DEVICE_REGS_H_
#define _SPH_DEVICE_REGS_H_

#ifndef RING3_VALIDATION
#include <linux/types.h>
#else
#include <stdint.h>
#endif


#define ICE_LLC_ATTR_CONFIG_VIA_AXI_REG 0x9
#define ICE_PAGE_SZ_CONFIG_REG_COUNT 128

/* PCU P-Request register base using which ICE
 * frequency is set
 */
#define PCU_CR_THREAD_P_REQ_BASE 0x0DF000

#define ICEDC_ACF_OFFSET (0xE0000) /*896*1024*/
#define ICEDC_ICEBO_REGION_SZ (0x2000) /*8K*/
#define ICEDC_ICEBO_OFFSET(bo_id) \
	(ICEDC_ACF_OFFSET + (ICEDC_ICEBO_REGION_SZ * (bo_id + 2)))
#define ICEBO_GPSB_OFFSET (0x630) /* Offset within each ICEBO region of 8K*/


#define INVALID_OFFSET 0xffffffff
#define TLC_DRAM_SIZE (32*1024)
#define COMPUTECLUSTER_SP_SIZE_IN_KB 256
#define TLC_TRAX_MEM_SIZE (1024)
#define TRAX_HEADER_SIZE_IN_BYTES 256
#define CNC_CR_BID_WIDTH   4
#define CNC_CR_NUMBER_OF_BIDS (1<<CNC_CR_BID_WIDTH)
#define CREDIT_ACC_REG_SIZE (8)
#define CNC_CR_NUM_OF_REGS_PER_BID 8
#define CNC_CR_NUM_OF_REGS      1
#define ICE_MAX_GP_REG 32

struct config {
	uint32_t ice_gecoe_dec_partial_access_count_offset;
	uint32_t ice_gecoe_enc_partial_access_count_offset;
	uint32_t ice_gecoe_dec_meta_miss_count_offset;
	uint32_t ice_gecoe_enc_uncom_mode_count_offset;
	uint32_t ice_gecoe_enc_null_mode_count_offset;
	uint32_t ice_gecoe_enc_sm_mode_count_offset;
	uint32_t ice_delphi_base;
	uint32_t ice_delphi_dbg_perf_cnt_1_reg_offset;
	uint32_t ice_delphi_dbg_perf_cnt_2_reg_offset;
	uint32_t ice_delphi_dbg_perf_status_reg_offset;
	uint32_t ice_delphi_gemm_cnn_startup_counter_offset;
	uint32_t ice_delphi_gemm_compute_cycle_offset;
	uint32_t ice_delphi_gemm_output_write_cycle_offset;
	uint32_t ice_delphi_cnn_compute_cycles_offset;
	uint32_t ice_delphi_cnn_output_write_cycles_offset;
	uint32_t ice_delphi_credit_cfg_latency_offset;
	uint32_t ice_delphi_perf_cnt_ovr_flw_indication_offset;
	uint32_t ice_mmu_1_system_map_mem_invalidate_offset;
	uint32_t ice_mmu_1_system_map_mem_pt_base_addr_offset;
	uint32_t ice_mmu_1_system_map_stream_id_l1_0;
	uint32_t ice_mmu_1_system_map_stream_id_l1_1;
	uint32_t ice_mmu_1_system_map_stream_id_l1_2;
	uint32_t ice_mmu_1_system_map_stream_id_l1_3;
	uint32_t ice_mmu_1_system_map_stream_id_l1_4;
	uint32_t ice_mmu_1_system_map_stream_id_l1_5;
	uint32_t ice_mmu_1_system_map_stream_id_l1_6;
	uint32_t ice_mmu_1_system_map_stream_id_l1_7;
	uint32_t ice_mmu_1_system_map_stream_id_l2_0;
	uint32_t ice_mmu_1_system_map_stream_id_l2_1;
	uint32_t ice_mmu_1_system_map_stream_id_l2_2;
	uint32_t ice_mmu_1_system_map_stream_id_l2_3;
	uint32_t ice_mmu_1_system_map_stream_id_l2_4;
	uint32_t ice_mmu_1_system_map_stream_id_l2_5;
	uint32_t ice_mmu_1_system_map_stream_id_l2_6;
	uint32_t ice_mmu_1_system_map_stream_id_l2_7;
	uint32_t ice_sem_base;
	uint32_t ice_sem_mmio_general_offset;
	uint32_t ice_sem_mmio_demon_enable_offset;
	uint32_t ice_sem_mmio_demon_control_offset;
	uint32_t ice_sem_mmio_demon_table_offset;
	uint32_t ice_dso_dtf_encoder_config_reg_offset;
	uint32_t ice_dso_cfg_dtf_src_cfg_reg_offset;
	uint32_t ice_dso_cfg_ptype_filter_ch0_reg_offset;
	uint32_t ice_dso_filter_match_low_ch0_reg_offset;
	uint32_t ice_dso_filter_match_high_ch0_reg_offset;
	uint32_t ice_dso_filter_mask_low_ch0_reg_offset;
	uint32_t ice_dso_filter_mask_high_ch0_reg_offset;
	uint32_t ice_dso_filter_inv_ch0_reg_offset;
	uint32_t ice_dso_cfg_ptype_filter_ch1_reg_offset;
	uint32_t ice_dso_filter_match_low_ch1_reg_offset;
	uint32_t ice_dso_filter_match_high_ch1_reg_offset;
	uint32_t ice_dso_filter_mask_low_ch1_reg_offset;
	uint32_t ice_dso_filter_mask_high_ch1_reg_offset;
	uint32_t ice_dso_filter_inv_ch1_reg_offset;
	uint32_t ice_dbg_cbbid_base;
	uint32_t ice_dbg_cbbid_cfg_offset;
	uint32_t ice_prog_cores_ctrl_offset;
	uint32_t ice_dse_base;
	uint32_t ice_axi_max_inflight_offset;
	uint32_t ice_tlc_low_base;
	uint32_t ice_tlc_hi_base;
	uint32_t ice_tlc_base;
	uint32_t ice_tlc_hi_dump_control_offset;
	uint32_t ice_tlc_hi_dump_buf_offset;
	uint32_t ice_tlc_hi_tlc_control_ucmd_reg_offset;
	uint32_t ice_tlc_hi_tlc_debug_reg_offset;
	uint32_t ice_tlc_hi_mailbox_doorbell_offset;
	uint32_t ice_tlc_barrier_watch_cfg_offset;
	uint32_t ice_dump_never;
	uint32_t ice_dump_now;
	uint32_t ice_dump_on_error;
	uint32_t ice_dump_on_marker;
	uint32_t ice_dump_all_marker;
	uint32_t icedc_intr_bit_ilgacc;
	uint32_t icedc_intr_bit_icererr;
	uint32_t icedc_intr_bit_icewerr;
	uint32_t icedc_intr_bit_asf_ice1_err;
	uint32_t icedc_intr_bit_asf_ice0_err;
	uint32_t icedc_intr_bit_icecnerr;
	uint32_t icedc_intr_bit_iceseerr;
	uint32_t icedc_intr_bit_icearerr;
	uint32_t icedc_intr_bit_ctrovferr;
	uint32_t icedc_intr_bit_iacntnot;
	uint32_t icedc_intr_bit_semfree;
	uint32_t bar0_mem_icerst_offset;
	uint32_t bar0_mem_icerdy_offset;
	uint32_t bar0_mem_icenote_offset;
	uint32_t bar0_mem_icepe_offset;
	uint32_t bar0_mem_iceinten_offset;
	uint32_t bar0_mem_iceintst_offset;
	uint32_t bar0_mem_idcspare_offset;
	uint32_t bar0_mem_idcintst_offset;
	uint32_t bar0_mem_icepool0_offset;
	uint32_t bar0_mem_icepool1_offset;
	uint32_t bar0_mem_icepool2_offset;
	uint32_t bar0_mem_icepool3_offset;
	uint32_t bar0_mem_icepool4_offset;
	uint32_t bar0_mem_icepool5_offset;
	uint32_t bar0_mem_icenota0_offset;
	uint32_t bar0_mem_icenota1_offset;
	uint32_t bar0_mem_icenota2_offset;
	uint32_t bar0_mem_icenota3_offset;
	uint32_t bar0_mem_evctprot0_offset;
	uint32_t bar0_mem_evctprot1_offset;
	uint32_t bar0_mem_evctprot2_offset;
	uint32_t bar0_mem_evctprot3_offset;
	uint32_t bar0_mem_evctprot4_offset;
	uint32_t bar0_mem_evctprot5_offset;
	uint32_t bar0_mem_evctprot6_offset;
	uint32_t bar0_mem_evctprot7_offset;
	uint32_t bar0_mem_evctprot8_offset;
	uint32_t bar0_mem_evctprot9_offset;
	uint32_t bar0_mem_evctprot10_offset;
	uint32_t bar0_mem_evctprot11_offset;
	uint32_t bar0_mem_evctprot12_offset;
	uint32_t bar0_mem_evctprot13_offset;
	uint32_t bar0_mem_evctprot14_offset;
	uint32_t bar0_mem_evctprot15_offset;
	uint32_t bar0_mem_evctprot16_offset;
	uint32_t bar0_mem_evctprot17_offset;
	uint32_t bar0_mem_evctprot18_offset;
	uint32_t bar0_mem_evctprot19_offset;
	uint32_t bar0_mem_evctprot20_offset;
	uint32_t bar0_mem_evctprot21_offset;
	uint32_t bar0_mem_evctprot22_offset;
	uint32_t bar0_mem_evctprot23_offset;
	uint32_t bar0_mem_evctprot24_offset;
	uint32_t bar0_mem_evctprot25_offset;
	uint32_t bar0_mem_evctprot26_offset;
	uint32_t bar0_mem_evctprot27_offset;
	uint32_t bar0_mem_evctprot28_offset;
	uint32_t bar0_mem_evctprot29_offset;
	uint32_t bar0_mem_evctprot30_offset;
	uint32_t bar0_mem_evctprot31_offset;
	uint32_t bar0_mem_idcinten_offset;
	uint32_t bar0_mem_icemasksts_offset;
	uint32_t bar0_mem_evctice0_offset;
	uint32_t mmio_cb_doorbell_offset;
	uint32_t mmio_cbd_base_addr_offset;
	uint32_t mmio_cbd_entries_nr_offset;
	uint32_t mmio_intr_mask_offset;
	uint32_t mmio_pre_idle_delay_cnt_offset;
	uint32_t mmio_cfg_idle_enable_mask;
	uint32_t mmio_intr_status_offset;
	uint32_t mmio_hw_revision_offset;
	uint32_t mmio_wd_intr_mask;
	uint32_t mmio_dtf_ctrl_offset;
	uint32_t mmio_ecc_serrcount_offset;
	uint32_t mmio_ecc_derrcount_offset;
	uint32_t mmio_parity_low_err_offset;
	uint32_t mmio_parity_high_err_offset;
	uint32_t mmio_parity_low_err_mask;
	uint32_t mmio_parity_high_err_mask;
	uint32_t mmio_parity_errcount_offset;
	uint32_t mmio_unmapped_err_id_offset;
	uint32_t mmio_cbb_err_code_offset;
	uint32_t mmio_cbb_error_info_offset;
	uint32_t mmio_tlc_info_offset;
	uint32_t mmio_gp_regs_offset;
	uint32_t mmio_hub_mem_gp_regs_reset;
	uint32_t mmio_cve_config_offset;
	uint32_t mmio_wd_enable_mask;
	uint32_t mmio_wd_init_offset;
	uint32_t mmio_tlc_pulse_offset;
	uint32_t mmio_tlc_wd_petting_mask;
	uint32_t mmio_dsram_single_err_intr_mask;
	uint32_t mmio_dsram_double_err_intr_mask;
	uint32_t mmio_sram_parity_err_intr_mask;
	uint32_t mmio_dsram_unmapped_addr_intr_mask;
	uint32_t mmio_intr_status_tlc_reserved_mask;
	uint32_t mmio_intr_status_tlc_panic_mask;
	uint32_t mmio_intr_status_dump_completed_mask;
	uint32_t mmio_intr_status_tlc_cb_completed_mask;
	uint32_t mmio_intr_status_tlc_fifo_empty_mask;
	uint32_t mmio_intr_status_tlc_err_mask;
	uint32_t mmio_intr_status_mmu_err_mask;
	uint32_t mmio_intr_status_mmu_page_no_write_perm_mask;
	uint32_t mmio_intr_status_mmu_page_no_read_perm_mask;
	uint32_t mmio_intr_status_mmu_page_no_exe_perm_mask;
	uint32_t mmio_intr_status_mmu_page_none_perm_mask;
	uint32_t mmio_intr_status_mmu_soc_bus_err_mask;
	uint32_t mmio_intr_status_btrs_wd_intr_mask;
	uint32_t mmu_atu0_base;
	uint32_t mmu_atu1_base;
	uint32_t mmu_atu2_base;
	uint32_t mmu_atu3_base;
	uint32_t mmu_base;
	uint32_t mmu_atu_misses_offset;
	uint32_t mmu_atu_transactions_offset;
	uint32_t mmu_read_issued_offset;
	uint32_t mmu_write_issued_offset;
	uint32_t mmu_atu_pt_base_addr_offset;
	uint32_t mmu_cfg_offset;
	uint32_t mmu_tlc_ivp_stream_mapping_offset;
	uint32_t mmu_dse_surf_0_3_stream_mapping_offset;
	uint32_t mmu_dse_surf_4_7_stream_mapping_offset;
	uint32_t mmu_dse_surf_8_11_stream_mapping_offset;
	uint32_t mmu_dse_surf_12_15_stream_mapping_offset;
	uint32_t mmu_dse_surf_16_19_stream_mapping_offset;
	uint32_t mmu_dse_surf_20_23_stream_mapping_offset;
	uint32_t mmu_dse_surf_24_27_stream_mapping_offset;
	uint32_t mmu_dse_surf_28_31_stream_mapping_offset;
	uint32_t mmu_delphi_stream_mapping_offset;
	uint32_t mmu_pt_idx_bits_table_bit0_lsb;
	uint32_t mmu_pt_idx_bits_table_bit1_lsb;
	uint32_t mmu_pt_idx_bits_table_bit2_lsb;
	uint32_t mmu_pt_idx_bits_table_bit3_lsb;
	uint32_t mmu_axi_tbl_pt_idx_bits_offset;
	uint32_t mmu_tlc_axi_attri_offset;
	uint32_t mmu_asip_axi_attri_offset;
	uint32_t mmu_dsp_axi_attri_offset;
	uint32_t mmu_page_walk_axi_attri_offset;
	uint32_t mmu_fault_details_offset;
	uint32_t mmu_fault_linear_addr_offset;
	uint32_t mmu_fault_physical_addr_offset;
	uint32_t mmu_chicken_bits_offset;
	uint32_t mmu_page_sizes_offset;
	uint32_t gpsb_x1_regs_clk_gate_ctl_offset;
	uint32_t gpsb_x1_regs_iccp_config2_offset;
	uint32_t gpsb_x1_regs_iccp_config3_offset;
	uint32_t mem_clk_gate_ctl_dont_squash_iceclk_lsb;
	uint32_t cbbid_tlc_offset;
	uint32_t axi_shared_read_status_offset;
	uint32_t tlc_dram_size;
	uint32_t computecluster_sp_size_in_kb;
	uint32_t tlc_trax_mem_size;
	uint32_t trax_header_size_in_bytes;
	uint32_t cnc_cr_number_of_bids;
	uint32_t cnc_cr_num_of_regs_per_bid;
	uint32_t cnc_cr_num_of_regs;
	uint32_t credit_acc_reg_size;
	uint32_t stop_all_barriers;
	uint32_t stop_on_section_id;
	uint32_t resume;
	uint32_t block_incoming_cnc_messages;
	uint32_t serve_incoming_cnc_messages;
	uint32_t axi_shared_read_cfg_offset;
        uint32_t cve_status_empty;
        uint32_t cve_status_pending;
        uint32_t cve_status_dispatched;
        uint32_t cve_status_running;
        uint32_t cve_status_completed;
        uint32_t cve_status_aborted;
        uint32_t cve_status_loaded;
	uint32_t bar1_msg_evctice0_msgregaddr;
	uint32_t bar1_msg_evctincice0_msgregaddr;
	uint32_t mmio_hw_revision_major_rev_mask;
	uint32_t mmio_hw_revision_minor_rev_mask;
	uint32_t cbbid_gecoe_offset;
	uint32_t mmio_dpcg_control;
	uint32_t a2i_icebo_pmon_global_offset;
	uint32_t a2i_icebo_pmon_event_0_offset;
	uint32_t a2i_icebo_pmon_event_1_offset;
	uint32_t a2i_icebo_pmon_event_2_offset;
	uint32_t a2i_icebo_pmon_event_3_offset;
	uint32_t a2i_icebo_pmon_counter_0_offset;
	uint32_t a2i_icebo_pmon_counter_1_offset;
	uint32_t a2i_icebo_pmon_counter_2_offset;
	uint32_t a2i_icebo_pmon_counter_3_offset;
	uint32_t a2i_icebo_pmon_status_offset;
	uint32_t ice_delphi_dbg_perf_status_total_cyc_cnt_saturated_mask;
	uint32_t ice_delphi_bdg_perf_status_per_lyr_cyc_cnt_saturated_mask;
};

typedef union {
    struct {
        uint32_t  RSVD_0               :   4;
        uint32_t  ICEPE                :  12;
        uint32_t  RSVD_1               :  16;
    }                                field;
    uint32_t                         val;
} idc_regs_icepe_t;


union ice_mmu_inner_mem_axi_table_pt_index_bits_t {
        struct {
uint32_t  TABLE_INDEX_BIT0     :   6;
uint32_t  TABLE_INDEX_BIT1     :   6;
uint32_t  TABLE_INDEX_BIT2     :   6;
uint32_t  TABLE_INDEX_BIT3     :   6;
uint32_t  RSVD_0               :   8;
        }                                field;
uint32_t                         val;
};

union mmio_hub_mem_cve_dpcg_control_reg_t {
	struct {
uint32_t DPCG_CTRL_SW_DISABLE		:   1;
uint32_t DPCG_CTRL_MSB_COUNTER_BITS	:   2;
uint32_t RSVD_0				:   29;
}				field;
uint32_t		val;
};

union cvg_mmu_1_system_map_mem_page_table_base_address_t {
        struct {
uint32_t  MMU_PAGE_TABLE_BASE_ADDRESS :  27;
uint32_t  UNUSED_MMU_PAGE_TABLE_BASE_ADDRESS :   5;
        }                                field;
uint32_t                         val;
};


union tlc_hi_mem_tlc_dump_control_reg_t {
        struct {
uint32_t  dumpTrigger          :   4;
uint32_t  disableSpDump        :   1;
uint32_t  disableDramDump      :   1;
uint32_t  disableTraxDump      :   1;
uint32_t  disableCreditAccDump :   1;
uint32_t  reserved             :  24;
        }                                field;
uint32_t                         val;
};


union tlc_hi_mem_tlc_dump_buffer_config_reg_t {
        struct {
uint32_t  maxDumpCount         :   6;
uint32_t  dumpBaseAddress      :  26;
        }                                field;
uint32_t                         val;
};


union cve_dse_mem_axi_max_inflight_t {
        struct {
uint32_t  AXI_MAX_WRITE_INFLIGHT :   8;
uint32_t  AXI_MAX_READ_INFLIGHT :   8;
uint32_t  RSVD_0               :  16;
        }                                field;
uint32_t                         val;
};


typedef union {
    struct {
        uint32_t  error_flag           :   1;
        uint32_t  current_shared_distance :   6;
        uint32_t  RSVD_0               :   5;
        uint32_t  current_timeout      :  11;
        uint32_t  RSVD_1               :   1;
        uint32_t  shared_leader_switch :   6;
        uint32_t  RSVD_2               :   1;
        uint32_t  shared_leader        :   1;
    }                                field;
    uint32_t                         val;
} AXI_SHARED_READ_STATUS_T;



union tlc_mem_tlc_barrier_watch_config_reg_t {
        struct {
uint32_t  watchMode            :   4;
uint32_t  tlcMode              :   4;
uint32_t  sectionID            :  16;
uint32_t  enableWatch          :   1;
uint32_t  reserved_interruptSent :   1;
uint32_t  reserved_stoppedAtBarrier :   1;
uint32_t  reserved             :   5;
        }                                field;
uint32_t                         val;
};

union cvg_mmu_1_system_map_mem_invalidate_t {
        struct {
uint32_t  MMU_INVALIDATE       :  16;
uint32_t  UNUSED_MMU_INVALIDATE :  16;
        }                                field;
uint32_t                         val;
};

union ice_mmu_inner_mem_mmu_config_t {
        struct {
uint32_t  ACTIVATE_PERFORMANCE_COUNTERS :   1;
uint32_t  BLOCK_ENTRANCE       :   1;
uint32_t  ACTIVE_TRANSACTIONS  :   1;
uint32_t  IGNORE_NONE_PERMISSION_BIT :   1;
uint32_t  IGNORE_READ_PERMISSION_BIT :   1;
uint32_t  IGNORE_WRITE_PERMISSION_BIT :   1;
uint32_t  IGNORE_EXECUTE_PERMISSION_BIT :   1;
uint32_t  ATU_WITH_LARGER_LINEAR_ADDRESS :   4;
uint32_t  RSVD_0               :  21;
        }                                field;
uint32_t                         val;
};

union ice_mmu_fault_info_t {
	struct ICE_MMU_INNER_FAULT_DETAILS_t {
		/* (TLC=0,ASIP=1,DSP=2,DSE=3,DELPHI=4)*/
		uint32_t  ORIGINATOR           :   3;
		uint32_t  RW_N                 :   1;
		/*   One for read transaction, zero for write*/
		uint32_t  L1                   :   1;
		/*   One for Layer one (page directory) fault if page fault*/
		uint32_t  RSVD_0               :  27;
	}  mmu_fault_detail;

	uint32_t val;
};


union ice_mmu_inner_stream_mapping_config_t {
	struct ICE_MMU_INNER_MEM_TLC_DSP_STREAM_MAPPING {
		uint32_t  TLC_ATU              :   2;
		uint32_t  TLC_STREAM_ID_R      :   3;
		uint32_t  TLC_STREAM_ID_W      :   3;
		uint32_t  TLC_STREAM_ID_I      :   3;
		uint32_t  RSVD_0               :   5;
		uint32_t  DSP_ATU              :   2;
		uint32_t  DSP_STREAM_ID_R      :   3;
		uint32_t  DSP_STREAM_ID_W      :   3;
		uint32_t  DSP_STREAM_ID_I      :   3;
		uint32_t  RSVD_1               :   5;
	} tlc_ivp_stream_mapping;

	struct ICE_MMU_INNER_MEM_ASIP_STREAM_MAPPING {
		uint32_t  ASIP0_ATU            :   2;
		uint32_t  ASIP0_STREAM_ID_R    :   3;
		uint32_t  ASIP0_STREAM_ID_W    :   3;
		uint32_t  ASIP0_STREAM_ID_I    :   3;
		uint32_t  RSVD_0               :  21;
	} asip_stream_mapping;

	struct ICE_MMU_INNER_MEM_DSE_SURFACE_STREAM_MAPPING {
		uint32_t  ATU0                 :   2;
		uint32_t  STREAM_ID0           :   3;
		uint32_t  READ_IS_ADDRESS_BASED0 :   1;
		uint32_t  ATU_AND_STREAM_ARE_ADDRESS_BASED0 :   1;
		uint32_t  RSVD_0               :   1;
		uint32_t  ATU1                 :   2;
		uint32_t  STREAM_ID1           :   3;
		uint32_t  READ_IS_ADDRESS_BASED1 :   1;
		uint32_t  ATU_AND_STREAM_ARE_ADDRESS_BASED1 :   1;
		uint32_t  RSVD_1               :   1;
		uint32_t  ATU2                 :   2;
		uint32_t  STREAM_ID2           :   3;
		uint32_t  READ_IS_ADDRESS_BASED2 :   1;
		uint32_t  ATU_AND_STREAM_ARE_ADDRESS_BASED2 :   1;
		uint32_t  RSVD_2               :   1;
		uint32_t  ATU3                 :   2;
		uint32_t  STREAM_ID3           :   3;
		uint32_t  READ_IS_ADDRESS_BASED3 :   1;
		uint32_t  ATU_AND_STREAM_ARE_ADDRESS_BASED3 :   1;
		uint32_t  RSVD_3               :   1;
	} dse_stream_mapping;

	struct ICE_MMU_INNER_MEM_DELPHI_STREAM_MAPPING {
		uint32_t  ATU                  :   2;
		uint32_t  STREAM_ID            :   3;
		uint32_t  READ_IS_ADDRESS_BASED :   1;
		uint32_t  ATU_AND_STREAM_ARE_ADDRESS_BASED :   1;
		uint32_t  RSVD_0               :  25;
	}  delphi_stream_mapping;

	uint32_t val;
};

union mmio_hub_mem_interrupt_mask_t {
        struct {
uint32_t  TLC_CB_COMPLETED     :   1;
uint32_t  TLC_FIFO_EMPTY       :   1;
uint32_t  TLC_ERROR            :   1;
uint32_t  MMU_COMPLETED        :   1;
uint32_t  MMU_ERROR            :   1;
uint32_t  DUMP_COMPLETED       :   1;
uint32_t  TLC_PANIC            :   1;
uint32_t  TLC_RESERVED         :   8;
uint32_t  MASK_RESERVED        :   1;
uint32_t  MMU_PAGE_NO_WRITE_PERMISSION :   1;
uint32_t  MMU_PAGE_NO_READ_PERMISSION :   1;
uint32_t  MMU_PAGE_NO_EXECUTE_PERMISSION :   1;
uint32_t  MMU_PAGE_NONE_PERMISSION :   1;
uint32_t  MMU_SOC_BUS_ERROR    :   1;
uint32_t  ASIP2HOST_INT        :   1;
uint32_t  IVP2HOST_INT         :   1;
uint32_t  INTERNAL_CVE_WATCHDOG_INTERRUPT :   1;
uint32_t  BTRS_CVE_WATCHDOG_INTERRUPT :   1;
uint32_t  INTERNAL_CVE_SECONDARY_WATCHDOG_INTERRUPT :   1;
uint32_t  INTERNAL_CVE_CNC_WATCHDOG_INTERRUPT :   1;
uint32_t  DSRAM_SINGLE_ERR_INTERRUPT :   1;
uint32_t  DSRAM_DOUBLE_ERR_INTERRUPT :   1;
uint32_t  SRAM_PARITY_ERR_INTERRUPT :   1;
uint32_t  DSRAM_UNMAPPED_ADDR_INTERRUPT :   1;
uint32_t  RSVD_0               :   1;
        }                                field;
uint32_t                         val;
};
union CVE_SHARED_CB_DESCRIPTOR_FLAGS {
	struct {
		uint32_t isPreloadable:1;
		uint32_t isReloadable:1;
		uint32_t disable_CB_COMPLETED_int:1;
		uint32_t reserved:29;
	};
	uint32_t fixed_size;
};

union CVE_SHARED_CB_DESCRIPTOR {
	struct {
		uint32_t driver_reserved0;
		uint32_t driver_reserved1;
		uint32_t address;
		uint32_t commands_nr;
		uint32_t start_time;
		uint32_t completion_time;
		uint32_t status;
		union CVE_SHARED_CB_DESCRIPTOR_FLAGS flags;
		uint32_t host_haddress;
		uint32_t	host_haddress_reserved;
		uint32_t cbd_reg[2];
		uint32_t cbdId;
		uint16_t tlcStartCmdWinIp;
		uint16_t tlcEndCmdWinIp;
		uint32_t tlc_reserved0;
		uint32_t tlc_reserved1;
	};
	struct {
		uint32_t fixed_size[(64 / sizeof(uint32_t))];
	};
};

typedef union {
   struct {
	uint32_t gemm_teardown_perf_cnt_ovr_flow            :   1;
	uint32_t gemm_startup_perf_cnt_ovr_flow             :   1;
	uint32_t gemm_compute_perf_cnt_ovr_flow             :   1;
	uint32_t pe_startup_perf_cnt_ovr_flow               :   1;
	uint32_t pe_compute_perf_cnt_ovr_flow               :   1;
	uint32_t pe_teardown_perf_cnt_ovr_flow              :   1;
	uint32_t cfg_latency_perf_cnt_ovr_flow              :   1;
	uint32_t credit_reset_latency_perf_cnt_ovr_flow     :   1;
	uint32_t RSVD                                       :   24;
     }                            field;
     uint32_t                     val;
} ICE_PMON_DELPHI_OVERFLOW_INDICATION;

typedef union {
    struct {
	uint32_t cfg_latency_perf_cnt            :   16;
	uint32_t credit_reset_latency_perf_cnt   :   16;
    }                               field;
    uint32_t                        val;
} ICE_PMON_DELPHI_CFG_CREDIT_LATENCY;

typedef union {
    struct {
        uint32_t gemm_startup_perf_cnt       :   16;
        uint32_t pe_startup_perf_cnt         :   16;
    }                               field;
    uint32_t                        val;
} ICE_PMON_DELPHI_GEMM_CNN_STARTUP_COUNTER;

typedef union {
	struct {
	uint32_t  total_cyc_cnt_saturated    :   1;
	uint32_t  per_lyr_cyc_cnt_saturated  :   1;
	uint32_t  RSVD                       :  30;
	}                                field;
uint32_t                         val;
} ICE_PMON_DELPHI_DBG_PERF_STATUS_REG_T;

typedef union {
    struct {
        uint32_t  enable_counter_0     :   1;
        uint32_t  enable_counter_1     :   1;
        uint32_t  enable_counter_2     :   1;
        uint32_t  enable_counter_3     :   1;
        uint32_t  RSVD_0               :   4;
        uint32_t  reset_pmon           :   1;
        uint32_t  RSVD_1               :  23;

    }                                field;
    uint32_t                         val;
} ICEBO_PMON_GLOBAL_T;
typedef union {
    struct {
        uint32_t  shared_read_enable   :   1;
        uint32_t  max_shared_distance  :   6;
        uint32_t  RSVD_0               :   2;
        uint32_t  enable_timeout       :   1;
        uint32_t  timeout_threshold    :  10;
        uint32_t  RSVD_1               :  12;

    }                                field;
    uint32_t                         val;
} AXI_SHARED_READ_CFG_T;
typedef union {
    struct {
        uint32_t  value                :   6;
        uint32_t  RSVD_1               :   2;
        uint32_t  OVF                  :   1;
        uint32_t  OVFIE                :   1;
        uint32_t  RSVD_2               :  22;

    }                                field;
    uint32_t                         val;
} idc_regs_evctprot0_t;
union icedc_intr_status_t {
	struct {
		uint64_t  illegal_access : 1;
		uint64_t  ice_read_err : 1;
		uint64_t  ice_write_err : 1;
		uint64_t  rsvd3 : 2;
		uint64_t  asf_ice1_err : 1;
		uint64_t  asf_ice0_err : 1;
		uint64_t  rsvd2 : 1;
		uint64_t  cntr_err : 1;
		uint64_t  sem_err : 1;
		uint64_t  attn_err : 1;
		uint64_t  cntr_oflow_err : 1;
		uint64_t  rsvd1 : 20;
		uint64_t  ia_cntr_not : 4;
		uint64_t  ia_sem_free_not : 4;
		uint64_t  rsvd0 : 24;
	} field;
	uint64_t val;
};
union mmio_hub_mem_dtf_control_t_a_step {
	struct {
uint32_t  DTF_ON               :   1;
uint32_t  DTF_HEADER_PACK_MODE :   1;
uint32_t  DTF_FILTER_AND_MODE  :   1;
uint32_t  DTF_VTUNE_MODE       :   1;
uint32_t  RSVD_0               :   4;
uint32_t  DTF_WAIT_CYCLES      :   8;
uint32_t  RSVD_1               :  16;
	}                                field;
uint32_t                         val;
};

union mmio_hub_mem_dtf_control_t_b_step {
	struct {
uint32_t  DTF_ON               :   1;
uint32_t  DTF_HEADER_PACK_MODE :   1;
uint32_t  DTF_FILTER_AND_MODE  :   1;
uint32_t  DTF_VTUNE_MODE       :   1;
uint32_t  DTF_VTUNE2_MODE      :   1;
uint32_t  RSVD_0               :   3;
uint32_t  DTF_WAIT_CYCLES      :   8;
uint32_t  RSVD_1               :  16;
	}                                field;
uint32_t                         val;
};

union mmio_hub_mem_dtf_control_t_c_step {
	struct {
uint32_t  DTF_ON               :   1;
uint32_t  DTF_HEADER_PACK_MODE :   1;
uint32_t  DTF_FILTER_AND_MODE  :   1;
uint32_t  DTF_VTUNE_MODE       :   1;
uint32_t  DTF_VTUNE2_MODE      :   1;
uint32_t  RSVD_0               :   3;
uint32_t  DTF_WAIT_CYCLES      :   8;
uint32_t  RSVD_1               :  16;
	}                                field;
uint32_t                         val;
};

union mmio_hub_mem_unmapped_err_id_t {
	struct {
uint32_t  TID_ERR              :   4;
uint32_t  RSVD_0               :  28;
	}                                field;
uint32_t                         val;
};
union mmio_hub_mem_cve_config_t {
	struct {
uint32_t  CVE_IDLE_ENABLE      :   1;
uint32_t  RSVD_0               :   3;
uint32_t  CVE_IDLE_SKIP_TLC_CHECK :   1;
uint32_t  CVE_IDLE_SKIP_IVP_CHECK :   1;
uint32_t  CVE_IDLE_SKIP_ASIP_CHECK :   1;
uint32_t  CVE_IDLE_SKIP_DSE_CHECK :   1;
uint32_t  CVE_WATCHDOG_ENABLE  :   1;
uint32_t  RSVD_1               :   1;
uint32_t  CVE_IDLE_SKIP_MMU_CHECK :   1;
uint32_t  CVE_SECONDARY_WATCHDOG_ENABLE :   1;
uint32_t  CVE_CNC_WATCHDOG_ENABLE :   1;
uint32_t  RSVD_2               :   4;
uint32_t  MFW_CNC_BRG_AGGR_DISABLED :   1;
uint32_t  MFW_CNC_BRG_DMA_AGGR_DISABLED :   1;
uint32_t  TLC_CNC_BRG_AGGR_DISABLED :   1;
uint32_t  CVE_IDLE_SKIP_DELPHI_CHECK :   1;
uint32_t  RSVD_3               :  11;
	}                                field;
uint32_t                         val;
};
union mmio_hub_mem_cve_watchdog_init_t {
	struct {
uint32_t  data                 :  32;
	}                                field;
uint32_t                         val;
};

/* ICCP_CONFIG2 desc:  ICCP configuration */
union mem_iccp_config2_t {
	struct {
	/* Cdyn of single ICE, when ICE reset is active */
	uint32_t  RESET_CDYN           :  15;
	/* RESERVED */
	uint32_t  RESERVED             :   1;
	/* Cdyn of single ICE, after ICE reset de-assertion,
	* before first request was sent */
	uint32_t  INITIAL_CDYN         :  15;
	/* RESERVED */
	uint32_t  RESERVED2            :   1;
	}                                field;
	uint32_t                         val;
};

/* ICCP_CONFIG3 desc:  ICCP configuration */
union mem_iccp_config3_t {
    struct {
	/*  Cdyn of single ICE, when there's a
	 *  pending ICCP request in no throttling mode */
	uint32_t  BLOCKED_CDYN         :  15;
	/*  RESERVED */
	uint32_t  RESERVED             :   1;
	/*  Assumed Cdyn of a single ICE, when USE_DEFAULT_CDYN
	 *  is set. */
	uint32_t  DEFAULT_CDYN         :  15;
	 /*  Chicken bit to disable ICE ICCP request. Overrides
	  *  reset/init/requested/blocked Cdyn, but use only
	  *  DEFAULT_CDYN */
	uint32_t  USE_DEFAULT_CDYN     :   1;
	}                                field;
	uint32_t                         val;
};

typedef struct __attribute__((aligned(64))){
	uint8_t		tlcRawDram[TLC_DRAM_SIZE] __attribute__((aligned(64)));
	uint8_t 	scratchPad[COMPUTECLUSTER_SP_SIZE_IN_KB*1024] __attribute__((aligned(64)));
	uint8_t		tlcTraceMem[TLC_TRAX_MEM_SIZE+TRAX_HEADER_SIZE_IN_BYTES] __attribute__((aligned(64)));
	uint8_t		creditAccRegisters[(CNC_CR_NUMBER_OF_BIDS*CNC_CR_NUM_OF_REGS_PER_BID+CNC_CR_NUM_OF_REGS)*CREDIT_ACC_REG_SIZE] __attribute__((aligned(64)));
	uint32_t	controlRegValue __attribute__((aligned(64)));
	uint32_t	dumpReason;
	uint32_t	marker;
	uint32_t	dumpCounter;
	uint32_t	cycleCount;
	uint32_t	version;
	uint32_t	profile;
	uint32_t	compilationDate;
	uint32_t	compilationTime;
	uint32_t 	magicValue[7];
}CVECOREBLOB_T;



union tlc_error_handling_reg_t {
	struct CBB_ERROR_CODE_t {
		uint32_t err_type	: 8;
		uint32_t err_category	: 8;
		uint32_t cbb_id		: 16;
	} cbb_err_code;

	uint32_t val;
};

#endif /* _SPH_DEVICE_REGS_H_ */
