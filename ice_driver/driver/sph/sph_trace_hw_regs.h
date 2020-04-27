/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/


#ifndef _SPH_TRACE_HW_REGS_H_
#define _SPH_TRACE_HW_REGS_H_

#define MTB_LBAR_OFFSET    0x10
#define MTB_LBAR_SIZE    0x100000
#define REG_MSU_MSC0BAR    0xA0108
#define INTEL_TH_PCI_DEVICE_ID 0x45c5
#define SR_PAGE_SIZE 0x400

const u8 icebo_port_lookup[] = {0x0a, 0x0e, 0x12, 0x16, 0x1a, 0x1e};
#define NUM_ICE_BO 6


const u32 default_dso_reg_vals[MAX_DSO_CONFIG_REG] = {
			  0x00000000, /* DSO_DTF_ENCODER_CONFIG_REG */
			  0x40078780, /* DSO_CFG_DTF_SRC_CONFIG_REG */
			  0x00000000, /* DSO_CFG_PTYPE_FILTER_CH0_REG */
			  0x00000000, /* DSO_FILTER_MATCH_LOW_CH0_REG */
			  0x00000000, /* DSO_FILTER_MATCH_HIGH_CH0_REG */
			  0x00000000, /* DSO_FILTER_MASK_LOW_CH0_REG */
			  0x00000000, /* DSO_FILTER_MASK_HIGH_CH0_REG */
			  0x00000000, /* DSO_FILTER_INV_CH0_REG */
			  0x00000000, /* DSO_CFG_PTYPE_FILTER_CH1_REG */
			  0x00000000, /* DSO_FILTER_MATCH_LOW_CH1_REG */
			  0x00000000, /* DSO_FILTER_MATCH_HIGH_CH1_REG */
			  0x00000000, /* DSO_FILTER_MASK_LOW_CH1_REG */
			  0x00000000, /* DSO_FILTER_MASK_HIGH_CH1_REG */
			  0x00000000  /* DSO_FILTER_INV_CH1_REG */
			};

/* Any change in enum value would impact the functioanlity */
enum dso_reg_index {
		 DSO_DTF_ENCODER_CONFIG_REG_INDEX = 0,
		 DSO_CFG_DTF_SRC_CONFIG_REG_INDEX = 1,
		 DSO_CFG_PTYPE_FILTER_CH0_REG_INDEX = 2,
		 DSO_FILTER_MATCH_LOW_CH0_REG_INDEX = 3,
		 DSO_FILTER_MATCH_HIGH_CH0_REG_INDEX = 4,
		 DSO_FILTER_MASK_LOW_CH0_REG_INDEX = 5,
		 DSO_FILTER_MASK_HIGH_CH0_REG_INDEX = 6,
		 DSO_FILTER_INV_CH0_REG_INDEX = 7,
		 DSO_CFG_PTYPE_FILTER_CH1_REG_INDEX = 8,
		 DSO_FILTER_MATCH_LOW_CH1_REG_INDEX = 9,
		 DSO_FILTER_MATCH_HIGH_CH1_REG_INDEX = 10,
		 DSO_FILTER_MASK_LOW_CH1_REG_INDEX = 11,
		 DSO_FILTER_MASK_HIGH_CH1_REG_INDEX = 12,
		 DSO_FILTER_INV_CH1_REG_INDEX = 13
		};

const char* ice_pmon_strings[] = {
	"ATU0_Misses",
	"ATU1_Misses",
	"ATU2_Misses",
	"ATU3_Misses",
	"ATU0_Transactions",
	"ATU1_Transactions",
	"ATU2_Transactions",
	"ATU3_Transactions",
	"Read_Issued",
	"Write_Issued",
	"Gecoe_dec_partial_access",
	"Gecoe_enc_partial_access",
	"Gecoe_dec_meta_miss",
	"Gecoe_enc_uncom_mode",
	"Gecoe_enc_null_mode",
	"Gecoe_enc_sm_mode",
	"Per_Layer_Cycles",
	"Total_Cycles",
	"Cycles_Cnt_Staurated",
	"Gemm_CNN_Starup",
	"Gemm_Compute_Cycles",
	"Gemm_Output_Write_Cycles",
	"CNN_Compute_Cycles",
	"CNN_Output_Write_Cycles",
	"Config_Credit_Latency",
	"Overflow_Indication"
	};

#endif /*_SPH_TRACE_HW_REGS_H_*/
