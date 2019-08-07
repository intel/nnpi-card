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
#endif /*_SPH_TRACE_HW_REGS_H_*/
