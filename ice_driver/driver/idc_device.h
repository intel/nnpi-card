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

#ifndef IDC_DEVICE_H_
#define IDC_DEVICE_H_

#include "cve_device.h"
#include "sph_device_regs.h"

#define NUM_ICE_UNIT MAX_CVE_DEVICES_NR
#define NUM_POOL_REG MAX_IDC_POOL_NR
#define NUM_COUNTER_REG MAX_HW_COUNTER_NR
#define INVALID_CNTR_ID NUM_COUNTER_REG /* Defines invalid ID for counter */

#define get_low_dword(a) ((a) & 0xffffffff)
#define get_high_dword(a) (((a) >> 32) & 0xffffffff)

#define IDC_ISR_BH_QUEUE_SZ (NUM_ICE_UNIT * 2)

struct dev_isr_status {
	uint64_t ice_status;
	uint64_t idc_status;
	uint32_t ice_isr_status[NUM_ICE_UNIT];
	int8_t valid;
};


struct idc_device {
	/* ICEDC error interrupt enable */
	atomic64_t idc_err_intr_enable;
	struct cve_device cve_dev[NUM_ICE_UNIT];
#ifdef RING3_VALIDATION
	uint64_t bar1_base_address;
#else
	dma_addr_t bar1_base_address;
#endif

	struct dev_isr_status isr_status[IDC_ISR_BH_QUEUE_SZ];
	atomic_t status_q_head;
	atomic_t status_q_tail;
};

#define ice_to_idc(ice_dev)\
	((struct idc_device *)((char *)(ice_dev)\
	- (char *)(&((struct idc_device *)0)->cve_dev[ice_dev->dev_index])))

#endif /* IDC_DEVICE_H_ */

