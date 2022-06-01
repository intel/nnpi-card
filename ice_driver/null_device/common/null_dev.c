/*
 * NNP-I Linux Driver
 * Copyright (c) 2018-2021, Intel Corporation.
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

//#include <math.h>
#include "null_dev.h"
#ifndef NULL_DEVICE_RING0
#include <stdbool.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#else
#include "dummy_icedc.h"
#endif
int scheduled_ice[MAX_ICE_COUNT] = {0};
uint64_t ice_error_interrupt = 0;

int write_mmio(uint64_t reg_offset)
{
	int ret;
	int offset_rem = reg_offset_rem(reg_offset,
			CVE_MMIO_HUB_NEW_COMMAND_BUFFER_DOOR_BELL_MMOFFSET);

	if (offset_rem == 0) {
		int ice_id = reg_offset_ice(reg_offset,
			CVE_MMIO_HUB_NEW_COMMAND_BUFFER_DOOR_BELL_MMOFFSET);

		if ((ice_id >= 0) && (ice_id < MAX_ICE_COUNT)) {
			scheduled_ice[ice_id] = 1;
#ifdef NULL_DEVICE_RING0
		ret = null_dev_irq(ice_id);
		if (!ret)
			null_device_log("dummy irq sent to interrupt handler\n");
#endif
		}
	}
	return 0;
}

int read_mmio(uint64_t reg_offset, uint64_t *value)
{
	uint64_t ice_interrupt = 0;
	int i = 0;
	int offset_rem = reg_offset_rem(reg_offset,
			CVE_MMIO_HUB_INTERRUPT_STATUS_MMOFFSET);
	int offset_rem2 = reg_offset_rem(reg_offset,
				ICE_MMIO_GP_RESET_REG_ADDRESS);

	if (offset_rem == 0) {
		int ice_id = reg_offset_ice(reg_offset,
			CVE_MMIO_HUB_INTERRUPT_STATUS_MMOFFSET);

		if ((ice_id >= 0) && (ice_id < MAX_ICE_COUNT))
			reg_offset = CVE_MMIO_HUB_INTERRUPT_STATUS_MMOFFSET;
	} else if (offset_rem2 == 0) {
		int ice_id2 = reg_offset_ice(reg_offset,
				ICE_MMIO_GP_RESET_REG_ADDRESS);

		if ((ice_id2 >= 0) && (ice_id2 < MAX_ICE_COUNT))
			reg_offset = ICE_MMIO_GP_RESET_REG_ADDRESS;
	}

	switch (reg_offset) {

	case IDC_REGS_IDC_MMIO_BAR0_MEM_ICERDY_MMOFFSET:
		*value = ICE_READY;
	break;

	case IDC_REGS_IDC_MMIO_BAR0_MEM_IDCINTST_MMOFFSET:
#ifdef NULL_DEVICE_RING0
		*value = 0;
#else
		if (idc_error == NULL) {
			*value = 0;
		} else {
			null_device_log("IDC_REGS_MEM_IDCINTST_VALUE: %s\n",
								idc_error);
			if (strtol(idc_error, NULL, 16) & ICEDC_INETRRUPT_STATUS_ILLEGAL_MASK) {

				null_device_log("Invalid IDC_REGS_MEM_IDCINTST_VALUE: %s set\n",
											idc_error);
				*value = 0;
			} else {
				*value = strtol(idc_error, NULL, 16);
			}
		}
#endif
	break;

	case IDC_REGS_IDC_MMIO_BAR0_MEM_ICEINTST_MMOFFSET:
		for (i = 0; i < MAX_ICE_COUNT; i++) {

			if (scheduled_ice[i] == 1) {
				ice_interrupt |= (1ULL << i);
				scheduled_ice[i] = 0;
			}
		}
#ifdef NULL_DEVICE_RING0
		*value = ice_interrupt << 4;
#else
		if (ice_error == NULL) {
			*value = ice_interrupt << 4;
		} else {
			null_device_log("CVE_INTERRUPT_STATUS_VALUE: %s\n",
								ice_error);
			if (strtol(ice_error, NULL, 16) & ICE_INTERRUPT_STATUS_ILLEGAL_MASK) {

				null_device_log("Invalid CVE_INTERRUPT_STATUS_VALUE: %s set\n",
											ice_error);
				*value = ice_interrupt << 4;
			} else {

				ice_interrupt = (uint64_t)ice_interrupt << 4;
				ice_error_interrupt = ice_interrupt;
				*value = ice_interrupt;
			}
		}
#endif
	break;

	case (IDC_REGS_IDC_MMIO_BAR0_MEM_ICEINTST_MMOFFSET + 4):
			*value = ice_error_interrupt;
			ice_error_interrupt = 0;
	break;


	case CVE_MMIO_HUB_INTERRUPT_STATUS_MMOFFSET:
#ifdef NULL_DEVICE_RING0
			*value = MMU_COMPLETED;
#else
		if (ice_error == NULL) {
			*value = MMU_COMPLETED;
		} else {
			if (strtol(ice_error, NULL, 16) & ICE_INTERRUPT_STATUS_ILLEGAL_MASK) {

				*value = MMU_COMPLETED;
			} else {

				*value = strtol(ice_error, NULL, 16);
			}
		}
#endif
	break;

	case ICE_MMIO_GP_RESET_REG_ADDRESS:
		*value = ECB_SUCCESS_STATUS;
	break;

	default:
		*value = 0;
	break;
	}

	return 0;
}
