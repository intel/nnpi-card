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
#ifndef _NULL_DEV_H_
#define _NULL_DEV_H_

#include <stdarg.h>
#include <linux/string.h>
#include <linux/types.h>
#ifndef NULL_DEVICE_RING0
#include <stdio.h>
#include <stdint.h>
#endif
#define IDC_REGS_IDC_MMIO_BAR0_MEM_ICERDY_MMOFFSET 0x10
#define CVE_MMIO_HUB_NEW_COMMAND_BUFFER_DOOR_BELL_MMOFFSET 0x8
#define IDC_REGS_IDC_MMIO_BAR0_MEM_ICEINTST_MMOFFSET 0x40
#define CVE_MMIO_HUB_INTERRUPT_STATUS_MMOFFSET 0x108
#define ICE_MMIO_GP_RESET_REG_ADDRESS 0x1AC //need to realign when regs are aligned to L0
#define IDC_REGS_IDC_MMIO_BAR0_MEM_IDCINTST_MMOFFSET 0x50

#define ICEDC_INETRRUPT_STATUS_ILLEGAL_MASK 0xFFFFFFFFFFFFF098

/*
 *IDC_ILLEGAL_ACCESS 0x01
 *IDC_ICE_READ_ERR 0x02
 *IDC_ICE_WRITE_ERR 0x04
 *IDC_ASF_ICE1_ERR 0x20
 *IDC_ASF_ICE0_ERR 0x40
 *IDC_CNTR_ERR 0x100
 *IDC_SEM_ERR 0x200
 *IDC_ATTN_ERR 0x400
 *IDC_CNTR_OFLOW_ERR 0x800
 */
#define ICE_INTERRUPT_STATUS_ILLEGAL_MASK 0xFF60FFE8

/*
 *TLC_CB_COMPLETED 0x00000001
 *TLC_FIFO_EMPTY 0x00000002
 *TLC_ERROR 0x00000004
 *MMU_ERROR 0x00000010
 *MMU_PAGE_NO_WRITE_PERMISSION 0x00010000
 *MMU_PAGE_NO_READ_PERMISSION 0x00020000
 *MMU_PAGE_NO_EXECUTE_PERMISSION 0x00040000
 *MMU_PAGE_NONE_PERMISSION 0x00080000
 *MMU_SOC_BUS_ERROR 0x00100000
 *INTERNAL_CVE_WATCHDOG_INTERRUPT 0x00800000
 *BTRS_CVE_WATCHDOG_INTERRUPT 0x01000000
 */

#define MAX_ICE_COUNT 12
#define MMU_COMPLETED 3
#define ECB_SUCCESS_STATUS 5
#define ICE_READY 65535

#ifndef NULL_DEVICE_RING0
const char *idc_error;
const char *ice_error;
const char *interrupt_delay;
#endif

#define __FILENAME__ \
	(strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)

#ifndef RELEASE
#define null_device_log(fmt, ...)\
	_null_device_log("NULL_DEVICE: %s(%d) :%s : "fmt, __FILENAME__, \
				__LINE__, __func__, ##__VA_ARGS__)
#else
#define null_device_log(fmt, ...)
#endif

#ifndef NULL_DEVICE_RING0
#define _null_device_log(fmt, ...) \
		print_info(fmt, ##__VA_ARGS__)
#else
#define _null_device_log(fmt, ...) \
		pr_info(fmt, ##__VA_ARGS__)
#endif
/* while reading/writing the mmio registers
 * ice_offset macro is used to set the reg_offset
 * with reference to cve_project_internal.h in kmd
 * defined the reg_offset macros
 */

#define reg_offset_rem(reg_offset, register_val) \
		((reg_offset - register_val  - 1048576) % 262144)

#define reg_offset_ice(reg_offset, register_val) \
		((reg_offset - register_val  - 1048576) / 262144)

extern int scheduled_ice[MAX_ICE_COUNT];
extern uint64_t ice_error_interrupt;
int write_mmio(uint64_t reg_offset);
int read_mmio(uint64_t reg_offset, uint64_t *value);

#ifndef NULL_DEVICE_RING0
static inline void print_info(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vfprintf(stdout, fmt, args);
	va_end(args);
}
#endif
#endif
