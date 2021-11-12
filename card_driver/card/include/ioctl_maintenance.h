/********************************************
 * Copyright (C) 2019-2021 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/
#ifndef _SPHCS_IOCTL_MAINTENANCE_H
#define _SPHCS_IOCTL_MAINTENANCE_H

#include <linux/ioctl.h>
#ifndef __KERNEL__
#include <stdint.h>
#else
#include <linux/types.h>
#endif

#define SPHCS_MAINTENANCE_DEV_NAME "sphcs_maint"

#define IOCTL_MAINT_GET_TCC                _IOWR('i',  0, uint32_t)
#define IOCTL_MAINT_GET_POWER_INFO         _IOWR('i',  1, struct maint_ioctl_power_info)
#define IOCTL_MAINT_SET_RATL               _IOWR('i',  2, struct maint_ioctl_ratl)
#define IOCTL_MAINT_GET_RATL               _IOWR('i',  3, struct maint_ioctl_ratl)
#define IOCTL_MAINT_THERMAL_TRIP           _IOWR('i',  4, struct maint_ioctl_thermal_trip)
#define IOCTL_MAINT_SYS_INFO               _IOWR('i',  5, struct maint_ioctl_sys_info)
#define IOCTL_MAINT_FPGA_UPDATE            _IOWR('i',  6, struct maint_ioctl_fpga_update)

#define MAINT_BIOS_VERSION_LEN    72
#define MAINT_BOARD_NAME_LEN      72
#define MAINT_IMAGE_VERSION_LEN   128

struct maint_ioctl_ratl {
	uint32_t time_window_ms;
	uint32_t max_avg_temp;
	uint8_t  is_enabled;
	uint8_t  o_errno;
};

struct maint_ioctl_power_info {
	uint32_t minimum_power;
	uint32_t maximum_power;
	uint32_t maximum_time_window;
};

struct maint_ioctl_thermal_trip {
	uint32_t trip_num;
	uint32_t temperature;
	uint32_t trip_temperature;
};

struct maint_ioctl_sys_info {
	uint32_t ice_mask;
	uint64_t total_unprotected_memory;
	uint64_t total_ecc_memory;
	char bios_version[MAINT_BIOS_VERSION_LEN];
	char board_name[MAINT_BOARD_NAME_LEN];
	char image_version[MAINT_IMAGE_VERSION_LEN];
	uint8_t stepping;
};

struct maint_ioctl_fpga_update {
	uint32_t temperature_mc;
	uint32_t max_temperature_mc;
	uint32_t thermal_event_mc;
	uint8_t  DDR_thermal_status;
	uint32_t avg_power_mW;
	uint32_t power_limit1_mW;

};

#endif
