



/*******************************************************************************
 * INTEL CORPORATION CONFIDENTIAL Copyright(c) 2017-2020 Intel Corporation. All Rights Reserved.
 *
 * The source code contained or described herein and all documents related to the
 * source code ("Material") are owned by Intel Corporation or its suppliers or
 * licensors. Title to the Material remains with Intel Corporation or its suppliers
 * and licensors. The Material contains trade secrets and proprietary and
 * confidential information of Intel or its suppliers and licensors. The Material
 * is protected by worldwide copyright and trade secret laws and treaty provisions.
 * No part of the Material may be used, copied, reproduced, modified, published,
 * uploaded, posted, transmitted, distributed, or disclosed in any way without
 * Intel's prior express written permission.
 *
 * No license under any patent, copyright, trade secret or other intellectual
 * property right is granted to or conferred upon you by disclosure or delivery of
 * the Materials, either expressly, by implication, inducement, estoppel or
 * otherwise. Any license under such intellectual property rights must be express
 * and approved by Intel in writing.
 ********************************************************************************/

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
#define IOCTL_MAINT_SET_BIOS_UPDATE_STATE  _IOW('i', 7, uint32_t)

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
