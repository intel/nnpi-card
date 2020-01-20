/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#include "sph_debug.h"
#include "ioctl_maintenance.h"

int sph_power_init(void);

/*
 * IOCTL handlers
 */
int power_handle_get_power_info(void __user *arg);
int power_handle_set_ratl(void __user *arg);
int power_handle_get_ratl(void __user *arg);
int power_handle_get_tcc(void __user *arg);
uint32_t sph_power_get_tdp(void);
void power_hw_get_ratl(uint32_t *max_avg_temp,
		       uint32_t *time_window_ms,
		       uint8_t  *is_enabled,
		       bool      should_log);

#define TJ_MAX_TCC_OFFSET_MAX 63  //6 bits

#define CHECK_MSR_SIZE(t, nQW) SPH_STATIC_ASSERT(sizeof(t) == 8*(nQW), "Size of " #t " Does not match!!")

#pragma pack(push, 1)

/**
 * MSR structures
 */
struct PACKAGE_THERM_INTERRUPT {
	union {
		uint64_t value;
		struct {
			uint64_t PACKAGE_HIGH_INTERRUPT_ENABLE :1;     //0
			uint64_t PACKAGE_LOW_INTERRUPT_ENABLE  :1;     //1
			uint64_t PACKAGE_PROCHOT_INTERRUPT_ENABLE :1;  //2
			uint64_t RESERVED                         :1;  //3
			uint64_t PACKAGE_CRITICAL_INTERRUPT_ENABLE :1; //4
			uint64_t RESERVED2                         :3; //5-7
			uint64_t PACKAGE_THRESHOLD_1_VALUE            :7;    //8-14
			uint64_t PACKAGE_THRESHOLD_1_INTERRUPT_ENABLE :1;    //15
			uint64_t PACKAGE_THRESHOLD_2_VALUE            :7;    //16-22
			uint64_t PACKAGE_THRESHOLD_2_INTERRUPT_ENABLE :1;    //23
			uint64_t PACKAGE_POWER_LIMIT_NOTIFICATION_ENABLE :1; //24
			uint64_t RESERVED3                               :39; //24-63
		};
	};
};
CHECK_MSR_SIZE(struct PACKAGE_THERM_INTERRUPT, 1);

struct TEMPERATURE_TARGET {
	union {
		uint64_t value;
		struct {
			uint64_t TCC_OFFSET_TIME_WINDOW  :7;
			uint64_t TCC_OFFSET_CLAMPING_BIT :1;
			uint64_t FAN_TEMP_TARGET_OFST    :8;
			uint64_t REF_TEMP                :8;
			uint64_t TJ_MAX_TCC_OFFSET       :6;
			uint64_t RESERVED                :34;
		};
	};
};
CHECK_MSR_SIZE(struct TEMPERATURE_TARGET, 1);

struct PKG_POWER_INFO {
	union {
		uint64_t value;
		struct {
			uint64_t THERMAL_SPEC_POWER :15;
			uint64_t RESERVED           :1;
			uint64_t MINIMUM_POWER      :15;
			uint64_t RESERVED2          :1;
			uint64_t MAXIMUM_POWER      :15;
			uint64_t RESERVED3          :1;
			uint64_t MAXIMUM_TIME_WINDOW:7;
			uint64_t RESERVED4          :9;
		};
	};
};
CHECK_MSR_SIZE(struct PKG_POWER_INFO, 1);

struct RAPL_POWER_UNIT {
	union {
		uint64_t value;
		struct {
			uint64_t POWER_UNITS         :4;
			uint64_t RESERVED            :4;
			uint64_t ENERGY_STATUS_UNITS :5;
			uint64_t RESERVED2           :3;
			uint64_t TIME_UNITS          :4;
			uint64_t RESERVED3           :44;
		};
	};
};
CHECK_MSR_SIZE(struct RAPL_POWER_UNIT, 1);

#pragma pack(pop)


