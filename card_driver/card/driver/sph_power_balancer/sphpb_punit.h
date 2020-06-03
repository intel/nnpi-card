/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

/**
 * @file sphpb_puint.h
 *
 * @brief Header file defining sphpb_puint interface module
 *
 * This header file defines sphpb_puint module.
 *
 */

#ifndef _INTEL_SPHPB_PUNIT_H_
#define _INTEL_SPHPB_PUNIT_H_


#include "nnp_debug.h"


#define CHECK_MSR_SIZE(t, n_qw) NNP_STATIC_ASSERT(sizeof(t) == 8*(n_qw), "Size of " #t " Does not match!!")

#define SPHPB_ICCP_ENTRIES_COUNT 15
#define ICCP_ICEBO_MAX_PICOFARAD 5600
#define ICEBO_RING_MAX_RATIO	0xFFFF

#define RING_FREQ_DIVIDER_FACTOR 100
#define ICE_FREQ_DIVIDER_FACTOR 25

/* uncore clock ticks msr's */
#define RING_FREQ_MSR 0x620
#define MSR_UNC_PERF_UNCORE_CLOCK_TICKS 0x395
#define SPH_MSR_CORE_PERF_LIMIT_REASONS 0x64F


struct UNC_PERF_GLOBAL_CTRL_MSR {
	union {
		uint64_t value;

		struct {
			uint64_t	pmi_sel_core0		: 1;
			uint64_t	pmi_sel_core1		: 1;
			uint64_t	pmi_sel_core2		: 1;
			uint64_t	pmi_sel_core3		: 1;
			uint64_t	reserved		: 25;
			uint64_t	en			: 1;
			uint64_t	wake_on_pmi		: 1;
			uint64_t	frz_on_pmi		: 1;
			uint64_t	reserved1		: 32;
		} BitField;

		struct {
			uint64_t low					:32;
			uint64_t high					:32;
		} U64;
	};
};
CHECK_MSR_SIZE(struct UNC_PERF_GLOBAL_CTRL_MSR, 1);



struct UNC_PERF_FIXED_CTRL_MSR {
	union {
		uint64_t value;

		struct {
			uint64_t reserved				: 20;
			uint64_t ovf_en					: 1;
			uint64_t reserved1				: 1;
			uint64_t cnt_en					: 1;
			uint64_t reserved2				: 41;
		} BitField;

		struct {
			uint64_t low					:32;
			uint64_t high					:32;
		} U64;

	};
};
CHECK_MSR_SIZE(struct UNC_PERF_FIXED_CTRL_MSR, 1);




struct RING_FREQUENCY_MSR {
	union {
		uint64_t value;
		struct {
			uint64_t MAX_RATIO				:7;     //0-6
			uint64_t RESERVED				:1;     //7
			uint64_t MIN_RATIO				:7;     //8-14
			uint64_t RESERVED_1				:49;     //15-63
		} BitField;
		struct {
			uint64_t low					:32;
			uint64_t high					:32;
		} U64;
	};
};
CHECK_MSR_SIZE(struct RING_FREQUENCY_MSR, 1);

struct CORE_PERF_LIMIT_REASONS_MSR {
	union {
		uint64_t value;

		struct {
			/* status */
			uint64_t prochot_status				: 1; // 0
			uint64_t thermal_status				: 1; // 1
			uint64_t unused1				: 2; // 2-3
			uint64_t residency_state_regulation_status	: 1; // 4
			uint64_t ratl_status				: 1; // 5
			uint64_t vr_therm_alert_status			: 1; // 6
			uint64_t vr_therm_design_current_status		: 1; // 7
			uint64_t other_status				: 1; // 8
			uint64_t unused2				: 1; // 9
			uint64_t pl1_status				: 1; //10
			uint64_t pl2_status				: 1; //11
			uint64_t max_turbo_limit_status			: 1; //12
			uint64_t turbo_transition_attenuation_status	: 1; //13
			uint64_t unused3				: 2; //14-15

			/* log */
			uint64_t prochot_log				: 1; //16
			uint64_t thermal_log				: 1; //17
			uint64_t unused4				: 2; //18-19
			uint64_t residency_state_regulation_log		: 1; //20
			uint64_t ratl_log				: 1; //21
			uint64_t vr_therm_alert_log			: 1; //22
			uint64_t vr_therm_design_current_log		: 1; //23
			uint64_t other_log				: 1; //24
			uint64_t unused5				: 1; //25
			uint64_t pl1_log				: 1; //26
			uint64_t pl2_log				: 1; //27
			uint64_t max_turbo_limit_log			: 1; //28
			uint64_t turbo_transition_attenuation_log	: 1; //29
			uint64_t unused6				: 34;//30-63
		} BitField;

		struct {
			uint64_t low					:32;
			uint64_t high					:32;
		} U64;
	};
};
CHECK_MSR_SIZE(struct CORE_PERF_LIMIT_REASONS_MSR, 1);

#endif //_INTEL_SPHPB_PUNIT_H_

