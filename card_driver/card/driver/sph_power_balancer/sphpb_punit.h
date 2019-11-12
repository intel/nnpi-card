/********************************************
 * Copyright (C) 2019 Intel Corporation
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


#include "sph_debug.h"


#define CHECK_MSR_SIZE(t, nQW) SPH_STATIC_ASSERT(sizeof(t) == 8*(nQW), "Size of " #t " Does not match!!")

#define SPHPB_ICCP_ENTRIES_COUNT 15
#define ICCP_ICEBO_MAX_PICOFARAD 5600
#define ICEBO_RING_MAX_RATIO	0xFFFF

#define RING_FREQ_DIVIDER_FACTOR 100
#define ICE_FREQ_DIVIDER_FACTOR 25

/* uncore clock ticks msr's */
#define RING_FREQ_MSR 0x620
#define MSR_UNC_PERF_UNCORE_CLOCK_TICKS 0x395


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

#endif //_INTEL_SPHPB_PUNIT_H_

