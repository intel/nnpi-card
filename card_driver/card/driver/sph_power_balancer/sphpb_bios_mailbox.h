/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

/*
 * @file sphpb_icedriver.h
 *
 * @brief Header file defining sphpb_icedriver interface module
 *
 * This header file defines sphpb_icedriver module.
 *
 */
#include "sphpb.h"


#define BIOS_MAILBOX_START		((uint32_t)(0x5da0))
#define BIOS_MAILBOX_LENGTH		((size_t)(4 + 4))

/* PCU MAIL BOX INTERFACE */
#define BIOS_MAILBOX_DATA_OFFSET		0x0
#define BIOS_MAILBOX_INTERFACE_OFFSET		0x4


// BIOS mailbox command encodings
enum bios_mailbox_command {
	MAILBOX_BIOS_CMD_ZERO =                                  0, // The zero command; does
								    // nothing.
	MAILBOX_BIOS_CMD_READ_PCS =                              3, // Read-only access to PECI
								    // PCS for debug.
	MAILBOX_BIOS_CMD_VR_INTERFACE =                          4, // Generic debug access to
								    // input voltage regulator
	MAILBOX_BIOS_CMD_READ_PCU_MISC_CONFIG =                  5, // Read misc config bits for
								    // the PCU
	MAILBOX_BIOS_CMD_WRITE_PCU_MISC_CONFIG =                 6, // Write misc config bits for
								    // the PCU
	MAILBOX_BIOS_CMD_READ_ACOUSTIC_MITIGATION_RANGE =        7,
	MAILBOX_BIOS_CMD_WRITE_ACOUSTIC_MITIGATION_RANGE =       8,
	MAILBOX_BIOS_CMD_READ_BIOS_MC_REQ_ERROR =                9, // Reads &BIOS_MC_REQ_ERROR_DFX
	MAILBOX_BIOS_CMD_PKGC_BCLK_LONGER_THAN_8SEC =           12,
	MAILBOX_BIOS_CMD_READ_AUTONOMOUS_PARAMS =               16,
	MAILBOX_BIOS_CMD_WRITE_AUTONOMOUS_PARAMS =              17,
	MAILBOX_BIOS_CMD_PKGC_EXPOSED_EMONS =                   20, // Expose Pkg C-state break
								    // conditions architecturally
	MAILBOX_BIOS_CMD_TCSS_DEVEN_INTERFACE =                 21,
	MAILBOX_BIOS_CMD_STS_HANDLER =                          23,
	MAILBOX_BIOS_CMD_SVID_VR_HANDLER =                      24,
	MAILBOX_BIOS_CMD_READ_VR_TDC_CONFIG =                   25,
	MAILBOX_BIOS_CMD_WRITE_VR_TDC_CONFIG =                  26,
	MAILBOX_BIOS_CMD_STATIC_VR_INTERFACE =                  27, // LKF Only
	MAILBOX_BIOS_CMD_VR_IMON_CALIBRATION =                  27, // SPH Only?
	MAILBOX_BIOS_CMD_READ_C6DRAM_CONFIG =                   28,
	MAILBOX_BIOS_CMD_WRITE_C6DRAM_CONFIG =                  29,
	MAILBOX_BIOS_CMD_ODOMETER_CONFIG =                      31,
	MAILBOX_BIOS_CMD_EPG_CONFIG =                           32,
	MAILBOX_BIOS_CMD_WRITE_PID_TUNING =                     33,
	MAILBOX_BIOS_CMD_SAGV_CONFIG_HANDLER =                  34,
	MAILBOX_BIOS_CMD_READ_CPU_C10_PRE_WAKEUP_DELAY =        35,
	MAILBOX_BIOS_CMD_WRITE_CPU_C10_PRE_WAKEUP_DELAY =       36,
	MAILBOX_BIOS_CMD_FLEXIBLE_TELEMETRY =                   37,
	MAILBOX_BIOS_CMD_READ_LLC_SHRINK_DEMOTION_CONFIG =      38,
	MAILBOX_BIOS_CMD_WRITE_LLC_SHRINK_DEMOTION_CONFIG =     39,
	MAILBOX_BIOS_CMD_READ_ODOMETER_TELEMETRY =              40,
	MAILBOX_BIOS_CMD_READ_PCI_AFE_CR =                      41,
	MAILBOX_BIOS_CMD_WRITE_PCI_AFE_CR =                     42,
	MAILBOX_BIOS_CMD_MISC_ALG_CONFIG_INTERFACE =            43,
	MAILBOX_BIOS_CMD_EXTRA_DOMAIN_ENERGY_REPORT =           46,
	MAILBOX_BIOS_CMD_CORE_CSTATE_DEMOTION_CONFIG_READ =     47,
	MAILBOX_BIOS_CMD_CORE_CSTATE_DEMOTION_CONFIG_WRITE =    48,
	MAILBOX_BIOS_CMD_READ_EDRAM_RATIO =                     51,
	MAILBOX_BIOS_CMD_OC_INTERFACE =                         55,
	MAILBOX_BIOS_CMD_MSPE_CONFIG =                          61,
	MAILBOX_BIOS_CMD_CRASHLOG_CONTROL =                     62

/* NOTE: TGL Team reserved opcodes: 63-68, 80+. Need to sync for ADL */
};

// Subcommands
// STS
#define STS_MAILBOX_SUBCMD_GET_PARAMS  0
#define STS_MAILBOX_SUBCMD_CONFIGURE   1
#define STS_MAILBOX_SUBCMD_READ_SAMPLE 2

// VR Config
#define SVID_VR_MAILBOX_SUBCMD_SVID_GET_STRAP_CONFIGURATION       0
#define SVID_VR_MAILBOX_SUBCMD_SVID_GET_ACDC_LOADLINE             1
#define SVID_VR_MAILBOX_SUBCMD_SVID_SET_ACDC_LOADLINE             2
#define SVID_VR_MAILBOX_SUBCMD_SVID_SET_PS_CUTOFF                 3
#define SVID_VR_MAILBOX_SUBCMD_SVID_SET_IMON_CONFIG               4
#define SVID_VR_MAILBOX_SUBCMD_SVID_GET_MAX_ICC                   5
#define SVID_VR_MAILBOX_SUBCMD_SVID_SET_MAX_ICC                   6
#define SVID_VR_MAILBOX_SUBCMD_SVID_GET_VOLTAGE_LIMIT             7
#define SVID_VR_MAILBOX_SUBCMD_SVID_SET_VOLTAGE_LIMIT             8
#define SVID_VR_MAILBOX_SUBCMD_SVID_SET_PMON_CONFIG               9
#define SVID_VR_MAILBOX_SUBCMD_SVID_GET_PMON_PMAX                10
#define SVID_VR_MAILBOX_SUBCMD_SVID_SET_PMON_PMAX                11
#define SVID_VR_MAILBOX_SUBCMD_SVID_SET_VR_SLEW_RATE             12
#define SVID_VR_MAILBOX_SUBCMD_SVID_SET_DISABLE_FAST_PKGC_RAMP   13
#define SVID_VR_MAILBOX_SUBCMD_SVID_SET_PSYS_PS4_DISABLE         14
#define SVID_VR_MAILBOX_SUBCMD_SVID_GET_PSYS_PS4_DISABLE         15
#define SVID_VR_MAILBOX_SUBCMD_SVID_GET_PSYS_REGISTER            16
#define SVID_VR_MAILBOX_SUBCMD_SVID_SET_PSYS_REGISTER            17
// New CNL get operations - get_op# = set_op# + 16
#define SVID_VR_MAILBOX_SUBCMD_SVID_GET_PS_CUTOFF                19  // 3 + 16
#define SVID_VR_MAILBOX_SUBCMD_SVID_GET_IMON_CONFIG              20  // 4 + 16
#define SVID_VR_MAILBOX_SUBCMD_SVID_GET_PMON_CONFIG              25  // 9 + 16
#define SVID_VR_MAILBOX_SUBCMD_SVID_GET_VR_SLEW_RATE             28  // 12 + 16
#define SVID_VR_MAILBOX_SUBCMD_SVID_GET_DISABLE_FAST_PKGC_RAMP   29  // 13 + 16


// Odometer
#define ODOMETER_CONFIG_MAILBOX_SUBCMD_RGB_DISABLE   0
#define ODOMETER_CONFIG_MAILBOX_SUBCMD_RSR_DISABLE   1

// Expose Pkg C-state break conditions architecturally
// PKGC Expose Emons subcommands (PARAM1)
#define PKGC_EXPOSED_EMONS_MAILBOX_SUBCMD_LOCK                         0
#define PKGC_EXPOSED_EMONS_MAILBOX_SUBCMD_START                        1
#define PKGC_EXPOSED_EMONS_MAILBOX_SUBCMD_STOP                         2
#define PKGC_EXPOSED_EMONS_MAILBOX_SUBCMD_READ_EMONS                   3
#define PKGC_EXPOSED_EMONS_MAILBOX_SUBCMD_READ_ENTRANCE_COUNTERS       4
#define PKGC_EXPOSED_EMONS_MAILBOX_SUBCMD_READ_LATENCY_REQUIREMENTS    5

// EPG
#define EPG_CONFIG_MAILBOX_SUBCMD_SET_POWER_OVERHEAD_0  0
#define EPG_CONFIG_MAILBOX_SUBCMD_SET_POWER_OVERHEAD_1  1

// SAGV Heuristics Subcommands
enum MAILBOX_BIOS_CMD_SAGV_CONFIG_HANDLER_Subcommands {
	BIOS_SAGV_CONFIG_GET_POLICY_SUBCOMMAND =                0,
	BIOS_SAGV_CONFIG_SET_POLICY_SUBCOMMAND =                1,
	BIOS_SAGV_CONFIG_HYSTERESIS_SUBCOMMAND =                2,
	BIOS_SAGV_CONFIG_BW_THRESHOLD_SUBCOMMAND =              3,
	BIOS_SAGV_CONFIG_LATENCY_TO_BW_MULT_SUBCOMMAND =        4,
	BIOS_SAGV_CONFIG_BW_WEIGHTS_SUBCOMMAND =                5,
	BIOS_SAGV_CONFIG_RTH_SUBCOMMAND =                       6,
	BIOS_SAGV_RUNTIME_IA_BW_HINT_SUBCOMMAND =               7,
};

enum BIOS_SAGV_CONFIG_POLICIES {
	SAGV_POLICY_DYNAMIC =           0,
	SAGV_POLICY_FIXED_LOW =         1,
	SAGV_POLICY_FIXED_MED =         2,
	SAGV_POLICY_FIXED_HIGH =        3,
};

// MISC_ALGORITHM_CONFIG_INTERFACE Subcommands
#define BIOS_MISC_ALG_CONFIG_READ_HDC_DIS_WHEN_OSREQ_ABOVE_PE_SUBCOMMAND               0
#define BIOS_MISC_ALG_CONFIG_WRITE_HDC_DIS_WHEN_OSREQ_ABOVE_PE_SUBCOMMAND              1
#define BIOS_MISC_ALG_CONFIG_READ_EPB_PECI_CONTROL_SUBCOMMAND                          2
#define BIOS_MISC_ALG_CONFIG_WRITE_EPB_PECI_CONTROL_SUBCOMMAND                         3
#define BIOS_MISC_ALG_CONFIG_READ_RING_DISTRESS_DISABLE_SUBCOMMAND                     4
#define BIOS_MISC_ALG_CONFIG_WRITE_RING_DISTRESS_DISABLE_SUBCOMMAND                    5

// Flexible Telemetry Subcommands
#define FLEXIBLE_TELEMETRY_MAILBOX_SUBCMD_GET_DURATION    0
#define FLEXIBLE_TELEMETRY_MAILBOX_SUBCMD_GET_MAGNITUDE   1
#define FLEXIBLE_TELEMETRY_MAILBOX_SUBCMD_GET_CONFIG0     2
#define FLEXIBLE_TELEMETRY_MAILBOX_SUBCMD_GET_CONFIG1     3
#define FLEXIBLE_TELEMETRY_MAILBOX_SUBCMD_SET_CONFIG0     4
#define FLEXIBLE_TELEMETRY_MAILBOX_SUBCMD_SET_CONFIG1     5

// Extra Domain Energy Report subcommands
#define BIOS_SA_ENERGY_REPORT_SUBCOMMAND        0
#define BIOS_PCH_ENERGY_REPORT_SUBCOMMAND       1
#define BIOS_OTHER_ENERGY_REPORT_SUBCOMMAND     2
#define BIOS_EDRAM_ENERGY_REPORT_SUBCOMMAND     3
#define BIOS_FIVR_ENERGY_REPORT_SUBCOMMAND      4

// Mailbox subcommands and constants for #define MAILBOX_BIOS_CMD_OC_INTERFACE
#define BIOS_OC_INTERFACE_SUBCMD_READ_OC_MISC_CONFIG                     0
#define BIOS_OC_INTERFACE_SUBCMD_WRITE_OC_MISC_CONFIG                    1
#define BIOS_OC_INTERFACE_SUBCMD_READ_OC_PERSISTENT_OVERRIDES            2
#define BIOS_OC_INTERFACE_SUBCMD_WRITE_OC_PERSISTENT_OVERRIDES           3
#define BIOS_OC_INTERFACE_SUBCMD_READ_TJ_MAX_OFFSET                      4
#define BIOS_OC_INTERFACE_SUBCMD_WRITE_TJ_MAX_OFFSET                     5
#define BIOS_OC_INTERFACE_SUBCMD_READ_PLL_VCC_TRIM_OFFSET                6
#define BIOS_OC_INTERFACE_SUBCMD_WRITE_PLL_VCC_TRIM_OFFSET               7
#define BIOS_OC_INTERFACE_SUBCMD_READ_PVD_RATIO_THRESHOLD_OVERRIDE       8
#define BIOS_OC_INTERFACE_SUBCMD_WRITE_PVD_RATIO_THRESHOLD_OVERRIDE      9
#define BIOS_OC_INTERFACE_SUBCMD_READ_VCCIN_MAX_LIMIT                   10
#define BIOS_OC_INTERFACE_SUBCMD_WRITE_VCCIN_MAX_LIMIT                  11

// Mailbox subcommands and constants for #define MAILBOX_BIOS_CMD_VR_IMON_CALIBRATION
#define BIOS_IMON_CALIBRATION_VCCIN_READ_SUBCOMMAND    0
#define BIOS_IMON_CALIBRATION_VCCIN_WRITE_SUBCOMMAND   1
#define BIOS_IMON_CALIBRATION_SA_READ_SUBCOMMAND       2
#define BIOS_IMON_CALIBRATION_SA_WRITE_SUBCOMMAND      3
#define BIOS_IMON_CALIBRATION_OFFSET_READ_SUBCOMMAND  20
#define BIOS_IMON_CALIBRATION_OFFSET_WRITE_SUBCOMMAND 21


/////////////////////////////////////////////////////////
//  PLEASE NOTE CC CODES ARE NOT ORDERED SEQUENTIALLY! //
/////////////////////////////////////////////////////////
enum MAILBOX_BIOS_COMPLETION_CODES {
////////////////////////////////////////////////////
// BIOS generic mailbox Completion Code encodings //
////////////////////////////////////////////////////
	MAILBOX_BIOS_CC_SUCCESS =               0x0,
	MAILBOX_BIOS_CC_ILLEGAL_CMD =           0x1, // For bad cmd encodings
	MAILBOX_BIOS_CC_TIMEOUT =               0x2,
	MAILBOX_BIOS_CC_ILLEGAL_DATA =          0x4, // Bad data with good cmd (attempt
						     // to write reserved bits, etc.)
	MAILBOX_BIOS_CC_LOCKED =                0x6, // Command was locked (can be due to
						     // various reasons)
	MAILBOX_BIOS_CC_ILLEGAL_SUBCOMMAND =    0x8, // For cases where there is
						     // subcommand support

/////////////////////////////////////////////////
// Command specific Completion Code encodings: //
/////////////////////////////////////////////////
// VR_INTERFACE Error codes
	MAILBOX_BIOS_CC_ILLEGAL_VR_ID =         0x5,
	MAILBOX_BIOS_CC_VR_ERROR =              0x7,

// EDRAM Error codes
	MAILBOX_BIOS_CC_EDRAM_NOT_FUNCTIONAL =  0x9,

// AFE Read/Write Error Codes
	MAILBOX_BIOS_CC_ILLEGAL_ADDRESS =       0xb,
};


union BIOS_MAILBOX_INTERFACE {
	/*
	 * Individual bit fields.
	 */
	struct {
		uint32_t Command	:  8; // Command/Error Code
		uint32_t Param1		:  8; // Parameter 1
		uint32_t Param2		: 13; // Parameter 2
		uint32_t Reserved	:  2; // Reserved
		uint32_t RunBusy	:  1; // Run/Busy indicator bit
					      // This bit will be cleared after
					      // the message is consumed.
	};

	uint32_t InterfaceValue;   /* All bit fields as a 32-bit value. */
};


int sphpb_map_bios_mailbox(struct sphpb_pb *sphpb);
void sphpb_unmap_bios_mailbox(struct sphpb_pb *sphpb);

int set_sagv_freq(enum BIOS_SAGV_CONFIG_POLICIES qclk,
		  enum BIOS_SAGV_CONFIG_POLICIES psf0);

int get_imon_sa_calib_config(uint16_t *imon_offset,
			     uint16_t *imon_slope_factor);

int set_imon_sa_calib_config(uint16_t imon_offset,
			     uint16_t imon_slope_factor);

int get_imon_vccin_calib_config(uint16_t *imon_offset,
				uint16_t *imon_slope);

int set_imon_vccin_calib_config(uint16_t imon_offset,
				uint16_t imon_slope);

int get_offset_calib_config(int16_t *offset);

int set_offset_calib_config(int16_t offset);
