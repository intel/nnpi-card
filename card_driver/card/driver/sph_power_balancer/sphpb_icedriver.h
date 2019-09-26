/********************************************
 * Copyright (C) 2019 Intel Corporation
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


#define ICEBO0_CORE_INDEX	2
#define NUM_ICEBOS		6

#define IDC_PCI_DEVICE_ID		0x45c4
#define BAR_0_OFFSET			0x10
#define IDC_BAR_0_MAILBOX_START		((uint32_t)(892 * 1024))
#define IDC_BAR_0_MAILBOX_LENGTH	((size_t)(4 * 1024))

/* PCU MAIL BOX INTERFACE */
#define PCU_CR_ICEDRIVER_PCODE_MAILBOX_INTERFACE	0x0
#define	PCU_CR_ICEDRIVER_PCODE_MAILBOX_DATA0		0x8
#define PCU_CR_ICEDRIVER_PCODE_MAILBOX_DATA1		0x10


#define MAILBOX_ICEDRIVER_PCODE_CC_SUCCESS		0x0
#define MAILBOX_ICEDRIVER_PCODE_CC_ILLEGAL_CMD		0x1
#define MAILBOX_ICEDRIVER_PCODE_CC_TIMEOUT		0x2
#define MAILBOX_ICEDRIVER_PCODE_CC_ILLEGAL_DATA		0x3
#define MAILBOX_ICEDRIVER_PCODE_CC_ILLEGAL_SUBCOMMAND	0x4

/* ICE FREQUENCY REQUEST */
union PCODE_CR_THREAD_P_REQ {
	struct {
		uint32_t reserved			: 14;
		uint32_t energy_efficiency_policy	: 4;
		uint32_t p_state_offset			: 6;
		uint32_t p_state_request		: 7;
		uint32_t turbo_disable			: 1;
	} BitField;

	uint32_t value;
};


/* MAILBOX COMMANDS: */
enum icedrv_pcu_mailbox_cmd {
	ICEDRV_PCU_MAILBOX_ICEBO_FREQ_READ	= 1,
	ICEDRV_PCU_MAILBOX_ICCP_READ_LEVEL	= 2,
	ICEDRV_PCU_MAILBOX_ICCP_WRITE_LEVEL	= 3,
	ICEDRV_PCU_MAILBOX_ICE2RING_RATIO_READ	= 4,
	ICEDRV_PCU_MAILBOX_ICE2RING_RATIO_WRITE	= 5
};

union PCODE_MAILBOX_INTERFACE {
	/*
	 * Individual bit fields.
	 */
	struct {
		uint32_t Command	: 8;	/* Pcode mailbox command */
		uint32_t Param1		: 8;	/* Pcode mailbox Param1 */
		uint32_t Param2		: 8;	/* Pcode mailbox Param2 */
		uint32_t Reserved	: 7;	/* Reserved */
		uint32_t RunBusy	: 1;	/* Run/Busy bit. mailbox buffer is ready. pcode will clear this bit after the message is consumed. */
	} BitField;

	uint32_t InterfaceData;   /* All bit fields as a 32-bit value. */
};



/*
 * ICCP_SETTING_START
 *	https://hsdes.intel.com/appstore/article/#/1306484223
 *	cmd=2 READ ICCP levels
 *	cmd=3 WRITE ICCP levels
 *	subcmd/param (PCU_CR_ICEDRIVER_PCODE_MAILBOX_DATA0): index of level. We have 16 levels, 0..15
 *	PCU_CR_ICEDRIVER_PCODE_MAILBOX_DATA1 :
 *	data[31:16]: ICEBO_CR_Value. CR_ICCP_MAX_CDYN_LEVEL_0/1/2/3/../14
 *	data[15:0]: Pcode ICCP level : Format: factor in U6.10 with respect to the ICEBO Cdyn Fuse.
 *	NOTE: there are 16 values (0..15) in the Pcode array, but ICEBO has only 15 (0..14) thresholds/CR:    (index 15 is assumed once value is above th 14)
 */

union icedrv_pcu_mailbox_iccp_value {
	struct {
		u32 pcode_cdyn		: 16;
		u32 icebo_cdyn		: 16;
	} BitField;

	u32 value;
};

/*
 * ICEBO to Ring Ratio
 *	https://hsdes.intel.com/appstore/article/#/1306671120
 *	Command#4: READ factor/downbin
 *	Command#5: Write factror/downbin
 *	Pcode calculates RING ratio from ICEBO/IA RATIO:   y = X * factor - downbin
 *	the factor is in U1.15m and downbin is byte size variable.
 *	This mailbox enables read/write for factor and downbin
 *	Reminder: RingFreq = 100Mhz*RingRatio.  ICEBO_Freq=25Mhz*IceboRatio
 *	If we want factor=0.5 (meaning RING will run 2x faster than ICEBO as it has 4X faster ref clock), and bias=0 we need: data=0x00004000
 *	If we want factor=0.75 (Ring will run 3X faster than RING), and 1 bin down in addition:   data=0x01006000
 */

union icedrv_pcu_mailbox_icebo_ring_ratio {
	struct {
		u32 factor		: 16;
		u32 downbin		: 16;
	} BitField;
	u32 value;
};

/*
 * ICEBO Freq Value
 * voltage = (voltage) * (2 ^ (-8)) = pF
 * frequency = (frequency) * 25Mhz )
 */

union icedrv_pcu_mailbox_icebo_frequency_read {
	struct {
		u32 voltage		: 16;
		u32 frequency		: 16;
	} BitField;
	u32 value;
};



int sphpb_map_idc_mailbox_base_registers(struct sphpb_pb *sphpb);
int sphpb_unmap_idc_mailbox_base_registers(struct sphpb_pb *sphpb);

int sphpb_set_iccp_cdyn(struct sphpb_pb *sphpb, uint32_t level, uint32_t value);
int sphpb_get_iccp_cdyn(struct sphpb_pb *sphpb, uint32_t level, uint32_t *value);

int sphpb_set_icebo_ring_ratio(struct sphpb_pb *sphpb, uint32_t value);
int sphpb_get_icebo_ring_ratio(struct sphpb_pb *sphpb, uint32_t *value);

int sphpb_get_ice_frequency(struct sphpb_pb *sphpb, uint32_t ice_num, uint32_t *freq);
int sphpb_set_ice_frequency(struct sphpb_pb *sphpb, uint32_t ice_num, uint32_t freq);

int sphpb_get_icebo_frequency(struct sphpb_pb *sphpb, uint32_t icebo_num, uint32_t *freq);

