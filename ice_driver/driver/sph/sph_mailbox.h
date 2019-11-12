/*
 * NNP-I Linux Driver
 * Copyright (c) 2019, Intel Corporation.
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

#ifndef SPHPB_ICEDRIVER_H_
#define SPHPB_ICEDRIVER_H_
#define ICEBO0_CORE_INDEX	2
#define NUM_ICEBOS		6
#define ICEBO_FREQ_FACTOR 25 /* 25Mhz */

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
	ICEDRV_PCU_MAILBOX_ICE2RING_RATIO_WRITE	= 5,
	ICEDRV_PCU_MAILBOX_T_STATE_REQUEST	= 6
};

union PCODE_MAILBOX_INTERFACE {
	/*
	 * Individual bit fields.
	 */
	struct {
		/* Pcode mailbox command */
		uint32_t Command	: 8;
		/* Pcode mailbox Param1 */
		uint32_t Param1		: 8;
		/* Pcode mailbox Param2 */
		uint32_t Param2		: 8;
		/* Reserved */
		uint32_t Reserved	: 7;
		/*
		 * Run/Busy bit. mailbox buffer is ready.
		 * pcode will clear this bit after the message is consumed.
		 */
		uint32_t RunBusy	: 1;
	} BitField;

	uint32_t InterfaceData;   /* All bit fields as a 32-bit value. */
};



/*
 * ICCP_SETTING_START
 *	https://hsdes.intel.com/appstore/article/#/1306484223
 *	cmd=2 READ ICCP levels
 *	cmd=3 WRITE ICCP levels
 *	subcmd/param: index of level.
 *			We have 16 levels, 0..15
 *	PCU_CR_ICEDRIVER_PCODE_MAILBOX_DATA0 :
 *	data[31:16]: ICEBO_CR_Value. CR_ICCP_MAX_CDYN_LEVEL_0/1/2/3/../14
 *	data[15:0]: Pcode ICCP level : Format: factor in U6.10 with respect to
 *						the ICEBO Cdyn Fuse.
 *	NOTE: there are 16 values (0..15) in the Pcode array, but ICEBO has
 *	only 15 (0..14)xi thresholds/CR:  (index 15 is assumed once value is
 *	above th 14)
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
 *	Pcode calculates RING ratio from ICEBO/IA RATIO:
 *						y = X * factor - downbin
 *	the factor is in U1.15m and downbin is byte size variable.
 *	This mailbox enables read/write for factor and downbin
 *	Reminder: RingFreq = 100Mhz*RingRatio.  ICEBO_Freq=25Mhz*IceboRatio
 *	If we want factor=0.5 (meaning RING will run 2x faster than ICEBO as
 *		it has 4X faster ref clock), and bias=0 we need: data=0x00004000
 *	If we want factor=0.75 (Ring will run 3X faster than RING), and 1 bin
 *		down in addition:   data=0x01006000
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


/*
 *	T_STATE_REQUEST
 *	https://hsdes.intel.com/appstore/article/#/1306845893
 *	cmd=6, TREQ Request to PCODE
 *
 *	IO_ICEDRIVER_MAILBOX_INTERFACE.param1 = TARGETED_ICEBO_MASK
 *	Special Case :-
 *	* If IO_ICEDRIVER_MAILBOX_INTERFACE.param1 = 0 is set
 *			then it will Broadcast to all ICEBOs.
 *
 *	PCU_CR_ICEDRIVER_PCODE_MAILBOX_DATA0 :
 *	data[3:0]: T_STATE_REQ, Duty cycle value. A value of XX means
 *			that the 'ON' time is XX/16. A value of 0 means
 *			50% D.C. Maximal value is 15/16.
 *	data[4:4]: THROTTLE_ACTIVE, If set, we are in T-State throttle mode
 *	  Special Case :-
 *		*If PCU_CR_ICEDRIVER_PCODE_MAILBOX_DATA0[3:0] = 0  ==>
 *			it will program Duty Cycle as  50%
 */

union icedrv_pcu_mailbox_treq_value {
	struct {
		u32 tstate_req		: 4;
		u32 throttle_active	: 1;
		u32 reserved		: 27;
	} BitField;
	u32 value;
};

int write_icedriver_mailbox(struct ice_sphmbox *sphmb,
			    union PCODE_MAILBOX_INTERFACE iface,
			    uint32_t i_data0, uint32_t i_data1,
			    uint32_t *o_data0, uint32_t *o_data1);
int sphpb_map_idc_mailbox_base_registers(struct ice_sphmbox *sphmb);
int sphpb_unmap_idc_mailbox_base_registers(struct ice_sphmbox *sphmb);

#endif /* SPHPB_ICEDRIVER_H_ */
