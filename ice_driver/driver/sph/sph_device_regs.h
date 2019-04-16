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

#include <idc_regs_regs.h>
#include "cve_cbbid.h"
#include "tlc_hi_regs.h"
#include "axi2idi_regs_regs.h"
#include "gpsb_x1_regs_regs.h"

#ifndef _SPH_DEVICE_REGS_H_
#define _SPH_DEVICE_REGS_H_

#ifdef _DEBUG
#include "debugCbbId_regs.h"

/*
 * MMIO register through which Driver can emit messages over CnC
 * which then appear in DTF log. Can be used for debugging those
 * events which are not visible over CnC.
 *
 * WARNING:
 * Currently Coral gives TLC Error when writing to 0xF000.
 * Also Dst in CnC comes as TLC. Vaish to clarify [ICE-8099].
*/
/* 0xF004 */
#define ICE_DEBUG_CFG_REG (CVE_DEBUGCBBID_BASE +\
				CVE_DEBUGCBBID_DEBUG_CBBID_CFG_REG_MMOFFSET \
				 + (1 * 4))
#endif

#define ICE_LLC_ATTR_CONFIG_VIA_AXI_REG 0x9
#define ICE_PAGE_SZ_CONFIG_REG_COUNT 128

/* 0x2000*/
#define ICE_CBBID_TLC_OFFSET CBBID_TLC_OFFSET
/* 0x124*/
#define ICE_TLC_HI_TLC_MAILBOX_DOORBELL_MMOFFSET \
			CVE_TLC_HI_TLC_MAILBOX_DOORBELL_MMOFFSET
/*0x0000*/
#define ICEDC_INTR_BIT_ILGACC IDC_REGS_IDCINTST_ILGACC_LSB
/*0x0001*/
#define ICEDC_INTR_BIT_ICERERR IDC_REGS_IDCINTST_ICERERR_LSB
/*0x0002*/
#define ICEDC_INTR_BIT_ICEWERR IDC_REGS_IDCINTST_ICEWERR_LSB
/*0x0005*/
#define ICEDC_INTR_BIT_ASF_ICE1_ERR IDC_REGS_IDCINTST_ASF_ICE1_ERR_LSB
/*0x0006*/
#define ICEDC_INTR_BIT_ASF_ICE0_ERR IDC_REGS_IDCINTST_ASF_ICE0_ERR_LSB
/*0x0008*/
#define ICEDC_INTR_BIT_ICECNERR IDC_REGS_IDCINTST_ICECNERR_LSB
/*0x0009*/
#define ICEDC_INTR_BIT_ICESEERR IDC_REGS_IDCINTST_ICESEERR_LSB
/*0x000a*/
#define ICEDC_INTR_BIT_ICEARERR IDC_REGS_IDCINTST_ICEARERR_LSB
/*0x000b*/
#define ICEDC_INTR_BIT_CTROVFERR IDC_REGS_IDCINTST_CTROVFERR_LSB
/*0x0020*/
#define ICEDC_INTR_BIT_IACNTNOT IDC_REGS_IDCINTST_IACNTNOT_LSB
/*0x0024*/
#define ICEDC_INTR_BIT_SEMFREE IDC_REGS_IDCINTST_SEMFREE_LSB
/*0x50*/
#define ICEDC_INTR_ENABLE_OFFSET IDC_REGS_IDC_MMIO_BAR0_MEM_IDCINTEN_MMOFFSET
/*0x58*/
#define ICEDC_INTR_STATUS_OFFSET IDC_REGS_IDC_MMIO_BAR0_MEM_IDCINTST_MMOFFSET

#define ICEDC_ACF_OFFSET (0xE0000) /*896*1024*/
#define ICEDC_ICEBO_REGION_SZ (0x2000) /*8K*/
#define ICEDC_ICEBO_OFFSET(bo_id) \
	(ICEDC_ACF_OFFSET + (ICEDC_ICEBO_REGION_SZ * (bo_id + 2)))

#define ICEBO_GPSB_OFFSET (0x630) /* Offset within each ICEBO region of 8K*/
#define ICEDC_ICEBO_CLK_GATE_CTL_OFFSET \
	 GPSB_X1_REGS_CLK_GATE_CTL_MMOFFSET /*0x14*/
#define ICEDC_ICEBO_CLK_GATE_CTL_DISABLE_SQUASH_BIT_SHIFT \
	MEM_CLK_GATE_CTL_DONT_SQUASH_ICECLK_LSB /*0x2*/

#define ICEDC_ERROR_INTR_ENABLE_ALL \
	((1UL << ICEDC_INTR_BIT_ILGACC) | \
	(1UL << ICEDC_INTR_BIT_ICERERR) | \
	(1UL << ICEDC_INTR_BIT_ICEWERR) | \
	(1UL << ICEDC_INTR_BIT_ASF_ICE1_ERR) | \
	(1UL << ICEDC_INTR_BIT_ASF_ICE0_ERR) | \
	(1UL << ICEDC_INTR_BIT_ICECNERR) | \
	(1UL << ICEDC_INTR_BIT_ICESEERR) | \
	(1UL << ICEDC_INTR_BIT_ICEARERR) | \
	(1UL << ICEDC_INTR_BIT_CTROVFERR) | \
	(15UL << ICEDC_INTR_BIT_IACNTNOT) | \
	(15UL << ICEDC_INTR_BIT_SEMFREE))

union icedc_intr_status_t {
	struct {
		/*  Illegal Access bus bridge */
		uint64_t  illegal_access : 1;
		/* ICE read Error bus */
		uint64_t  ice_read_err : 1;
		/* ICE Write Error bus */
		uint64_t  ice_write_err : 1;
		/*  Reserved */
		uint64_t  rsvd3 : 2;
		/* Error indicated during last power sequence from ICEBO */
		/* Error from ASF Ice1 in a pair */
		uint64_t  asf_ice1_err : 1;
		/* Error from ASF Ice0 in a pair */
		uint64_t  asf_ice0_err : 1;
		/*  Reserved */
		uint64_t  rsvd2 : 1;
		/* Counter Error, an ICE accessed a counter */
		/* not associated with it */
		uint64_t  cntr_err : 1;
		/* Semaphore Error, an ICE accessed a */
		/* semaphores not associated with it */
		uint64_t  sem_err : 1;
		/* Attention Request Error, an ICE attempted
		 * to send a notification
		 * to another ICE which is not within its pool
		 */
		uint64_t  attn_err : 1;
		/* one of the counters had an overflow
		 * and its OVF IE bit is set
		 */
		uint64_t  cntr_oflow_err : 1;
		/*  Reserved */
		uint64_t  rsvd1 : 20;
		/* Counter Value notification event to IA.
		 * There are 4 notifications that may be set.
		 */
		uint64_t  ia_cntr_not : 4;
		uint64_t  ia_sem_free_not : 4;
		/* Semaphore Free notification event to IA.
		 * There are 4 notifications that may be set.
		 */
		/* Reserved */
		uint64_t  rsvd0 : 24;
	} field;
	uint64_t val;
};

union cedc_intr_enable_t {
	struct {
		/* Each of the bit is associated with the the respective event
		 * in icedc_intr_status_t. 0 value does not trigger the
		 * associated event(default), MSI. 1 enables
		 * the associated Event triggering
		 */
		uint64_t  evt_enable_lo : 12;
		/* Reserved */
		uint64_t  rsvd1 : 20;
		uint64_t  evt_enable_hi : 8;
		/* Reserved */
		uint64_t  rsvd0 : 24;
	} field;
	uint64_t val;
};

#endif /* _SPH_DEVICE_REGS_H_ */
