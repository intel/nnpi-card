/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/



#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/sysfs.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/kobject.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/anon_inodes.h>
#include <linux/uaccess.h>
#include <linux/fcntl.h>

#include "sph_log.h"
#include  "cve_device.h"
#include "os_interface.h"
#include "cve_device_group.h"
#include "cve_linux_internal.h"
#include "sph_mailbox.h"
#include "sph_iccp.h"
#include "project_device_interface.h"

#define MAX_CDYN_INPUT_VALUE 0xFFFF

#define NUM_ICCP_LEVELS 16
struct  ice_iccp_init_table {
	/* ICEBO CR value */
	uint16_t icebo_cr;
	/* PCode ICCP value in U6.10 format*/
	uint16_t pcode_iccp;
};

const struct ice_iccp_init_table iccp_tbl[NUM_ICCP_LEVELS] = {
				{0x014F, 0x00A7},
				{0x01A9, 0x00D4},
				{0x0202, 0x0101},
				{0x025C, 0x012E},
				{0x02B5, 0x015A},
				{0x030F, 0x0187},
				{0x0368, 0x01B4},
				{0x03C2, 0x01E1},
				{0x041B, 0x020D},
				{0x0475, 0x023A},
				{0x04CF, 0x0267},
				{0x0528, 0x0294},
				{0x0582, 0x02C1},
				{0x05DB, 0x02ED},
				{0x0635, 0x031A},
				{0x068E, 0x0347}
				};

int set_iccp_cdyn(struct ice_sphmbox *sphmb, uint32_t level,
						uint32_t value)
{
	union PCODE_MAILBOX_INTERFACE iface;

	iface.InterfaceData = 0;
	iface.BitField.Command = ICEDRV_PCU_MAILBOX_ICCP_WRITE_LEVEL;
	iface.BitField.Param1 = (uint8_t)level;

	return write_icedriver_mailbox(sphmb, iface,
				       value, 0x0,
				       NULL, NULL);
}

int get_iccp_cdyn(struct ice_sphmbox *sphmb, uint32_t level,
						uint32_t *value)
{
	union PCODE_MAILBOX_INTERFACE iface;

	iface.InterfaceData = 0;
	iface.BitField.Command = ICEDRV_PCU_MAILBOX_ICCP_READ_LEVEL;
	iface.BitField.Param1 = (uint8_t)level;

	return write_icedriver_mailbox(sphmb, iface,
				       0x0, 0x0,
				       value, NULL);
}

int ice_iccp_levels_init(struct cve_device_group *dg)
{
	int iccp_entry;
	int ret;
	union icedrv_pcu_mailbox_iccp_value iccp;


	/* Initialize iccp levels using mailbox*/
	for (iccp_entry = 0; iccp_entry < NUM_ICCP_LEVELS; iccp_entry++) {
		iccp.BitField.pcode_cdyn = iccp_tbl[iccp_entry].pcode_iccp;
		iccp.BitField.icebo_cdyn = iccp_tbl[iccp_entry].icebo_cr;
		/* call cdyn mailbox set function for each level*/
		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"set iccp level%d icebo_cr 0x%x, pcode iccpi 0x%x\n",
			iccp_entry, iccp_tbl[iccp_entry].icebo_cr,
			iccp_tbl[iccp_entry].pcode_iccp);
		ret = set_iccp_cdyn(&dg->sphmb, iccp_entry, iccp.value);
		if (ret) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
				"unable to write iccp entry (%d) value - Err(%d)\n",
					iccp_entry, ret);
			return ret;
		}
	}

	return 0;
}

void ice_iccp_levels_term(struct cve_device_group *dg)
{
	/* place holder */
}
