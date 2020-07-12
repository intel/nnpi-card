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
				{0x0145, 0x00A2},
				{0x01D3, 0x00E9},
				{0x0261, 0x0130},
				{0x02EF, 0x0177},
				{0x037D, 0x01BE},
				{0x040B, 0x0205},
				{0x049A, 0x024D},
				{0x0528, 0x0294},
				{0x05B6, 0x02DB},
				{0x0644, 0x0322},
				{0x06D2, 0x0369},
				{0x0760, 0x03B0},
				{0x07EF, 0x03F7},
				{0x087D, 0x043E},
				{0x090B, 0x0485},
				{0x0999, 0x04CC}
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
