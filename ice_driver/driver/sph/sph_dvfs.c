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

#include <linux/init.h>
#include <linux/kernel.h>

#include  "cve_device.h"
#include "os_interface.h"
#include "cve_device_group.h"
#include "cve_linux_internal.h"
#include "sph_dvfs.h"


static int sphpb_set_icebo_ring_ratio(struct ice_sphmbox *sphmb, uint16_t value)
{
	union PCODE_MAILBOX_INTERFACE iface;

	iface.InterfaceData = 0;
	iface.BitField.Command = ICEDRV_PCU_MAILBOX_ICE2RING_RATIO_WRITE;

	return write_icedriver_mailbox(sphmb, iface,
				       (uint32_t)value, 0x0,
				       NULL, NULL);
}

static int sphpb_get_icebo_ring_ratio(struct ice_sphmbox *sphmb,
							uint16_t *value)
{
	union PCODE_MAILBOX_INTERFACE iface;

	iface.InterfaceData = 0;
	iface.BitField.Command = ICEDRV_PCU_MAILBOX_ICE2RING_RATIO_READ;

	return write_icedriver_mailbox(sphmb, iface,
				       0x0, 0x0,
				       (uint32_t *)value, NULL);
}

int icedrv_set_icebo_to_ring_ratio(uint16_t value)
{
	int ret;
	struct cve_device_group *dg;
	struct ice_sphmbox *sphmb = NULL;

	dg = cve_dg_get();
	if (!dg) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"null dg pointer (%d) !!\n", -EINVAL);
		return -EINVAL;
	}
	sphmb = &dg->sphmb;
	ret = sphpb_set_icebo_ring_ratio(sphmb, value);
	if (ret) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"failure in sphpb_set_icebo_ring_ratio() - %d\n", ret);
	}

	return ret;
}

int icedrv_get_icebo_to_ring_ratio(uint16_t *value)
{
	int ret;
	struct cve_device_group *dg;
	struct ice_sphmbox *sphmb = NULL;

	dg = cve_dg_get();
	if (!dg) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"null dg pointer (%d) !!\n", -EINVAL);
		return -EINVAL;
	}
	sphmb = &dg->sphmb;
	ret = sphpb_get_icebo_ring_ratio(sphmb, value);
	if (ret) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"failure in sphpb_set_icebo_ring_ratio() - %d\n", ret);
	}

	return ret;
}
int icedrv_set_ice_to_ice_ratio(uint32_t icebo, uint32_t value)
{
	cve_os_log(CVE_LOGLEVEL_ERROR, "feature not supported\n");

	return -EINVAL;
}

int icedrv_get_ice_to_ice_ratio(uint32_t icebo, uint32_t *value)
{
	cve_os_log(CVE_LOGLEVEL_ERROR, "feature not supported\n");

	return -EINVAL;
}
