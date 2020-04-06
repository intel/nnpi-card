/*
 * NNP-I Linux Driver
 * Copyright (c) 2017-2019, Intel Corporation.
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

#include "project_settings.h"
#include "device_interface.h"

/* Multi CVE configuration */
struct cve_device_groups_config coh_cve_dg_config =
#if defined(FPGA)
	DG_CONFIG_SINGLE_GROUP_SINGLE_DEVICE;
#else
	DG_CONFIG_SINGLE_GROUP_ALL_DEVICES;
#endif

struct cve_driver_settings g_driver_settings = {
	.flags = NEED_TLB_INVALIDATION_IF_PAGES_ADDED,
	.config = &coh_cve_dg_config
};

void cve_print_driver_settings(void)
{
	u32 i;

	cve_os_log(CVE_LOGLEVEL_INFO,
			"Driver Configuration: Groups NR: %d, Devices NR: %d\n",
			g_driver_settings.config->groups_nr,
			g_driver_settings.config->devices_nr);

	for (i = 0; i < g_driver_settings.config->groups_nr; i++) {
		cve_os_log(CVE_LOGLEVEL_INFO,
				"Group %d Configuration: Devices Count: %d, LLC size: %d\n",
				i,
				g_driver_settings.config->groups[i].devices_nr,
				g_driver_settings.config->groups[i].llc_size);
	}
}

