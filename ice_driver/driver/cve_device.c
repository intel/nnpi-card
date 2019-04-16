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

#include "cve_device.h"
#include "cve_driver_internal_macros.h"
#include "os_interface.h"
#include "memory_manager.h"
#include "project_device_interface.h"
#include "device_interface.h"
#include "cve_firmware.h"
#include "ice_trace.h"

#ifndef RING3_VALIDATION
#include "ice_sw_counters.h"
#endif

#include "ice_debug_event.h"

int cve_device_init(struct cve_device *dev, int index)
{
	/* struct hw_revision_t hw_rev; */

	int retval = CVE_DEFAULT_ERROR_CODE;

	dev->dev_index = index;


	/* TODO : Need to be reconsidered - should this
	 * initialization be part of device_interface init ?
	 */
	retval = project_hook_init_cve_dump_buffer(dev);
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"project_hook_init_cve_dump_buffer failed %d\n",
				retval);
		goto out;
	}


	dev->interrupts_status = 0;

	dev->di_cve_needs_reset = 0;
	/* INVALID_CONTEXT_ID (0) will trigger
	 * a reset on the first time.
	 */
	dev->last_context_id = INVALID_CONTEXT_ID;

	/* on power up the counters are disabled */
	dev->is_hw_counters_enabled = 0;

	/*Init CVE major and minor version*/
	dev->version_info.format = "Revision = %x.%x\n";

	/* Initializes Invalid Persistent Nw*/
	dev->pnetwork_id = INVALID_NETWORK_ID;

	/* Power state of device is not known at this point */
	dev->power_state = ICE_POWER_UNKNOWN;

#if 0
	get_hw_revision(dev, &hw_rev);
	dev->version_info.major = hw_rev.major_rev;
	dev->version_info.minor = hw_rev.minor_rev;
#endif

	/* base fw package loading */
	retval = cve_fw_load(dev);
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"FW base package loading failed %d\n", retval);
		goto out;
	}

	/* Init platform specific data*/
	retval = init_platform_data(dev);
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"init_platform_data failed %d\n", retval);
		goto init_platform_data_failed;
	}
	/* initialize trace specific fops*/
	retval = init_icedrv_trace(dev);
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_WARNING,
				"failed in init_icedrv_trace() %d\n", retval);
	}
	/* initialize ice debug event flow*/
	retval = init_icedrv_debug_event();
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_WARNING,
				"init_icedrv_debug_event failed %d\n", retval);
	}

	/*Add to list of devices in the device group */
	cve_dg_add_device(dev);

#ifndef RING3_VALIDATION
	retval = ice_swc_create_node(ICEDRV_SWC_CLASS_DEVICE,
					dev->dev_index,
					0,
					&dev->hswc);
	if (retval < 0) {
		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Unable to create SW Counter's Device node\n");
		goto init_platform_data_failed;
	}
#endif

	/* success */
	return 0;

init_platform_data_failed:
	/* cleanup fw binaries */
	cve_fw_unload(dev, dev->fw_loaded_list);
out:
	return retval;
}

void cve_device_clean(struct cve_device *dev)
{
	cve_dg_remove_device(dev);

	/* Remove ice debug event flow*/
	term_icedrv_debug_event();

	/* remove trace specific fops*/
	term_icedrv_trace(dev);

	/* mask the interrupts */
	cve_di_mask_interrupts(dev);

	/* base fw package unloading */
	cve_fw_unload(dev, dev->fw_loaded_list);

	cleanup_platform_data(dev);

	project_hook_free_cve_dump_buffer(dev);
}

