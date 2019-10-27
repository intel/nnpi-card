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
#include "device_interface.h"
#include "cve_firmware.h"
#include "ice_trace.h"

#include "ice_sw_counters.h"
#include "icedrv_internal_sw_counter_funcs.h"
#include "ice_debug_event.h"



int cve_device_init(struct cve_device *dev, int index, u64 pe_value)
{
	/* struct hw_revision_t hw_rev; */

	u64 pe_mask;
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

	/* on power up the counters are disabled */
	dev->is_hw_counters_enabled = 0;

	/*Init CVE major and minor version*/
	dev->version_info.format = "Revision = %x.%x\n";

	/* Initializes Invalid Persistent Nw*/
	dev->dev_ntw_id = INVALID_NETWORK_ID;

	pe_mask = BIT_ULL(dev->dev_index) << 4;
	/*If device is ON*/
	if ((pe_value & pe_mask) != pe_mask)
		ice_dev_set_power_state(dev, ICE_POWER_OFF);
	else
		ice_dev_set_power_state(dev, ICE_POWER_ON);

	/*set default value for ice freq due to issue in P-Code (ICE-14643)*/
	dev->frequency = ICE_FREQ_DEFAULT;

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

	/*initialize icedrv specific fops*/
	retval = init_icedrv_sysfs();
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_WARNING,
				"failed in init_icedrv_sysfs() %d\n", retval);
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

	/* initialize hw_config specific fops*/
	retval = init_icedrv_hw_config(dev);
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_WARNING,
				"init_icedrv_hw_config failed %d\n", retval);
	}

	/*Add to list of devices in the device group */
	cve_dg_add_device(dev);

	ice_di_start_llc_pmon(dev, true);

	ice_swc_create_dev_node(dev);

	ice_swc_counter_set(dev->hswc, ICEDRV_SWC_DEVICE_COUNTER_POWER_STATE,
		ice_dev_get_power_state(dev));

	getnstimeofday(&dev->idle_start_time);
	ice_swc_counter_set(dev->hswc,
		ICEDRV_SWC_DEVICE_COUNTER_IDLE_START_TIME,
		(dev->idle_start_time.tv_sec * USEC_PER_SEC) +
		(dev->idle_start_time.tv_nsec / NSEC_PER_USEC));
	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"idle_start_time.tv_sec=%ld idle_start_time.tv_nsec=%ld\n",
		dev->idle_start_time.tv_sec, dev->idle_start_time.tv_nsec);

	retval = init_ice_iccp(dev);
	if (retval) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "() failed: in iccp init %d\n",
									retval);
	}
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
	term_ice_iccp(dev);

	/*remove hw_config specific fops*/
	term_icedrv_hw_config(dev);

	cve_dg_remove_device(dev);

	ice_swc_destroy_dev_node(dev);

	/* Remove ice debug event flow*/
	term_icedrv_debug_event();

	/* remove trace specific fops*/
	term_icedrv_trace(dev);

	/*remove icedrv specific fops*/
	term_icedrv_sysfs();

	/* mask the interrupts */
	cve_di_mask_interrupts(dev);

	/* base fw package unloading */
	cve_fw_unload(dev, dev->fw_loaded_list);

	cleanup_platform_data(dev);

	project_hook_free_cve_dump_buffer(dev);

}

enum ICE_POWER_STATE ice_dev_get_power_state(struct cve_device *dev)
{
	return dev->power_state;
}

void ice_dev_set_power_state(struct cve_device *dev,
	enum ICE_POWER_STATE pstate)
{
	if ((pstate == ICE_POWER_OFF_INITIATED) &&
		(ice_get_power_off_delay_param() < 0)) {

		/* Donot initiate Power-off because it is disabled. Device
		 * will continue to be in POWER_ON state.
		 */
		goto out;
	}

	dev->power_state = pstate;

out:
	return;
}

