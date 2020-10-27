/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/



#include "cve_device.h"
#include "cve_driver_internal_macros.h"
#include "os_interface.h"
#include "memory_manager.h"
#include "device_interface.h"
#include "cve_firmware.h"
#include "ice_trace.h"

#include "ice_sw_counters.h"
#include "icedrv_internal_sw_counter_funcs.h"


int cve_device_init(struct cve_device *dev, int index, u64 pe_value)
{
	/* struct hw_revision_t hw_rev; */

	u64 pe_mask;
	int retval = CVE_DEFAULT_ERROR_CODE;
	u32 max_freq_allowed;

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

	/*Init CVE major and minor version*/
	dev->version_info.format = "Revision = %x.%x\n";

	/* Initializes Invalid Persistent Nw*/
	dev->dev_pntw_id = INVALID_NETWORK_ID;
	dev->dev_ntw_id = INVALID_NETWORK_ID;
	dev->dev_ctx_id = INVALID_CONTEXT_ID;

	pe_mask = BIT_ULL(dev->dev_index) << 4;
	/*If device is ON*/
	if ((pe_value & pe_mask) != pe_mask)
		ice_dev_set_power_state(dev, ICE_POWER_OFF);
	else
		ice_dev_set_power_state(dev, ICE_POWER_ON);

	/*set default value for ice freq due to issue in P-Code (ICE-14643)*/
	max_freq_allowed = get_ice_max_freq();
	if (max_freq_allowed < ICE_FREQ_DEFAULT)
		dev->frequency = max_freq_allowed;
	else
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
	init_platform_data(dev);

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

	dev->idle_start_time = trace_clock_global();
	ice_swc_counter_set(dev->hswc,
		ICEDRV_SWC_DEVICE_COUNTER_IDLE_START_TIME,
		(nsec_to_usec(dev->idle_start_time)));
	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"idle_start_time(usec)=%llu\n",
		nsec_to_usec(dev->idle_start_time));

	retval = init_ice_iccp(dev);
	if (retval) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "() failed: in iccp init %d\n",
									retval);
	}
	configure_pmon_names(dev);

	dev->cdyn_val = 0;
	dev->cdyn_requested = 0;
	dev->tlc_reg_val = 0;

	ice_reset_prev_reg_config(&dev->prev_reg_config);

	/* success */
	return 0;

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
		!ice_get_power_off_delay_param()) {

		/* Donot initiate Power-off because it is disabled. Device
		 * will continue to be in POWER_ON state.
		 */
		goto out;
	}

	dev->power_state = pstate;

out:
	return;
}

void ice_reset_prev_reg_config(struct ice_reg_stored_config *pconfig)
{
	ice_memset_s(pconfig->mmu_config_md5,
		sizeof(pconfig->mmu_config_md5[0]) * ICEDRV_MD5_MAX_SIZE, 0,
		sizeof(pconfig->mmu_config_md5[0]) * ICEDRV_MD5_MAX_SIZE);

	ice_memset_s(pconfig->page_sz_reg,
		sizeof(pconfig->page_sz_reg[0]) *
			ICE_PAGE_SZ_CONFIG_REG_COUNT,
		0xDEADBEEF,
		sizeof(pconfig->page_sz_reg[0]) *
			ICE_PAGE_SZ_CONFIG_REG_COUNT);

	pconfig->cbd_entries_nr = 0xDEADBEEF;
}

