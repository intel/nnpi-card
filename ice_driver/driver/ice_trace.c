/********************************************
 * Copyright (C) 2019-2021 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/



#ifndef RING3_VALIDATION
#include <linux/printk.h>
#include "icedrv_uncore.h"
#endif

#include "cve_linux_internal.h"
#include "cve_device.h"
#include "cve_driver_internal.h"
#include "ice_trace.h"

#include "cve_device_group.h"

#ifdef RING3_VALIDATION
#include "coral.h"
#endif

int __init_icedrv_trace(struct cve_device *ice_dev)
{
	int ret = 0;

	FUNC_ENTER()
	/* Set dso configuration status to default*/
	ice_dev->dso.dso_config_status = TRACE_STATUS_DEFAULT;
	ice_dev->logical_dso = false;
	ret = ice_trace_init_dso(ice_dev);
	if (ret)
		return ret;

	/* Set registers reader daemon  configuration status to default */
	ice_dev->daemon.daemon_config_status = TRACE_STATUS_DEFAULT;
	ice_dev->daemon.conf.daemon_table_len = 0;
	ice_dev->daemon.reset_conf.daemon_table_len = 0;
	ice_dev->daemon.restore_needed_from_suspend = false;

	/*Initalize perf Counter config length to 0 */
	ice_dev->perf_counter.perf_counter_config_len = 0;

	ret = ice_trace_register_uncore_callbacks(ice_dev);
#ifndef RING3_VALIDATION
	ret = ice_trace_init_bios_sr_page(ice_dev);
	ret = ice_trace_sysfs_init(ice_dev);
	ret = init_icedrv_uncore();
#endif

	FUNC_LEAVE();

	return ret;
}

void __term_icedrv_trace(struct cve_device *ice_dev)
{
	FUNC_ENTER();

#ifndef RING3_VALIDATION
	ice_trace_sysfs_term(ice_dev);
#endif
	ice_trace_unregister_uncore_callbacks(ice_dev);
	cve_os_dev_log(CVE_LOGLEVEL_DEBUG,
			ice_dev->dev_index,
			"icedrv_trace  term done\n");
	FUNC_LEAVE();

}

int ice_restore_trace_hw_regs(struct cve_device *ice_dev)
{
	int ret = 0;

	FUNC_ENTER();

	if (ice_dev->logical_dso) {
		ret = __ice_trace_dso_config_port_regsoffset(ice_dev);
		if (ret) {
			cve_os_dev_log(CVE_LOGLEVEL_ERROR, ice_dev->dev_index,
				"__ice_trace_dso_config_port_regsoffset() failed\n");
			goto out;
		}
	}

#ifndef RING3_VALIDATION
	if (ice_trace_hw_debug_check(ice_dev)) {
		ret = ice_trace_restore_hw_dso_regs(ice_dev);
		if (ret) {
			cve_os_dev_log(CVE_LOGLEVEL_ERROR, ice_dev->dev_index,
					"restore hw dso regs failed\n");
			goto out;
		} else {
			cve_os_dev_log(CVE_LOGLEVEL_INFO, ice_dev->dev_index,
					"hw dso regs restored\n");
		}
	}
#endif
	cve_os_dev_log(CVE_LOGLEVEL_DEBUG, ice_dev->dev_index,
		      "DSO config status %d\n", ice_dev->dso.dso_config_status);
	switch (ice_dev->dso.dso_config_status) {
	case TRACE_STATUS_USER_CONFIG_WRITE_PENDING:
	case TRACE_STATUS_SYSFS_USER_CONFIG_WRITE_PENDING:
	case TRACE_STATUS_SYSFS_USER_CONFIG_WRITE_DONE:
	case TRACE_STATUS_DEFAULT_CONFIG_WRITE_PENDING:
	case TRACE_STATUS_HW_CONFIG_WRITE_PENDING:
	case TRACE_STATUS_USER_CONFIG_WRITE_DONE:
		ret = ice_trace_write_dso_regs(ice_dev);
		if (ret) {
			cve_os_dev_log(CVE_LOGLEVEL_ERROR, ice_dev->dev_index,
						"write_dso_regs() failed\n");
			goto out;
		} else {
			cve_os_dev_log(CVE_LOGLEVEL_INFO, ice_dev->dev_index,
						"DSO registers restored\n");
		}
		break;
	default:
		cve_os_dev_log(CVE_LOGLEVEL_DEBUG, ice_dev->dev_index,
					"DSO registers restore skipped\n");
		break;

	}
	cve_os_dev_log(CVE_LOGLEVEL_DEBUG, ice_dev->dev_index,
		      "Perf Counter config status %d\n",
			ice_dev->perf_counter.perf_counter_config_status);
	switch (ice_dev->perf_counter.perf_counter_config_status) {
	case TRACE_STATUS_USER_CONFIG_WRITE_PENDING:
	case TRACE_STATUS_USER_CONFIG_WRITE_DONE:
	case TRACE_STATUS_SYSFS_USER_CONFIG_WRITE_PENDING:
	case TRACE_STATUS_SYSFS_USER_CONFIG_WRITE_DONE:
		ice_trace_configure_perf_counter(ice_dev);
		cve_os_dev_log(CVE_LOGLEVEL_INFO,
			ice_dev->dev_index,
			"Perf counter setup registers restored\n");
		break;
	default:
		cve_os_dev_log(CVE_LOGLEVEL_DEBUG, ice_dev->dev_index,
			"Perf counter registers restore skipped\n");
		break;
	}

	ret = ice_trace_restore_daemon_config(ice_dev, false);

out:
	FUNC_LEAVE();

	return ret;
}

int ice_trace_restore_daemon_config(struct cve_device *ice_dev,
					bool is_restore_from_suspend)
{
	int ret = 0;

	FUNC_ENTER();

	cve_os_dev_log(CVE_LOGLEVEL_DEBUG, ice_dev->dev_index,
	     "Daemon config status %d\n", ice_dev->daemon.daemon_config_status);

	switch (ice_dev->daemon.daemon_config_status) {
	case TRACE_STATUS_USER_CONFIG_WRITE_PENDING:
	case TRACE_STATUS_DEFAULT_CONFIG_WRITE_PENDING:
	case TRACE_STATUS_USER_CONFIG_WRITE_DONE:
	case TRACE_STATUS_SYSFS_USER_CONFIG_WRITE_PENDING:
	case TRACE_STATUS_SYSFS_USER_CONFIG_WRITE_DONE:
		ret = ice_trace_configure_registers_reader_demon(ice_dev);
		if (is_restore_from_suspend)
			ice_dev->daemon.restore_needed_from_suspend = false;

		cve_os_dev_log(CVE_LOGLEVEL_INFO, ice_dev->dev_index,
				"Reader daemon registers restored\n");
		break;
	default:
		cve_os_dev_log(CVE_LOGLEVEL_DEBUG, ice_dev->dev_index,
			"Register reader daemon registers restore skipped\n");
		break;

	}
	FUNC_LEAVE();

	return ret;
}

