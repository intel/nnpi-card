/*
 * NNP-I Linux Driver
 * Copyright (c) 2018-2019, Intel Corporation.
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
		ret = ice_trace_configure_perf_counter(ice_dev);
		if (ret) {
			cve_os_dev_log(CVE_LOGLEVEL_ERROR,
			  ice_dev->dev_index,
			  "Problem in Perf counter setup registers\n");
			goto out;
		} else {
			cve_os_dev_log(CVE_LOGLEVEL_INFO,
			  ice_dev->dev_index,
			  "Perf counter setup registers restored\n");
		}
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
		if (ret) {
			cve_os_dev_log(CVE_LOGLEVEL_ERROR, ice_dev->dev_index,
					"Problem in reader daemon write\n");
			goto out;
		} else {
			if (is_restore_from_suspend)
				ice_dev->daemon.restore_needed_from_suspend =
									false;
			cve_os_dev_log(CVE_LOGLEVEL_INFO, ice_dev->dev_index,
					"Reader daemon registers restored\n");
		}
		break;
	default:
		cve_os_dev_log(CVE_LOGLEVEL_DEBUG, ice_dev->dev_index,
			"Register reader daemon registers restore skipped\n");
		break;

	}
out:
	FUNC_LEAVE();

	return ret;
}

int ice_trace_config(struct ice_hw_trace_config *cfg)
{
#define __max_u32 0xFFFFFFFF

	unsigned int i;
	int ret;
	u32 obs_sz = 0;
	u32 cntr_sz = 0;
	u32 daemon_sz = 0;
	struct ice_observer_config *k_observers = NULL;
	struct ice_perf_counter_setup *k_counter_setups = NULL;
	struct ice_register_reader_daemon *k_reg_daemons = NULL;
	u32 device_mask = 0;
	u32 dev_index;
	u32 obs_trunc;
	u32 cntr_trunc;
	u32 daemon_trunc;

	FUNC_ENTER();

	/*Fixme: Scope for doing fine grained lock instead of big lock*/
	ret = cve_os_lock(&g_cve_driver_biglock, CVE_INTERRUPTIBLE);
	if (ret != 0) {
		ret = -ERESTARTSYS;
		goto out;
	}

	if (cfg->ice_observer_count == 0) {
		/*Reset to default setting*/
		for (i = 0; i < NUM_ICE_UNIT; i++) {
			ret = ice_trace_set_ice_observers(NULL, i);
			if (ret)
				goto unlock;
		}
	} else {
		obs_trunc = __max_u32 / sizeof(struct ice_observer_config);
		if (cfg->ice_observer_count > obs_trunc) {
			cve_os_log(CVE_LOGLEVEL_WARNING,
			    "ice observer count exceeds the Maximum limit and it can lead to integer overflow. So, count is truncated from %d to %d\n",
			    cfg->ice_observer_count, obs_trunc);
			cfg->ice_observer_count = obs_trunc;
		}

		obs_sz = sizeof(struct ice_observer_config) *
			cfg->ice_observer_count;
		ret = OS_ALLOC_ZERO(obs_sz, (void **)&k_observers);
		if (ret < 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
			     "observer alloc failed:%d SZ:%d\n", ret, obs_sz);
			goto unlock;
		}
		ret = cve_os_read_user_memory(cfg->observer_list,
						obs_sz, k_observers);
		if (ret != 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
			       "observer os_read_user_memory failed %d\n", ret);
			goto obs_free;
		}
		/* create the device mask along with sanity check*/
		for (i = 0; i < cfg->ice_observer_count; i++) {
			/* first set bit is considered */
			dev_index = ffs(k_observers[i].ice_number) - 1;
			if (dev_index >= NUM_ICE_UNIT) {
				cve_os_log(CVE_LOGLEVEL_ERROR,
			      "Invalid dev_index %d ice_number(bitmask) 0x%x\n",
					dev_index, k_observers[i].ice_number);
				ret = -EINVAL;
				goto obs_free;
			}
			device_mask = device_mask | 1 << dev_index;
			ret = ice_trace_set_ice_observers(&k_observers[i],
								dev_index);
			if (ret)
				goto obs_free;
		}
		for (i = 0; i < NUM_ICE_UNIT; i++) {
			if ((~device_mask) & (1 << i)) {
				ret = ice_trace_set_ice_observers(NULL, i);
				if (ret)
					goto obs_free;
			}
		}
	}

	if (cfg->ice_perf_counter_setup_count == 0) {
		/*Reset to default setting*/
	} else {
		cntr_trunc = __max_u32 /
				sizeof(struct ice_perf_counter_setup);
		if (cfg->ice_perf_counter_setup_count > cntr_trunc) {
			cve_os_log(CVE_LOGLEVEL_WARNING,
				"ice performance counter setup count exceeds the Maximum limit and it can lead to integer overflow. So, it is truncated from %d to %d\n",
				cfg->ice_perf_counter_setup_count,
				cntr_trunc);
			cfg->ice_perf_counter_setup_count = cntr_trunc;
		}

		cntr_sz = sizeof(struct ice_perf_counter_setup) *
			cfg->ice_perf_counter_setup_count;

		ret = OS_ALLOC_ZERO(cntr_sz, (void **)&k_counter_setups);
		if (ret < 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
			  "perf cntr alloc failed:%d SZ:%d\n", ret, cntr_sz);
			goto obs_free;
		}
		ret = cve_os_read_user_memory(cfg->counter_setup_list,
						cntr_sz, k_counter_setups);
		if (ret != 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
			   "perf counter os_read_user_memory failed %d\n", ret);
			goto cntr_free;
		}
	}

	for (i = 0; i < cfg->ice_perf_counter_setup_count; i++) {
		ret = ice_trace_set_perf_counter_setup(&k_counter_setups[i]);
		if (ret != 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
			   "perf counter setup failed %d\n", ret);
			goto cntr_free;
		}
	}

	device_mask = 0;
	if (cfg->ice_reg_daemon_count == 0) {
		/*Reset to default setting*/
		for (i = 0; i < NUM_ICE_UNIT; i++)
			ice_trace_set_reg_reader_daemon(NULL, i);
	} else {
		daemon_trunc = __max_u32 /
				sizeof(struct ice_register_reader_daemon);
		if (cfg->ice_reg_daemon_count > daemon_trunc) {
			cve_os_log(CVE_LOGLEVEL_WARNING,
				"ice register dameon count exceeds the Maximum limit and it can lead to integer overflow. So, it is truncated from %d to %d\n",
				cfg->ice_reg_daemon_count, daemon_trunc);
			cfg->ice_reg_daemon_count = daemon_trunc;
		}

		daemon_sz = sizeof(struct ice_register_reader_daemon) *
			cfg->ice_reg_daemon_count;
		ret = OS_ALLOC_ZERO(daemon_sz, (void **)&k_reg_daemons);
		if (ret < 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
			   "daemons alloc failed:%d SZ:%d\n", ret, daemon_sz);
			goto cntr_free;
		}
		ret = cve_os_read_user_memory(cfg->reg_daemon_list,
						daemon_sz, k_reg_daemons);
		if (ret != 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
			    "reg daemons os_read_user_memory failed %d\n", ret);
			goto daemon_free;
		}
		/* create the device mask along with sanity check*/
		for (i = 0; i < cfg->ice_reg_daemon_count; i++) {
			/* first set bit is considered */
			dev_index = ffs(k_reg_daemons[i].ice_number) - 1;
			if (dev_index >= NUM_ICE_UNIT) {
				cve_os_log(CVE_LOGLEVEL_ERROR,
			      "Invalid dev_index %d ice_number(bitmask) 0x%x\n",
					dev_index, k_reg_daemons[i].ice_number);
				ret = -EINVAL;
				goto daemon_free;
			}
			device_mask = device_mask | 1 << dev_index;
			ice_trace_set_reg_reader_daemon(&k_reg_daemons[i],
								dev_index);
		}
		for (i = 0; i < NUM_ICE_UNIT; i++) {
			if ((~device_mask) & (1 << i))
				ice_trace_set_reg_reader_daemon(NULL, i);
		}
	}

daemon_free:
	OS_FREE(k_reg_daemons, daemon_sz);
cntr_free:
	OS_FREE(k_counter_setups, cntr_sz);
obs_free:
	OS_FREE(k_observers, obs_sz);
unlock:
	cve_os_unlock(&g_cve_driver_biglock);
out:
	FUNC_LEAVE();

	return ret;
}

