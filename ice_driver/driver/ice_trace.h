/*
 *  NNP-I Linux Driver
 *  Copyright (c) 2018-2019, Intel Corporation.
 *
 *  This program is free software; you can redistribute it and/or modify it
 *  under the terms and conditions of the GNU General Public License,
 *  version 2, as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope it will be useful, but WITHOUT
 *  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 *  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 *  more details.
 *
 */
#ifndef _ICE_TRACE_H_
#define _ICE_TRACE_H_

int init_icedrv_trace(struct cve_device *ice_dev);
void term_icedrv_trace(struct cve_device *ice_dev);
int ice_restore_trace_hw_regs(struct cve_device *ice_dev);
int ice_trace_config(struct ice_hw_trace_config *cfg);

/* Device specific internal functions */
int ice_trace_set_ice_observers(struct ice_observer_config *dso_config,
							u32 dev_index);
int ice_trace_set_perf_counter_setup(struct ice_perf_counter_setup *perf_ctr);
int ice_trace_set_reg_reader_daemon(struct ice_register_reader_daemon *daemon,
							u32 dev_index);

int ice_trace_register_uncore_callbacks(struct cve_device *ice_dev);
void ice_trace_unregister_uncore_callbacks(struct cve_device *ice_dev);
int ice_trace_write_dso_regs(struct cve_device *ice_dev);
int ice_trace_configure_registers_reader_demon(struct cve_device *ice_dev);
int ice_trace_configure_perf_counter(struct cve_device *ice_dev);
int ice_trace_configure_one_perf_counter(struct cve_device *ice_dev,
								u32 curr_cfg);
bool ice_trace_hw_debug_check(struct cve_device *ice_dev);
int ice_trace_init_bios_sr_page(struct cve_device *ice_dev);
int ice_trace_restore_hw_dso_regs(struct cve_device *ice_dev);
int ice_trace_sysfs_init(struct cve_device *ice_dev);
void ice_trace_sysfs_term(struct cve_device *ice_dev);
int ice_trace_init_dso(struct cve_device *ice_dev);
#endif /* _ICE_TRACE_H_ */

