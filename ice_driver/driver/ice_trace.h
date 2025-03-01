/********************************************
 * Copyright (C) 2019-2021 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/


#ifndef _ICE_TRACE_H_
#define _ICE_TRACE_H_

#include "cve_driver_internal.h"

int __init_icedrv_trace(struct cve_device *ice_dev);
void __term_icedrv_trace(struct cve_device *ice_dev);
int ice_restore_trace_hw_regs(struct cve_device *ice_dev);

/* Device specific internal functions */
int ice_trace_register_uncore_callbacks(struct cve_device *ice_dev);
int ice_trace_dso_register_uncore_callbacks(struct ice_dso_regs_data *dso);
void ice_trace_unregister_uncore_callbacks(struct cve_device *ice_dev);
int ice_trace_write_dso_regs(struct cve_device *ice_dev);
int ice_trace_configure_registers_reader_demon(struct cve_device *ice_dev);
int ice_trace_configure_perf_counter(struct cve_device *ice_dev);
int ice_trace_configure_one_perf_counter(struct cve_device *ice_dev,
								u32 curr_cfg);
bool ice_trace_hw_debug_check(struct cve_device *ice_dev);
int ice_trace_init_bios_sr_page(struct cve_device *ice_dev);
int ice_trace_restore_hw_dso_regs(struct cve_device *ice_dev);
int ice_trace_restore_daemon_config(struct cve_device *ice_dev,
					bool is_restore_from_suspend);
int ice_trace_sysfs_init(struct cve_device *ice_dev);
void ice_trace_sysfs_term(struct cve_device *ice_dev);
int ice_trace_init_dso(struct cve_device *ice_dev);
int ice_trace_set_default_dso(struct cve_device *ice_dev);
int __ice_trace_dso_config_port_regsoffset(struct cve_device *ice_dev);
#if ICEDRV_ENABLE_HSLE_FLOW
#define init_icedrv_trace(x) __no_op_stub
#define term_icedrv_trace(x) __no_op_stub
#else
#define init_icedrv_trace(x) __init_icedrv_trace(x)
#define term_icedrv_trace(x) __term_icedrv_trace(x)
#endif /*ICEDRV_ENABLE_HSLE_FLOW*/

#endif /* _ICE_TRACE_H_ */

