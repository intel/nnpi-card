/********************************************
 * Copyright (C) 2019-2021 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#include <linux/debugfs.h>

int sphcs_init_maint_interface(void);
void sphcs_release_maint_interface(void);
void sphcs_maint_init_debugfs(struct dentry *parent);
int sphcs_maint_send_sys_info(void);
int sphcs_fpga_power_sysfs_init(struct kobject *kobj);
void sphcs_fpga_power_sysfs_deinit(struct kobject *kobj);
