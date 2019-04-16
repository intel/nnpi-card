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
#ifndef _CVE_LINUX_INTERNAL_H_
#define _CVE_LINUX_INTERNAL_H_

#ifndef RING3_VALIDATION
#include <linux/clk.h>
#include <linux/device.h>
#include <linux/bitops.h>
#include <linux/cdev.h>
#else
#include "linux_kernel_mock.h"
#endif
#include "cve_device.h"

#ifdef IDC_ENABLE
#include "idc_device.h"
#endif

#define DO_FUNC_TRACE 0

#if DO_FUNC_TRACE
#include "os_interface.h"
#define FUNC_ENTER() {cve_os_log(CVE_LOGLEVEL_ERROR, "ENTER\n"); }
#define FUNC_LEAVE() {cve_os_log(CVE_LOGLEVEL_ERROR, "LEAVE\n"); }
#else
#define FUNC_ENTER()
#define FUNC_LEAVE()
#endif

#define MAX_BARS_PCI_DEVICE 6

#define BAR0_MASK BIT(0)
#define BAR2_MASK BIT(2)

struct mmio_base_addr {
	u32 len[MAX_BARS_PCI_DEVICE];
	void *iobase[MAX_BARS_PCI_DEVICE];
};

struct cve_device_group;

#ifdef IDC_ENABLE
struct cve_os_device {
	struct device *dev;
#ifndef RING3_VALIDATION
	struct reset_control *rstc;
	struct clk *cve_clk;
	struct mmio_base_addr cached_mmio_base;
	struct dentry *dev_dir;
	struct debugfs_regset32 regset;
#endif
	struct idc_device idc_dev;
};
#else
struct cve_os_device {
	struct device *dev;
#ifndef RING3_VALIDATION
	struct reset_control *rstc;
	struct clk *cve_clk;
	struct mmio_base_addr cached_mmio_base;
	struct dentry *dev_dir;
	struct debugfs_regset32 regset;
#endif
	struct cve_device cve_dev;
};
#endif

/*
 * ((struct cve_os_device *)(char *)cve_dev_ptr)
 * TODO:
*/
#ifdef IDC_ENABLE
#define to_cve_os_device(cve_dev_ptr)\
((struct cve_os_device *)((char *)(cve_dev_ptr)\
-(char *)(&((struct cve_os_device *)0)->idc_dev.cve_dev[\
cve_dev_ptr->dev_index])))
#else
#define to_cve_os_device(cve_dev_ptr)\
container_of(cve_dev_ptr, struct cve_os_device, cve_dev)
#endif

/*
 * platform specific driver registration function
 * called by the driver initialization function,
 * which is common for all platforms
 */
int cve_register_driver(void);

/*
 * platform specific driver un-registration function
 * called by the driver exit function,
 * which is common for all platforms
 */
void cve_unregister_driver(void);

/*
 * the common part of the device removal function,
 * called from the platform-specific driver removed function
 */
void cve_remove_common(struct cve_os_device *linux_device);

/*
 * the common part of the device probe function
 * called from the platform-specific driver probe function
 * inputs:
 * linux_device: pointing on linux device struct.
 * dev_ind: the device index which will be applied to
 *          the device pointed by linux_device, during device_init.
 */
int cve_probe_common(struct cve_os_device *linux_device, int dev_ind);

/*
 * interrupt handler -
 * referenced by the platform-specific interrupt registration function
 */
cve_isr_retval_t cve_os_interrupt_handler(int irq, void *dev_id);
cve_isr_retval_t cve_os_interrupt_handler_bh(int irq, void *os_dev);

/* device structure which is used by several linux-specific files */
extern struct device *g_linux_device;

/* base address of the MMIO space */
extern struct mmio_base_addr g_cached_mmio_base;

#endif /* _CVE_LINUX_INTERNAL_H_ */
