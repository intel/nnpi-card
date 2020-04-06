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

#ifndef _ICEDRV_UNCORE_H_
#define _ICEDRV_UNCORE_H_

#include <linux/mm.h>
#include <linux/types.h>
#include <linux/miscdevice.h>
#include <linux/dma-mapping.h>
#include <linux/device.h>
#include <linux/debugfs.h>
#include <linux/uaccess.h>
#include <linux/dma-buf.h>
#include <linux/device.h>
#include <linux/scatterlist.h>
#include <linux/pci.h>

struct icedrv_regbar_callbacks {

	void (*regbar_write)(u8 port, u16 crOffset, u32 value);
	u32 (*regbar_read)(u8 port, u16 crOffset);
};
int icli_map_regbar(struct pci_dev *pdev);
int intel_icedrv_uncore_regbar_cb(struct icedrv_regbar_callbacks **regbar_cb);
int init_icedrv_uncore(void);
#endif
