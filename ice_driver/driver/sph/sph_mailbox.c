/*
 * NNP-I Linux Driver
 * Copyright (c) 2019, Intel Corporation.
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

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/sysfs.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/kobject.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/anon_inodes.h>
#include <linux/uaccess.h>
#include <linux/fcntl.h>
#include <linux/pci.h>
#include <linux/delay.h>

#include  "cve_device.h"
#include "os_interface.h"
#include "cve_device_group.h"
#include "cve_linux_internal.h"
#include "sph_mailbox.h"

#define SPHMB_DELAY_NS 1000
#define SPHMB_RETRY_NUM 1000

static bool poll_mailbox_ready(struct ice_sphmbox *sphmb)
{
	u32 *mbx_interface;
	union PCODE_MAILBOX_INTERFACE iface;
	int retries = SPHMB_RETRY_NUM; /* 1ms */

	mbx_interface = sphmb->idc_mailbox_base +
				PCU_CR_ICEDRIVER_PCODE_MAILBOX_INTERFACE;

	do {
		ndelay(SPHMB_DELAY_NS);
		iface.InterfaceData = ioread32(mbx_interface);
	} while (iface.BitField.RunBusy  && --retries > 0);

	return iface.BitField.RunBusy == 0;
}


int write_icedriver_mailbox(struct ice_sphmbox *sphmb,
			    union PCODE_MAILBOX_INTERFACE iface,
			    uint32_t i_data0, uint32_t i_data1,
			    uint32_t *o_data0, uint32_t *o_data1)
{
	u32 *mbx_interface, *mbx_data0, *mbx_data1;
	uint32_t verify_data0, verify_data1;
	uint32_t verify_data0_1, verify_data1_1;
	union PCODE_MAILBOX_INTERFACE verify_iface0;
	union PCODE_MAILBOX_INTERFACE verify_iface1;
	int ret = 0;

	if (!sphmb) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"null sphmb pointer (%d) !!\n", -EINVAL);
		return -EINVAL;
	}

	if (!sphmb->idc_mailbox_base) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"Mailbox is not supported - ERR (%d) !!\n", -EINVAL);
		return -EINVAL;
	}

	ICEDRV_SPIN_LOCK(&sphmb->lock);


	mbx_interface = sphmb->idc_mailbox_base +
				PCU_CR_ICEDRIVER_PCODE_MAILBOX_INTERFACE;
	mbx_data0 = sphmb->idc_mailbox_base +
				PCU_CR_ICEDRIVER_PCODE_MAILBOX_DATA0;
	mbx_data1 = sphmb->idc_mailbox_base +
				PCU_CR_ICEDRIVER_PCODE_MAILBOX_DATA1;

	iface.BitField.RunBusy = 1;

	if (!poll_mailbox_ready(sphmb)) {
		ret = -EBUSY;
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"Mailbox is not ready for usage - ERR (%d) !!\n", ret);
		goto err;
	}

	cve_os_log(CVE_LOGLEVEL_DEBUG, "write to mbox (%d, %d, %d, %d, %d)\n",
				iface.BitField.Command, iface.BitField.Param1,
				iface.BitField.Param2, i_data0, i_data1);


	iowrite32(i_data1, mbx_data1);
	iowrite32(i_data0, mbx_data0);
	iowrite32(iface.InterfaceData, mbx_interface);

	if (!poll_mailbox_ready(sphmb)) {
		ret = -EBUSY;
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"Mailbox post write is not ready for usage - ERR (%d) !!\n",
			ret);
		goto err;
	}

	verify_iface0.InterfaceData = ioread32(mbx_interface);
	verify_data0 = ioread32(mbx_data0);
	verify_data1 = ioread32(mbx_data1);

	ndelay(SPHMB_DELAY_NS);

	verify_iface1.InterfaceData = ioread32(mbx_interface);
	verify_data0_1 = ioread32(mbx_data0);
	verify_data1_1 = ioread32(mbx_data1);

	if (verify_iface0.InterfaceData != verify_iface1.InterfaceData ||
	    verify_data0 != verify_data0_1 ||
	    verify_data1 != verify_data1_1) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"Inconsistent mailbox data after write !!\n");
		ret = -EIO;
		goto err;
	}

	if (verify_iface0.BitField.Command != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"Failed to write through mailbox status=%d\n",
					verify_iface0.BitField.Command);
		ret = -EIO;
		goto err;
	}

	cve_os_log(CVE_LOGLEVEL_DEBUG, "reply from mbox (%d, %d, %d)\n",
		       verify_iface0.InterfaceData, verify_data0, verify_data1);
	if (o_data0)
		*o_data0 = verify_data0;

	if (o_data1)
		*o_data1 = verify_data1;


err:
	ICEDRV_SPIN_UNLOCK(&sphmb->lock);

	return ret;
}
/* map IDC Mailbox in bar0 from IDC Device */
int sphpb_map_idc_mailbox_base_registers(struct ice_sphmbox *sphmb)
{
	struct cve_os_device *os_dev;
	struct cve_device *ice_dev = ice_get_first_dev();

	if (!ice_dev) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "No valid ice device\n");
		return -ENODEV;
	}

	if (!sphmb) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"null sphmb pointer (%d) !!\n", -EINVAL);
		return -EINVAL;
	}

	os_dev = to_cve_os_device(ice_dev);
	if (!os_dev) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"bad os_dev pointer (%d) !!\n", -EINVAL);
		return -EINVAL;
	}

	sphmb->idc_mailbox_base = os_dev->cached_mmio_base.iobase[0] +
					(size_t)(IDC_BAR_0_MAILBOX_START);
	spin_lock_init(&sphmb->lock);

	return 0;
}

/* unmap IDC Mailbox in bar0 from IDC Device */
int sphpb_unmap_idc_mailbox_base_registers(struct ice_sphmbox *sphmb)
{
	if (!sphmb) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"null sphmb pointer (%d) !!\n", -EINVAL);
		return -EINVAL;
	}

	if (!sphmb->idc_mailbox_base)
		return -ENODEV;

	sphmb->idc_mailbox_base = NULL;

	return 0;
}

