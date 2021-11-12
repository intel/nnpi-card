/********************************************
 * Copyright (C) 2019-2021 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/



#include <asm/page.h>
#include <asm/cacheflush.h>
#include <linux/scatterlist.h>
#include <linux/dma-mapping.h>
#include <linux/pci.h>

#include "os_interface.h"
#include "cve_driver_internal.h"
#include "cve_linux_internal.h"

#ifdef FPGA
#include <linux/highmem.h>
#endif

int cve_os_is_kernel_memory(uintptr_t vaddr)
{
	return virt_addr_valid(vaddr);
}

int project_hook_enable_msi_interrupt(struct cve_os_device *os_dev)
{
	int retval = 0;

#ifdef FPGA
	/* register the interrupt handler  */
	retval = pci_enable_msi(to_pci_dev(os_dev->dev));

#endif

	return retval;
}

int cve_sync_sgt_to_llc(struct sg_table *sgt)
{
	return 0;
}
