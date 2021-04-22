/*
 * NNP-I Linux Driver
 * Copyright (c) 2018-2021, Intel Corporation.
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

#include "dummy_pci.h"
#include "null_dev.h"

int pcim_enable_device_null(struct pci_dev *pdev)
{
	/* Success */
	return 0;
}

int pcim_iomap_regions_null(struct pci_dev *pdev, int mask, const char *name)
{
	/* Success */
	return 0;
}

void *pci_iomap_null(struct pci_dev *dev, int bar, unsigned long maxlen)
{
	return 0;
}

dma_addr_t pci_resource_start_null(struct pci_dev *pdev, u8 bar)
{
	return 0;
}

u32 pci_resource_len_null(struct pci_dev *pdev, u8 bar)
{

	u32 len;

	if (bar == BAR_0)
		len = 0x800000;
	else if (bar == BAR_2)
		len = 0x80000;
	else
		len = 0;


	return len;
}

int devm_request_threaded_irq_null(struct device *dev, unsigned int irq,
			      dummy_irq_handler handler,
			      dummy_irq_handler thread_fn,
			      unsigned long irqflags, const char *devname,
			      void *dev_id)
{

	interrupt_top_half = handler;
	if (interrupt_top_half != NULL)
		null_device_log("dummy interrupt irq successful\n");
	create_dummy_threaded_irq(dev_id);

	return 0;
}

void pci_set_master_null(struct pci_dev *dev)
{
	return;
}

int pci_set_dma_mask_null(struct pci_dev *dev, u64 mask)
{
	*dev->dev.dma_mask = mask;
	return 0;
}

int pci_set_consistent_dma_mask_null(struct pci_dev *dev, u64 mask)
{
	return 0;
}
