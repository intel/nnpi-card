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
#ifndef _DUMMY_PCI_H
#define _DUMMY_PCI_H

#include <linux/pci.h>
#include <linux/types.h>

#include "dummy_icedc.h"

#define BAR_0 0
#define BAR_2 2

int pcim_enable_device_null(struct pci_dev *pdev);
int pcim_iomap_regions_null(struct pci_dev *pdev, int mask, const char *name);
void* pci_iomap_null(struct pci_dev *dev, int bar, unsigned long maxlen);
dma_addr_t pci_resource_start_null(struct pci_dev *pdev, u8 bar);
u32 pci_resource_len_null(struct pci_dev *pdev, u8 bar);
void pci_set_drvdata_null(struct pci_dev *pdev, void *data);
int devm_request_threaded_irq_null(struct device *dev, unsigned int irq,
			      dummy_irq_handler handler,
			      dummy_irq_handler thread_fn,
			      unsigned long irqflags, const char *devname,
			      void *dev_id);
void pci_set_master_null(struct pci_dev *dev);
int pci_set_dma_mask_null(struct pci_dev *dev, u64 mask);
int pci_set_consistent_dma_mask_null(struct pci_dev *dev, u64 mask);
void *pci_get_drvdata_null(struct pci_dev *pdev);
#endif
