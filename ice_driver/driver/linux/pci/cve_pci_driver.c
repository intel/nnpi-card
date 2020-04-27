/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/



#include <linux/pci.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/pm.h>
#include <linux/pm_runtime.h>

#include "cve_driver_internal.h"
#include "cve_linux_internal.h"
#include "cve_project_internal.h"
#include "dispatcher.h"
#include "cve_device.h"
#include "project_device_interface.h"

#ifdef NULL_DEVICE_RING0
#include "dummy_icedc.h"
#include "dummy_pci.h"

struct pci_dev g_dev;
static u64 g_dma_mask;
#endif
#define CVE_PM_AUTOSUSPEND_DELAY_MILI 5000

/*used to count devices*/
static int dev_index;
static int cve_pci_probe(struct pci_dev *pdev, const struct pci_device_id *id);
static void cve_pci_remove(struct pci_dev *pdev);
static void store_pci_bars(struct cve_os_device *dev,
		void __iomem * const *ioaddr);
static void print_pci_valid_bars(struct cve_os_device *dev);

static const struct pci_device_id m_cve_pci_tbl[] = {
		{PCI_DEVICE(PCI_VENDOR_ID_INTEL, CVE_PCI_DEVICE_ID)},
		{0,} };

MODULE_DEVICE_TABLE(pci, m_cve_pci_tbl);

#ifndef NULL_DEVICE_RING0
/* OS interface functions */
static struct pci_driver m_cve_pci_driver = {
	.name = MODULE_NAME,
	.id_table = m_cve_pci_tbl,
	.probe = cve_pci_probe,
	.remove = cve_pci_remove,
};
#endif

static void store_pci_bars(struct cve_os_device *dev,
		void __iomem * const *ioaddr)
{
	u8 i;

	for (i = 0 ; i < MAX_BARS_PCI_DEVICE ; i++) {
		dev->cached_mmio_base.iobase[i] = ioaddr[i];
#ifdef NULL_DEVICE_RING0
		dev->cached_mmio_base.len[i] =
				pci_resource_len_null(to_pci_dev(dev->dev), i);
#else
		dev->cached_mmio_base.len[i] =
				pci_resource_len(to_pci_dev(dev->dev), i);
#endif

#ifdef NULL_DEVICE_RING0
	ioaddr_bar[i] = (uint64_t) ioaddr[i];
#endif
	}

}

static void print_pci_valid_bars(struct cve_os_device *dev)
{
	u8 i;

	for (i = 0; i < MAX_BARS_PCI_DEVICE; i++)
		if (dev->cached_mmio_base.iobase[i])
			cve_os_log(CVE_LOGLEVEL_DEBUG,
				"BAR%d = 0x%lx, Size=0x%x\n",
				i,
				(uintptr_t)dev->cached_mmio_base.iobase[i],
				dev->cached_mmio_base.len[i]);
}

static int cve_pci_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	int retval = CVE_DEFAULT_ERROR_CODE;
#ifdef SIMICS
	void __iomem *ioaddr[6];
#else /* FPGA */
	void __iomem * const *ioaddr;
#endif
	struct cve_os_device *linux_device;
	struct idc_device *idc_dev;

	FUNC_ENTER();

	/* store the generic device structure */
	linux_device = devm_kzalloc(&pdev->dev,
			sizeof(struct cve_os_device),
			GFP_KERNEL);

	if (linux_device == NULL) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"Failed to allocate %d\n",
				retval);
		goto out;
	}

	linux_device->dev = &pdev->dev;

	/* enable device */
#ifdef NULL_DEVICE_RING0
	retval = pcim_enable_device_null(pdev);
#else
	retval = pcim_enable_device(pdev);
#endif
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"pcim_enable_device failed %d\n",
				retval);
		goto out;
	}

	/* map regions for BAR0 and BAR2 */
#ifdef NULL_DEVICE_RING0
	retval = pcim_iomap_regions_null(pdev,
#else
	retval = pcim_iomap_regions(pdev,
#endif
			BAR0_MASK | BAR2_MASK,
			pci_name(pdev));
	if (retval) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"pcim_iomap_regions failed %d\n",
				retval);
		goto out;
	}

	idc_dev = &linux_device->idc_dev;
#ifdef SIMICS
#ifdef NULL_DEVICE_RING0
	ioaddr[0] = pci_iomap_null(pdev, 0, 0);

	/* Get physical address of Bar-1 and point to ICE Access Window*/
	idc_dev->bar1_base_address = pci_resource_start_null(pdev, 2) +
					IDC_ICE_ACCESS_WINDOW_OFFSET;
#else
	ioaddr[0] = pci_iomap(pdev, 0, 0);

	/* Get physical address of Bar-1 and point to ICE Access Window*/
	idc_dev->bar1_base_address = pci_resource_start(pdev, 2) +
					IDC_ICE_ACCESS_WINDOW_OFFSET;
#endif
#else /* FPGA */
	ioaddr = pcim_iomap_table(pdev);
#endif

	/*
	 * go over the ioaddr and store the BARs addresses and lengths
	 * into the appropriate struct
	 */
	store_pci_bars(linux_device, ioaddr);

	pci_set_drvdata(pdev, linux_device);

	print_pci_valid_bars(linux_device);

#ifndef NULL_DEVICE_RING0
	/* enabling MSI interrupts */
	retval = project_hook_enable_msi_interrupt(linux_device);
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "pci_enable_msi failed %d\n",
				retval);
		goto out;
	}
#endif

#ifdef NULL_DEVICE_RING0
	retval = devm_request_threaded_irq_null(&pdev->dev,
			pdev->irq,
			cve_os_interrupt_handler,
			cve_os_interrupt_handler_bh,
			IRQF_SHARED,
			MODULE_NAME,
			linux_device);
#else
	retval = devm_request_threaded_irq(&pdev->dev,
			pdev->irq,
			cve_os_interrupt_handler,
			cve_os_interrupt_handler_bh,
			IRQF_SHARED,
			MODULE_NAME,
			linux_device);
#endif
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "devm_request_irq failed %d\n",
				retval);
		goto out;
	}

	/* configure DMA */
#ifdef NULL_DEVICE_RING0
	pci_set_master_null(pdev);

	retval = pci_set_dma_mask_null(pdev, CVE_DMA_BIT_MASK);
#else
	pci_set_master(pdev);

	retval = pci_set_dma_mask(pdev, CVE_DMA_BIT_MASK);
#endif
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "pci_set_dma_mask failed %d\n",
				retval);
		goto out;
	}

#ifdef NULL_DEVICE_RING0
	retval = pci_set_consistent_dma_mask_null(pdev, CVE_DMA_BIT_MASK);
#else
	retval = pci_set_consistent_dma_mask(pdev, CVE_DMA_BIT_MASK);
#endif
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"pci_set_consistent_dma_mask failed %d\n",
				retval);
		goto out;
	}

	retval = cve_probe_common(linux_device, dev_index++);
	if (retval) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "cdev_add failed %d\n", retval);
		goto out;
	}

	/* success */
	retval = 0;
out:
	FUNC_LEAVE();
	return retval;
}

static void cve_pci_remove(struct pci_dev *pdev)
{
	struct cve_os_device *linux_device;

	FUNC_ENTER();

	linux_device = pci_get_drvdata(pdev);

	cve_remove_common(linux_device);
#ifdef NULL_DEVICE_RING0
	remove_threaded_irq_null();
#endif
	FUNC_LEAVE();
}

/* init/cleanup */

int cve_register_driver(void)
{
	int retval;

	FUNC_ENTER();
#ifdef NULL_DEVICE_RING0
	g_dev.dev.init_name = "dummy-ice-pci";
	retval = device_register(&g_dev.dev);
	if (retval) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"device_register() failed %d\n", retval);
		goto out;
	}

	g_dev.dev.dma_mask = &g_dma_mask;

	retval = cve_pci_probe(&g_dev, NULL);
#else
	retval = pci_register_driver(&m_cve_pci_driver);
#endif
	if (retval) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"pci_register_driver failed %d\n", retval);
#ifdef NULL_DEVICE_RING0
		device_unregister(&g_dev.dev);
#endif
		goto out;
	}

	/* success */
	retval = 0;
out:
	FUNC_LEAVE();
	return retval;
}

void cve_unregister_driver(void)
{
	FUNC_ENTER();
#ifdef NULL_DEVICE_RING0
	cve_pci_remove(&g_dev);
	device_unregister(&g_dev.dev);
#else
	pci_unregister_driver(&m_cve_pci_driver);
#endif
	FUNC_LEAVE();
}

