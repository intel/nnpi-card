/********************************************
 * Copyright (C) 2019-2021 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/
#ifndef _SPH_IBECC_H
#define _SPH_IBECC_H

#include <linux/processor.h>
#include <linux/pci.h>
#include <linux/bitops.h>
#include <linux/io.h>
#include <linux/version.h>

#define CAPID0_C_OFF 0xEC
#define MCHBAR_HI_OFF 0x4c
#define MCHBAR_LO_OFF 0x48
#define MCHBAR_EN BIT_ULL(0)
#define MCHBAR_MASK GENMASK_ULL(38, 16)
#define MCHBAR_SIZE BIT_ULL(16)

/* IBECC registers */
#define IBECC_BASE 0xd800
#define IBECC_ACTIVATE_OFF IBECC_BASE
#define IBECC_PROTECTED_RANGE_0_OFF (IBECC_BASE + 0xC)
#define IBECC_PROTECTED_RANGE_1_OFF (IBECC_BASE + 0x10)
#define IBECC_PROTECTED_RANGE_2_OFF (IBECC_BASE + 0x14)
#define IBECC_PROTECTED_RANGE_3_OFF (IBECC_BASE + 0x18)
#define IBECC_PROTECTED_RANGE_4_OFF (IBECC_BASE + 0x1C)
#define IBECC_PROTECTED_RANGE_5_OFF (IBECC_BASE + 0x20)
#define IBECC_PROTECTED_RANGE_6_OFF (IBECC_BASE + 0x24)
#define IBECC_PROTECTED_RANGE_7_OFF (IBECC_BASE + 0x28)
#define IBECC_INJ_ADDR_MASK_OFF (IBECC_BASE + 0x180)
#define IBECC_INJ_ADDR_BASE_OFF (IBECC_BASE + 0x188)
#define IBECC_INJ_CONTROL_OFF (IBECC_BASE + 0x198)

/* IBECC_PROTECTED_RANGE register layout */
#define IBECC_PROTECTED_RANGE_EN BIT(31)
#define IBECC_PROTECTED_RANGE_BASE_OFF 0
#define IBECC_PROTECTED_RANGE_BASE_MASK GENMASK(13, 0)
#define IBECC_PROTECTED_RANGE_MASK_OFF 16
#define IBECC_PROTECTED_RANGE_MASK_MASK GENMASK(29, 16)

#define ECC_ENJ_CONTROL_MODE_COR_ERR 0x1
#define ECC_ENJ_CONTROL_MODE_UC_ERR 0x5

/* ECC_ENJ_CONTROL register layout */
#define ECC_ENJ_CONTROL_MODE_OFF 0
#define ECC_ENJ_CONTROL_MODE_MASK GENMASK(2, 0)

static inline bool is_ibecc_activated(void __iomem *mchbar)
{
	if (!(ioread32(mchbar + IBECC_ACTIVATE_OFF) & BIT(0))) {
		sph_log_info(START_UP_LOG, "IBECC disabled\n");
		return false;
	}

	return true;
}
static inline struct pci_dev *is_ibecc_enabled(void)
{
	u32 capid0;
	struct pci_dev *dev0 = NULL;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 16, 0) /* SPH_IGNORE_STYLE_CHECK */
	/* check stepping first */
	if (boot_cpu_data.x86_stepping < 1) {
		sph_log_info(START_UP_LOG, "IBECC is not supported in step A\n");
		goto err;
	}
#endif

	/* get device object of device 0 */
	dev0 = pci_get_domain_bus_and_slot(0, 0, PCI_DEVFN(0, 0));
	if (dev0 == NULL) {
		sph_log_err(START_UP_LOG, "dev0 not found\n");
		goto err;
	}

	/* check that bit 15 of CAPID0 is 0 */
	pci_read_config_dword(dev0, CAPID0_C_OFF, &capid0);
	if (capid0 & BIT(15)) {
		sph_log_info(START_UP_LOG, "IBECC is not supported\n");
		goto err;
	}

	return dev0;
err:
	return NULL;
}

static inline void __iomem *ibecc_map_mchbar(struct pci_dev *dev0)
{
	u32 mchbar_addr_lo;
	u32 mchbar_addr_hi;
	u64 mchbar_addr;
	void __iomem *mchbar = NULL;

	/* Map MCHBAR */
	pci_read_config_dword(dev0, MCHBAR_LO_OFF, &mchbar_addr_lo);
	pci_read_config_dword(dev0, MCHBAR_HI_OFF, &mchbar_addr_hi);

	mchbar_addr = ((u64)mchbar_addr_hi << 32) | mchbar_addr_lo;

	if ((mchbar_addr & MCHBAR_EN))
		mchbar = ioremap(mchbar_addr & MCHBAR_MASK, MCHBAR_SIZE);

	return mchbar;
}

static inline void ibecc_unmap_mchbar(void __iomem *mchbar)
{
	iounmap(mchbar);
}
#endif
