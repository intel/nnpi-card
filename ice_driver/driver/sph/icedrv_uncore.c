/********************************************
 * Copyright (C) 2019-2021 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/



#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include "icedrv_uncore.h"
#include "cve_device.h"
#include "sph_log.h"

#define DEVICE0_2CORES_12_ICES  0x458d
#define DEVICE0_2CORES_11_ICES  0x4589
#define DEVICE0_2CORES_10_ICES  0x4585
#define DEVICE0_2CORES_8_ICES   0x4581

#define MCHBAR_OFFSET		0x48
#define MCHBAR_MAP_SIZE		0x7200

#define REGBAR_OFFSET		0x7110
#define REGBAR_MAP_SIZE		((size_t)(0x1 << 24))

bool init_uncore = true;
resource_size_t g_addr;
/*struct device *g_dev_ret;*/

void icedrv_regbar_write(u8 port, u16 crOffset, u32 value)
{
	uint64_t tmpVal;
	uint64_t regOffset;
	void __iomem *io_addr;
	int error;

	if (!g_addr) {
		error = -EIO;
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"%d error in regbar allocation\n", error);
	}

	regOffset = ((port << 16) & (uint32_t)(0xFF0000)) + crOffset;
	tmpVal = (uint64_t)(regOffset & (uint32_t)(0xFFFFFF));

	cve_os_log(CVE_LOGLEVEL_DEBUG,
		" regOffset to write is %llx\n", regOffset);

	io_addr = ioremap(g_addr + tmpVal, 4);

	*((uint32_t *)(io_addr)) = value;

	iounmap(io_addr);

	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"regbar port 0x%x croffset 0x%x written with 0x%x OK\n",
			port, crOffset, value);
}
uint32_t icedrv_regbar_read(u8 port, u16 crOffset)
{
	uint64_t tmpVal;
	uint64_t regOffset;
	void __iomem *io_addr;
	uint32_t value = 0;

	if (!g_addr)
		return -EIO;

	regOffset = ((port << 16) & (uint32_t)(0xFF0000)) + crOffset;
	tmpVal = (uint64_t)(regOffset & (uint32_t)(0xFFFFFF));

	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"regOffset to write is %llx\n", regOffset);

	io_addr = ioremap(g_addr + tmpVal, 4);

	value = *((uint32_t *)(io_addr));
	iounmap(io_addr);

	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"regbar port 0x%x croffset 0x%x read OK\n",
			port, crOffset);
	return value;
}

struct icedrv_regbar_callbacks s_regbar_cb = {
	.regbar_write = icedrv_regbar_write,
	.regbar_read = icedrv_regbar_read
};

int intel_icedrv_uncore_regbar_cb(struct icedrv_regbar_callbacks **regbar_cb)
{
	*regbar_cb = &s_regbar_cb;

	cve_os_log(CVE_LOGLEVEL_DEBUG, "regbar mapped\n");

	return 0;
}


int init_icedrv_uncore(void)
{
	struct pci_dev *pDev = NULL;
	int ret = 0;

	if (init_uncore) {

		while ((pDev = pci_get_device(PCI_VENDOR_ID_INTEL,
							PCI_ANY_ID, pDev))) {
			if ((pDev->device == DEVICE0_2CORES_12_ICES) ||
			    (pDev->device == DEVICE0_2CORES_11_ICES) ||
			    (pDev->device == DEVICE0_2CORES_10_ICES) ||
			    (pDev->device == DEVICE0_2CORES_8_ICES)) {
				return icli_map_regbar(pDev);
			}
		}
	}

	return ret;
}

int icli_map_regbar(struct pci_dev *pdev)
{
	int where = MCHBAR_OFFSET;
	resource_size_t addr;
	u32 pci_dword;
	void __iomem *io_addr = NULL;
	int ret = 0;


	g_addr = (resource_size_t)0x0;

	/*read MCHBAR address from device 0 - in offset MCHBAR_OFFSET*/
	pci_read_config_dword(pdev, where, &pci_dword);
	addr = pci_dword;

#ifdef CONFIG_PHYS_ADDR_T_64BIT
	pci_read_config_dword(pdev, where + 4, &pci_dword);
	addr |= ((resource_size_t)pci_dword << 32);
#endif

	addr &= ~(PAGE_SIZE - 1);

	/*map mchabar to read regbar address*/
	io_addr = ioremap(addr, MCHBAR_MAP_SIZE);
	if (!io_addr) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"unable to map mchbar %llx\n", addr);
		return -EIO;
	}

	/*regbar address is located in REGBAR_OFFSET on MCHBAR.*/
	pci_dword = ioread32(io_addr + REGBAR_OFFSET);
	addr = pci_dword;

#ifdef CONFIG_PHYS_ADDR_T_64BIT
	pci_dword = ioread32(io_addr + REGBAR_OFFSET + 4);
	addr |= ((resource_size_t)pci_dword << 32);
#endif

	/*unmap mchbar*/
	iounmap(io_addr);

	/*IF BIT 0 of regbar address is 1
	 *it means that regbar was allocated in BIOS
	 */
	if (!(addr & 0x1)) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"regbar not allocated by bios %llx\n", addr);
		return -EIO;
	}

	addr &= ~(PAGE_SIZE - 1);

	g_addr = addr;

	cve_os_log(CVE_LOGLEVEL_INFO, "init_icedrv_uncore is successful\n");
	init_uncore = false;
	return ret;
}
