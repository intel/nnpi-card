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

#include "sph_log.h"
#include "sph_version.h"
#include "sphpb.h"
#include "sphpb_icedriver.h"

bool poll_mailbox_ready(struct sphpb_pb *sphpb)
{
	u32 *mbx_interface;
	union PCODE_MAILBOX_INTERFACE iface;
	int retries = 1000; /* 1ms */

	mbx_interface = sphpb->idc_mailbox_base + PCU_CR_ICEDRIVER_PCODE_MAILBOX_INTERFACE;

	do {
		ndelay(1000);
		iface.InterfaceData = ioread32(mbx_interface);
	} while (iface.BitField.RunBusy  && --retries > 0);

	return iface.BitField.RunBusy == 0;
}


int write_icedriver_mailbox(struct sphpb_pb *sphpb,
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


	if (!g_the_sphpb->idc_mailbox_base) {
		sph_log_err(POWER_BALANCER_LOG, "Mailbox is not supported - ERR (%d) !!\n", -EINVAL);
		return -EINVAL;
	}

	SPH_SPIN_LOCK(&sphpb->lock);


	mbx_interface = sphpb->idc_mailbox_base + PCU_CR_ICEDRIVER_PCODE_MAILBOX_INTERFACE;
	mbx_data0 = sphpb->idc_mailbox_base + PCU_CR_ICEDRIVER_PCODE_MAILBOX_DATA0;
	mbx_data1 = sphpb->idc_mailbox_base + PCU_CR_ICEDRIVER_PCODE_MAILBOX_DATA1;

	iface.BitField.RunBusy = 1;

	if (!poll_mailbox_ready(sphpb)) {
		ret = -EBUSY;
		sph_log_err(POWER_BALANCER_LOG, "Mailbox is not ready for usage - ERR (%d) !!\n", ret);
		goto err;
	}

	sph_log_err(POWER_BALANCER_LOG, "write to mbox (%d, %d, %d, %d, %d)\n",
		    iface.BitField.Command, iface.BitField.Param1, iface.BitField.Param2,
		    i_data0, i_data1);


	iowrite32(i_data1, mbx_data1);
	iowrite32(i_data0, mbx_data0);
	iowrite32(iface.InterfaceData, mbx_interface);

	if (!poll_mailbox_ready(sphpb)) {
		ret = -EBUSY;
		sph_log_err(POWER_BALANCER_LOG, "Mailbox post write is not ready for usage - ERR (%d) !!\n", ret);
		goto err;
	}

	verify_iface0.InterfaceData = ioread32(mbx_interface);
	verify_data0 = ioread32(mbx_data0);
	verify_data1 = ioread32(mbx_data1);

	ndelay(1000);

	verify_iface1.InterfaceData = ioread32(mbx_interface);
	verify_data0_1 = ioread32(mbx_data0);
	verify_data1_1 = ioread32(mbx_data1);

	if (verify_iface0.InterfaceData != verify_iface1.InterfaceData ||
	    verify_data0 != verify_data0_1 ||
	    verify_data1 != verify_data1_1) {
		sph_log_err(POWER_BALANCER_LOG, "Inconsistent mailbox data after write !!\n");
		ret = -EIO;
		goto err;
	}

	if (verify_iface0.BitField.Command != 0) {
		sph_log_err(POWER_BALANCER_LOG, "Failed to write through mailbox status=%d\n", verify_iface0.BitField.Command);
		ret = -EIO;
		goto err;
	}

	sph_log_err(POWER_BALANCER_LOG, "reply from mbox (%d, %d, %d)\n", verify_iface0.InterfaceData, verify_data0, verify_data1);
	if (o_data0)
		*o_data0 = verify_data0;

	if (o_data1)
		*o_data1 = verify_data1;


err:
	SPH_SPIN_UNLOCK(&g_the_sphpb->lock);

	return ret;
}

int icli_map_idc_bar0_mailbox(struct pci_dev *pdev, struct sphpb_pb *sphpb)
{
	int where = BAR_0_OFFSET;
	resource_size_t addr;
	u32 pci_dword;
	void __iomem *io_addr = NULL;
	int ret = 0;

	//read BAR0 address from IDC - in offset BAR_0_OFFSET
	pci_read_config_dword(pdev, where, &pci_dword);
	addr = pci_dword;

#ifdef CONFIG_PHYS_ADDR_T_64BIT
	pci_read_config_dword(pdev, where + 4, &pci_dword);
	addr |= (((resource_size_t)pci_dword) << 32);
#endif

	addr &= ~(PAGE_SIZE - 1);

	addr += (size_t)(IDC_BAR_0_MAILBOX_START);
	//map BAR0 PCU Mailbox offset.
	io_addr = ioremap(addr, IDC_BAR_0_MAILBOX_LENGTH);
	if (!io_addr) {
		sph_log_err(POWER_BALANCER_LOG, "unable to map idc bar 0 - mailbox chunk %llx\n", addr);
		return -EIO;
	}

	sphpb->idc_mailbox_base = io_addr;

	return ret;
}



//map IDC Mailbox in bar0 from IDC Device
int sphpb_map_idc_mailbox_base_registers(struct sphpb_pb *sphpb)
{
	struct pci_dev *pDev = NULL;

	while ((pDev = pci_get_device(PCI_VENDOR_ID_INTEL, PCI_ANY_ID, pDev))) {
		if (pDev->device == IDC_PCI_DEVICE_ID)
			return icli_map_idc_bar0_mailbox(pDev, sphpb);
	}

	return -ENODEV;
}

//map IDC Mailbox in bar0 from IDC Device
int sphpb_unmap_idc_mailbox_base_registers(struct sphpb_pb *sphpb)
{
	if (!sphpb->idc_mailbox_base)
		return -ENODEV;

	iounmap(sphpb->idc_mailbox_base);

	sphpb->idc_mailbox_base = NULL;

	return 0;
}




int sphpb_set_iccp_cdyn(struct sphpb_pb *sphpb, uint32_t level, uint32_t value)
{
	union PCODE_MAILBOX_INTERFACE iface;

	iface.InterfaceData = 0;
	iface.BitField.Command = ICEDRV_PCU_MAILBOX_ICCP_WRITE_LEVEL;
	iface.BitField.Param1 = (uint8_t)level;

	return write_icedriver_mailbox(sphpb, iface,
				       value, 0x0,
				       NULL, NULL);
}

int sphpb_get_iccp_cdyn(struct sphpb_pb *sphpb, uint32_t level, uint32_t *value)
{
	union PCODE_MAILBOX_INTERFACE iface;

	iface.InterfaceData = 0;
	iface.BitField.Command = ICEDRV_PCU_MAILBOX_ICCP_READ_LEVEL;
	iface.BitField.Param1 = (uint8_t)level;

	return write_icedriver_mailbox(sphpb, iface,
				       0x0, 0x0,
				       value, NULL);
}

int sphpb_set_icebo_ring_ratio(struct sphpb_pb *sphpb, uint32_t value)
{
	union PCODE_MAILBOX_INTERFACE iface;

	iface.InterfaceData = 0;
	iface.BitField.Command = ICEDRV_PCU_MAILBOX_ICE2RING_RATIO_WRITE;

	return write_icedriver_mailbox(sphpb, iface,
				       value, 0x0,
				       NULL, NULL);
}

int sphpb_get_icebo_ring_ratio(struct sphpb_pb *sphpb, uint32_t *value)
{
	union PCODE_MAILBOX_INTERFACE iface;

	iface.InterfaceData = 0;
	iface.BitField.Command = ICEDRV_PCU_MAILBOX_ICE2RING_RATIO_READ;

	return write_icedriver_mailbox(sphpb, iface,
				       0x0, 0x0,
				       value, NULL);
}

int sphpb_get_icebo_frequency(struct sphpb_pb *sphpb, uint32_t icebo_num, uint32_t *freq)
{
	union PCODE_MAILBOX_INTERFACE iface;
	int ret = 0;

	iface.InterfaceData = 0;
	iface.BitField.Command = ICEDRV_PCU_MAILBOX_ICEBO_FREQ_READ;
	iface.BitField.Param1 = (uint8_t)icebo_num;

	ret = write_icedriver_mailbox(sphpb, iface,
				      0x0, 0x0,
				      freq, NULL);
	if (ret)
		return ret;

	return 0;

}
