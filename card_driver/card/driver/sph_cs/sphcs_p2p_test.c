/********************************************
 * Copyright (C) 2019-2021 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#include <linux/module.h>    // included for all kernel modules
#include <linux/kernel.h>    // included for KERN_INFO
#include <linux/init.h>      // included for __init and __exit macros
#include <linux/mm.h>
#include <linux/types.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/device.h>
#include <linux/dma-mapping.h>
#include <linux/wait.h>

#include "sph_log.h"
#include "ioctl_p2p_test.h"
#include "sphcs_cs.h"

DECLARE_WAIT_QUEUE_HEAD(dma_wait);
static bool dma_completed;

union sph_p2p_test_ioctl_param {
	struct ioctl_p2p_test_dma test_dma;
};

static int dma_complete_callback(struct sphcs *sphcs,
		void *ctx,
		const void *user_data,
		int status,
		u32 xferTimeUS)
{

	if (status == SPHCS_DMA_STATUS_FAILED) {
		/* dma failed */
		sph_log_err(GENERAL_LOG, "DMA failed\n");
	} else {
		sph_log_info(GENERAL_LOG, "DMA completed\n");
	}

	dma_completed = true;
	wake_up(&dma_wait);

	return 0;
}

static int ioctl_test_dma_write(struct ioctl_p2p_test_dma *param)
{
	dma_addr_t buf_dma_addr;
	void *buf_vaddr;
	int rc;

	sph_log_info(GENERAL_LOG, "DMA Wr %u bytes to address 0x%llX\n", param->peer_buf_size, param->peer_buf_host_addr);

	buf_vaddr = dma_alloc_coherent(g_the_sphcs->hw_device, param->peer_buf_size, &buf_dma_addr, GFP_KERNEL);
	if (buf_vaddr == NULL) {
		sph_log_err(GENERAL_LOG, "couldn't allocate memory\n");
		return -ENOMEM;
	}

	if (copy_from_user(buf_vaddr, (void __user *)param->user_buffer, param->peer_buf_size) != 0) {
		sph_log_err(GENERAL_LOG, "Failed to copy from user buffer\n");
		rc = -EACCES;
		goto failed_to_copy;
	}

	dma_completed = false;

	rc = sphcs_dma_sched_start_xfer_single(g_the_sphcs->dmaSched,
					       &g_dma_desc_c2h_high,
					       buf_dma_addr,
					       param->peer_buf_host_addr,
					       param->peer_buf_size,
					       dma_complete_callback,
					       NULL,
					       NULL,
					       0);
	if (rc != 0) {
		sph_log_err(GENERAL_LOG, "Faield to start DMA\n");
		goto failed_to_start_dma;
	}

	wait_event(dma_wait, dma_completed);

	dma_free_coherent(g_the_sphcs->hw_device, param->peer_buf_size, buf_vaddr, buf_dma_addr);
	return 0;

failed_to_start_dma:
failed_to_copy:
	dma_free_coherent(g_the_sphcs->hw_device, param->peer_buf_size, buf_vaddr, buf_dma_addr);

	return rc;

}

static int ioctl_test_dma_read(struct ioctl_p2p_test_dma *param)
{
	dma_addr_t buf_dma_addr;
	void *buf_vaddr;
	int rc;

	sph_log_info(GENERAL_LOG, "DMA Rd %u bytes from address 0x%llX\n", param->peer_buf_size, param->peer_buf_host_addr);

	buf_vaddr = dma_alloc_coherent(g_the_sphcs->hw_device, param->peer_buf_size, &buf_dma_addr, GFP_KERNEL);
	if (buf_vaddr == NULL) {
		sph_log_err(GENERAL_LOG, "couldn't allocate memory\n");
		return -ENOMEM;
	}

	dma_completed = false;

	rc = sphcs_dma_sched_start_xfer_single(g_the_sphcs->dmaSched,
					       &g_dma_desc_h2c_high,
					       param->peer_buf_host_addr,
					       buf_dma_addr,
					       param->peer_buf_size,
					       dma_complete_callback,
					       NULL,
					       NULL,
					       0);
	if (rc != 0) {
		sph_log_err(GENERAL_LOG, "Faield to start DMA\n");
		goto failed_to_start_dma;
	}

	wait_event(dma_wait, dma_completed);

	if (copy_to_user((void __user *)param->user_buffer, buf_vaddr, param->peer_buf_size) != 0) {
		sph_log_err(GENERAL_LOG, "Failed to copy to user buffer\n");
		rc = -EACCES;
		goto failed_to_copy;
	}

	dma_free_coherent(g_the_sphcs->hw_device, param->peer_buf_size, buf_vaddr, buf_dma_addr);
	return 0;

failed_to_copy:
failed_to_start_dma:
	dma_free_coherent(g_the_sphcs->hw_device, param->peer_buf_size, buf_vaddr, buf_dma_addr);

	return rc;
}

static long ioctl_misc(struct file *file, unsigned int cmd, unsigned long arg)
{
	union sph_p2p_test_ioctl_param ioctl_param;
	int rc = 0;

	if (cmd & IOC_IN) {
		if (copy_from_user(&ioctl_param, (void __user *)arg, _IOC_SIZE(cmd)) != 0) {
			sph_log_err(GENERAL_LOG, "copy_from_user failed\n");
			rc = -EACCES;
			goto out;
		}
	}

	switch (cmd) {
	case IOCTL_P2P_DMA_WR:
		rc = ioctl_test_dma_write(&ioctl_param.test_dma);
		break;

	case IOCTL_P2P_DMA_RD:
		rc = ioctl_test_dma_read(&ioctl_param.test_dma);
		break;
	}

	if (cmd & IOC_OUT) {
		if (copy_to_user((void __user *)arg, &ioctl_param, _IOC_SIZE(cmd)) != 0) {
			sph_log_err(GENERAL_LOG, "copy_to_user failed\n");
			rc = -EACCES;
		}
	}
out:
	return rc;
}

/* user interface functions */
static const struct file_operations m_misc_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = ioctl_misc,
#ifdef CONFIG_COMPAT
	.compat_ioctl = ioctl_misc,
#endif
};

static struct miscdevice misc_device = {
		.minor = MISC_DYNAMIC_MINOR,
		.name = "sph_p2p_test",
		.fops = &m_misc_fops,
		.mode = 0666
};

int sphcs_p2p_test_init(void)
{
	int rc;

	/* misc device initialization */
	rc = misc_register(&misc_device);
	if (rc < 0)
		sph_log_err(GENERAL_LOG, "misc_register failed %d\n", rc);

	return rc;
}

void sphcs_p2p_test_cleanup(void)
{
	/* unregister misc device */
	misc_deregister(&misc_device);
}
