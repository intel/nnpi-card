// SPDX-License-Identifier: GPL-2.0-or-later

/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 ********************************************/

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/stringify.h>
#include "pcie.h"
#include "device.h"
#include "device_chardev.h"
#include "nnp_log.h"

static struct nnpdrv_device_hw_callbacks nnp_dev_callbacks = {
	.create_nnp_device = nnpdrv_device_create,
	.card_doorbell_value_changed = nnpdrv_card_doorbell_value_changed,
	.destroy_nnp_device = nnpdrv_device_destroy,
	.process_messages = nnpdrv_device_process_messages,
	.pci_error_detected = nnpdrv_device_pci_error_detected,
	.reset_prepare = nnpdrv_device_reset_prepare,
	.reset_done = nnpdrv_device_reset_done
};

static int nnpdrv_init_module(void)
{
	int ret = 0;

	nnp_log_debug(START_UP_LOG, "init module\n");

	ret = nnpdrv_device_init();
	if (ret)
		return ret;

	ret = nnpdev_device_chardev_init();
	if (ret) {
		nnp_log_err(START_UP_LOG, "failed to init chardev class\n");
		goto err_return;
	}

	ret = nnpdrv_pci_init(&nnp_dev_callbacks);
	if (ret) {
		nnp_log_err(START_UP_LOG, "failed to init pcie\n");
		ret = -ENODEV;
		goto err_return;
	}

	nnp_log_info(START_UP_LOG, "NNP-I host driver is up\n");

	return 0;

err_return:
	return ret;
}

void nnpdrv_cleanup(void)
{
	nnp_log_debug(GO_DOWN_LOG, "Cleaning Up the Module\n");

	nnpdrv_hw_cleanup();

	nnpdrv_device_fini();
	nnpdev_device_chardev_cleanup();
}

module_init(nnpdrv_init_module);
module_exit(nnpdrv_cleanup);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Intel(R) NNPI Host Driver");
MODULE_AUTHOR("Intel Corporation");
MODULE_FIRMWARE(NNP_FIRMWARE_NAME);
