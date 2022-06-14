/* SPDX-License-Identifier: GPL-2.0-or-later */

/********************************************
 * Copyright (C) 2019-2021 Intel Corporation
 ********************************************/
#ifndef _NNPDRV_PCIE_H
#define _NNPDRV_PCIE_H

#include <linux/version.h>

struct nnp_device;
struct device;

#define NNP_MAX_COMMAND_HWQ_DEPTH    16
#define NNP_MAX_RESPONSE_HWQ_DEPTH   16

struct nnp_hw_device_info {
	struct device *hw_device;
	int            pci_bus;
	int            pci_slot;
	const char    *name;
};

/*
 * Functions implemented by the nnp "pci" layer,
 * called by the nnp "device" layer
 */
struct nnpdrv_device_hw_ops {
	int (*write_mesg)(void *hw_handle, u64 *msg, u32 size, u64 *timed_wait);
	int (*flush_command_fifo)(void *hw_handle);
	u32 (*get_card_doorbell_value)(void *hw_handle);
	int (*set_host_doorbell_value)(void *hw_handle, u32 value);
	int (*reset)(void *hw_handle);
	u32 (*get_postcode)(void *hw_handle);
	u32 (*get_bios_flash_progress)(void *hw_handle);
	int (*get_membar_addr)(void *hw_handle,
			       u64   *out_phy_addr,
			       void **out_vaddr,
			       size_t  *out_len);
	int (*error_inject)(void *hw_handle,
			    int   err_type);
	dma_addr_t (*get_host_doorbell_addr)(void *hw_handle);
};

/*
 * Functions implemented by the nnp "device" layer,
 * called by the nnp "pci" layer
 */
struct nnpdrv_device_hw_callbacks {
	int (*create_nnp_device)(void                              *hw_handle,
				 const struct nnp_hw_device_info   *hw_dev_info,
				 const struct nnpdrv_device_hw_ops *hw_ops,
				 struct nnp_device                **out_nnpdev);

	int (*destroy_nnp_device)(struct nnp_device *nnpdev);

	void (*card_doorbell_value_changed)(struct nnp_device *nnpdev,
					    u32                doorbell_val);

	int (*process_messages)(struct nnp_device *nnpdev,
				u64               *msg,
				u32                size);

	int (*pci_error_detected)(struct nnp_device *nnpdev,
				  u32                error_type);

	void (*reset_prepare)(struct nnp_device *nnpdev, bool is_hang);
	void (*reset_done)(struct nnp_device *nnpdev);
};

int nnpdrv_pci_init(struct nnpdrv_device_hw_callbacks *callbacks);
void nnpdrv_hw_cleanup(void);

/*
 * Possible values for 'error_type' argument passed to pci_error_detected
 * callback.
 */
#define NNP_PCIE_NON_FATAL_ERROR   1
#define NNP_PCIE_FATAL_ERROR       2
#define NNP_PCIE_PERMANENT_FAILURE 3
#define NNP_PCIE_LINK_RETRAIN_REQUIRED 4

/*
 * Possible values for 'err_type' argument of error_inject function
 */
#define NNP_PCIE_INJECT_RESTORE           0
#define NNP_PCIE_INJECT_CORR              1
#define NNP_PCIE_INJECT_UNCORR            2
#define NNP_PCIE_INJECT_UNCORR_FATAL      3

#endif
