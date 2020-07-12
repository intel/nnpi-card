/* SPDX-License-Identifier: GPL-2.0-or-later */

/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 ********************************************/
#ifndef _NNPDRV_DEVICE_H
#define _NNPDRV_DEVICE_H

#include <linux/kernel.h>
#include <linux/workqueue.h>
#include <linux/debugfs.h>
#include <linux/kref.h>
#include <linux/completion.h>
#include <linux/idr.h>
#include <linux/hashtable.h>
#include <linux/spinlock.h>
#include <linux/cdev.h>
#include "pcie.h"
#include "msg_scheduler.h"
#include "nnp_inbound_mem.h"
#include "ipc_protocol.h"

#define NNP_MAX_DEVS		256
#define DEVICE_NAME_LEN         32
#define NNP_DEVICE_MAX_BOOT_IMAGE_PATH_SIZE 256

#define NNP_FIRMWARE_NAME "intel/nnpi/disk.img"

/* device state bits */
#define NNP_DEVICE_BOOT_BIOS_READY        BIT(1)
#define NNP_DEVICE_BOOT_BIOS_READY_EMMC   BIT(2)
#define NNP_DEVICE_BOOT_SYSINFO_READY     BIT(3)
#define NNP_DEVICE_BOOT_STARTED           BIT(4)
#define NNP_DEVICE_BIOS_UPDATE_READY      BIT(5)
#define NNP_DEVICE_BIOS_UPDATE_STARTED    BIT(6)
#define NNP_DEVICE_BIOS_UPDATE_DONE       BIT(7)
#define NNP_DEVICE_CARD_DRIVER_READY      BIT(8)
#define NNP_DEVICE_CARD_READY             BIT(9)
#define NNP_DEVICE_CARD_ENABLED           BIT(10)

#define NNP_DEVICE_CARD_BOOT_STATE_MASK   GENMASK(9, 1)

#define NNP_DEVICE_ACTIVE_MASK       (NNP_DEVICE_CARD_READY | \
				      NNP_DEVICE_CARD_ENABLED)

#define NNP_DEVICE_FAILED_VERSION    BIT(16)
#define NNP_DEVICE_BOOT_FAILED       BIT(17)
#define NNP_DEVICE_HOST_DRIVER_ERROR BIT(18)
#define NNP_DEVICE_KERNEL_CRASH	     BIT(20)
#define NNP_DEVICE_PCI_ERROR         BIT(21)
#define NNP_DEVICE_CARD_IN_RESET     BIT(22)
#define NNP_DEVICE_FATAL_MCE_ERROR   BIT(23)
#define NNP_DEVICE_FATAL_DRAM_ECC_ERROR   BIT(24)
#define NNP_DEVICE_FATAL_ICE_ERROR   BIT(25)
#define NNP_DEVICE_HANG              BIT(26)
#define NNP_DEVICE_PROTOCOL_ERROR    BIT(27)
#define NNP_DEVICE_ERROR_MASK        GENMASK(31, 16)

struct host_crash_dump {
	void *vaddr;
	dma_addr_t dma_addr;
	u32 dump_size;
};

struct nnp_device_counters {
	struct {
		int enable;
		u64 commands_wait_time;  /*
					  * Total time spend waiting for free
					  * slots in h/w command queue
					  */
		u64 commands_sent_count; /*
					  * Number of commands sent on the h/w
					  * command queue
					  */
		u64 commands_sched_count; /*
					   * Number of commands scheduled to
					   * be sent to h/w queue
					   */
		u64 responses_consume_time; /*
					     * Total time spent reading
					     * responses from h/w queue
					     */
		u64 responses_count;  /*
				       * Total number of responses received
				       * from device
				       */
	} ipc;

	struct {
		u64 os_crashed;  /*
				  * Number of times device needed to be reset
				  * due to device fatal error
				  */
		u64 ecc_nonfatal;  /*
				    * Number of times a non-fatal
				    * uncorrectable ECC error happened
				    * on device
				    */
		u64 ecc_fatal; /*
				* Number of times a fatal, uncorrectable
				* ECC error happened on device
				*/
		u64 dram_ecc_nonfatal;  /*
					 * Number of times a non-fatal
					 * uncorrectable ECC error happened
					 * on device DRAM
					 */
		u64 dram_ecc_fatal; /*
				     * Number of times a fatal, uncorrectable
				     * ECC error happened on device DRAM
				     */
		u64 mce_nonfatal;  /*
				    * Number of times a non-fatal
				    * uncorrectable MCE error happened
				    * on device
				    */
		u64 mce_fatal; /*
				* Number of times a fatal, uncorrectable MCE
				* error happened on device
				*/
	} uncorr;

	struct {
		u64 ecc; /*
			  * Number of times a correctable ECC error
			  * happened on device
			  */
		u64 dram_ecc; /*
			       * Number of times a correctable ECC error
			       * happened on device DRAM
			       */
	} corr;
};

struct nnp_device {
	struct kref    ref;
	void          *hw_handle;
	const struct nnp_hw_device_info   *hw_device_info;
	const struct nnpdrv_device_hw_ops *hw_ops;
	struct workqueue_struct *wq;
	spinlock_t     lock; /* protects boot state and other fields */
	struct completion *release_completion;
	struct work_struct free_work;

	struct cdev cdev;
	struct device *dev;
	struct host_crash_dump host_crash_dump;
	struct msg_scheduler       *cmdq_sched;
	struct msg_scheduler_queue *public_cmdq;
	union nnp_inbound_mem  *inbound_mem;

	u32          id;
	char         name[DEVICE_NAME_LEN];
	u32          boot_image_loaded;
	char         reset_boot_image_path[NNP_DEVICE_MAX_BOOT_IMAGE_PATH_SIZE];

	u64            response_buf[32];
	u32            response_num_msgs;

	struct ida cmd_chan_ida;
	DECLARE_HASHTABLE(cmd_chan_hash, 6);
	wait_queue_head_t waitq;

	dma_addr_t                  bios_system_info_dma_addr;
	struct nnp_c2h_system_info *bios_system_info;
	bool                        bios_system_info_valid;
	dma_addr_t                  card_sys_info_dma_addr;
	struct nnp_sys_info        *card_sys_info;
	bool                        card_sys_info_valid;

	u32            num_ice_devices;
	u32            state;
	u32            curr_boot_state;
	u16            protocol_version;
	u16            chan_protocol_version;
	u32            num_active_contexts;
	u32            card_doorbell_val;
	u32            pci_error;

	u32 correctable_ecc_threshold;
	u32 correctable_ecc_counter;
	u32 uncorrectable_ecc_threshold;
	u32 uncorrectable_ecc_counter;
	u32 correctable_dram_ecc_threshold;
	u32 correctable_dram_ecc_counter;
	u32 uncorrectable_dram_ecc_threshold;
	u32 uncorrectable_dram_ecc_counter;

	struct dentry *debugfs_dir;

	bool ipc_h2c_en[IPC_OP_MAX];
	bool ipc_c2h_en[IPC_OP_MAX];
	u8   ipc_chan_resp_op_size[32];
	u8   ipc_chan_cmd_op_size[32];
	struct nnp_device_counters counters;
};

int nnpdrv_device_init(void);
void nnpdrv_device_fini(void);

int nnpdrv_device_create(void                              *hw_handle,
			 const struct nnp_hw_device_info   *hw_device_info,
			 const struct nnpdrv_device_hw_ops *hw_ops,
			 struct nnp_device                **out_nnpdev);

struct msg_scheduler_queue *nnpdrv_create_cmd_queue(struct nnp_device *nnpdev,
						    u32                weight);

int nnpdrv_destroy_cmd_queue(struct nnp_device          *nnpdev,
			     struct msg_scheduler_queue *q);

static inline int nnpdrv_msg_scheduler_queue_add_msg(
					struct msg_scheduler_queue *queue,
					u64 *msg, int size)
{
	struct nnp_device *nnpdev = (struct nnp_device *)queue->device_hw_data;

	if (nnpdev->counters.ipc.enable)
		nnpdev->counters.ipc.commands_sched_count++;

	return msg_scheduler_queue_add_msg(queue, msg, size);
}

void nnpdrv_device_get(struct nnp_device *nnpdev);
int nnpdrv_device_put(struct nnp_device *nnpdev);

void nnpdrv_card_doorbell_value_changed(struct nnp_device *nnpdev,
					u32                doorbell_val);

int nnpdrv_device_destroy(struct nnp_device *nnpdev);

int nnpdrv_device_process_messages(struct nnp_device *nnpdev,
				   u64               *msg,
				   u32                size);

int nnpdrv_device_pci_error_detected(struct nnp_device *nnpdev,
				     u32                error_type);
void nnpdrv_device_disable(struct nnp_device *nnpdev);
void nnpdrv_device_enable(struct nnp_device *nnpdev);
int nnpdrv_device_force_reset(struct nnp_device *nnpdev);
void nnpdrv_device_reset_prepare(struct nnp_device *nnpdev, bool is_hang);
void nnpdrv_device_reset_done(struct nnp_device *nnpdev);

struct nnpdrv_cmd_chan *nnpdrv_device_find_channel(struct nnp_device *nnpdev,
						   u16             protocol_id);
void nnpdrv_submit_device_event_to_channels(struct nnp_device *nnpdev,
					    union c2h_event_report *event_msg,
					    bool                   force);
void nnpdrv_device_disable(struct nnp_device *nnpdev);
void nnpdrv_device_enable(struct nnp_device *nnpdev);

#endif
