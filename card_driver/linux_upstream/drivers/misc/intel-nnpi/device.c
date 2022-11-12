// SPDX-License-Identifier: GPL-2.0-or-later

/********************************************
 * Copyright (C) 2019-2021 Intel Corporation
 ********************************************/

#include "device.h"
#include <linux/module.h>
#include <linux/device.h>
#include <linux/pci.h>
#include <linux/idr.h>
#include <linux/jiffies.h>
#include <linux/workqueue.h>
#include <linux/wait.h>
#include <linux/sched/clock.h>
#include <linux/mutex.h>
#include <linux/debugfs.h>
#include "nnp_log.h"
#include "nnp_debug.h"
#include "pcie.h"
#include "host_chardev.h"
#include "bootimage.h"
#include "nnp_boot_defs.h"
#include "device_chardev.h"
#include "cmd_chan.h"
#include "ipc_c2h_events.h"
#include "device_sysfs.h"
#include "nnp_time.h"
#include "trace.h"

static u32 s_num_devices;
static DEFINE_MUTEX(s_device_num_mutex);

static void nnpdrv_device_set_boot_state(struct nnp_device *nnpdev, u32 mask);

static int nnpdrv_first_device_init(void)
{
	int ret = 0;

	mutex_lock(&s_device_num_mutex);
	if (s_num_devices == 0) {
		/* initialize host chardev interface */
		ret = init_host_interface();
		if (likely(ret == 0))
			s_num_devices++;
	}
	mutex_unlock(&s_device_num_mutex);

	return ret;
}

static void nnpdrv_last_device_fini(void)
{
	mutex_lock(&s_device_num_mutex);
	s_num_devices--;
	if (s_num_devices == 0) {
		/* Release host interface and bootimage timer */
		release_host_interface();
		nnpdrv_bootimage_fini();
	}
	mutex_unlock(&s_device_num_mutex);
}

static struct ida s_dev_ida;
struct dentry *s_debugfs_dir;

int nnpdrv_device_init(void)
{
	s_debugfs_dir = debugfs_create_dir("intel_nnpi", NULL);
	if (IS_ERR_OR_NULL(s_debugfs_dir)) {
		nnp_log_info(START_UP_LOG, "failed to initialize debugfs dir\n");
		s_debugfs_dir = NULL;
	}

	ida_init(&s_dev_ida);

	return 0;
}

void nnpdrv_device_fini(void)
{
	ida_destroy(&s_dev_ida);
	debugfs_remove_recursive(s_debugfs_dir);
}

struct query_version_work {
	struct work_struct work;
	struct nnp_device *nnpdev;
	u16 protocol_version;
	u16 chan_protocol_version;
	u64 chan_resp_op_size;
	u64 chan_cmd_op_size;
};

static void process_query_version_reply(struct work_struct *work)
{
	struct query_version_work *query_version_work;
	u32 protocol_version;
	u32 card_boot_state;
	u64 chan_resp_op_size;
	u64 chan_cmd_op_size;
	int i;

	query_version_work =
		container_of(work, struct query_version_work, work);
	protocol_version = NNP_IPC_PROTOCOL_VERSION;
	card_boot_state = (query_version_work->nnpdev->card_doorbell_val &
		       NNP_CARD_BOOT_STATE_MASK) >> NNP_CARD_BOOT_STATE_SHIFT;

	chan_resp_op_size = query_version_work->chan_resp_op_size;
	for (i = 0; i < 32; i++) {
		query_version_work->nnpdev->ipc_chan_resp_op_size[i] =
			(chan_resp_op_size & 0x3);
		chan_resp_op_size >>= 2;
	}

	chan_cmd_op_size = query_version_work->chan_cmd_op_size;
	for (i = 0; i < 32; i++) {
		query_version_work->nnpdev->ipc_chan_cmd_op_size[i] =
			(chan_cmd_op_size & 0x3);
		chan_cmd_op_size >>= 2;
	}

	nnp_log_debug(GENERAL_LOG,
		      "Got DriverReady message, ipcProtocolVer=%d.%d.%d chan_protocol_ver=%d.%d.%d\n",
		      NNP_VERSION_MAJOR(query_version_work->protocol_version),
		      NNP_VERSION_MINOR(query_version_work->protocol_version),
		      NNP_VERSION_DOT(query_version_work->protocol_version),
		   NNP_VERSION_MAJOR(query_version_work->chan_protocol_version),
		   NNP_VERSION_MINOR(query_version_work->chan_protocol_version),
		   NNP_VERSION_DOT(query_version_work->chan_protocol_version));

	query_version_work->nnpdev->protocol_version =
		query_version_work->protocol_version;
	query_version_work->nnpdev->chan_protocol_version =
		query_version_work->chan_protocol_version;

	if (NNP_VERSION_MAJOR(query_version_work->protocol_version) !=
	    NNP_VERSION_MAJOR(protocol_version) ||
	    NNP_VERSION_MINOR(query_version_work->protocol_version) !=
	    NNP_VERSION_MINOR(protocol_version) ||
	    query_version_work->chan_resp_op_size == 0) {
		nnp_log_err(GENERAL_LOG,
			    "FATAL: Mismatch driver version !!!\n");
		nnp_log_err(GENERAL_LOG, "Card driver protocol version %d.%d.%d\n",
			NNP_VERSION_MAJOR(query_version_work->protocol_version),
			NNP_VERSION_MINOR(query_version_work->protocol_version),
			NNP_VERSION_DOT(query_version_work->protocol_version));
		nnp_log_err(GENERAL_LOG, "Host driver protocol version %d.%d.%d\n",
			NNP_VERSION_MAJOR(protocol_version),
			NNP_VERSION_MINOR(protocol_version),
			NNP_VERSION_DOT(protocol_version));
		nnp_log_err(GENERAL_LOG,
			    "Card channel response opcode size vec 0x%llx\n",
			    query_version_work->chan_resp_op_size);
		nnpdrv_device_set_boot_state(query_version_work->nnpdev,
					     NNP_DEVICE_FAILED_VERSION);
		/* set host driver state in doorbell register */
		query_version_work->nnpdev->hw_ops->set_host_doorbell_value(
					query_version_work->nnpdev->hw_handle,
					NNP_HOST_DRV_STATE_VERSION_ERROR <<
					NNP_HOST_DRV_STATE_SHIFT);
	} else if (card_boot_state == NNP_CARD_BOOT_STATE_DRV_READY) {
		nnpdrv_device_set_boot_state(query_version_work->nnpdev,
					     NNP_DEVICE_CARD_DRIVER_READY);
	} else if (card_boot_state == NNP_CARD_BOOT_STATE_CARD_READY) {
		/* Card driver finished initialization */
		nnp_log_info(GENERAL_LOG,
			     "========== Card %u Driver is up and working ==========\n",
			     query_version_work->nnpdev->id);

		nnpdrv_device_set_boot_state(query_version_work->nnpdev,
					     NNP_DEVICE_CARD_DRIVER_READY |
					     NNP_DEVICE_CARD_READY |
					     NNP_DEVICE_CARD_ENABLED);
	}

	kfree(query_version_work);
}

static void IPC_OPCODE_HANDLER(QUERY_VERSION_REPLY)(
					struct nnp_device        *nnpdev,
					union c2h_query_version_reply_msg *msg)
{
	struct query_version_work *query_version_work;

	query_version_work = kmalloc(sizeof(*query_version_work),
				     GFP_ATOMIC);
	if (!query_version_work)
		return;

	query_version_work->protocol_version = msg->protocolversion;
	query_version_work->chan_protocol_version = msg->chan_protocol_ver;
	query_version_work->chan_resp_op_size = 0;
	query_version_work->chan_cmd_op_size = 0;

	query_version_work->nnpdev = nnpdev;
	INIT_WORK(&query_version_work->work, process_query_version_reply);

	queue_work(nnpdev->wq, &query_version_work->work);
}

static void IPC_OPCODE_HANDLER(QUERY_VERSION_REPLY2)(
					struct nnp_device        *nnpdev,
					union c2h_query_version_reply2_msg *msg)
{
	struct query_version_work *query_version_work;

	query_version_work = kmalloc(sizeof(*query_version_work),
				     GFP_ATOMIC);
	if (!query_version_work)
		return;

	query_version_work->protocol_version = msg->protocolversion;
	query_version_work->chan_protocol_version = msg->chan_protocol_ver;
	query_version_work->chan_resp_op_size = msg->chan_resp_op_size;
	query_version_work->chan_cmd_op_size = 0;

	query_version_work->nnpdev = nnpdev;
	INIT_WORK(&query_version_work->work, process_query_version_reply);

	queue_work(nnpdev->wq, &query_version_work->work);
}

static void IPC_OPCODE_HANDLER(QUERY_VERSION_REPLY3)(
					struct nnp_device        *nnpdev,
					union c2h_query_version_reply3_msg *msg)
{
	struct query_version_work *query_version_work;

	query_version_work = kmalloc(sizeof(*query_version_work),
				     GFP_ATOMIC);
	if (!query_version_work)
		return;

	query_version_work->protocol_version = msg->protocolversion;
	query_version_work->chan_protocol_version = msg->chan_protocol_ver;
	query_version_work->chan_resp_op_size = msg->chan_resp_op_size;
	query_version_work->chan_cmd_op_size = msg->chan_cmd_op_size;

	query_version_work->nnpdev = nnpdev;
	INIT_WORK(&query_version_work->work, process_query_version_reply);

	queue_work(nnpdev->wq, &query_version_work->work);
}

/*
 * process_bios_message - process a message from HWQ coming from bios.
 * bios protocol may have different size messages.
 * avail_size is the number of 64-bit units available from the msg pointer
 * if the message size is larger, the function should return 0 and do not
 * processthe message, otherwise the function should process the message
 * and return the actual processed message size (in 64-bit units).
 */
static int process_bios_message(struct nnp_device         *nnpdev,
				union nnp_bios_ipc_header *msg,
				u32                        avail_size)
{
	/* size field does not include header */
	int msg_size = ((msg->size + 7) / 8) + 1;

	if (msg_size > avail_size)
		return 0;

	nnp_log_err(GENERAL_LOG,
		    "Got bios message msg_type=%u\n", msg->msg_type);

	return msg_size;
}

struct nnpdrv_cmd_chan *nnpdrv_device_find_channel(struct nnp_device *nnpdev,
						   u16              protocol_id)
{
	struct nnpdrv_cmd_chan *cmd_chan;

	spin_lock(&nnpdev->lock);
	hash_for_each_possible(nnpdev->cmd_chan_hash,
			       cmd_chan,
			       hash_node,
			       protocol_id)
		if (cmd_chan->protocol_id == protocol_id) {
			if (!nnpdrv_cmd_chan_get(cmd_chan))
				break;
			spin_unlock(&nnpdev->lock);
			return cmd_chan;
		}
	spin_unlock(&nnpdev->lock);

	return NULL;
}

static void nnpdrv_destroy_all_channels(struct nnp_device *nnpdev)
{
	struct nnpdrv_cmd_chan *cmd_chan;
	int i;
	bool found = true;

	do {
		found = false;
		spin_lock(&nnpdev->lock);
		hash_for_each(nnpdev->cmd_chan_hash,
			      i,
			      cmd_chan,
			      hash_node) {
			if (atomic_xchg(&cmd_chan->destroyed, 1) == 0) {
				spin_unlock(&nnpdev->lock);
				nnpdrv_cmd_chan_put(cmd_chan);
				found = true;
				break;
			}
		}
	} while (found);
	spin_unlock(&nnpdev->lock);
}

static void nnpdrv_device_inform_event(struct nnp_device     *nnpdev,
				       union c2h_event_report *event)
{
	char *event_env[10];
	int num_env = 0;
	int i;
	const char *boot_state;
	const char *state;
	const char *fail_reason;

	/*
	 * if event has threshold update event counter and return
	 * without generating event if threshold have not riched
	 */
	spin_lock(&nnpdev->lock);
	if (event->event_code == NNP_IPC_ERROR_MCE_CORRECTABLE) {
		nnpdev->correctable_ecc_counter++;
		if (nnpdev->correctable_ecc_counter <
		    nnpdev->correctable_ecc_threshold) {
			spin_unlock(&nnpdev->lock);
			return;
		}
		nnpdev->correctable_ecc_counter = 0;
	} else if (event->event_code == NNP_IPC_ERROR_MCE_UNCORRECTABLE &&
		   event->event_val != 0) {
		nnpdev->uncorrectable_ecc_counter++;
		if (nnpdev->uncorrectable_ecc_counter <
		    nnpdev->uncorrectable_ecc_threshold) {
			spin_unlock(&nnpdev->lock);
			return;
		}
		nnpdev->uncorrectable_ecc_counter = 0;
	} else if (event->event_code == NNP_IPC_ERROR_DRAM_ECC_CORRECTABLE) {
		nnpdev->correctable_dram_ecc_counter++;
		if (nnpdev->correctable_dram_ecc_counter <
		    nnpdev->correctable_dram_ecc_threshold) {
			spin_unlock(&nnpdev->lock);
			return;
		}
		nnpdev->correctable_dram_ecc_counter = 0;
	} else if (event->event_code == NNP_IPC_CTX_DRAM_ECC_UNCORRECTABLE) {
		nnpdev->uncorrectable_dram_ecc_counter++;
		if (nnpdev->uncorrectable_dram_ecc_counter <
		    nnpdev->uncorrectable_dram_ecc_threshold) {
			spin_unlock(&nnpdev->lock);
			return;
		}
		nnpdev->uncorrectable_dram_ecc_counter = 0;
	}
	spin_unlock(&nnpdev->lock);

	if (event->event_code == NNP_IPC_ERROR_OS_CRASHED) {
		event_env[num_env++] =
			kasprintf(GFP_KERNEL, "NNPI_EVENT=crash");
		event_env[num_env++] =
			kasprintf(GFP_KERNEL, "NNPI_ERROR_CLASS=fatal");
	} else if (event->event_code == NNP_IPC_ERROR_PCI_ERROR ||
		   event->event_code == NNP_IPC_ERROR_PROTOCOL_ERROR) {
		event_env[num_env++] =
			kasprintf(GFP_KERNEL, "NNPI_EVENT=pci_error");
		event_env[num_env++] =
			kasprintf(GFP_KERNEL, "NNPI_ERROR_CLASS=fatal");
	} else if (event->event_code == NNP_IPC_ERROR_MCE_CORRECTABLE) {
		if (event->event_val != 0)
			event_env[num_env++] =
				kasprintf(GFP_KERNEL, "NNPI_EVENT=ecc_error");
		else
			event_env[num_env++] =
				kasprintf(GFP_KERNEL, "NNPI_EVENT=mce_error");
		event_env[num_env++] =
			kasprintf(GFP_KERNEL, "NNPI_ERROR_CLASS=correctable");
	} else if (event->event_code == NNP_IPC_ERROR_MCE_UNCORRECTABLE) {
		if (event->event_val != 0)
			event_env[num_env++] =
				kasprintf(GFP_KERNEL, "NNPI_EVENT=ecc_error");
		else
			event_env[num_env++] =
				kasprintf(GFP_KERNEL, "NNPI_EVENT=mce_error");
		event_env[num_env++] =
			kasprintf(GFP_KERNEL, "NNPI_ERROR_CLASS=uncorrectable");
	} else if (event->event_code == NNP_IPC_ERROR_MCE_UNCORRECTABLE_FATAL) {
		if (event->event_val != 0)
			event_env[num_env++] =
				kasprintf(GFP_KERNEL, "NNPI_EVENT=ecc_error");
		else
			event_env[num_env++] =
				kasprintf(GFP_KERNEL, "NNPI_EVENT=mce_error");
		event_env[num_env++] =
			kasprintf(GFP_KERNEL, "NNPI_ERROR_CLASS=fatal");
	} else if (event->event_code == NNP_IPC_THERMAL_TRIP_EVENT) {
		event_env[num_env++] =
			kasprintf(GFP_KERNEL, "NNPI_EVENT=thermal");
		event_env[num_env++] =
			kasprintf(GFP_KERNEL, "NNPI_ERROR_CLASS=no_error");
		event_env[num_env++] =
			kasprintf(GFP_KERNEL, "NNPI_THERMAL_TRIP=%d",
				  event->event_val);
		event_env[num_env++] =
			kasprintf(GFP_KERNEL, "NNPI_THERMAL_TRIP_DIR=%s",
				  (event->obj_id_2 >= event->obj_id ?
				   "up" : "down"));
	} else if (event->event_code == NNP_IPC_DEVICE_STATE_CHANGED) {
		nnpdrv_device_sysfs_get_state_strings(nnpdev,
						      &state,
						      &boot_state,
						      &fail_reason);
		event_env[num_env++] =
			kasprintf(GFP_KERNEL, "NNPI_EVENT=state");
		event_env[num_env++] =
			kasprintf(GFP_KERNEL, "NNPI_ERROR_CLASS=no_error");
		event_env[num_env++] =
			kasprintf(GFP_KERNEL, "NNPI_STATE=%s", state);
		event_env[num_env++] =
			kasprintf(GFP_KERNEL, "NNPI_BOOT_STATE=%s", boot_state);
		event_env[num_env++] =
			kasprintf(GFP_KERNEL,
				  "NNPI_FAIL_REASON=%s", fail_reason);
	} else if (event->event_code == NNP_IPC_ERROR_DRAM_ECC_CORRECTABLE) {
		event_env[num_env++] =
			kasprintf(GFP_KERNEL, "NNPI_EVENT=dram_ecc_error");
		event_env[num_env++] =
			kasprintf(GFP_KERNEL, "NNPI_ERROR_CLASS=correctable");
	} else if (event->event_code == NNP_IPC_CTX_DRAM_ECC_UNCORRECTABLE) {
		event_env[num_env++] =
			kasprintf(GFP_KERNEL, "NNPI_EVENT=dram_ecc_error");
		event_env[num_env++] =
			kasprintf(GFP_KERNEL, "NNPI_ERROR_CLASS=uncorrectable");
	} else if (event->event_code ==
		   NNP_IPC_ERROR_DRAM_ECC_UNCORRECTABLE_FATAL) {
		event_env[num_env++] = kasprintf(GFP_KERNEL,
						 "NNPI_EVENT=dram_ecc_error");
		event_env[num_env++] = kasprintf(GFP_KERNEL,
						 "NNPI_ERROR_CLASS=fatal");
	}

	if (num_env > 0) {
		event_env[num_env] = NULL;
		kobject_uevent_env(&nnpdev->dev->kobj, KOBJ_CHANGE, event_env);
		for (i = 0; i < num_env; ++i)
			kfree(event_env[i]);
	}
}

void nnpdrv_submit_device_event_to_channels(struct nnp_device *nnpdev,
					    union c2h_event_report *event_msg,
					    bool                   force)
{
	struct nnpdrv_cmd_chan *cmd_chan;
	int i;

	spin_lock(&nnpdev->lock);
	hash_for_each(nnpdev->cmd_chan_hash,
		      i,
		      cmd_chan,
		      hash_node) {
		if (is_card_fatal_event(event_msg->event_code) &&
		    !is_card_fatal_drv_event(
				cmd_chan->card_critical_error.event_code)) {
			cmd_chan->card_critical_error.value = event_msg->value;
			wake_up_all(&nnpdev->waitq);
		}

		if (force || cmd_chan->get_device_events)
			nnpdrv_cmd_chan_add_response(cmd_chan,
						     (u64 *)event_msg,
						     sizeof(*event_msg));
	}
	spin_unlock(&nnpdev->lock);

	/*
	 * Destroy all communication channels to the device
	 */
	if (is_card_fatal_drv_event(event_msg->event_code))
		nnpdrv_destroy_all_channels(nnpdev);
}

static void nnpdrv_device_process_events(struct nnp_device *nnpdev,
				union c2h_event_report *event_msg)
{
	struct nnpdrv_cmd_chan *cmd_chan;
	struct chan_hostres_map *hostres_map;

	if (is_card_fatal_event(event_msg->event_code)) {
		/* Handle device critical error */
		spin_lock(&nnpdev->lock);
		switch (event_msg->event_code) {
		case NNP_IPC_ERROR_OS_CRASHED:
			nnpdev->state |= NNP_DEVICE_KERNEL_CRASH;
			nnpdev->host_crash_dump.dump_size =
				((u32)event_msg->obj_id_2 << 16) |
				(u32)event_msg->obj_id;
			nnpdev->counters.uncorr.os_crashed++;
			break;
		case NNP_IPC_ERROR_PCI_ERROR:
			nnpdev->state |= NNP_DEVICE_PCI_ERROR;
			nnpdev->pci_error = event_msg->event_val;
			if (event_msg->event_val == NNP_PCIE_FATAL_ERROR)
				nnpdev->counters.uncorr.os_crashed++;
			break;
		case NNP_IPC_ERROR_PROTOCOL_ERROR:
			nnpdev->state |= NNP_DEVICE_PROTOCOL_ERROR;
			break;
		case NNP_IPC_ERROR_MCE_UNCORRECTABLE_FATAL:
			nnpdev->state |= NNP_DEVICE_FATAL_MCE_ERROR;
			nnpdev->counters.uncorr.os_crashed++;
			if (event_msg->event_val == 1)
				nnpdev->counters.uncorr.ecc_fatal++;
			else
				nnpdev->counters.uncorr.mce_fatal++;
			break;
		case NNP_IPC_ERROR_DRAM_ECC_UNCORRECTABLE_FATAL:
			nnpdev->state |= NNP_DEVICE_FATAL_DRAM_ECC_ERROR;
			nnpdev->counters.uncorr.dram_ecc_fatal++;
			break;
		case NNP_IPC_ERROR_FATAL_ICE_ERROR:
			nnpdev->state |= NNP_DEVICE_FATAL_ICE_ERROR;
			break;
		case NNP_IPC_ERROR_CARD_RESET:
			if (event_msg->event_val != 0) {
				if (nnpdev->state & NNP_DEVICE_HANG)
					nnp_log_info(GENERAL_LOG,
						     "Device#%d hang detected - reset is needed\n",
						     nnpdev->id);
				else
					nnp_log_info(GENERAL_LOG,
						     "ERROR_CARD_RESET event received for device#%d\n",
						     nnpdev->id);
			}
			break;
		default:
			nnp_log_err(GENERAL_LOG,
				    "Unknown event received - %u\n",
				    event_msg->event_code);
		}
		spin_unlock(&nnpdev->lock);

		nnpdrv_submit_device_event_to_channels(nnpdev, event_msg, true);
	} else {
		switch (event_msg->event_code) {
		case NNP_IPC_ERROR_MCE_CORRECTABLE:
			nnpdev->counters.corr.ecc++;
			break;
		case NNP_IPC_ERROR_DRAM_ECC_CORRECTABLE:
			nnpdev->counters.corr.dram_ecc++;
			break;
		case NNP_IPC_ERROR_MCE_UNCORRECTABLE:
			nnp_log_debug(GENERAL_LOG,
				      "ECC error received code - %u\n",
				      event_msg->event_code);
			if (event_msg->event_val == 1)
				nnpdev->counters.uncorr.ecc_nonfatal++;
			else
				nnpdev->counters.uncorr.mce_nonfatal++;
			break;
		case NNP_IPC_CTX_DRAM_ECC_UNCORRECTABLE:
			nnpdev->counters.uncorr.dram_ecc_nonfatal++;
			break;
		case NNP_IPC_THERMAL_TRIP_EVENT:
			nnp_log_debug(GENERAL_LOG, "Thermal trip event num=%d temp=%u\n",
				      event_msg->event_val,
				      event_msg->obj_id_2);
			break;
		case NNP_IPC_CREATE_CHANNEL_SUCCESS:
		case NNP_IPC_CREATE_CHANNEL_FAILED:
		case NNP_IPC_CHANNEL_SET_RB_SUCCESS:
		case NNP_IPC_CHANNEL_SET_RB_FAILED:
			cmd_chan = nnpdrv_device_find_channel(nnpdev,
							     event_msg->obj_id);
			if (unlikely(!cmd_chan)) {
				nnp_log_err(GENERAL_LOG,
					    "Got channel create reply for not existing channel %d\n",
					    event_msg->obj_id);
			} else {
				cmd_chan->event_msg.value = event_msg->value;
				nnpdrv_cmd_chan_put(cmd_chan);
				wake_up_all(&nnpdev->waitq);
			}
			break;
		case NNP_IPC_CHANNEL_MAP_HOSTRES_SUCCESS:
		case NNP_IPC_CHANNEL_MAP_HOSTRES_FAILED:
			cmd_chan =
				nnpdrv_device_find_channel(nnpdev,
							   event_msg->obj_id);
			if (unlikely(!cmd_chan)) {
				nnp_log_err(GENERAL_LOG,
					    "Got channel create reply for not existing channel %d\n",
					    event_msg->obj_id);
			} else {
				hostres_map =
					nnpdrv_cmd_chan_find_hostres(cmd_chan,
							event_msg->obj_id_2);
				if (!hostres_map) {
					nnp_log_err(GENERAL_LOG,
						    "Got channel(%d) hostres reply for not existing hostres %d\n",
						    event_msg->obj_id,
						    event_msg->obj_id_2);
				} else {
					hostres_map->event_msg.value =
						event_msg->value;
					wake_up_all(&nnpdev->waitq);
				}
				nnpdrv_cmd_chan_put(cmd_chan);
			}
			break;
		case NNP_IPC_DESTROY_CHANNEL_FAILED:
			nnp_log_err(GENERAL_LOG,
				    "Channel destroyed failed channel %d val %d\n",
				    event_msg->obj_id, event_msg->event_val);
			fallthrough;
		case NNP_IPC_CHANNEL_DESTROYED:
			cmd_chan = nnpdrv_device_find_channel(nnpdev,
							     event_msg->obj_id);
			if (unlikely(!cmd_chan)) {
				nnp_log_err(GENERAL_LOG,
					    "Got channel destroyed reply for not existing channel %d\n",
					    event_msg->obj_id);
			} else {
				/*
				 * put twice - one for the get made by find, one
				 */
				if (atomic_xchg(&cmd_chan->destroyed, 1) == 0)
					nnpdrv_cmd_chan_put(cmd_chan);
				nnpdrv_cmd_chan_set_closing(cmd_chan);
				nnpdrv_cmd_chan_put(cmd_chan);
			}
			break;
		case NNP_IPC_CHANNEL_UNMAP_HOSTRES_FAILED:
			nnp_log_err(GENERAL_LOG,
				    "Channel hostres unmap failed on device channel %d map %d val %d\n",
				    event_msg->obj_id, event_msg->obj_id_2,
				    event_msg->event_val);
			fallthrough;
		case NNP_IPC_CHANNEL_UNMAP_HOSTRES_SUCCESS:
			cmd_chan = nnpdrv_device_find_channel(nnpdev,
							     event_msg->obj_id);
			if (unlikely(!cmd_chan)) {
				nnp_log_err(GENERAL_LOG,
					    "Got channel unmap hostres reply for not existing channel %d\n",
					    event_msg->obj_id);
			} else {
				if (nnpdrv_chan_unmap_hostres(cmd_chan,
						event_msg->obj_id_2) != 0)
					nnp_log_err(GENERAL_LOG,
						    "channel hostres unmap failed for chan %d map %d\n",
						    event_msg->obj_id,
						    event_msg->obj_id_2);
				nnpdrv_cmd_chan_put(cmd_chan);
			}
			break;
		default:
			nnp_log_err(GENERAL_LOG,
				    "Unknown event received - %u\n",
				    event_msg->event_code);
			return;
		}

		nnpdrv_submit_device_event_to_channels(nnpdev,
						       event_msg, false);
	}

	/*
	 * ECC errors may be context specific - call to notify channel
	 */
	if (event_msg->obj_valid &&
	    event_msg->event_code == NNP_IPC_CTX_DRAM_ECC_UNCORRECTABLE) {
		union c2h_event_report ev;
		struct nnpdrv_cmd_chan *cmd_chan;

		ev.value = event_msg->value;
		ev.context_id = event_msg->obj_id;
		ev.ctx_valid = 1;

		cmd_chan = nnpdrv_device_find_channel(nnpdev, ev.context_id);
		if (cmd_chan) {
			nnpdrv_cmd_chan_add_response(cmd_chan,
						     (u64 *)&ev, sizeof(ev));
			nnpdrv_cmd_chan_put(cmd_chan);
		} else {
			nnp_log_err(GENERAL_LOG,
				    "Got context severity DRAM ECC error for non existing context id %d!!\n",
				    ev.context_id);
		}
	}

	/* inform device event */
	nnpdrv_device_inform_event(nnpdev, event_msg);
}

struct event_report_work {
	struct work_struct work;
	struct nnp_device    *nnpdev;
	union c2h_event_report msg;
};

static void device_event_report_handler(struct work_struct *work)
{
	struct event_report_work *req = container_of(work,
						    struct event_report_work,
						    work);

	nnpdrv_device_process_events(req->nnpdev, &req->msg);

	kfree(req);
}

void IPC_OPCODE_HANDLER(EVENT_REPORT)(struct nnp_device *nnpdev,
				      union c2h_event_report *event_msg)
{
	struct event_report_work *req;

	if (event_msg->ctx_valid) {
		struct nnpdrv_cmd_chan *cmd_chan;

		cmd_chan = nnpdrv_device_find_channel(nnpdev,
						      event_msg->context_id);
		if (cmd_chan) {
			if (nnpdrv_cmd_chan_add_response(cmd_chan,
				(u64 *)event_msg, sizeof(*event_msg)))
				nnp_log_err(GENERAL_LOG,
					    "Adding message response id=%d failure\n",
					    event_msg->context_id);
			nnpdrv_cmd_chan_put(cmd_chan);
		} else {
			nnp_log_err(GENERAL_LOG,
				    "Got context Event Report for non existing context id %d\n",
				    event_msg->context_id);
		}
		return;
	}

	req = kzalloc(sizeof(*req), GFP_NOWAIT);
	if (!req)
		return;

	memcpy(&req->msg, event_msg, sizeof(*event_msg));
	req->nnpdev = nnpdev;
	INIT_WORK(&req->work, device_event_report_handler);
	queue_work(nnpdev->wq, &req->work);
}

static void IPC_OPCODE_HANDLER(SYS_INFO)(struct nnp_device        *nnpdev,
					 union c2h_sys_info        *msg)
{
	u32 ice_mask;

	if (!nnpdev->card_sys_info)
		return;

	nnpdev->card_sys_info_valid = true;

	ice_mask = nnpdev->card_sys_info->ice_mask;
	nnpdev->num_ice_devices = 0;
	for (; ice_mask; ice_mask >>= 1) {
		if (ice_mask & 1)
			nnpdev->num_ice_devices++;
	}
}

static int dispatch_chan_message(struct nnp_device *nnpdev,
				 u64               *hw_msg,
				 u32                size)
{
	int op_code = ((union c2h_chan_msg_header *)hw_msg)->opcode;
	int chan_id = ((union c2h_chan_msg_header *)hw_msg)->chan_id;
	struct nnpdrv_cmd_chan *chan;
	int msg_size = 0;

	if (unlikely(op_code < 32 || op_code > 63)) {
		/* Should not happen! */
		nnp_log_err(IPC_LOG, "chan response opcode out-of-range received %d (0x%llx)\n",
			    op_code, *hw_msg);
		NNP_ASSERT(0);
		return -EINVAL;
	}

	msg_size = nnpdev->ipc_chan_resp_op_size[op_code - 32];
	if (unlikely(msg_size == 0)) {
		/* Should not happen! */
		nnp_log_err(IPC_LOG, "Unknown response chan opcode received %d (0x%llx)\n",
			    op_code, *hw_msg);
		NNP_ASSERT(0);
		return -EINVAL;
	}

	if (size < msg_size)
		return -EFAULT;

	chan = nnpdrv_device_find_channel(nnpdev, chan_id);
	if (!chan) {
		nnp_log_err(GENERAL_LOG,
			    "Got response for invalid channel chan_id=%d 0x%llx\n",
			    chan_id, *hw_msg);
		return msg_size;
	}

	nnpdrv_cmd_chan_add_response(chan, hw_msg, msg_size * 8);
	nnpdrv_cmd_chan_put(chan);

	return msg_size;
}

/*
 * HWQ messages handler,
 * This function is *NOT* re-entrant!!!
 * The pci layer call this function from bottom-half context,
 * The function may not block !!!
 */
int nnpdrv_device_process_messages(struct nnp_device *nnpdev,
				   u64               *hw_msg,
				   u32                hw_nof_msg)
{
	int j = 0;
	u64 *msg;
	u32 nof_msg;
	u64 start_time;
	bool sw_counter_enable = nnpdev->counters.ipc.enable;
	bool fatal_protocol_error = false;
	int ret;

	/* ignore any response if protocol error detected */
	if ((nnpdev->state & NNP_DEVICE_PROTOCOL_ERROR) != 0)
		return hw_nof_msg;

	if (sw_counter_enable)
		start_time = nnp_time_us();
	else
		start_time = 0;

	/*
	 * if we have pending messages from previous round
	 * copy the new messages to the pending list and process
	 * the pending list.
	 * otherwise process the messages reveived from hw directly
	 */
	if (nnpdev->response_num_msgs > 0) {
		NNP_ASSERT(hw_nof_msg + nnpdev->response_num_msgs < 32);
		if (unlikely(hw_nof_msg + nnpdev->response_num_msgs >= 32))
			return 0; /* prevent buffer overrun */

		memcpy(&nnpdev->response_buf[nnpdev->response_num_msgs],
		       hw_msg, hw_nof_msg * sizeof(u64));
		msg = nnpdev->response_buf;
		nof_msg = nnpdev->response_num_msgs + hw_nof_msg;
	} else {
		msg = hw_msg;
		nof_msg = hw_nof_msg;
	}

	/*
	 * loop for each message
	 */
	do {
		int op_code =
			((union c2h_query_version_reply_msg *)&msg[j])->opcode;
		int msg_size = 0;
		int partial_msg = 0;

		/* opcodes above OP_BIOS_PROTOCOL are routed to a channel */
		if (op_code > NNP_IPC_C2H_OP_BIOS_PROTOCOL) {
			ret = dispatch_chan_message(nnpdev,
						    &msg[j], (nof_msg - j));
			if (ret > 0) {
				j += ret;
			} else {
				if (ret == -EFAULT)
					partial_msg = true;
				else
					fatal_protocol_error = true;
				break;
			}
			continue;
		}

		/* dispatch the message request */
		#define HANDLE_RESPONSE(name, type)                         \
			do {                                                \
				msg_size = sizeof(type) / sizeof(u64);      \
				if (msg_size > (nof_msg - j))               \
					partial_msg = 1;                    \
				else {                                      \
					if (nnpdev->ipc_c2h_en[op_code])     \
						DO_TRACE(trace_host_ipc(1,  \
								&msg[j],    \
								msg_size,   \
								nnpdev->id)); \
					CALL_IPC_OPCODE_HANDLER(name, type, \
								nnpdev,     \
								&msg[j]);   \
				}                                           \
			} while (0)

		switch (op_code) {
		case C2H_OPCODE_NAME(EVENT_REPORT):
			HANDLE_RESPONSE(EVENT_REPORT, union c2h_event_report);
			break;

		case C2H_OPCODE_NAME(QUERY_VERSION_REPLY):
			HANDLE_RESPONSE(QUERY_VERSION_REPLY,
					union c2h_query_version_reply_msg);
			break;

		case C2H_OPCODE_NAME(QUERY_VERSION_REPLY2):
			HANDLE_RESPONSE(QUERY_VERSION_REPLY2,
					union c2h_query_version_reply2_msg);
			break;

		case C2H_OPCODE_NAME(QUERY_VERSION_REPLY3):
			HANDLE_RESPONSE(QUERY_VERSION_REPLY3,
					union c2h_query_version_reply3_msg);
			break;

		case C2H_OPCODE_NAME(SYS_INFO):
			HANDLE_RESPONSE(SYS_INFO, union c2h_sys_info);
			break;

		case C2H_OPCODE_NAME(BIOS_PROTOCOL):
			msg_size = process_bios_message(nnpdev,
					(union nnp_bios_ipc_header *)&msg[j],
					(nof_msg - j));
			if (nnpdev->ipc_c2h_en[op_code])
				DO_TRACE(trace_host_ipc(1, &msg[j],
							msg_size, nnpdev->id));
			partial_msg = (msg_size == 0);
			break;

		default:
			/* Should not happen! */
			nnp_log_err(IPC_LOG, "Unknown response opcode received %d (0x%llx)\n",
				    op_code, msg[j]);
			NNP_ASSERT(0);
			fatal_protocol_error = true;
			break;
		}

		/* exit the loop if not a full sized message arrived */
		if (partial_msg)
			break;

		j += msg_size;
	} while (j < nof_msg);

	if (fatal_protocol_error) {
		union c2h_event_report event;

		event.value = 0;
		event.opcode = NNP_IPC_C2H_OP_EVENT_REPORT;
		event.event_code = NNP_IPC_ERROR_PROTOCOL_ERROR;

		nnpdev->state |= NNP_DEVICE_PROTOCOL_ERROR;
		IPC_OPCODE_HANDLER(EVENT_REPORT)(nnpdev, &event);
	}

	/*
	 * if unprocessed messages left, copy it to the pending messages buffer
	 * for the next time
	 */
	if (j < nof_msg) {
		memcpy(&nnpdev->response_buf[0], &msg[j],
		       (nof_msg - j) * sizeof(u64));
		nnpdev->response_num_msgs = nof_msg - j;
	} else {
		nnpdev->response_num_msgs = 0;
	}

	if (sw_counter_enable) {
		nnpdev->counters.ipc.responses_count += j;
		nnpdev->counters.ipc.responses_consume_time +=
			(nnp_time_us() - start_time);
	}

	return hw_nof_msg;
}

static int cmdq_sched_handler(u64 *msg, int size, void *hw_data)
{
	struct nnp_device *nnpdev = (struct nnp_device *)hw_data;
	int op_code = ((union h2c_chan_msg_header *)msg)->opcode;
	int ret;
	u64 wait_time;
	u64 *timed_wait = NULL;

	if (nnpdev->counters.ipc.enable)
		timed_wait = &wait_time;

	if (nnpdev->ipc_h2c_en[op_code])
		DO_TRACE(trace_host_ipc(0, msg, size, nnpdev->id));

	ret = nnpdev->hw_ops->write_mesg(nnpdev->hw_handle,
					 msg, size, timed_wait);
	if (ret == 0 && timed_wait) {
		nnpdev->counters.ipc.commands_sent_count += size;
		nnpdev->counters.ipc.commands_wait_time += wait_time;
	}

	return ret;
}

struct msg_scheduler_queue *nnpdrv_create_cmd_queue(struct nnp_device *nnpdev,
						    u32                weight)
{
	return msg_scheduler_queue_create(nnpdev->cmdq_sched,
					  nnpdev,
					  cmdq_sched_handler,
					  weight);
}

int nnpdrv_destroy_cmd_queue(struct nnp_device          *nnpdev,
			     struct msg_scheduler_queue *q)
{
	return msg_scheduler_queue_destroy(nnpdev->cmdq_sched, q);
}

static void dump_system_info(struct nnp_device *nnpdev)
{
	char    bios_version_str[NNP_BIOS_VERSION_LEN];
	unsigned int i;
	u16    *v;

	if (!nnpdev->bios_system_info)
		return;

	nnp_log_debug(START_UP_LOG,
		      "sysinfo(%u)\n\tversion=%hhu board_id=0x%x fab_id=0x%x bom_id=0x%x\n"
		      "\tplatform_type=0x%x platform_flavor=0x%x\n",
		      nnpdev->id, nnpdev->bios_system_info->version,
		      nnpdev->bios_system_info->board_id,
		      nnpdev->bios_system_info->fab_id,
		      nnpdev->bios_system_info->bom_id,
		      nnpdev->bios_system_info->platform_type,
		      nnpdev->bios_system_info->platform_flavor);

	nnp_log_debug(START_UP_LOG,
		      "sysinfo(%u) cpu_family=0x%x Step=%hhu Sku=0x%x Did=0x%x num_cores=%hu num_threads=%hu\n",
		      nnpdev->id,
		      nnpdev->bios_system_info->cpu_info.cpu_family,
		      nnpdev->bios_system_info->cpu_info.cpu_stepping,
		      nnpdev->bios_system_info->cpu_info.cpu_sku,
		      nnpdev->bios_system_info->cpu_info.cpu_did,
		      nnpdev->bios_system_info->cpu_info.cpu_core_count,
		      nnpdev->bios_system_info->cpu_info.cpu_thread_count);

	nnp_log_debug(START_UP_LOG,
		      "sysinfo(%u) ice_count=%hu Mask=0x%x\n",
		      nnpdev->id,
		      nnpdev->bios_system_info->ice_info.ice_count,
		      nnpdev->bios_system_info->ice_info.ice_available_mask);

	nnp_log_debug(START_UP_LOG,
		      "sysinfo(%u) csme_version Code: %u.%u.%u hotfix=%u\n",
		      nnpdev->id,
		      nnpdev->bios_system_info->csme_version.code_major,
		      nnpdev->bios_system_info->csme_version.code_minor,
		      nnpdev->bios_system_info->csme_version.code_build_no,
		      nnpdev->bios_system_info->csme_version.code_hot_fix);

	nnp_log_debug(START_UP_LOG,
		      "sysinfo(%u) csme_version Rcvy: %u.%u.%u hotfix=%u\n",
		      nnpdev->id,
		      nnpdev->bios_system_info->csme_version.rcvymajor,
		      nnpdev->bios_system_info->csme_version.rcvyminor,
		      nnpdev->bios_system_info->csme_version.rcvybuildno,
		      nnpdev->bios_system_info->csme_version.rcvy_hot_fix);

	nnp_log_debug(START_UP_LOG,
		      "sysinfo(%d) csme_version Fitc: %u.%u.%u hotfix=%u\n",
		      nnpdev->id,
		      nnpdev->bios_system_info->csme_version.fitc_major,
		      nnpdev->bios_system_info->csme_version.fitc_minor,
		      nnpdev->bios_system_info->csme_version.fitcbuildno,
		      nnpdev->bios_system_info->csme_version.fitc_hot_fix);

	nnp_log_debug(START_UP_LOG,
		      "sysinfo(%d) pmc_version: %u.%u.%u hotfix=%u\n",
		      nnpdev->id,
		      nnpdev->bios_system_info->pmc_version.major,
		      nnpdev->bios_system_info->pmc_version.minor,
		      nnpdev->bios_system_info->pmc_version.build,
		      nnpdev->bios_system_info->pmc_version.hotfix);

	v = (u16 *)&nnpdev->bios_system_info->bios_ver;

	NNP_ASSERT(nnpdev->bios_system_info->bios_ver.null_terminator == 0);
	for (i = 0; i < NNP_BIOS_VERSION_LEN - 1 && v[i] != 0; ++i) {
#ifdef DEBUG
		if ((v[i] & 0xff00) != 0)
			nnp_log_err(START_UP_LOG,
				    "sysinfo(%u) bios version upper bits of char(%u) are truncated: %hu\n",
				    nnpdev->id, i, v[i]);
#endif
		bios_version_str[i] = v[i];
	}
	bios_version_str[i] = '\0';

	nnp_log_debug(START_UP_LOG, "sysinfo(%u) bios version: %s\n",
		      nnpdev->id,
		      bios_version_str);
}

static void nnpdrv_device_set_boot_state(struct nnp_device *nnpdev, u32 mask)
{
	u32 state, prev_state;
	union h2c_setup_crash_dump_msg setup_crash_dump_msg;
	union h2c_bios_system_info_req sysinfo_msg;
	bool becomes_ready = false;
	union c2h_event_report  state_changed_event;
	union h2c_setup_sys_info_page sys_info_page_msg;
	int ret;

	spin_lock(&nnpdev->lock);
	prev_state = nnpdev->state;
	if ((mask & NNP_DEVICE_CARD_BOOT_STATE_MASK) != 0) {
		nnpdev->state &= ~(NNP_DEVICE_CARD_BOOT_STATE_MASK);
		nnpdev->state &= ~(NNP_DEVICE_ERROR_MASK);
	}
	nnpdev->state |= mask;
	state = nnpdev->state;
	spin_unlock(&nnpdev->lock);

	nnp_log_debug(GENERAL_LOG, "device state change 0x%x --> 0x%x\n",
		      prev_state, state);

	/*
	 * Report the state change event to management API clients.
	 * Do not report SYSINFO_READY state, this is an "internal" state
	 */
	if (state != NNP_DEVICE_BOOT_SYSINFO_READY) {
		state_changed_event.value = 0;
		state_changed_event.opcode = NNP_IPC_C2H_OP_EVENT_REPORT;
		state_changed_event.event_code = NNP_IPC_DEVICE_STATE_CHANGED;
		state_changed_event.obj_id = state & 0xffff;
		state_changed_event.obj_id_2 = (state >> 16) & 0xffff;
		nnpdrv_device_inform_event(nnpdev, &state_changed_event);
	}

	/* unload boot image if boot started or failed */
	if (nnpdev->boot_image_loaded &&
	    (((state & NNP_DEVICE_BOOT_STARTED) &&
	      !(prev_state & NNP_DEVICE_BOOT_STARTED)) ||
	     (state & NNP_DEVICE_BOOT_FAILED))) {
		nnpdev->boot_image_loaded = 0;
		if (nnpdev->reset_boot_image_path[0] == '\0') {
			ret = nnpdrv_bootimage_unload_boot_image(
							nnpdev,
							NNP_FIRMWARE_NAME);
		} else {
			ret = nnpdrv_bootimage_unload_boot_image(
						nnpdev,
						nnpdev->reset_boot_image_path);
			nnpdev->reset_boot_image_path[0] = '\0';
		}
		if (ret)
			nnp_log_err(GENERAL_LOG,
				    "Unexpected error while unloading boot image. rc=%d\n",
				    ret);
	}

	if (state & NNP_DEVICE_ERROR_MASK)
		return;

	if ((state & NNP_DEVICE_BOOT_BIOS_READY) &&
	    !(prev_state & NNP_DEVICE_BOOT_BIOS_READY)) {
		becomes_ready = true;
	}

	if (becomes_ready || mask == NNP_DEVICE_BOOT_BIOS_READY) {
		if (!becomes_ready)
			nnp_log_err(START_UP_LOG,
				    "Re-sending sysinfo page to bios!!\n");

		/* Send request to fill system_info buffer */
		memset(sysinfo_msg.value, 0, sizeof(sysinfo_msg));
		sysinfo_msg.opcode = NNP_IPC_H2C_OP_BIOS_PROTOCOL;
		sysinfo_msg.msg_type = NNP_IPC_H2C_TYPE_SYSTEM_INFO_REQ;
		sysinfo_msg.size = 2 * sizeof(u64);
		sysinfo_msg.sysinfo_addr =
			(u64)nnpdev->bios_system_info_dma_addr;
		sysinfo_msg.sysinfo_size = NNP_PAGE_SIZE;

		nnp_log_info(START_UP_LOG,
			     "Sending sysinfo page to bios for device %d\n",
			     nnpdev->id);

		if (nnpdev->hw_ops->flush_command_fifo)
			nnpdev->hw_ops->flush_command_fifo(nnpdev->hw_handle);

		nnpdev->hw_ops->write_mesg(nnpdev->hw_handle,
					   &sysinfo_msg.value[0],
					   sizeof(sysinfo_msg) / sizeof(u64),
					   NULL);
		return;
	}

	/* Handle boot image request */
	if ((state & NNP_DEVICE_BOOT_SYSINFO_READY) &&
	    !(prev_state & NNP_DEVICE_BOOT_SYSINFO_READY) &&
	    !nnpdev->boot_image_loaded) {
		dump_system_info(nnpdev);
		nnpdev->bios_system_info_valid = true;
		nnpdev->boot_image_loaded = 1;
		if (nnpdev->reset_boot_image_path[0] == '\0') {
			ret = nnpdrv_bootimage_load_boot_image(nnpdev,
							     NNP_FIRMWARE_NAME);
		} else {
			ret = nnpdrv_bootimage_load_boot_image(
						nnpdev,
						nnpdev->reset_boot_image_path);
		}
		/*
		 * ENOENT means the image not available in memory
		 * but staged to be loaded
		 */
		if (ret && ret != -ENOENT)
			nnp_log_err(GENERAL_LOG,
				    "Unexpected error while loading boot image. rc=%d\n",
				    ret);
	}

	/* Handle transition to active state */
	if (((state & NNP_DEVICE_CARD_DRIVER_READY) ==
	     NNP_DEVICE_CARD_DRIVER_READY ||
	     (state & NNP_DEVICE_CARD_READY) == NNP_DEVICE_CARD_READY) &&
	    (prev_state & NNP_DEVICE_CARD_DRIVER_READY) !=
	    NNP_DEVICE_CARD_DRIVER_READY &&
	    (prev_state & NNP_DEVICE_CARD_READY) !=
	    NNP_DEVICE_CARD_READY) {
		/* set host driver state to "Driver ready" */
		nnpdev->hw_ops->set_host_doorbell_value(nnpdev->hw_handle,
			NNP_HOST_DRV_STATE_READY << NNP_HOST_DRV_STATE_SHIFT);

		/* send crash dump memory address */
		setup_crash_dump_msg.opcode = NNP_IPC_H2C_OP_SETUP_CRASH_DUMP;
		setup_crash_dump_msg.dma_addr =
			NNP_IPC_DMA_ADDR_TO_PFN(
				nnpdev->host_crash_dump.dma_addr);
		if (nnpdev->hw_ops->get_membar_addr) {
			u64 membar_addr;
			void *membar_vaddr;

			nnpdev->hw_ops->get_membar_addr(nnpdev->hw_handle,
							&membar_addr,
							&membar_vaddr,
							NULL);
			setup_crash_dump_msg.membar_addr = membar_addr;
			nnpdev->inbound_mem =
				(union nnp_inbound_mem *)membar_vaddr;
		} else {
			setup_crash_dump_msg.membar_addr = 0;
			nnpdev->inbound_mem = NULL;
		}

		ret = nnpdrv_msg_scheduler_queue_add_msg(nnpdev->public_cmdq,
						   setup_crash_dump_msg.value,
						   2);
		if (ret)
			nnp_log_err(GENERAL_LOG,
				    "Unexpected error while adding a message. rc=%d\n",
				    ret);

		/* send system info dma page address to card */
		sys_info_page_msg.value = 0;
		sys_info_page_msg.opcode = NNP_IPC_H2C_OP_SETUP_SYS_INFO_PAGE;
		sys_info_page_msg.dma_addr =
			NNP_IPC_DMA_ADDR_TO_PFN(nnpdev->card_sys_info_dma_addr);
		nnpdrv_msg_scheduler_queue_add_msg(nnpdev->public_cmdq,
						   &sys_info_page_msg.value, 1);
	}
}

int nnpdrv_device_create(void                              *hw_handle,
			 const struct nnp_hw_device_info   *hw_device_info,
			 const struct nnpdrv_device_hw_ops *hw_ops,
			 struct nnp_device                **out_nnpdev)
{
	struct nnp_device *nnpdev;
	int ret;

	nnpdev = kzalloc(sizeof(*nnpdev), GFP_KERNEL);
	if (!nnpdev)
		return -ENOMEM;

	nnpdev->id = -1;
	ret = ida_simple_get(&s_dev_ida, 0, NNP_MAX_DEVS, GFP_KERNEL);
	if (ret < 0) {
		nnp_log_err(START_UP_LOG, "failed to allocate NNP-I device number\n");
		goto err_early_exit;
	}

	nnpdev->id = ret;

	nnp_log_debug(START_UP_LOG, "nnpdev id is : %u\n", nnpdev->id);

	ret = snprintf(nnpdev->name,
		       sizeof(nnpdev->name),
		       "nnpdev%u", nnpdev->id);
	if (ret < 0 || ret >= sizeof(nnpdev->name)) {
		ret = -EFAULT;
		goto err_early_exit;
	}

	nnpdev->hw_handle = hw_handle;
	nnpdev->hw_device_info = hw_device_info;
	nnpdev->hw_ops = hw_ops;
	nnpdev->num_ice_devices = 0;
	nnpdev->protocol_version = 0;

	ida_init(&nnpdev->cmd_chan_ida);
	hash_init(nnpdev->cmd_chan_hash);
	init_waitqueue_head(&nnpdev->waitq);

	if (s_debugfs_dir) {
		nnpdev->debugfs_dir = debugfs_create_dir(&nnpdev->name[6],
							 s_debugfs_dir);
		if (IS_ERR_OR_NULL(nnpdev->debugfs_dir))
			nnpdev->debugfs_dir = NULL;
	}

	ret = nnpdrv_first_device_init();
	if (unlikely(ret))
		goto err_early_exit;

	nnpdev->cmdq_sched = msg_scheduler_create();
	if (!nnpdev->cmdq_sched) {
		nnp_log_err(START_UP_LOG, "failed to create msgQ scheduler\n");
		goto err_exit;
	}

	if (nnpdev->debugfs_dir)
		msg_scheduler_init_debugfs(nnpdev->cmdq_sched,
					   nnpdev->debugfs_dir,
					   "msg_sched");

	nnpdev->public_cmdq = nnpdrv_create_cmd_queue(nnpdev, 1);
	if (!nnpdev->public_cmdq) {
		nnp_log_err(START_UP_LOG,
			    "failed to create public command q\n");
		goto err_exit;
	}

	nnpdev->wq = create_singlethread_workqueue("nnpdev_wq");
	if (!nnpdev->wq) {
		ret = -ENOMEM;
		goto err_exit;
	}

	/* setup crash dump memory */
	nnpdev->host_crash_dump.vaddr = dma_alloc_coherent(
					nnpdev->hw_device_info->hw_device,
					1lu << (NNP_PAGE_SHIFT +
						NNP_CRASH_DUMP_SIZE_PAGE_ORDER),
					&nnpdev->host_crash_dump.dma_addr,
					GFP_KERNEL);

	if (!nnpdev->host_crash_dump.vaddr) {
		nnp_log_err(START_UP_LOG, "FATAL: failed to allocate crash dump buffer\n");
		goto err_exit;
	}

	/* setup memory for bios system info */
	nnpdev->bios_system_info = dma_alloc_coherent(
					nnpdev->hw_device_info->hw_device,
					2 * NNP_PAGE_SIZE,
					&nnpdev->bios_system_info_dma_addr,
					GFP_KERNEL);
	if (!nnpdev->bios_system_info) {
		nnp_log_err(START_UP_LOG,
			    "FATAL: failed to allocate system info buffer\n");
		goto err_exit;
	}

	nnpdev->card_sys_info_dma_addr = nnpdev->bios_system_info_dma_addr +
					 NNP_PAGE_SIZE;
	nnpdev->card_sys_info =
		(struct nnp_sys_info *)((uintptr_t)nnpdev->bios_system_info +
					NNP_PAGE_SIZE);

	/* Create the character device interface to this device */
	ret = nnpdev_device_chardev_create(nnpdev);
	if (ret)
		goto err_exit;

	/* set host driver state to "Not ready" */
	ret = nnpdev->hw_ops->set_host_doorbell_value(nnpdev->hw_handle,
		NNP_HOST_DRV_STATE_NOT_READY << NNP_HOST_DRV_STATE_SHIFT);
	if (ret)
		nnp_log_debug(START_UP_LOG,
			      "Doorbel call to set driver state ready failure rc=%d\n",
			      ret);

	memset(nnpdev->ipc_h2c_en, 0, sizeof(nnpdev->ipc_h2c_en));
	memset(nnpdev->ipc_c2h_en, 0, sizeof(nnpdev->ipc_c2h_en));

	kref_init(&nnpdev->ref);
	spin_lock_init(&nnpdev->lock);
	*out_nnpdev = nnpdev;

	nnp_log_debug(START_UP_LOG, "Created NNP-I device %u\n", nnpdev->id);

	return 0;

err_exit:
	if (nnpdev->bios_system_info)
		dma_free_coherent(nnpdev->hw_device_info->hw_device,
				  2 * NNP_PAGE_SIZE,
				  nnpdev->bios_system_info,
				  nnpdev->bios_system_info_dma_addr);
	if (nnpdev->host_crash_dump.vaddr)
		dma_free_coherent(nnpdev->hw_device_info->hw_device,
				1lu << (NNP_PAGE_SHIFT +
					NNP_CRASH_DUMP_SIZE_PAGE_ORDER),
				nnpdev->host_crash_dump.vaddr,
				nnpdev->host_crash_dump.dma_addr);
	if (nnpdev->wq)
		destroy_workqueue(nnpdev->wq);
	nnpdrv_destroy_cmd_queue(nnpdev, nnpdev->public_cmdq);
	if (nnpdev->cmdq_sched)
		msg_scheduler_destroy(nnpdev->cmdq_sched);
	debugfs_remove_recursive(nnpdev->debugfs_dir);
	ida_destroy(&nnpdev->cmd_chan_ida);
	nnpdrv_last_device_fini();
err_early_exit:
	if (-1 != nnpdev->id)
		ida_simple_remove(&s_dev_ida, nnpdev->id);
	debugfs_remove_recursive(nnpdev->debugfs_dir);
	kfree(nnpdev);
	nnp_log_err(START_UP_LOG, "create device failed\n");
	return ret;
}

struct doorbell_work {
	struct work_struct work;
	struct nnp_device *nnpdev;
	u32                val;
};

static void doorbell_changed_handler(struct work_struct *work)
{
	struct doorbell_work *req = container_of(work,
						 struct doorbell_work,
						 work);
	u32 boot_state;
	u32 error_state;
	u32 doorbell_val = req->val;
	struct nnp_device *nnpdev = req->nnpdev;
	union c2h_event_report  state_changed_event;

	nnpdev->card_doorbell_val = doorbell_val;

	error_state = (doorbell_val & NNP_CARD_ERROR_MASK) >>
			NNP_CARD_ERROR_SHIFT;
	boot_state = (doorbell_val & NNP_CARD_BOOT_STATE_MASK) >>
			NNP_CARD_BOOT_STATE_SHIFT;

	if (error_state) {
		nnpdrv_device_set_boot_state(nnpdev, NNP_DEVICE_BOOT_FAILED);
	} else if (boot_state != nnpdev->curr_boot_state) {
		nnpdev->curr_boot_state = boot_state;
		if (boot_state == NNP_CARD_BOOT_STATE_BIOS_READY) {
			nnpdrv_device_set_boot_state(nnpdev,
						   NNP_DEVICE_BOOT_BIOS_READY);
		} else if (boot_state == NNP_CARD_BOOT_STATE_BIOS_READY_EMMC) {
			nnpdrv_device_set_boot_state(nnpdev,
					NNP_DEVICE_BOOT_BIOS_READY_EMMC);
		} else if (boot_state ==
			   NNP_CARD_BOOT_STATE_BIOS_SYSINFO_READY) {
			nnpdrv_device_set_boot_state(nnpdev,
						NNP_DEVICE_BOOT_SYSINFO_READY);
		} else if (boot_state == NNP_CARD_BOOT_STATE_BOOT_STARTED) {
			nnpdrv_device_set_boot_state(nnpdev,
						     NNP_DEVICE_BOOT_STARTED);
		} else if (boot_state == NNP_CARD_BOOT_STATE_DRV_READY ||
			   boot_state == NNP_CARD_BOOT_STATE_CARD_READY) {
			union h2c_query_version_msg msg;

			nnp_log_debug(GENERAL_LOG, "send query version to card");

			msg.value = 0;
			msg.opcode = NNP_IPC_H2C_OP_QUERY_VERSION;
			if (nnpdrv_msg_scheduler_queue_add_msg(
				nnpdev->public_cmdq, &msg.value, 1) ||
			    msg_scheduler_queue_flush(nnpdev->public_cmdq))
				nnp_log_err(GENERAL_LOG, "Query version msg error\n");
		} else if (boot_state == NNP_CARD_BOOT_STATE_NOT_READY) {
			/* card is down reset the device boot and error state */
			spin_lock(&nnpdev->lock);
			nnpdev->state = 0;
			nnpdev->bios_system_info_valid = false;
			nnpdev->card_sys_info_valid = false;
			spin_unlock(&nnpdev->lock);

			state_changed_event.value = 0;
			state_changed_event.opcode =
				NNP_IPC_C2H_OP_EVENT_REPORT;
			state_changed_event.event_code =
				NNP_IPC_DEVICE_STATE_CHANGED;
			nnpdrv_device_inform_event(nnpdev,
						   &state_changed_event);
		}
	}

	kfree(req);
}

void nnpdrv_card_doorbell_value_changed(struct nnp_device *nnpdev,
					u32                doorbell_val)
{
	struct doorbell_work *req;

	nnp_log_debug(GENERAL_LOG,
		      "Got card doorbell value 0x%x\n", doorbell_val);

	req = kzalloc(sizeof(*req), GFP_NOWAIT);
	if (!req)
		return;

	req->nnpdev = nnpdev;
	req->val = doorbell_val;
	INIT_WORK(&req->work, doorbell_changed_handler);
	queue_work(nnpdev->wq, &req->work);
}

static void notify_device_disconnect(struct nnp_device *nnpdev,
				     bool               is_reset)
{
	union c2h_event_report event;

	/*
	 * Report critical error event to all clients
	 */
	event.value = 0;
	event.opcode = NNP_IPC_C2H_OP_EVENT_REPORT;
	event.event_code = NNP_IPC_ERROR_CARD_RESET;
	event.event_val = is_reset ? 1 : 0;
	IPC_OPCODE_HANDLER(EVENT_REPORT)(nnpdev, &event);
}

int nnpdrv_device_destroy(struct nnp_device *nnpdev)
{
	struct completion completion;
	u32 id = nnpdev->id;

	nnp_log_debug(GO_DOWN_LOG, "Destroying NNP-I device %u\n", nnpdev->id);

	/*
	 * Notify all client applications to stop using the device
	 */
	notify_device_disconnect(nnpdev, false);

	/*
	 * Decrement nnp_device refcount and wait until
	 * all clients get disconnected, refcount reaches 0 and nnp_device
	 * is released and freed
	 */
	init_completion(&completion);
	nnpdev->release_completion = &completion;
	nnpdrv_device_put(nnpdev);
	nnp_log_info(GO_DOWN_LOG, "Waiting device %u clients to exit\n", id);
	wait_for_completion(&completion);
	nnpdrv_last_device_fini();
	nnp_log_info(GO_DOWN_LOG, "Device %u destroy done\n", id);

	return 0;
}

static void nnpdrv_free_device(struct work_struct *work)
{
	struct nnp_device *nnpdev = container_of(work,
						 struct nnp_device,
						 free_work);

	struct completion *completion = nnpdev->release_completion;

	nnp_log_debug(GO_DOWN_LOG, "Freeing NNP-I device %u\n", nnpdev->id);

	NNP_ASSERT(nnpdev->release_completion);

	/* destroy device character device */
	nnpdev_device_chardev_destroy(nnpdev);

	dma_free_coherent(nnpdev->hw_device_info->hw_device,
			1 << (NNP_PAGE_SHIFT + NNP_CRASH_DUMP_SIZE_PAGE_ORDER),
			nnpdev->host_crash_dump.vaddr,
			nnpdev->host_crash_dump.dma_addr);

	dma_free_coherent(nnpdev->hw_device_info->hw_device,
			  2 * NNP_PAGE_SIZE,
			  nnpdev->bios_system_info,
			  nnpdev->bios_system_info_dma_addr);

	destroy_workqueue(nnpdev->wq);

	if (nnpdrv_destroy_cmd_queue(nnpdev, nnpdev->public_cmdq))
		nnp_log_err(GO_DOWN_LOG, "cmd queue destruction went wrong\n");

	if (msg_scheduler_destroy(nnpdev->cmdq_sched))
		nnp_log_err(GO_DOWN_LOG, "cmd queue scheduler destruction went wrong\n");

	ida_simple_remove(&s_dev_ida, nnpdev->id);
	debugfs_remove_recursive(nnpdev->debugfs_dir);
	ida_destroy(&nnpdev->cmd_chan_ida);
	kfree(nnpdev);
	complete(completion);
}

static void release_nnp_device(struct kref *kref)
{
	struct nnp_device *nnpdev = container_of(kref,
						 struct nnp_device,
						 ref);

	/*
	 * schedule work item to actually free the device since
	 * the device refcount can reach zero from within nnpdev->wq work item.
	 * This will cause dead-lock since we try to flush and destroy that
	 * workqueue when freeing the device.
	 */
	INIT_WORK(&nnpdev->free_work, nnpdrv_free_device);
	queue_work(system_wq, &nnpdev->free_work);
}

void nnpdrv_device_get(struct nnp_device *nnpdev)
{
	int ret;

	ret = kref_get_unless_zero(&nnpdev->ref);
	NNP_ASSERT(ret != 0);
}

int nnpdrv_device_put(struct nnp_device *nnpdev)
{
	return kref_put(&nnpdev->ref, release_nnp_device);
}

void nnpdrv_device_disable(struct nnp_device *nnpdev)
{
	spin_lock(&nnpdev->lock);
	nnpdev->state &= ~(NNP_DEVICE_CARD_ENABLED);
	spin_unlock(&nnpdev->lock);
}

void nnpdrv_device_enable(struct nnp_device *nnpdev)
{
	spin_lock(&nnpdev->lock);
	nnpdev->state |= NNP_DEVICE_CARD_ENABLED;
	spin_unlock(&nnpdev->lock);
}

/* called from pcie layer when pcie error is detected */
int nnpdrv_device_pci_error_detected(struct nnp_device *nnpdev,
				     u32                error_type)
{
	union c2h_event_report event;

	/*
	 * report the event through event report path.
	 */
	event.value = 0;
	event.opcode = NNP_IPC_C2H_OP_EVENT_REPORT;
	event.event_code = NNP_IPC_ERROR_PCI_ERROR;
	event.event_val = error_type;

	IPC_OPCODE_HANDLER(EVENT_REPORT)(nnpdev, &event);

	return 0;
}

/* called from pcie layer before the device is about to reset */
void nnpdrv_device_reset_prepare(struct nnp_device *nnpdev, bool is_hang)
{
	/* BAR2 can not longer be accessed */
	nnpdev->inbound_mem = NULL;

	/*
	 * Put the device in error state due to reset started.
	 * Error condition will be cleared when boot state is changed.
	 */
	if (!is_hang) {
		nnpdrv_device_set_boot_state(nnpdev, NNP_DEVICE_CARD_IN_RESET);

		/* set host driver state to "Not ready" */
		nnpdev->hw_ops->set_host_doorbell_value(nnpdev->hw_handle,
						NNP_HOST_DRV_STATE_NOT_READY <<
						NNP_HOST_DRV_STATE_SHIFT);
	} else {
		nnpdrv_device_set_boot_state(nnpdev, NNP_DEVICE_HANG);
	}

	/*
	 * Remove and invalidate all message queues so that
	 * no more messages will be sent to the h/w queue
	 */
	msg_scheduler_invalidate_all(nnpdev->cmdq_sched);

	/*
	 * Notify all client applications to stop using the device
	 */
	notify_device_disconnect(nnpdev, true);
}

/* called from pcie layer after the device has successfully done reset */
void nnpdrv_device_reset_done(struct nnp_device *nnpdev)
{
	u64 membar_addr;
	void *membar_vaddr;

	/* re-enable the public command q */
	msg_scheduler_queue_make_valid(nnpdev->public_cmdq);

	/* recover BAR2 address after reset succeeded */
	nnpdev->hw_ops->get_membar_addr(nnpdev->hw_handle,
					&membar_addr,
					&membar_vaddr,
					NULL);
	nnpdev->inbound_mem = (union nnp_inbound_mem *)membar_vaddr;
}

int nnpdrv_device_force_reset(struct nnp_device *nnpdev)
{
	int ret;

	/*
	 * reset h/w layer - will generate FLR
	 */
	ret = nnpdev->hw_ops->reset(nnpdev->hw_handle);
	if (ret)
		nnp_log_err(GENERAL_LOG,
			    "failed to reset h/w layer during froce reset ret=%d\n",
			    ret);

	return ret;
}
