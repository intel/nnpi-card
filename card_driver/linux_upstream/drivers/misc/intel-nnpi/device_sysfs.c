// SPDX-License-Identifier: GPL-2.0-or-later

/********************************************
 * Copyright (C) 2019-2021 Intel Corporation
 ********************************************/
#include "device_sysfs.h"
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/sysfs.h>
#include <linux/slab.h>
#include <linux/device.h>
#include <linux/kobject.h>
#include <linux/delay.h>
#include "cmd_chan.h"
#include "nnp_inbound_mem.h"
#include "nnp_log.h"
#include "ipc_c2h_events.h"
#include "trace.h"
#include <linux/trace_clock.h>

#define CLOCK_TYPE_STR_MAX_SIZE 7
#define CLOCK_VALUE_STR_MAX_SIZE 32

static ssize_t enable_show(struct device           *dev,
			   struct device_attribute *attr,
			   char                    *buf)
{
	struct nnp_device *nnpdev;

	nnpdev = (struct nnp_device *)dev_get_drvdata(dev);
	if (!nnpdev)
		return -EINVAL;

	if ((nnpdev->state & NNP_DEVICE_CARD_ENABLED) != 0)
		buf[0] = '1';
	else
		buf[0] = '0';
	buf[1] = '\n';

	return 2;
}

static ssize_t enable_store(struct device           *dev,
			    struct device_attribute *attr,
			    const char              *buf,
			    size_t                   count)
{
	struct nnp_device *nnpdev;
	unsigned long val;
	bool do_abort = false;

	nnpdev = (struct nnp_device *)dev_get_drvdata(dev);
	if (!nnpdev)
		return -EINVAL;

	if (!strncmp(buf, "abort", 5)) {
		val = 0;
		do_abort = true;
	} else if (kstrtoul(buf, 0, &val) < 0) {
		return -EINVAL;
	}

	if (val != 0) {
		nnpdrv_device_enable(nnpdev);
	} else {
		nnpdrv_device_disable(nnpdev);

		if (do_abort) {
			union c2h_event_report abort_req;

			abort_req.value = 0;
			abort_req.opcode = NNP_IPC_C2H_OP_EVENT_REPORT;
			abort_req.event_code = NNP_IPC_ABORT_REQUEST;

			nnpdrv_submit_device_event_to_channels(nnpdev,
							       &abort_req,
							       true);
		}
	}

	return count;
}
static DEVICE_ATTR_RW(enable);

static ssize_t boot_image_show(struct device           *dev,
			       struct device_attribute *attr,
			       char                    *buf)
{
	struct nnp_device *nnpdev;
	ssize_t ret;

	nnpdev = (struct nnp_device *)dev_get_drvdata(dev);
	if (!nnpdev)
		return -EINVAL;

	if (nnpdev->reset_boot_image_path[0] == '\0')
		ret = snprintf(buf, PAGE_SIZE, "%s\n", NNP_FIRMWARE_NAME);
	else
		ret = snprintf(buf, PAGE_SIZE,
			       "%s\n", nnpdev->reset_boot_image_path);

	return ret;
}

static ssize_t boot_image_store(struct device           *dev,
				struct device_attribute *attr,
				const char              *buf,
				size_t                   count)
{
	struct nnp_device *nnpdev;

	nnpdev = (struct nnp_device *)dev_get_drvdata(dev);
	if (!nnpdev)
		return -EINVAL;

	strncpy(nnpdev->reset_boot_image_path, buf,
		NNP_DEVICE_MAX_BOOT_IMAGE_PATH_SIZE - 1);
	nnpdev->reset_boot_image_path[NNP_DEVICE_MAX_BOOT_IMAGE_PATH_SIZE - 1] =
		'\0';

	return count;
}
static DEVICE_ATTR_RW(boot_image);

static ssize_t reset_store(struct device           *dev,
			   struct device_attribute *attr,
			   const char              *buf,
			   size_t                   count)
{
	struct nnp_device *nnpdev;
	int force;
	unsigned long val;
	int ret;

	nnpdev = (struct nnp_device *)dev_get_drvdata(dev);
	if (!nnpdev)
		return -EINVAL;

	force = strncmp(buf, "force", count) == 0 ? 1 : 0;
	if (!force)
		if (kstrtoul(buf, 0, &val) < 0)
			return -EINVAL;

	if (!force && !val)
		return -EINVAL;

	/*
	 * If force was not specified we wont reset in those cases:
	 * a) the device is enabled
	 * b) the device reset has been already started
	 * c) there are active contexts on the device.
	 */
	if (!force &&
	    ((nnpdev->state & NNP_DEVICE_CARD_ENABLED) ||
	     (nnpdev->state & NNP_DEVICE_CARD_IN_RESET) ||
	     nnpdev->num_active_contexts > 0))
		return -EBUSY;

	ret = nnpdrv_device_force_reset(nnpdev);
	if (ret)
		return -EFAULT;

	return count;
}
static DEVICE_ATTR_WO(reset);

static ssize_t clock_stamp_store(struct device		*dev,
				 struct device_attribute *attr,
				 const char              *buf,
				 size_t                   count)
{
	struct nnp_device *nnpdev;
	union clock_stamp_msg clock_msg;
	char clock_type_host[CLOCK_TYPE_STR_MAX_SIZE + 1];
	int i;

	if (count <= 1 ||
	    (count > (CLOCK_VALUE_STR_MAX_SIZE + CLOCK_TYPE_STR_MAX_SIZE))) {
		nnp_log_err(START_UP_LOG,
			    "Invalid Input. Input should be: <type_str,clock> or <type_str>. size: %lu\n",
			    count);
		return -EINVAL;
	}

	nnpdev = (struct nnp_device *)dev_get_drvdata(dev);
	if (!nnpdev)
		return -EINVAL;

	clock_msg.value[0] = 0;
	clock_msg.value[1] = 0;
	memset(clock_type_host, '\0', CLOCK_TYPE_STR_MAX_SIZE + 1);
	clock_msg.opcode = NNP_IPC_H2C_OP_CLOCK_STAMP;

	/*
	 * user's input can be one of these options:
	 * 1. <type_str,clock_value_decimal>
	 * 2. <type_str>
	 */
	for (i = 0; i < count; i++) {
		if (buf[i] == ',' || buf[i] == '\n') {
			break;
		} else if (i >= CLOCK_TYPE_STR_MAX_SIZE) {
			nnp_log_err(START_UP_LOG,
				    "Invalid clock. Input should be: <type_str,clock> or <type_str>. size: %lu\n",
				    count);
			return -EINVAL;
		}

		clock_msg.i_type[i] = buf[i];
		clock_type_host[i] = buf[i];
	}

	if (buf[i] != ',') {
		/* ',' was not found */
		clock_msg.i_clock = trace_clock_local();
	} else {
		/* both type_str and clock were found */
		if (kstrtoull(&buf[i + 1], 0, &clock_msg.i_clock) < 0) {
			nnp_log_err(START_UP_LOG,
				    "Invalid clock. Input should be: <type_str,clock> or <type_str>. size: %lu\n",
				    count);
			return -EINVAL;
		}
	}

	nnpdev->hw_ops->write_mesg(nnpdev->hw_handle,
					&clock_msg.value[0],
					sizeof(clock_msg) / sizeof(u64),
					NULL);

	DO_TRACE(trace_host_clock_stamp(clock_type_host,
					clock_msg.i_clock, nnpdev->id));

	return count;
}
static DEVICE_ATTR_WO(clock_stamp);

void nnpdrv_device_sysfs_get_state_strings(struct nnp_device *nnpdev,
					   const char **state,
					   const char **boot_state,
					   const char **fail_reason)
{
	/* Find Boot State */
	if (nnpdev->state & NNP_DEVICE_ERROR_MASK)
		*boot_state = "failed";
	else if (nnpdev->state & NNP_DEVICE_CARD_READY)
		*boot_state = "Ready";
	else if (nnpdev->state & NNP_DEVICE_CARD_DRIVER_READY)
		*boot_state = "Driver Ready";
	else if (nnpdev->state & NNP_DEVICE_BOOT_STARTED)
		*boot_state = "Boot Started";
	else if (nnpdev->state & (NNP_DEVICE_BOOT_BIOS_READY |
				  NNP_DEVICE_BOOT_SYSINFO_READY))
		*boot_state = "Bios Ready";
	else
		*boot_state = "Unknown";

	/* Find failure Reason*/
	if (nnpdev->state & NNP_DEVICE_FAILED_VERSION) {
		*fail_reason = "version Mismatch";
	} else if (nnpdev->state & NNP_DEVICE_BOOT_FAILED) {
		*fail_reason = "Boot failed";
	} else if (nnpdev->state & NNP_DEVICE_HOST_DRIVER_ERROR) {
		*fail_reason = "Driver Error";
	} else if (nnpdev->state & NNP_DEVICE_KERNEL_CRASH) {
		*fail_reason = "OS Crash";
	} else if (nnpdev->state & NNP_DEVICE_PCI_ERROR) {
		if (nnpdev->pci_error == NNP_PCIE_LINK_RETRAIN_REQUIRED)
			*fail_reason = "PCI Error (rescan required)";
		else
			*fail_reason = "PCI Error";
	} else if (nnpdev->state & NNP_DEVICE_CARD_IN_RESET) {
		*fail_reason = "Reset in progress";
	} else if (nnpdev->state & NNP_DEVICE_FATAL_MCE_ERROR) {
		*fail_reason = "Fatal MCE Error";
	} else if (nnpdev->state & NNP_DEVICE_FATAL_DRAM_ECC_ERROR) {
		*fail_reason = "Fatal DRAM ECC Error";
	} else if (nnpdev->state & NNP_DEVICE_FATAL_ICE_ERROR) {
		*fail_reason = "Fatal ICE execution error";
	} else if (nnpdev->state & NNP_DEVICE_HANG) {
		*fail_reason = "Device Not Responding (Hang)";
	} else {
		*fail_reason = "None";
	}

	/* find device state */
	if (nnpdev->state & NNP_DEVICE_ERROR_MASK) {
		*state = "failed";
	} else if ((nnpdev->state & NNP_DEVICE_ACTIVE_MASK) ==
		 NNP_DEVICE_ACTIVE_MASK) {
		*state = "Active";
	} else if ((nnpdev->state & NNP_DEVICE_CARD_READY) &&
		 !(nnpdev->state & NNP_DEVICE_CARD_ENABLED)) {
		if (nnpdev->num_active_contexts)
			*state = "Disabled";
		else
			*state = "Disabled and Idle";
	} else {
		*state = "Unknown";
	}
}

static ssize_t post_code_show(struct device   *dev,
			      struct device_attribute *attr,
			      char                    *buf)
{
	struct nnp_device *nnpdev;
	ssize_t ret = 0;

	nnpdev = (struct nnp_device *)dev_get_drvdata(dev);
	if (!nnpdev)
		return -EINVAL;

	if (nnpdev->hw_ops->get_postcode)
		ret = snprintf(&buf[ret],
			       PAGE_SIZE,
			       "0x%04x\n",
			       nnpdev->hw_ops->get_postcode(nnpdev->hw_handle));
	return ret;
}
static DEVICE_ATTR_RO(post_code);

static ssize_t bios_flash_progress_show(struct device   *dev,
					struct device_attribute *attr,
					char                    *buf)
{
	struct nnp_device *nnpdev;
	ssize_t ret = 0;

	nnpdev = (struct nnp_device *)dev_get_drvdata(dev);
	if (!nnpdev)
		return -EINVAL;

	if (nnpdev->hw_ops->get_bios_flash_progress)
		ret = snprintf(&buf[ret],
			       PAGE_SIZE, "%03d %%\n",
			       nnpdev->hw_ops->get_bios_flash_progress(
							nnpdev->hw_handle));
	return ret;
}
static DEVICE_ATTR_RO(bios_flash_progress);

static ssize_t ice_units_show(struct device   *dev,
			      struct device_attribute *attr,
			      char                    *buf)
{
	struct nnp_device *nnpdev;
	ssize_t ret = 0;

	nnpdev = (struct nnp_device *)dev_get_drvdata(dev);
	if (!nnpdev)
		return -EINVAL;

	ret = snprintf(&buf[ret], PAGE_SIZE, "%d\n", nnpdev->num_ice_devices);

	return ret;
}
static DEVICE_ATTR_RO(ice_units);

static ssize_t bios_version_show(struct device   *dev,
				 struct device_attribute *attr,
				 char                    *buf)
{
	struct nnp_device *nnpdev;
	ssize_t ret = 0;

	nnpdev = (struct nnp_device *)dev_get_drvdata(dev);
	if (!nnpdev)
		return -EINVAL;

	if (nnpdev->card_sys_info_valid &&
	    nnpdev->card_sys_info->bios_version[0] != '\0') {
		ret = snprintf(&buf[ret], PAGE_SIZE, "%s\n",
			       nnpdev->card_sys_info->bios_version);
	} else if (nnpdev->bios_system_info_valid &&
		   nnpdev->bios_system_info) {
		unsigned int i;
		u16 *v = (u16 *)&nnpdev->bios_system_info->bios_ver;

		NNP_ASSERT(nnpdev->bios_system_info->bios_ver.null_terminator ==
			   0);

		for (i = 0; ret < PAGE_SIZE && v[i] != 0 &&
		     i < (sizeof(struct nnp_c2h_bios_version) / sizeof(u16));
		     ++i) {
#ifdef DEBUG
			if ((v[i] & 0xff00) != 0)
				nnp_log_err(GENERAL_LOG,
					    "sysinfo(%u) bios version upper bits of char(%u) are truncated: %hu\n",
					    nnpdev->id, i, v[i]);
#endif
			buf[ret++] = v[i];
		}
		ret += snprintf(&buf[ret], PAGE_SIZE - ret, "\n");
	}

	return ret;
}
static DEVICE_ATTR_RO(bios_version);

static ssize_t image_version_show(struct device   *dev,
				  struct device_attribute *attr,
				  char                    *buf)
{
	struct nnp_device *nnpdev;
	ssize_t ret = 0;

	nnpdev = (struct nnp_device *)dev_get_drvdata(dev);
	if (!nnpdev)
		return -EINVAL;

	if (nnpdev->card_sys_info_valid &&
	    nnpdev->card_sys_info->image_version[0] != '\0')
		ret = snprintf(&buf[ret], PAGE_SIZE, "%s\n",
			       nnpdev->card_sys_info->image_version);
	return ret;
}
static DEVICE_ATTR_RO(image_version);

static ssize_t board_name_show(struct device   *dev,
			       struct device_attribute *attr,
			       char                    *buf)
{
	struct nnp_device *nnpdev;
	ssize_t ret = 0;

	nnpdev = (struct nnp_device *)dev_get_drvdata(dev);
	if (!nnpdev)
		return -EINVAL;

	if (nnpdev->card_sys_info_valid &&
	    nnpdev->card_sys_info->board_name[0] != '\0')
		ret = snprintf(&buf[ret], PAGE_SIZE, "%s\n",
			       nnpdev->card_sys_info->board_name);
	return ret;
}
static DEVICE_ATTR_RO(board_name);

static ssize_t board_part_num_show(struct device   *dev,
				   struct device_attribute *attr,
				   char                    *buf)
{
	struct nnp_device *nnpdev;
	ssize_t ret = 0;

	nnpdev = (struct nnp_device *)dev_get_drvdata(dev);
	if (!nnpdev)
		return -EINVAL;

	if (nnpdev->card_sys_info_valid &&
	    nnpdev->card_sys_info->brd_part_no[0] != '\0')
		ret = snprintf(&buf[ret], PAGE_SIZE, "%s\n",
			       nnpdev->card_sys_info->brd_part_no);
	return ret;
}
static DEVICE_ATTR_RO(board_part_num);

static ssize_t board_serial_num_show(struct device   *dev,
				     struct device_attribute *attr,
				     char                    *buf)
{
	struct nnp_device *nnpdev;
	ssize_t ret = 0;

	nnpdev = (struct nnp_device *)dev_get_drvdata(dev);
	if (!nnpdev)
		return -EINVAL;

	if (nnpdev->card_sys_info_valid &&
	    nnpdev->card_sys_info->prd_serial[0] != '\0')
		ret = snprintf(&buf[ret], PAGE_SIZE, "%s\n",
			       nnpdev->card_sys_info->prd_serial);
	return ret;
}
static DEVICE_ATTR_RO(board_serial_num);

static ssize_t active_contexts_num_show(struct device   *dev,
					struct device_attribute *attr,
					char                    *buf)
{
	struct nnp_device *nnpdev;
	ssize_t ret = 0;

	nnpdev = (struct nnp_device *)dev_get_drvdata(dev);
	if (!nnpdev)
		return -EINVAL;

	ret = snprintf(&buf[ret], PAGE_SIZE, "%u\n",
		       nnpdev->num_active_contexts);
	return ret;
}
static DEVICE_ATTR_RO(active_contexts_num);

static ssize_t fpga_revision_show(struct device   *dev,
				  struct device_attribute *attr,
				  char                    *buf)
{
	struct nnp_device *nnpdev;
	ssize_t ret = 0;

	nnpdev = (struct nnp_device *)dev_get_drvdata(dev);
	if (!nnpdev)
		return -EINVAL;

	if (nnpdev->card_sys_info_valid)
		ret = snprintf(&buf[ret], PAGE_SIZE, "%u\n",
			       nnpdev->card_sys_info->fpga_rev);
	return ret;
}
static DEVICE_ATTR_RO(fpga_revision);

static ssize_t card_stepping_show(struct device   *dev,
				  struct device_attribute *attr,
				  char                    *buf)
{
	struct nnp_device *nnpdev;
	ssize_t ret = 0;

	nnpdev = (struct nnp_device *)dev_get_drvdata(dev);
	if (!nnpdev)
		return -EINVAL;

	if (nnpdev->card_sys_info_valid)
		ret = snprintf(&buf[ret], PAGE_SIZE,
			       "%d\n", nnpdev->card_sys_info->stepping);

	return ret;
}
static DEVICE_ATTR_RO(card_stepping);

static ssize_t boot_state_show(struct device   *dev,
			       struct device_attribute *attr,
			       char                    *buf)
{
	struct nnp_device *nnpdev;
	ssize_t ret = 0;
	const char *boot_state;
	const char *state;
	const char *fail_reason;

	nnpdev = (struct nnp_device *)dev_get_drvdata(dev);
	if (!nnpdev)
		return -EINVAL;

	/* Find State strings*/
	nnpdrv_device_sysfs_get_state_strings(nnpdev,
					      &state,
					      &boot_state,
					      &fail_reason);

	ret = snprintf(&buf[ret], PAGE_SIZE, "%s\n", boot_state);

	return ret;
}
static DEVICE_ATTR_RO(boot_state);

static ssize_t boot_fail_reason_show(struct device   *dev,
				     struct device_attribute *attr,
				     char                    *buf)
{
	struct nnp_device *nnpdev;
	ssize_t ret = 0;
	const char *boot_state;
	const char *state;
	const char *fail_reason;

	nnpdev = (struct nnp_device *)dev_get_drvdata(dev);
	if (!nnpdev)
		return -EINVAL;

	/* Find State strings*/
	nnpdrv_device_sysfs_get_state_strings(nnpdev,
					      &state,
					      &boot_state,
					      &fail_reason);

	ret = snprintf(&buf[ret], PAGE_SIZE, "%s\n", fail_reason);

	return ret;
}
static DEVICE_ATTR_RO(boot_fail_reason);

static ssize_t card_state_show(struct device   *dev,
			       struct device_attribute *attr,
			       char                    *buf)
{
	struct nnp_device *nnpdev;
	ssize_t ret = 0;
	const char *boot_state;
	const char *state;
	const char *fail_reason;

	nnpdev = (struct nnp_device *)dev_get_drvdata(dev);
	if (!nnpdev)
		return -EINVAL;

	/* Find State strings*/
	nnpdrv_device_sysfs_get_state_strings(nnpdev,
					      &state,
					      &boot_state,
					      &fail_reason);

	ret = snprintf(&buf[ret], PAGE_SIZE, "%s\n", state);

	return ret;
}
static DEVICE_ATTR_RO(card_state);

static ssize_t total_unprotected_mem_show(struct device           *dev,
					  struct device_attribute *attr,
					  char                    *buf)
{
	struct nnp_device *nnpdev;
	ssize_t ret = 0;

	nnpdev = (struct nnp_device *)dev_get_drvdata(dev);
	if (!nnpdev)
		return -EINVAL;

	if (nnpdev->card_sys_info_valid)
		ret += snprintf(&buf[ret], PAGE_SIZE, "%lld\n",
			nnpdev->card_sys_info->total_unprotected_memory);
	else
		ret += snprintf(buf, PAGE_SIZE, "0\n");

	return ret;
}
static DEVICE_ATTR_RO(total_unprotected_mem);

static ssize_t total_protected_mem_show(struct device           *dev,
					struct device_attribute *attr,
					char                    *buf)
{
	struct nnp_device *nnpdev;
	ssize_t ret = 0;

	nnpdev = (struct nnp_device *)dev_get_drvdata(dev);
	if (!nnpdev)
		return -EINVAL;

	if (nnpdev->card_sys_info_valid)
		ret += snprintf(&buf[ret], PAGE_SIZE, "%lld\n",
				nnpdev->card_sys_info->total_ecc_memory);
	else
		ret += snprintf(buf, PAGE_SIZE, "0\n");

	return ret;
}
static DEVICE_ATTR_RO(total_protected_mem);

static ssize_t protocol_version_show(struct device           *dev,
				     struct device_attribute *attr,
				     char                    *buf)
{
	struct nnp_device *nnpdev;
	ssize_t ret = 0;

	nnpdev = (struct nnp_device *)dev_get_drvdata(dev);
	if (!nnpdev)
		return -EINVAL;

	ret += snprintf(buf, PAGE_SIZE, "%d.%d.%d\n",
			NNP_VERSION_MAJOR(nnpdev->protocol_version),
			NNP_VERSION_MINOR(nnpdev->protocol_version),
			NNP_VERSION_DOT(nnpdev->protocol_version));

	return ret;
}
static DEVICE_ATTR_RO(protocol_version);

static ssize_t channels_show(struct device           *dev,
			     struct device_attribute *attr,
			     char                    *buf)
{
	struct nnp_device *nnpdev;
	struct nnpdrv_cmd_chan *chan;
	int i;
	ssize_t ret = 0;

	nnpdev = (struct nnp_device *)dev_get_drvdata(dev);
	if (!nnpdev)
		return -EINVAL;

	spin_lock(&nnpdev->lock);
	hash_for_each(nnpdev->cmd_chan_hash,
		      i,
		      chan,
		      hash_node) {
		if (ret >= PAGE_SIZE)
			break;
		ret += snprintf(&buf[ret], PAGE_SIZE - ret, "%d,%d\n",
				chan->protocol_id, chan->proc_info->pid);
	}
	spin_unlock(&nnpdev->lock);

	return ret;
}
static DEVICE_ATTR_RO(channels);

static ssize_t cecc_threshold_store(struct device           *dev,
				    struct device_attribute *attr,
				    const char              *buf,
				    size_t                   count)
{
	struct nnp_device *nnpdev;
	unsigned long val;

	nnpdev = (struct nnp_device *)dev_get_drvdata(dev);
	if (!nnpdev)
		return -EINVAL;

	if (kstrtoul(buf, 0, &val) < 0)
		return -EINVAL;

	nnpdev->correctable_ecc_threshold = val;
	nnpdev->correctable_ecc_counter = 0;

	return count;
}

static ssize_t cecc_threshold_show(struct device           *dev,
				   struct device_attribute *attr,
				   char                    *buf)
{
	struct nnp_device *nnpdev;
	ssize_t ret = 0;

	nnpdev = (struct nnp_device *)dev_get_drvdata(dev);
	if (!nnpdev)
		return -EINVAL;

	ret += scnprintf(buf, PAGE_SIZE,
			 "%d\n", nnpdev->correctable_ecc_threshold);

	return ret;
}
static DEVICE_ATTR_RW(cecc_threshold);

static ssize_t ucecc_threshold_store(struct device           *dev,
				     struct device_attribute *attr,
				     const char              *buf,
				     size_t                   count)
{
	struct nnp_device *nnpdev;
	unsigned long val;

	nnpdev = (struct nnp_device *)dev_get_drvdata(dev);
	if (!nnpdev)
		return -EINVAL;

	if (kstrtoul(buf, 0, &val) < 0)
		return -EINVAL;

	nnpdev->uncorrectable_ecc_threshold = val;
	nnpdev->uncorrectable_ecc_counter = 0;

	return count;
}

static ssize_t ucecc_threshold_show(struct device           *dev,
				    struct device_attribute *attr,
				    char                    *buf)
{
	struct nnp_device *nnpdev;
	ssize_t ret = 0;

	nnpdev = (struct nnp_device *)dev_get_drvdata(dev);
	if (!nnpdev)
		return -EINVAL;

	ret += sprintf(buf, "%d\n", nnpdev->uncorrectable_ecc_threshold);

	return ret;
}
static DEVICE_ATTR_RW(ucecc_threshold);

static ssize_t pcie_inject_store(struct device           *dev,
				 struct device_attribute *attr,
				 const char              *buf,
				 size_t                   count)
{
	struct nnp_device *nnpdev;
	u32 pcie_err_type;
	int ret;

	nnpdev = (struct nnp_device *)dev_get_drvdata(dev);
	if (!nnpdev)
		return -EINVAL;

	if (!nnpdev->hw_ops || !nnpdev->hw_ops->error_inject)
		return -EFAULT;

	if (!strncmp(buf, "corr", 4))
		pcie_err_type = NNP_PCIE_INJECT_CORR;
	else if (!strncmp(buf, "uncorr", 6))
		pcie_err_type = NNP_PCIE_INJECT_UNCORR;
	else if (!strncmp(buf, "fatal", 5))
		pcie_err_type = NNP_PCIE_INJECT_UNCORR_FATAL;
	else if (!strncmp(buf, "none", 4))
		pcie_err_type = NNP_PCIE_INJECT_RESTORE;
	else
		return -EINVAL;

	/*
	 * Setup h/w layer to generate the requested error
	 * on the next dma transaction
	 */
	ret = nnpdev->hw_ops->error_inject(nnpdev->hw_handle,
					   pcie_err_type);
	if (ret)
		return ret;

	return count;
}
static DEVICE_ATTR_WO(pcie_inject);

static ssize_t crashlog_size_show(struct device           *dev,
				  struct device_attribute *attr,
				  char                    *buf)
{
	struct nnp_device *nnpdev;
	u32 dump_size;

	nnpdev = (struct nnp_device *)dev_get_drvdata(dev);
	if (!nnpdev)
		return -EINVAL;

	spin_lock(&nnpdev->lock);

	if (nnpdev->host_crash_dump.dump_size) {
		dump_size = nnpdev->host_crash_dump.dump_size;
	} else if (nnpdev->inbound_mem &&
		   nnpdev->inbound_mem->magic == NNP_INBOUND_MEM_MAGIC &&
		   nnpdev->inbound_mem->crash_dump_size) {
		dump_size = nnpdev->inbound_mem->crash_dump_size;
	} else {
		dump_size = 0;
	}
	spin_unlock(&nnpdev->lock);

	return sprintf(buf, "%d\n", dump_size);
}
static DEVICE_ATTR_RO(crashlog_size);

static ssize_t ipc_counters_show(struct device           *dev,
				 struct device_attribute *attr,
				 char                    *buf)
{
	struct nnp_device *nnpdev;
	ssize_t ret = 0;

	nnpdev = (struct nnp_device *)dev_get_drvdata(dev);
	if (!nnpdev)
		return -EINVAL;

	ret += snprintf(&buf[ret], PAGE_SIZE - ret, "enable: %d\n",
			nnpdev->counters.ipc.enable);
	ret += snprintf(&buf[ret], PAGE_SIZE - ret, "cmd_wait_time: %llu\n",
			nnpdev->counters.ipc.commands_wait_time);
	ret += snprintf(&buf[ret], PAGE_SIZE - ret, "cmd_sent_count: %llu\n",
			nnpdev->counters.ipc.commands_sent_count);
	ret += snprintf(&buf[ret], PAGE_SIZE - ret, "cmd_sched_count: %llu\n",
			nnpdev->counters.ipc.commands_sched_count);
	ret += snprintf(&buf[ret], PAGE_SIZE - ret, "resp_consume_time: %llu\n",
			nnpdev->counters.ipc.responses_consume_time);
	ret += snprintf(&buf[ret], PAGE_SIZE - ret, "resp_count: %llu\n",
			nnpdev->counters.ipc.responses_count);

	return ret;
}

static ssize_t ipc_counters_store(struct device           *dev,
				  struct device_attribute *attr,
				  const char              *buf,
				  size_t                   count)
{
	struct nnp_device *nnpdev;
	unsigned long val;

	nnpdev = (struct nnp_device *)dev_get_drvdata(dev);
	if (!nnpdev)
		return -EINVAL;

	if (kstrtoul(buf, 0, &val) < 0)
		return -EINVAL;

	nnpdev->counters.ipc.enable = (val != 0);

	return count;
}
static DEVICE_ATTR_RW(ipc_counters);

static int ipc_event_set(struct device *dev,
			 const char    *buf,
			 size_t         count,
			 bool           is_cmd,
			 bool           enable)
{
	unsigned long index;
	struct nnp_device *nnpdev;

	if (kstrtoul(buf, 0, &index) < 0)
		return -EINVAL;

	if (index < 0 || index >= IPC_OP_MAX)
		return -EINVAL;

	if (is_cmd)
		nnpdev->ipc_h2c_en[index] = enable;
	else
		nnpdev->ipc_c2h_en[index] = enable;

	return count;
}

static int ipc_event_get(struct device *dev,
			 char    *buf,
			 bool           is_cmd)
{
	bool *arr;
	struct nnp_device *nnpdev;
	int ret = 0, i = 0;

	if (is_cmd)
		arr = nnpdev->ipc_h2c_en;
	else
		arr = nnpdev->ipc_c2h_en;

	for (i = 0 ; i < IPC_OP_MAX ; i++)
		if (arr[i])
			ret += snprintf(buf + ret, PAGE_SIZE, "%d\n", i);

	return ret;
}

static ssize_t ipc_event_h2c_en_store(struct device           *dev,
				      struct device_attribute *attr,
				      const char              *buf,
				      size_t                   count)
{
	return ipc_event_set(dev, buf, count, true, true);
}

static ssize_t ipc_event_h2c_en_show(struct device           *dev,
				     struct device_attribute *attr,
				     char                    *buf)
{
	return ipc_event_get(dev, buf, true);
}
static DEVICE_ATTR_RW(ipc_event_h2c_en);

static ssize_t ipc_event_h2c_dis_store(struct device           *dev,
				       struct device_attribute *attr,
				       const char              *buf,
				       size_t                   count)
{
	return ipc_event_set(dev, buf, count, true, false);
}
static DEVICE_ATTR_WO(ipc_event_h2c_dis);

static ssize_t ipc_event_c2h_en_store(struct device           *dev,
				      struct device_attribute *attr,
				      const char              *buf,
				      size_t                   count)
{
	return ipc_event_set(dev, buf, count, false, true);
}

static ssize_t ipc_event_c2h_en_show(struct device           *dev,
				     struct device_attribute *attr,
				     char                    *buf)
{
	return ipc_event_get(dev, buf, false);
}
static DEVICE_ATTR_RW(ipc_event_c2h_en);

static ssize_t ipc_event_c2h_dis_store(struct device           *dev,
				       struct device_attribute *attr,
				       const char              *buf,
				       size_t                   count)
{
	return ipc_event_set(dev, buf, count, false, false);
}
static DEVICE_ATTR_WO(ipc_event_c2h_dis);

static ssize_t uncorr_counters_show(struct device           *dev,
				    struct device_attribute *attr,
				    char                    *buf)
{
	struct nnp_device *nnpdev;
	ssize_t ret = 0;

	nnpdev = (struct nnp_device *)dev_get_drvdata(dev);
	if (!nnpdev)
		return -EINVAL;

	ret += snprintf(&buf[ret], PAGE_SIZE - ret, "os_crashed: %llu\n",
			nnpdev->counters.uncorr.os_crashed);
	ret += snprintf(&buf[ret], PAGE_SIZE - ret, "ecc_nonfatal: %llu\n",
			nnpdev->counters.uncorr.ecc_nonfatal);
	ret += snprintf(&buf[ret], PAGE_SIZE - ret, "ecc_fatal: %llu\n",
			nnpdev->counters.uncorr.ecc_fatal);
	ret += snprintf(&buf[ret], PAGE_SIZE - ret, "dram_ecc_nonfatal: %llu\n",
			nnpdev->counters.uncorr.dram_ecc_nonfatal);
	ret += snprintf(&buf[ret], PAGE_SIZE - ret, "dram_ecc_fatal: %llu\n",
			nnpdev->counters.uncorr.dram_ecc_fatal);
	ret += snprintf(&buf[ret], PAGE_SIZE - ret, "mce_nonfatal: %llu\n",
			nnpdev->counters.uncorr.mce_nonfatal);
	ret += snprintf(&buf[ret], PAGE_SIZE - ret, "mce_fatal: %llu\n",
			nnpdev->counters.uncorr.mce_fatal);

	return ret;
}
static DEVICE_ATTR_RO(uncorr_counters);

static ssize_t corr_counters_show(struct device           *dev,
				  struct device_attribute *attr,
				  char                    *buf)
{
	struct nnp_device *nnpdev;
	ssize_t ret = 0;

	nnpdev = (struct nnp_device *)dev_get_drvdata(dev);
	if (!nnpdev)
		return -EINVAL;

	ret += snprintf(&buf[ret], PAGE_SIZE - ret, "ecc: %llu\n",
			nnpdev->counters.corr.ecc);
	ret += snprintf(&buf[ret], PAGE_SIZE - ret, "dram_ecc: %llu\n",
			nnpdev->counters.corr.dram_ecc);

	return ret;
}
static DEVICE_ATTR_RO(corr_counters);

static struct attribute *nnp_dev_attrs[] = {
	&dev_attr_enable.attr,
	&dev_attr_boot_image.attr,
	&dev_attr_reset.attr,
	&dev_attr_clock_stamp.attr,
	&dev_attr_total_unprotected_mem.attr,
	&dev_attr_total_protected_mem.attr,
	&dev_attr_protocol_version.attr,
	&dev_attr_channels.attr,
	&dev_attr_cecc_threshold.attr,
	&dev_attr_ucecc_threshold.attr,
	&dev_attr_pcie_inject.attr,
	&dev_attr_crashlog_size.attr,
	&dev_attr_post_code.attr,
	&dev_attr_bios_flash_progress.attr,
	&dev_attr_ice_units.attr,
	&dev_attr_bios_version.attr,
	&dev_attr_image_version.attr,
	&dev_attr_board_name.attr,
	&dev_attr_board_part_num.attr,
	&dev_attr_board_serial_num.attr,
	&dev_attr_active_contexts_num.attr,
	&dev_attr_fpga_revision.attr,
	&dev_attr_card_stepping.attr,
	&dev_attr_boot_state.attr,
	&dev_attr_boot_fail_reason.attr,
	&dev_attr_card_state.attr,
	&dev_attr_ipc_counters.attr,
	&dev_attr_ipc_event_h2c_en.attr,
	&dev_attr_ipc_event_h2c_dis.attr,
	&dev_attr_ipc_event_c2h_en.attr,
	&dev_attr_ipc_event_c2h_dis.attr,
	&dev_attr_uncorr_counters.attr,
	&dev_attr_corr_counters.attr,
	NULL
};

static struct attribute_group nnp_dev_attrs_grp = {
		.attrs = nnp_dev_attrs
};

static ssize_t crashlog_read(struct file *filp,
			     struct kobject *kobj,
			     struct bin_attribute *attr,
			     char *buf,
			     loff_t offset,
			     size_t count)
{
	struct device *dev = kobj_to_dev(kobj);
	struct nnp_device *nnpdev;
	void *vaddr;
	u32 dump_size;
	ssize_t ret;

	nnpdev = (struct nnp_device *)dev_get_drvdata(dev);
	if (!nnpdev)
		return -EINVAL;

	spin_lock(&nnpdev->lock);

	if (nnpdev->host_crash_dump.dump_size) {
		dump_size = nnpdev->host_crash_dump.dump_size;
		vaddr = nnpdev->host_crash_dump.vaddr;
	} else if (nnpdev->inbound_mem &&
		   nnpdev->inbound_mem->magic == NNP_INBOUND_MEM_MAGIC &&
		   nnpdev->inbound_mem->crash_dump_size) {
		dump_size = nnpdev->inbound_mem->crash_dump_size;
		vaddr = nnpdev->inbound_mem->crash_dump;
	} else {
		vaddr = "crashlog empty\n";
		dump_size = strlen(vaddr);
	}
	spin_unlock(&nnpdev->lock);

	if (dump_size > 0) {
		ret = memory_read_from_buffer(buf,
					      count,
					      &offset,
					      vaddr,
					      dump_size);
	} else {
		ret = 0;
	}

	return ret;
}

static const struct bin_attribute crashlog_attr = {
	.attr = {
		.name = "crashlog",
		.mode = 0400
	},
	.size = NNP_CRASH_DUMP_SIZE,
	.read = crashlog_read,
	.write = NULL,
	.mmap = NULL,
	.private = (void *)0
};

int nnpdrv_device_sysfs_init(struct nnp_device *nnpdev)
{
	int ret;

	if (!nnpdev || !nnpdev->dev)
		return -EINVAL;

	ret = sysfs_create_group(&nnpdev->dev->kobj, &nnp_dev_attrs_grp);
	if (ret)
		return ret;

	/* set channels and crashlog attributes be accessible by root only */
	ret = sysfs_chmod_file(&nnpdev->dev->kobj,
			       &dev_attr_channels.attr, 0400);
	ret |= sysfs_chmod_file(&nnpdev->dev->kobj,
				&dev_attr_crashlog_size.attr, 0400);

	/* set ipc event permissions to 0666 */
	ret |= sysfs_chmod_file(&nnpdev->dev->kobj,
				&dev_attr_ipc_event_h2c_en.attr, 0666);
	ret |= sysfs_chmod_file(&nnpdev->dev->kobj,
				&dev_attr_ipc_event_h2c_dis.attr, 0666);
	ret |= sysfs_chmod_file(&nnpdev->dev->kobj,
				&dev_attr_ipc_event_c2h_en.attr, 0666);
	ret |= sysfs_chmod_file(&nnpdev->dev->kobj,
				&dev_attr_ipc_event_c2h_dis.attr, 0666);
	ret |= sysfs_chmod_file(&nnpdev->dev->kobj,
				&dev_attr_clock_stamp.attr, 0666);

	if (ret)
		return ret;

	ret = device_create_bin_file(nnpdev->dev, &crashlog_attr);
	if (ret)
		goto fail_bin;

	ret = sysfs_create_link(&nnpdev->dev->kobj,
				&nnpdev->hw_device_info->hw_device->kobj,
				"device");
	if (ret)
		goto fail_link;

	return 0;

fail_link:
	device_remove_bin_file(nnpdev->dev, &crashlog_attr);
fail_bin:
	sysfs_remove_group(&nnpdev->dev->kobj, &nnp_dev_attrs_grp);
	return ret;
}

void nnpdrv_device_sysfs_fini(struct nnp_device *nnpdev)
{
	if (!nnpdev || !nnpdev->dev)
		return;

	device_remove_bin_file(nnpdev->dev, &crashlog_attr);
	sysfs_remove_link(&nnpdev->dev->kobj, "device");
	sysfs_remove_group(&nnpdev->dev->kobj, &nnp_dev_attrs_grp);
}
