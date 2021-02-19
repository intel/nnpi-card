/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/
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
#include <asm/msr.h>
#include <linux/sched/clock.h>
#include "sph_log.h"
#include "sphpb_bios_mailbox.h"

/* Power Calibration SYSFS */

/* uncore clock ticks msr's */
#define MSR_UNC_PERF_GLOBAL_CTRL 0xe01
#define MSR_UNC_PERF_FIXED_CTRL 0x394

/* power throttling threasholds*/
#define RING_FREQ_SETP 100llu //MHz
#define RING_THRESHOLD (400llu + RING_FREQ_SETP / 2u) //MHz
#define IA_FREQ_SETP 100000llu //KHz
#define IA_THRESHOLD (400000llu + IA_FREQ_SETP / 2u) //KHz
#define ICEBO_FREQ_SETP 25u //MHz
#define ICEBO_THRESHOLD (200u + ICEBO_FREQ_SETP / 2u) //MHz

/* sysfs related functions, structures */
static ssize_t show_imon_calib_entry(struct kobject *kobj,
				struct kobj_attribute *attr,
				char *buf);

static ssize_t store_imon_calib_entry(struct kobject *kobj,
				struct kobj_attribute *attr,
				const char *buf, size_t count);

/* sysfs related functions, structures */
static ssize_t show_offset_calib_entry(struct kobject *kobj,
				struct kobj_attribute *attr,
				char *buf);

static ssize_t store_offset_calib_entry(struct kobject *kobj,
				struct kobj_attribute *attr,
				const char *buf, size_t count);

static struct kobj_attribute vccin_imon_config_attr =
__ATTR(vccin_imon, 0664, show_imon_calib_entry, store_imon_calib_entry);
static struct kobj_attribute sa_imon_config_attr =
__ATTR(sa_imon, 0664, show_imon_calib_entry, store_imon_calib_entry);
static struct kobj_attribute offset_config_attr =
__ATTR(offset, 0664, show_offset_calib_entry, store_offset_calib_entry);

static struct attribute *imon_config_attrs[] = {
	&vccin_imon_config_attr.attr,
	&sa_imon_config_attr.attr,
	&offset_config_attr.attr,
	NULL,	/* need to NULL terminate the list of attributes */
};

static struct attribute_group imon_config_attr_group = {
		.name = "power_calibration",
		.attrs = imon_config_attrs,
};

/* Function to show imon offset and slope */
static ssize_t show_imon_calib_entry(struct kobject *kobj,
			       struct kobj_attribute *attr,
			       char *buf)
{
	uint16_t slope_value;
	uint16_t offset_value;
	int ret = -ENOSYS; /* SPH_IGNORE_STYLE_CHECK */

	if (strcmp(attr->attr.name, "sa_imon") == 0)
		ret = get_imon_sa_calib_config(&offset_value, &slope_value);
	else if (strcmp(attr->attr.name, "vccin_imon") == 0)
		ret = get_imon_vccin_calib_config(&offset_value, &slope_value);
	if (unlikely(ret < 0))
		return ret;

	ret = sprintf(buf, "%hu %hu\n", offset_value, slope_value);

	return ret;
}

/* Function to store imon offset and slope */
static ssize_t store_imon_calib_entry(struct kobject *kobj,
				struct kobj_attribute *attr,
				const char *buf, size_t count)
{
	uint16_t offset_value, old_slope, slope_value;
	int ret;

	ret = kstrtou16(buf, 0, &slope_value);
	if (unlikely(ret < 0))
		return ret;

	if (strcmp(attr->attr.name, "vccin_imon") == 0) {
		// Despite read-write here is not atomic, it is OK,
		// since no one else is able to change imon_offset
		ret = get_imon_vccin_calib_config(&offset_value, &old_slope);
		if (unlikely(ret < 0))
			return ret;

		ret = set_imon_vccin_calib_config(offset_value, slope_value);
		if (unlikely(ret < 0))
			return ret;
	} else if (strcmp(attr->attr.name, "sa_imon") == 0) {
		// Despite read-write here is not atomic, it is OK,
		// since no one else is able to change imon_offset
		ret = get_imon_sa_calib_config(&offset_value, &old_slope);
		if (unlikely(ret < 0))
			return ret;

		ret = set_imon_sa_calib_config(offset_value, slope_value);
		if (unlikely(ret < 0))
			return ret;
	} else {
		return -ENOSYS; /* SPH_IGNORE_STYLE_CHECK */
	}

	return count;
}

/* Function to show offset */
static ssize_t show_offset_calib_entry(struct kobject *kobj,
			       struct kobj_attribute *attr,
			       char *buf)
{
	int16_t offset_value;
	int ret;

	ret = get_offset_calib_config(&offset_value);
	if (unlikely(ret < 0))
		return ret;

	ret = sprintf(buf, "%hd\n", offset_value);

	return ret;
}

/* Function to store imon offset and slope */
static ssize_t store_offset_calib_entry(struct kobject *kobj,
				struct kobj_attribute *attr,
				const char *buf, size_t count)
{
	int16_t offset_value;
	int ret;

	ret = kstrtos16(buf, 0, &offset_value);
	if (unlikely(ret < 0))
		return ret;

	ret = set_offset_calib_config(offset_value);
	if (unlikely(ret < 0))
		return ret;

	return count;
}

int sphpb_imon_conf_sysfs_init(struct sphpb_pb *sphpb)
{
	int ret;

	/* Create the imon files config kobject */
	ret = sysfs_create_group(sphpb->kobj, &imon_config_attr_group);
	if (unlikely(ret < 0)) {
		sph_log_err(POWER_BALANCER_LOG, "power calibration sysfs group creation failed err(%d)\n", ret);
		return ret;
	}

	return 0;
}

void sphpb_imon_conf_sysfs_deinit(struct sphpb_pb *sphpb)
{
	/* Remove imon files config kobject */
	sysfs_remove_group(sphpb->kobj, &imon_config_attr_group);
}
