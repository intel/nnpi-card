/********************************************
 * Copyright (C) 2019 Intel Corporation
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
#include "sph_log.h"
#include "sphpb_icedriver.h"

/* sysfs related functions, structures */
static ssize_t show_iccp_entry(struct kobject *kobj,
				struct kobj_attribute *attr,
				char *buf);

static ssize_t store_iccp_entry(struct kobject *kobj,
				struct kobj_attribute *attr,
				const char *buf, size_t count);
static struct kobj_attribute max_cdyn_level_0_attr =
__ATTR(max_cdyn_level_0, 0664, show_iccp_entry, store_iccp_entry);
static struct kobj_attribute max_cdyn_level_1_attr =
__ATTR(max_cdyn_level_1, 0664, show_iccp_entry, store_iccp_entry);
static struct kobj_attribute max_cdyn_level_2_attr =
__ATTR(max_cdyn_level_2, 0664, show_iccp_entry, store_iccp_entry);
static struct kobj_attribute max_cdyn_level_3_attr =
__ATTR(max_cdyn_level_3, 0664, show_iccp_entry, store_iccp_entry);
static struct kobj_attribute max_cdyn_level_4_attr =
__ATTR(max_cdyn_level_4, 0664, show_iccp_entry, store_iccp_entry);
static struct kobj_attribute max_cdyn_level_5_attr =
__ATTR(max_cdyn_level_5, 0664, show_iccp_entry, store_iccp_entry);
static struct kobj_attribute max_cdyn_level_6_attr =
__ATTR(max_cdyn_level_6, 0664, show_iccp_entry, store_iccp_entry);
static struct kobj_attribute max_cdyn_level_7_attr =
__ATTR(max_cdyn_level_7, 0664, show_iccp_entry, store_iccp_entry);
static struct kobj_attribute max_cdyn_level_8_attr =
__ATTR(max_cdyn_level_8, 0664, show_iccp_entry, store_iccp_entry);
static struct kobj_attribute max_cdyn_level_9_attr =
__ATTR(max_cdyn_level_9, 0664, show_iccp_entry, store_iccp_entry);
static struct kobj_attribute max_cdyn_level_10_attr =
__ATTR(max_cdyn_level_10, 0664, show_iccp_entry, store_iccp_entry);
static struct kobj_attribute max_cdyn_level_11_attr =
__ATTR(max_cdyn_level_11, 0664, show_iccp_entry, store_iccp_entry);
static struct kobj_attribute max_cdyn_level_12_attr =
__ATTR(max_cdyn_level_12, 0664, show_iccp_entry, store_iccp_entry);
static struct kobj_attribute max_cdyn_level_13_attr =
__ATTR(max_cdyn_level_13, 0664, show_iccp_entry, store_iccp_entry);
static struct kobj_attribute max_cdyn_level_14_attr =
__ATTR(max_cdyn_level_14, 0664, show_iccp_entry, store_iccp_entry);

static struct attribute *max_cdyn_level_attrs[] = {
	&max_cdyn_level_0_attr.attr,
	&max_cdyn_level_1_attr.attr,
	&max_cdyn_level_2_attr.attr,
	&max_cdyn_level_3_attr.attr,
	&max_cdyn_level_4_attr.attr,
	&max_cdyn_level_5_attr.attr,
	&max_cdyn_level_6_attr.attr,
	&max_cdyn_level_7_attr.attr,
	&max_cdyn_level_8_attr.attr,
	&max_cdyn_level_9_attr.attr,
	&max_cdyn_level_10_attr.attr,
	&max_cdyn_level_11_attr.attr,
	&max_cdyn_level_12_attr.attr,
	&max_cdyn_level_13_attr.attr,
	&max_cdyn_level_14_attr.attr,
	NULL,	/* need to NULL terminate the list of attributes */
};

static struct attribute_group max_cdyn_level_group = {
		.name = "iccp",
		.attrs = max_cdyn_level_attrs,
};

static ssize_t show_iccp_entry(struct kobject *kobj,
			       struct kobj_attribute *attr,
			       char *buf)
{
	int ret = 0;
	int iccp_entry = -1;
	union icedrv_pcu_mailbox_iccp_value iccp;

	ret = sscanf(attr->attr.name, "max_cdyn_level_%d", &iccp_entry);
	if (ret < 1) {
		sph_log_err(POWER_BALANCER_LOG, "failed getting iccp index %s\n",
			    attr->attr.name);
		return 0;
	}

	ret = sphpb_get_iccp_cdyn(g_the_sphpb, iccp_entry, &iccp.value);
	if (ret) {
		sph_log_err(POWER_BALANCER_LOG, "unable to read iccp entry (%d) value - Err(%d)\n", iccp_entry, ret);
		return 0;
	}

	ret = sprintf((buf), "0x%x,0x%x\n", iccp.BitField.icebo_cdyn, iccp.BitField.pcode_cdyn);

	return ret;
}

static ssize_t store_iccp_entry(struct kobject *kobj,
				struct kobj_attribute *attr,
				const char *buf, size_t count)
{
	int ret = 0;
	union icedrv_pcu_mailbox_iccp_value iccp;
	int iccp_entry = -1;
	size_t len = count;
	const char *p = buf;
	char *end, *s;
	uint32_t val[2];
	int index = 0;


	if (!capable(CAP_SYS_RAWIO)) {
		ret = -EPERM;
		sph_log_err(POWER_BALANCER_LOG, "Unable to get input - err(%d)\n", ret);
		return 0;
	}

	/* scan the comma-separated list of allocation sizes */
	end = memchr(buf, '\n', len);
	if (end)
		len = end - buf;

	do {
		if (index > 2) {
			sph_log_err(POWER_BALANCER_LOG, "Bad string input for iccp level - err(%d)\n", -EINVAL);
			return 0;
		}
		end = memchr(p, ',', len);
		s = kstrndup(p, end ? end - p : len, GFP_KERNEL);
		if (!s) {
			sph_log_err(POWER_BALANCER_LOG, "Error parsing iccp input - err(%d)\n", -ENOMEM);
			return 0;
		}

		ret = kstrtouint(s, 16, &val[index]);
		kfree(s);

		if (ret < 0) {
			sph_log_err(POWER_BALANCER_LOG, "Bad string input for iccp level - err(%d)\n", -EINVAL);
			return ret;
		}

		index++;

		if (!end)
			break;

		/* consume the number and the following comma, hence +1 */
		len -= end - p + 1;
		p = end + 1;
	} while (len);


	ret = sscanf(attr->attr.name, "max_cdyn_level_%d", &iccp_entry);
	if (ret < 1) {
		sph_log_err(POWER_BALANCER_LOG, "failed getting iccp index %s\n",
			    attr->attr.name);
		return -EFAULT;
	}

	iccp.BitField.icebo_cdyn = val[0];
	iccp.BitField.pcode_cdyn = val[1];

	ret = sphpb_set_iccp_cdyn(g_the_sphpb, iccp_entry, iccp.value);
	if (ret) {
		sph_log_err(POWER_BALANCER_LOG, "unable to write iccp entry (%d) value - Err(%d)\n", iccp_entry, ret);
		return 0;
	}


	return count;
}

int sphpb_iccp_table_sysfs_init(struct sphpb_pb *sphpb)
{
	int ret;

	/* Create the iccp table files kobject */
	ret = sysfs_create_group(sphpb->kobj, &max_cdyn_level_group);
	if (ret)
		sph_log_err(POWER_BALANCER_LOG, "iccp sysfs group creation failed err(%d)\n", ret);

	return ret;
}


void sphpb_iccp_table_sysfs_deinit(struct sphpb_pb *sphpb)
{
	/* Remove iccp table files config kobject */
	sysfs_remove_group(sphpb->kobj, &max_cdyn_level_group);
}
