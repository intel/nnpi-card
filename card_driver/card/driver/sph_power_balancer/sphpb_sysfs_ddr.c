/********************************************
 * Copyright (C) 2019-2021 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/mutex.h>
#include "sph_log.h"
#include "sphpb_bios_mailbox.h"

/* DDR SYSFS */


static ssize_t store_ddr_entry(struct kobject *kobj,
				struct kobj_attribute *attr,
				const char *buf, size_t count);

static struct kobj_attribute ddr_frequency_attr =
__ATTR(freq_policy, 0664, NULL, store_ddr_entry);

static struct attribute *ddr_frequency_attrs[] = {
	&ddr_frequency_attr.attr,
	NULL,	/* need to NULL terminate the list of attributes */
};

static struct attribute_group ddr_attr_group = {
		.name = "ddr",
		.attrs = ddr_frequency_attrs,
};


/* Function to store ddr policy frequency */
static ssize_t store_ddr_entry(struct kobject *kobj,
				struct kobj_attribute *attr,
				const char *buf, size_t count)
{
	uint8_t input_value;
	int ret;

	ret = kstrtou8(buf, 0, &input_value);
	if (unlikely(ret < 0))
		return ret;

	switch (input_value) {
	case SAGV_POLICY_DYNAMIC:
	case SAGV_POLICY_FIXED_LOW:
	case SAGV_POLICY_FIXED_MED:
	case SAGV_POLICY_FIXED_HIGH:
		mutex_lock(&g_the_sphpb->mutex_lock);
		ret = set_ddr_freq(g_the_sphpb, input_value);
		mutex_unlock(&g_the_sphpb->mutex_lock);
		if (unlikely(ret < 0))
			return ret;
		break;

	default:
		return -EPROTO;
	}

	return count;
}

int sphpb_ddr_freq_sysfs_init(struct sphpb_pb *sphpb)
{
	int ret;

	/* Create the ddr files config kobject */
	ret = sysfs_create_group(sphpb->kobj, &ddr_attr_group);
	if (unlikely(ret < 0)) {
		sph_log_err(POWER_BALANCER_LOG, "ddr sysfs group creation failed err(%d)\n", ret);
		return ret;
	}

	return 0;
}

void sphpb_ddr_freq_sysfs_deinit(struct sphpb_pb *sphpb)
{
	/* Remove ddr files config kobject */
	sysfs_remove_group(sphpb->kobj, &ddr_attr_group);
}
