/********************************************
 * Copyright (C) 2019-2021 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include "sph_log.h"
#include "sphpb.h"


/* sysfs related functions, structures */
static ssize_t store_power_overshoot_protection(struct kobject *kobj,
					  struct kobj_attribute *attr,
					  const char *buf, size_t count);

static struct kobj_attribute power_overshoot_protection_attr =
__ATTR(protection, 0664, NULL, store_power_overshoot_protection);

static struct attribute *power_overshoot_attrs[] = {
	&power_overshoot_protection_attr.attr,
	NULL,	/* need to NULL terminate the list of attributes */
};

static struct attribute_group power_overshoot_attr_group = {
		.name = "overshoot",
		.attrs = power_overshoot_attrs,
};

static ssize_t store_power_overshoot_protection(struct kobject *kobj,
					  struct kobj_attribute *attr,
					  const char *buf, size_t count)
{
	uint32_t avg_power_mW, power_limit1_mW;
	int ret;

	ret = sscanf(buf, "%u,%u", &avg_power_mW, &power_limit1_mW);
	if (unlikely(ret != 2)) {
		sph_log_err(POWER_BALANCER_LOG, "Throttling failure: Unable to read average power and PL1. Err(%d)\n", ret);
		return -EINVAL;
	}

	ret = do_throttle(g_the_sphpb, avg_power_mW, power_limit1_mW);
	if (ret) {
		sph_log_err(POWER_BALANCER_LOG, "Throttling failure: do_throttle returned error - Err(%d)\n", ret);
		return ret;
	}

	return count;
}

int sphpb_power_overshoot_sysfs_init(struct sphpb_pb *sphpb)
{
	int ret = 0;

	/* Create the ring files config kobject */
	ret = sysfs_create_group(sphpb->kobj, &power_overshoot_attr_group);
	if (ret) {
		sph_log_err(POWER_BALANCER_LOG, "power overshoot sysfs group creation failed err(%d)\n", ret);
		return ret;
	}

	return 0;
}

void sphpb_power_overshoot_sysfs_deinit(struct sphpb_pb *sphpb)
{
	/* Remove ring files config kobject */
	sysfs_remove_group(sphpb->kobj, &power_overshoot_attr_group);
}
