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
#include <linux/smp.h>
#include "sph_log.h"
#include "sphpb_icedriver.h"
#include "sphpb_punit.h"


/* sysfs related functions, structures */
static ssize_t show_icebo_entry(struct kobject *kobj,
				struct kobj_attribute *attr,
				char *buf);


static struct kobj_attribute icebo_freq_attr =
	__ATTR(frequency, 0664, show_icebo_entry, NULL);

static struct attribute *icebo_attrs[] = {
	&icebo_freq_attr.attr,
	NULL,	/* need to NULL terminate the list of attributes */
};

static struct attribute_group icebo_attr_group = {
		.attrs = icebo_attrs,
};

static ssize_t show_icebo_entry(struct kobject *kobj,
				struct kobj_attribute *attr,
				char *buf)
{
	int ret = 0;
	uint32_t freq;
	int icebo = -1;
	union icedrv_pcu_mailbox_icebo_frequency_read mbx_value;

	ret = kstrtouint(kobj->name, 10, &icebo);
	if (ret < 0)
		return ret;

	icebo += ICEBO0_CORE_INDEX;


	ret = sphpb_get_icebo_frequency(g_the_sphpb, icebo, &mbx_value.value);
	if (ret) {
		sph_log_err(POWER_BALANCER_LOG, "unable to read icebo frequency for icebo (%d) - Err(%d)\n", icebo, ret);
		return ret;
	}

	/* multiply value in 25Mhz steps */
	freq = (mbx_value.BitField.frequency * ICE_FREQ_DIVIDER_FACTOR);

	ret = sprintf((buf), "%d\n", freq);

	return ret;
}


int sphpb_icebo_sysfs_init(struct sphpb_pb *sphpb)
{
	int i, j, ret;

	//Create kobject for icebos
	sphpb->icebo_kobj_root = kobject_create_and_add("icebo", sphpb->kobj);
	if (unlikely(sphpb->icebo_kobj_root == NULL)) {
		sph_log_err(POWER_BALANCER_LOG, "sphpb icebo_kboj_root creation failed");
		return -ENOMEM;
	}


	sphpb->icebo_kobj = kcalloc(NUM_ICEBOS, sizeof(struct kobject *), GFP_KERNEL);
	if (unlikely(sphpb->icebo_kobj == NULL))
		return -1;

	for (i = 0; i < NUM_ICEBOS; i++) {
		char name[128];

		sprintf(name, "%d", i);
		sphpb->icebo_kobj[i] = kobject_create_and_add(name, sphpb->icebo_kobj_root);
		if (unlikely(sphpb->icebo_kobj[i] == NULL))
			goto release_kobj;
		ret = sysfs_create_group(sphpb->icebo_kobj[i], &icebo_attr_group);
		if (ret) {
			sph_log_err(POWER_BALANCER_LOG, "icebo sysfs group creation failed err(%d)\n", ret);
			goto release_kobj;
		}
	}

	return 0;
release_kobj:
	for (j = 0; j < i; j++) {
		sysfs_remove_group(sphpb->icebo_kobj[j], &icebo_attr_group);
		kobject_put(sphpb->icebo_kobj[j]);
	}
	kfree(sphpb->icebo_kobj);

	return -1;
}

void sphpb_icebo_sysfs_deinit(struct sphpb_pb *sphpb)
{
	int i;

	for (i = 0; i < NUM_ICEBOS; i++) {
		sysfs_remove_group(sphpb->icebo_kobj[i], &icebo_attr_group);
		kobject_put(sphpb->icebo_kobj[i]);
	}
	kfree(sphpb->icebo_kobj);
	kobject_put(sphpb->icebo_kobj_root);

}
