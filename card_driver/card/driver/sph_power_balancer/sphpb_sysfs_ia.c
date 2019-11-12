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
#include "sphpb.h"

/* IA SYSFS */

//#define MSR_IA32_APERF 0xe8
//#define MSR_IA32_MPERF 0xe7

/* sysfs related functions, structures */
static ssize_t show_ia_entry(struct kobject *kobj,
				struct kobj_attribute *attr,
				char *buf);


static struct kobj_attribute ia_aperf_mperf_attr =
	__ATTR(ia_aperf_mperf, 0664, show_ia_entry, NULL);

static struct attribute *ia_cycls_attrs[] = {
	&ia_aperf_mperf_attr.attr,
	NULL,	/* need to NULL terminate the list of attributes */
};

static struct attribute_group ia_attr_group = {
		.attrs = ia_cycls_attrs,
};

struct cpu_perfstat curr_cpu_stat;

void aperfmperf_snapshot_khz(void *ptr)
{
	struct cpu_perfstat *cpu_stat = (struct cpu_perfstat *)ptr;
	unsigned long flags;

	local_irq_save(flags);
	rdmsrl(MSR_IA32_APERF, cpu_stat->aperf);
	rdmsrl(MSR_IA32_MPERF, cpu_stat->mperf);
	local_irq_restore(flags);

	cpu_stat->aperf *= cpu_khz;

	//Frequency calculation
	//aperf_delta / mperf_delta = frequency in Khz
}


static ssize_t show_ia_entry(struct kobject *kobj,
			       struct kobj_attribute *attr,
			       char *buf)
{
	int ret = 0;
	int cpu = 0;

	if (sscanf(kobj->name, "core_%d", &cpu) != 1)
		return -1;
	if (cpu >= num_possible_cpus())
		return -1;
	//check if cpu active else zero the struct values
	if (!cpu_online(cpu))
		memset(&curr_cpu_stat, 0, sizeof(struct cpu_perfstat));
	else
		smp_call_function_single(cpu, aperfmperf_snapshot_khz, &curr_cpu_stat, true);

	ret += sprintf((buf), "%llu,%llu\n", curr_cpu_stat.aperf, curr_cpu_stat.mperf);

	return ret;
}

int sphpb_ia_cycles_sysfs_init(struct sphpb_pb *sphpb)
{
	int i, j, ret;

	//Create kobject for ia
	sphpb->ia_kobj_root = kobject_create_and_add("cpus", sphpb->kobj);
	if (unlikely(sphpb->ia_kobj_root == NULL)) {
		sph_log_err(POWER_BALANCER_LOG, "sphpb ia_kboj_root creation failed");
		return -ENOMEM;
	}


	sphpb->ia_kobj = kcalloc(num_possible_cpus(), sizeof(struct kobject *), GFP_KERNEL);
	if (unlikely(sphpb->ia_kobj == NULL))
		return -1;

	for (i = 0; i < num_possible_cpus(); i++) {
		char name[128];

		sprintf(name, "core_%d", i);
		sphpb->ia_kobj[i] = kobject_create_and_add(name, sphpb->ia_kobj_root);
		if (unlikely(sphpb->ia_kobj[i] == NULL))
			goto release_kobj;
		ret = sysfs_create_group(sphpb->ia_kobj[i], &ia_attr_group);
		if (ret) {
			sph_log_err(POWER_BALANCER_LOG, "ia cycles sysfs group creation failed err(%d)\n", ret);
			goto release_kobj;
		}
	}

	return 0;
release_kobj:
	for (j = 0; j < i; j++) {
		sysfs_remove_group(sphpb->ia_kobj[j], &ia_attr_group);
		kobject_put(sphpb->ia_kobj[j]);
	}
	kfree(sphpb->ia_kobj);

	return -1;
}

void sphpb_ia_cycles_sysfs_deinit(struct sphpb_pb *sphpb)
{
	int i;

	for (i = 0; i < num_possible_cpus(); i++) {
		sysfs_remove_group(sphpb->ia_kobj[i], &ia_attr_group);
		kobject_put(sphpb->ia_kobj[i]);
	}
	kfree(sphpb->ia_kobj);

	kobject_put(sphpb->ia_kobj_root);
}
