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

struct ia_ratio_attr {
	struct kobj_attribute ia_attr;
	struct sphpb_pb *sphpb;
};

static bool ignore_ia_hints;

ssize_t ia_ratio_store(struct kobject *kobj,
			      struct kobj_attribute *kattr,
			      const char *buf,
			      size_t count)
{
	struct ia_ratio_attr *ia_attr = container_of(kattr,
					struct ia_ratio_attr,
					ia_attr);

	struct sphpb_pb *sphpb = ia_attr->sphpb;
	unsigned long val;

	if (ignore_ia_hints) {
		if (sphpb->debug_log)
			sph_log_info(POWER_BALANCER_LOG, "IA hints ignored");
		return count;
	}

	if (kstrtoul(buf, 0, &val) < 0)
		return -EINVAL;

	if (val > 255) {
		sph_log_info(POWER_BALANCER_LOG, "invalid value for IA ratio 0x%lx (values range [0-255])", val);
		return -EINVAL;
	}

	mutex_lock(&sphpb->mutex_lock);
	if (val == 0) {
		/* set to default */
		sphpb->ia_changed_by_user = 0;
		sphpb->current_cores_ratios.freqRatio.ia0 = sphpb->max_icebo_ratio / 2;
		sphpb->current_cores_ratios.freqRatio.ia1 = sphpb->max_icebo_ratio / 2;
	} else {
		if (!sphpb->ia_changed_by_user || (sphpb->ia_changed_by_user && val > sphpb->current_cores_ratios.freqRatio.ia0)) {
			sphpb->ia_changed_by_user = 1;
			sphpb->current_cores_ratios.freqRatio.ia0 = val;
			sphpb->current_cores_ratios.freqRatio.ia1 = val;
		}
	}
	mutex_unlock(&sphpb->mutex_lock);

	if (sphpb->debug_log)
		sph_log_info(POWER_BALANCER_LOG, "IA cores ratio updated: ia0= %u, ia1=%u",
						sphpb->current_cores_ratios.freqRatio.ia0, sphpb->current_cores_ratios.freqRatio.ia1);

	return count;
}

ssize_t ia_ratio_show(struct kobject *kobj,
		      struct kobj_attribute *kattr,
		      char *buf)
{
	struct ia_ratio_attr *ia_attr = container_of(kattr,
					struct ia_ratio_attr,
					ia_attr);

	struct sphpb_pb *sphpb = ia_attr->sphpb;
	ssize_t ret = 0;

	if (!strcmp(kattr->attr.name, "ia0_ratio"))
		ret = snprintf(buf, 64, "%llu\n", (uint64_t)sphpb->current_cores_ratios.freqRatio.ia0);
	else
		ret = snprintf(buf, 64, "%llu\n", (uint64_t)sphpb->current_cores_ratios.freqRatio.ia1);

	return ret;
}

ssize_t ignore_ia_store(struct kobject *kobj,
			      struct kobj_attribute *kattr,
			      const char *buf,
			      size_t count)
{
	bool val;

	if (strtobool(buf, &val) < 0)
		return -EINVAL;

	ignore_ia_hints = val ? true : false;

	return count;
}

ssize_t ignore_ia_show(struct kobject *kobj,
		      struct kobj_attribute *kattr,
		      char *buf)
{
	return snprintf(buf, 8, "%u\n", (uint8_t)ignore_ia_hints);
}

static struct ia_ratio_attr ia0_attr_data = {.ia_attr = __ATTR(ia0_ratio, 0664, ia_ratio_show, ia_ratio_store), .sphpb = NULL};
static struct ia_ratio_attr ia1_attr_data = {.ia_attr = __ATTR(ia1_ratio, 0664, ia_ratio_show, ia_ratio_store), .sphpb = NULL};
static struct ia_ratio_attr ignore_ia_attr_data = {.ia_attr = __ATTR(ignore_ia_hints, 0664, ignore_ia_show, ignore_ia_store), .sphpb = NULL};

static struct attribute *ia_ratio_attrs[] = {
	&ia0_attr_data.ia_attr.attr,
	&ia1_attr_data.ia_attr.attr,
	&ignore_ia_attr_data.ia_attr.attr,
	NULL,	/* need to NULL terminate the list of attributes */
};

static struct attribute_group ia_raio_attr_group = {
		.attrs = ia_ratio_attrs,
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
	//aperf_delta / mperf_delta = frequency in Mhz
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

	ia0_attr_data.sphpb = sphpb;
	ia1_attr_data.sphpb = sphpb;
	ignore_ia_attr_data.sphpb = sphpb;
	ignore_ia_hints = true;

	ret = sysfs_create_group(sphpb->ia_kobj_root, &ia_raio_attr_group);
	if (ret) {
		sph_log_err(POWER_BALANCER_LOG, "ia ratio sysfs group creation failed err(%d)\n", ret);
		goto release_kobj;
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

	sysfs_remove_group(sphpb->ia_kobj_root, &ia_raio_attr_group);
	kobject_put(sphpb->ia_kobj_root);
}
