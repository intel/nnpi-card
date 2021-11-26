/********************************************
 * Copyright (C) 2019-2021 Intel Corporation
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
#include  "cve_device.h"
#include "os_interface.h"
#include "sph_ice_error_status.h"
#include "cve_device_group.h"
#include "cve_linux_internal.h"
#include "project_device_interface.h"

/* show and store function for ice_error_status */

static u32 fld_intst[MAX_CVE_DEVICES_NR];
static u64 icedc_error;
static struct kobject *fld_kobject;

static ssize_t show_ice_error(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	u32 dev_index;
	int ret = 0;

	ret = ice_sscanf_s_u32(attr->attr.name, "ice%u", &dev_index);
	if (ret < 1) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "failed getting ice id %s\n",
			kobj->name);
		return ((ret == 0) ? -EFAULT : ret);
	}
	if (dev_index >= NUM_ICE_UNIT) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "wrong ice id %d\n", dev_index);
		return -EFAULT;
	}

	cve_os_log(CVE_LOGLEVEL_DEBUG, "ICE number %d\n", dev_index);
	cve_os_log(CVE_LOGLEVEL_DEBUG, "attr: %s\n", attr->attr.name);

	ret = ice_snprintf_s_u(buf, PAGE_SIZE, "0x%x\n", fld_intst[dev_index]);
	if (ret < 0)
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"Safelib failed snprintf %d\n", ret);

	return ret;
}

static ssize_t store_ice_error(struct kobject *kobj,
		struct kobj_attribute *attr,
		const char *buf, size_t count)
{
	int ret;
	u32 val, dev_index;

	ret = kstrtouint(buf, 16, &val);
	if (ret < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"kstrtouint failed. %d\n", ret);
		return ret;
	}

	ret = ice_sscanf_s_u32(attr->attr.name, "ice%u", &dev_index);
	if (ret < 1) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "failed getting ice id %s\n",
			kobj->name);
		return ((ret == 0) ? -EFAULT : ret);
	}
	if (dev_index >= NUM_ICE_UNIT) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "wrong ice id %d\n", dev_index);
		return -EFAULT;
	}

	cve_os_log(CVE_LOGLEVEL_DEBUG, "user given value  0x%x\n", val);
	cve_os_log(CVE_LOGLEVEL_DEBUG, "ICE number %d\n", dev_index);
	cve_os_log(CVE_LOGLEVEL_DEBUG, "attr: %s\n", attr->attr.name);

	fld_intst[dev_index] = val;

	return count;
}

static ssize_t show_all_ice_error(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	int i;
	int ret = 0;

	for (i = 0; i < 12; i++)
		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Error status in ICE%d is 0x%x\n", i, fld_intst[i]);

	ret = ice_snprintf_s_u(buf, PAGE_SIZE, "0x%x\n", fld_intst[1]);
	if (ret < 0)
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"Safelib failed snprintf %d\n", ret);

	return ret;
}

static ssize_t store_all_ice_error(struct kobject *kobj,
		struct kobj_attribute *attr,
		const char *buf, size_t count)
{
	int ret, i;
	u32 val;

	ret = kstrtouint(buf, 16, &val);
	if (ret < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"kstrtouint failed. %d\n", ret);
		return ret;
	}
	for (i = 0; i < 12; i++)
		fld_intst[i] = val;

	return count;
}

static ssize_t show_icedc_error(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	int ret = 0;

	ret = ice_snprintf_s_u(buf, PAGE_SIZE, "0x%llx\n", icedc_error);
	if (ret < 0)
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"Safelib failed snprintf %d\n", ret);

	return ret;
}

static ssize_t store_icedc_error(struct kobject *kobj,
		struct kobj_attribute *attr,
		const char *buf, size_t count)
{
	int ret;
	u64 val;

	ret = kstrtoull(buf, 16, &val);
	if (ret < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"kstrtoull failed. %d\n", ret);
		return ret;
	}
	icedc_error = val;
	return count;
}


/* attribute registration for ice_error_status*/

static struct kobj_attribute ice0_attr =
__ATTR(ice0, 0664, show_ice_error, store_ice_error);

static struct kobj_attribute ice1_attr =
__ATTR(ice1, 0664, show_ice_error, store_ice_error);

static struct kobj_attribute ice2_attr =
__ATTR(ice2, 0664, show_ice_error, store_ice_error);

static struct kobj_attribute ice3_attr =
__ATTR(ice3, 0664, show_ice_error, store_ice_error);

static struct kobj_attribute ice4_attr =
__ATTR(ice4, 0664, show_ice_error, store_ice_error);

static struct kobj_attribute ice5_attr =
__ATTR(ice5, 0664, show_ice_error, store_ice_error);

static struct kobj_attribute ice6_attr =
__ATTR(ice6, 0664, show_ice_error, store_ice_error);

static struct kobj_attribute ice7_attr =
__ATTR(ice7, 0664, show_ice_error, store_ice_error);

static struct kobj_attribute ice8_attr =
__ATTR(ice8, 0664, show_ice_error, store_ice_error);

static struct kobj_attribute ice9_attr =
__ATTR(ice9, 0664, show_ice_error, store_ice_error);

static struct kobj_attribute ice10_attr =
__ATTR(ice10, 0664, show_ice_error, store_ice_error);

static struct kobj_attribute ice11_attr =
__ATTR(ice11, 0664, show_ice_error, store_ice_error);

static struct kobj_attribute all_ice_attr =
__ATTR(all, 0664, show_all_ice_error, store_all_ice_error);

static struct kobj_attribute icedc_attr =
__ATTR(icedc, 0664, show_icedc_error, store_icedc_error);

static struct attribute *ice_error_status[] = {
	&ice0_attr.attr,
	&ice1_attr.attr,
	&ice2_attr.attr,
	&ice3_attr.attr,
	&ice4_attr.attr,
	&ice5_attr.attr,
	&ice6_attr.attr,
	&ice7_attr.attr,
	&ice8_attr.attr,
	&ice9_attr.attr,
	&ice10_attr.attr,
	&ice11_attr.attr,
	&all_ice_attr.attr,
	&icedc_attr.attr,
	NULL,	/* need to NULL terminate the list of attributes */
};

static struct attribute_group ice_error_status_group = {
		.attrs = ice_error_status,
};

int ice_flow_debug_init(void)
{
	int ret = 0;

	FUNC_ENTER();

	if (!icedrv_kobj) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"icedrv kobj doesn't exist\n");
		ret = -ENOMEM;
		goto out;
	}

	fld_kobject = kobject_create_and_add("intel_nnpi_flow_debug",
			icedrv_kobj);
	if (!fld_kobject) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"Cannot create sysfs dir for Flow Debug\n");
		ret = -ENOMEM;
		goto out;
	}

	ret = sysfs_create_group(fld_kobject, &ice_error_status_group);
	if (ret) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"Cannot create sysfs files for Flow Debug\n");
		goto fld_kobject_free;
	}
	goto out;

fld_kobject_free:
	kobject_put(fld_kobject);
	fld_kobject = NULL;

out:
	FUNC_LEAVE();
	return ret;
}

void ice_flow_debug_term(void)
{
	if (!fld_kobject)
		return;

	kobject_put(fld_kobject);
	fld_kobject = NULL;
	cve_os_log(CVE_LOGLEVEL_DEBUG,
			"sw debug kobj deleted\n");
}

u32 ice_os_get_user_intst(int dev_id)
{
	if ((dev_id >= 0) && (dev_id < MAX_CVE_DEVICES_NR))
		return fld_intst[dev_id];
	return 0;
}

u64 ice_os_get_user_idc_intst(void)
{
	return icedc_error;
}
