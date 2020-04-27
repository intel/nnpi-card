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

#include "sph_log.h"
#include  "cve_device.h"
#include "os_interface.h"
#include "cve_device_group.h"
#include "cve_linux_internal.h"
#include "sph_mailbox.h"
#include "sph_iccp.h"
#include "project_device_interface.h"

#define MAX_CDYN_INPUT_VALUE 0xFFFF

#define NUM_ICCP_LEVELS 16
struct  ice_iccp_init_table {
	/* ICEBO CR value */
	uint16_t icebo_cr;
	/* PCode ICCP value in U6.10 format*/
	uint16_t pcode_iccp;
};

const struct ice_iccp_init_table iccp_tbl[NUM_ICCP_LEVELS] = {
				{0x014F, 0x00A7},
				{0x01A9, 0x00D4},
				{0x0202, 0x0101},
				{0x025C, 0x012E},
				{0x02B5, 0x015A},
				{0x030F, 0x0187},
				{0x0368, 0x01B4},
				{0x03C2, 0x01E1},
				{0x041B, 0x020D},
				{0x0475, 0x023A},
				{0x04CF, 0x0267},
				{0x0528, 0x0294},
				{0x0582, 0x02C1},
				{0x05DB, 0x02ED},
				{0x0635, 0x031A},
				{0x068E, 0x0347}
				};

static struct kobject *iccp_kobj;

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
static struct kobj_attribute max_cdyn_level_15_attr =
__ATTR(max_cdyn_level_15, 0664, show_iccp_entry, store_iccp_entry);

static struct attribute *cdyn_level_attrs[] = {
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
	&max_cdyn_level_15_attr.attr,
	NULL,	/* need to NULL terminate the list of attributes */
};

static struct attribute_group icedrv_cdyn_level_group = {
		.attrs = cdyn_level_attrs,
};

static int iccp_cdyn_sysfs_init(void)
{
	int ret;

	/* Create the iccp table files kobject */
	ret = sysfs_create_group(iccp_kobj, &icedrv_cdyn_level_group);
	if (ret)
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"iccp cdyn sysfs group creation failed\n");

	return ret;
}


static void iccp_cdyn_sysfs_term(void)
{
	/* Remove iccp table files config kobject */
	sysfs_remove_group(iccp_kobj, &icedrv_cdyn_level_group);
}

int iccp_sysfs_init(void)
{
	int ret = 0;
	struct kobject *icedrv = get_icedrv_kobj();

	FUNC_ENTER();

	if (!icedrv) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
					"icedrv kobj doesn't exist\n");
		ret = -ENOMEM;
		goto out;
	}

	if (iccp_kobj)
		goto out;

	iccp_kobj = kobject_create_and_add("iccp", icedrv_kobj);
	if (!iccp_kobj) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"iccp kobj creation failed\n");
		ret = -ENOMEM;
		goto out;
	}

	ret = iccp_cdyn_sysfs_init();
	if (ret) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"iccp_cdyn_sysfs_init failed\n");
		ret = -ENOMEM;
		goto iccp_kobj_free;
	} else {
		goto out;
	}
iccp_kobj_free:
	kobject_put(iccp_kobj);
	iccp_kobj = NULL;
out:
	FUNC_LEAVE();
	return ret;
}

void iccp_sysfs_term(void)
{
	FUNC_ENTER();

	if (iccp_kobj) {
		iccp_cdyn_sysfs_term();
		kobject_put(iccp_kobj);
		iccp_kobj = NULL;
	}

	FUNC_LEAVE();
}

static ssize_t show_iccp_entry(struct kobject *kobj,
			       struct kobj_attribute *attr,
			       char *buf)
{
	int ret = 0;
	int iccp_entry = -1;
	union icedrv_pcu_mailbox_iccp_value iccp;
	struct ice_sphmbox *sphmb = NULL;
	struct cve_device_group *dg = cve_dg_get();

	if (!dg) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"null dg pointer (%d) !!\n", -EINVAL);
		return -EINVAL;
	}

	sphmb = &dg->sphmb;

	ret = sscanf(attr->attr.name, "max_cdyn_level_%d", &iccp_entry);
	if (ret < 1) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"failed getting iccp cydn index %s\n",
					kobj->name);
		return -EFAULT;
	}

	ret = get_iccp_cdyn(sphmb, iccp_entry, &iccp.value);
	if (ret) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"unable to read iccp entry (%d) value - Err(%d)\n",
					iccp_entry, ret);
		return 0;
	}

	ret = sprintf((buf), "0x%x,0x%x\n",
		iccp.BitField.pcode_cdyn, iccp.BitField.icebo_cdyn);

	return ret;
}

static ssize_t store_iccp_entry(struct kobject *kobj,
				struct kobj_attribute *attr,
				const char *buf, size_t count)
{
	int ret = 0;
	int iccp_entry = -1;
	union icedrv_pcu_mailbox_iccp_value iccp;
	char *iccp_s, *tmp_iccp_s, *tmp_iccp_rs;
	char *cfg_0_s, *cfg_1_s;
	u32 cfg[2];
	struct ice_sphmbox *sphmb = NULL;
	struct cve_device_group *dg = cve_dg_get();

	if (!dg) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"null dg pointer (%d) !!\n", -EINVAL);
		return -EINVAL;
	}

	sphmb = &dg->sphmb;

	ret = sscanf(attr->attr.name, "max_cdyn_level_%d", &iccp_entry);
	if (ret < 1) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"failed getting max_cdyn_level index %s\n",
					attr->attr.name);
		return -EFAULT;
	}

	iccp_s = (char *)buf;
	iccp_s = strim(iccp_s);

	tmp_iccp_s = strchr(buf, ',');
	tmp_iccp_rs = strrchr(buf, ',');

	if (tmp_iccp_s == NULL || tmp_iccp_rs == NULL) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"Bad input for iccp cdyn level\n");
		return -EINVAL;
	}

	if (tmp_iccp_s != tmp_iccp_rs) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"Bad input for iccp cdyn level\n");
		return -EINVAL;
	}

	cfg_0_s = strsep((char **)&iccp_s, ",");

	cfg_0_s = strim(cfg_0_s);

	cfg_1_s = strsep((char **)&iccp_s, ",");

	cfg_1_s = strim(cfg_1_s);

	ret = kstrtouint(cfg_0_s, 16, &cfg[0]);

	if (ret < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"Bad input for iccp cdyn level\n");
		return -EINVAL;
	}

	ret = kstrtouint(cfg_1_s, 16, &cfg[1]);

	if (ret < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"Bad input for iccp cdyn level\n");
		return -EINVAL;
	}

	if (cfg[0] > MAX_CDYN_INPUT_VALUE || cfg[1] > MAX_CDYN_INPUT_VALUE) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"Bad input for iccp cdyn level\n");
		return -EINVAL;
	}

	iccp.BitField.pcode_cdyn = cfg[0];
	iccp.BitField.icebo_cdyn = cfg[1];

	ret = set_iccp_cdyn(sphmb, iccp_entry, iccp.value);

	if (ret) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"unable to write iccp entry (%d) value - Err(%d)\n",
					iccp_entry, ret);
		return ret;
	}

	return count;
}

int set_iccp_cdyn(struct ice_sphmbox *sphmb, uint32_t level,
						uint32_t value)
{
	union PCODE_MAILBOX_INTERFACE iface;

	iface.InterfaceData = 0;
	iface.BitField.Command = ICEDRV_PCU_MAILBOX_ICCP_WRITE_LEVEL;
	iface.BitField.Param1 = (uint8_t)level;

	return write_icedriver_mailbox(sphmb, iface,
				       value, 0x0,
				       NULL, NULL);
}

int get_iccp_cdyn(struct ice_sphmbox *sphmb, uint32_t level,
						uint32_t *value)
{
	union PCODE_MAILBOX_INTERFACE iface;

	iface.InterfaceData = 0;
	iface.BitField.Command = ICEDRV_PCU_MAILBOX_ICCP_READ_LEVEL;
	iface.BitField.Param1 = (uint8_t)level;

	return write_icedriver_mailbox(sphmb, iface,
				       0x0, 0x0,
				       value, NULL);
}

int ice_iccp_levels_init(struct cve_device_group *dg)
{
	int iccp_entry;
	int ret;
	union icedrv_pcu_mailbox_iccp_value iccp;


	/* Initialize iccp levels using mailbox*/
	for (iccp_entry = 0; iccp_entry < NUM_ICCP_LEVELS; iccp_entry++) {
		iccp.BitField.pcode_cdyn = iccp_tbl[iccp_entry].pcode_iccp;
		iccp.BitField.icebo_cdyn = iccp_tbl[iccp_entry].icebo_cr;
		/* call cdyn mailbox set function for each level*/
		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"set iccp level%d icebo_cr 0x%x, pcode iccpi 0x%x\n",
			iccp_entry, iccp_tbl[iccp_entry].icebo_cr,
			iccp_tbl[iccp_entry].pcode_iccp);
		ret = set_iccp_cdyn(&dg->sphmb, iccp_entry, iccp.value);
		if (ret) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
				"unable to write iccp entry (%d) value - Err(%d)\n",
					iccp_entry, ret);
			return ret;
		}
	}

	return 0;
}

void ice_iccp_levels_term(struct cve_device_group *dg)
{
	/* place holder */
}
