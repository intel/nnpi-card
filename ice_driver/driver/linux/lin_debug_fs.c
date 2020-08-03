/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/



#include <linux/types.h>
#include <linux/debugfs.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/stat.h>
#include "os_interface.h"
#include "cve_debug.h"
#include "cve_device_group.h"

/* GLOBAL VARIABLES */
static struct dentry *dirret;
/* This variable contains the debug-fs value of debug_wd_en */
u32 enable_wdt_debugfs;

struct cve_debug_st {
	const	char *str;	/* debug fs file name*/
	u32 val;		/* debug configuration value*/
	umode_t mode;		/* debug fs permission */
};

static struct cve_debug_st cve_debug[] = {
		{"debug_wd_en", 1, 0644},
		{"dtf_src_en", 0, 0644},
		{"dtf_dst_en", 0, 0644},
		{"debug_recovery_en", 1, 0644},
};

/* PUBLIC FUNCTIONS */
void cve_debug_init(void)
{

	u32 i;

	/*debugfs section*/

	/* create a directory by the name cve in /sys/kernel/debugfs */
	dirret = debugfs_create_dir("cve", NULL);
	if (!dirret) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"error creating debug CVE directory\n");
		goto out;
	}

	for (i = 0 ; i < DEBUG_CONF_NUM ; i++) {
		/* create a file which handles on/off of debug config  */
		debugfs_create_u32(cve_debug[i].str,
				cve_debug[i].mode, dirret, &(cve_debug[i].val));

		cve_os_log(CVE_LOGLEVEL_DEBUG,
				"cve debug configuration -%s- = %d\n",
				cve_debug[i].str, cve_debug[i].val);
	}
out:
	return;
}

u32 cve_debug_get(enum cve_debug_config d_config)
{
	cve_os_log(CVE_LOGLEVEL_DEBUG,
			"debug configuration - %s - %d\n",
			cve_debug[d_config].str, cve_debug[d_config].val);
	return cve_debug[d_config].val;
}

void cve_debug_set(enum cve_debug_config d_config, u32 val)
{
	cve_debug[d_config].val = val;
}

void cve_debug_destroy(void)
{
	/*
	 * removing the directory recursively which
	 * in turn cleans all the file
	 */
	debugfs_remove_recursive(dirret);
}


