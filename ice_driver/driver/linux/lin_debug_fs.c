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
#include <linux/slab.h>
#include <linux/seq_file.h>
#include <linux/stat.h>
#include "os_interface.h"
#include "cve_debug.h"
#include "cve_device_group.h"
#include "cve_driver_internal.h"
#include "device_interface.h"
#include "device_interface_internal.h"
#include "ice_debug.h"

/* GLOBAL VARIABLES */
static struct dentry *dirret;
/* This variable contains the debug-fs value of debug_wd_en */
u32 enable_wdt_debugfs;

static int network_info_show(struct seq_file *m, void *v);
static int network_info_open(struct inode *inode, struct file *filp);
static int schedule_info_show(struct seq_file *m, void *v);
static int schedule_info_open(struct inode *inode, struct file *filp);
static int buffer_info_show(struct seq_file *m, void *v);
static int buffer_info_open(struct inode *inode, struct file *filp);
static int ice_counter_info_show(struct seq_file *m, void *v);
static int ice_counter_info_open(struct inode *inode, struct file *filp);
static int ice_firmware_info_show(struct seq_file *m, void *v);
static int ice_firmware_info_open(struct inode *inode, struct file *filp);

static const struct file_operations network_info_fops = {
	.open		= network_info_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static const struct file_operations schedule_info_fops = {
	.open		= schedule_info_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static const struct file_operations buffer_info_fops = {
	.open		= buffer_info_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static const struct file_operations ice_counter_info_fops = {
	.open		= ice_counter_info_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static const struct file_operations ice_firmware_info_fops = {
	.open		= ice_firmware_info_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

struct cve_debug_st {
	const	char *str;	/* debug fs file name*/
	u32 val;		/* debug configuration value*/
	umode_t mode;		/* debug fs permission */
};

static struct cve_debug_st cve_debug[] = {
		{"debug_wd_en", 1, 0644},
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

	debugfs_create_file("network_info",
			    0444,
			    dirret,
			    NULL,
			    &network_info_fops);

	debugfs_create_file("schedule_info",
			    0444,
			    dirret,
			    NULL,
			    &schedule_info_fops);

	debugfs_create_file("buffer_info",
			    0444,
			    dirret,
			    NULL,
			    &buffer_info_fops);

	debugfs_create_file("ice_counter_info",
			    0444,
			    dirret,
			    NULL,
			    &ice_counter_info_fops);

	debugfs_create_file("ice_firmware_info",
			    0444,
			    dirret,
			    NULL,
			    &ice_firmware_info_fops);
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

static int network_info_open(struct inode *inode, struct file *filp)
{
	return single_open(filp, network_info_show, inode->i_private);
}

static int network_info_show(struct seq_file *m, void *v)
{
	struct cve_device_group *dg;
	struct ds_context *ctx;
	struct ice_pnetwork *pntw;
	struct ice_network *ntw;
	struct cve_workqueue *wq;
	struct ice_infer *inf;
	u64 alloc_ntw_count = 0, alloc_pntw_count = 0;
	u64 alloc_inf_count = 0, sch_ntw_count = 0;
	int retval = CVE_DEFAULT_ERROR_CODE;

	retval = cve_os_lock(&g_cve_driver_biglock, CVE_INTERRUPTIBLE);
	if (retval != 0)
		return -ERESTARTSYS;

	dg = cve_dg_get();
	if (dg == NULL)
		goto out;

	ctx = dg->list_contexts;
	if (ctx == NULL)
		goto out;

	do {
		wq = ctx->wq_list;
		if (wq == NULL)
			goto out;

		pntw = wq->pntw_list;

		if (!pntw) {
			ctx = cve_dle_next(ctx, dg_list);
			continue;
		}

		do {
			alloc_pntw_count++;
			ntw = pntw->ntw_list;
			if (!ntw) {
				pntw = cve_dle_next(pntw, list);
				continue;
			}

			do {
				alloc_ntw_count++;
				if (!ntw->inf_list) {
					ntw = cve_dle_next(ntw, list);
					continue;
				}

				inf = ntw->inf_list;
				do {
					alloc_inf_count++;
					inf = cve_dle_next(inf,
							ntw_list);
				} while (inf != ntw->inf_list);

				ntw = cve_dle_next(ntw, list);
			} while (ntw != pntw->ntw_list);

			pntw = cve_dle_next(pntw, list);
		} while (pntw != wq->pntw_list);

		ctx = cve_dle_next(ctx, dg_list);
	} while (ctx != dg->list_contexts);

	pntw = dg->pntw_with_resources;

	if (pntw) {
		do {
			ntw = pntw->ntw_list;
			seq_printf(m, "PNTW ID: 0x%llx\tPNTW SW ID: 0x%llx\n",
				pntw->pntw_id, pntw->swc_node.sw_id);
			if (ntw) {
				do {
					sch_ntw_count++;
					if (ntw->jg_list) {
						seq_printf(m, "Ntw ID: 0x%llx\t SW ID: 0x%llx\tTotal Jobs: %d\tSubmitted Jobs: %d\tCompleted Jobs: %d\tAborted Jobs: %d\n",
						ntw->network_id,
						ntw->swc_node.sw_id,
						ntw->jg_list->total_jobs,
						ntw->jg_list->submitted_jobs_nr,
						ntw->jg_list->ended_jobs_nr,
						ntw->jg_list->aborted_jobs_nr);

						seq_puts(m, "Job info\n");
						ice_di_job_info_print(m,
								ntw->jg_list);
					}
					ntw = cve_dle_next(ntw, list);
				} while (ntw != pntw->ntw_list);
			}

			pntw = cve_dle_next(pntw, resource_list);
		} while (pntw != dg->pntw_with_resources);
	}

out:
	seq_printf(m, "Allocated Parent Networks: %lld\n", alloc_pntw_count);
	seq_printf(m, "Allocated Networks: %lld\n", alloc_ntw_count);
	seq_printf(m, "Scheduled Networks: %lld\n", sch_ntw_count);
	seq_printf(m, "Allocated Inferences: %lld\n", alloc_inf_count);
	cve_os_unlock(&g_cve_driver_biglock);

	return retval;
}

static int schedule_info_open(struct inode *inode, struct file *filp)
{
	return single_open(filp, schedule_info_show, inode->i_private);
}

static int schedule_info_show(struct seq_file *m, void *v)
{
	struct cve_device_group *dg;
	struct ice_pnetwork *pntw;
	struct ice_network *ntw;

	int retval = CVE_DEFAULT_ERROR_CODE;

	retval = cve_os_lock(&g_cve_driver_biglock, CVE_INTERRUPTIBLE);
	if (retval != 0)
		return -ERESTARTSYS;

	dg = cve_dg_get();
	if (dg == NULL) {
		seq_puts(m, "No active networks\n");
		goto out;
	}

	pntw = dg->pntw_with_resources;
	if (pntw == NULL) {
		seq_puts(m, "No active networks\n");
		goto out;
	}

	do {
		ntw = pntw->ntw_list;
		seq_printf(m, "PNTW ID: 0x%llx\tPNTW SW ID: 0x%llx\tPNTW ICE Mask: 0x%llx\n",
				pntw->pntw_id, pntw->swc_node.sw_id,
				pntw->pntw_icemask);
		if (ntw) {
			do {
				if (ntw->curr_exe)
					seq_printf(m, "Ntw ID = 0x%llx\tNtw SW ID: 0x%llx\tCurr exec Inf ID = 0x%llx\tInf SW ID: 0x%llx\n",
					ntw->network_id, ntw->swc_node.sw_id,
					ntw->curr_exe->infer_id,
					ntw->curr_exe->swc_node.sw_id);

				ntw = cve_dle_next(ntw, list);
			} while (ntw != pntw->ntw_list);
		}

		pntw = cve_dle_next(pntw, resource_list);
	} while (pntw != dg->pntw_with_resources);

out:
	cve_os_unlock(&g_cve_driver_biglock);

	return retval;

}

static int buffer_info_open(struct inode *inode, struct file *filp)
{
	return single_open(filp, buffer_info_show, inode->i_private);
}

static int buffer_info_show(struct seq_file *m, void *v)
{
	struct cve_device_group *dg;
	struct ice_pnetwork *pntw;
	struct ice_network *ntw;
	u64 *page_config = NULL;
	u32 buf_count = 0, inf_buf_count = 0;

	int retval = CVE_DEFAULT_ERROR_CODE;

	retval = cve_os_lock(&g_cve_driver_biglock, CVE_INTERRUPTIBLE);
	if (retval != 0)
		return -ERESTARTSYS;

	dg = cve_dg_get();
	if (dg == NULL) {
		seq_puts(m, "No active networks buffers\n");
		goto out;
	}

	pntw = dg->pntw_with_resources;
	if (pntw == NULL) {
		seq_puts(m, "No active network buffers\n");
		goto out;
	}

	do {
		seq_printf(m, "PNTW ID: 0x%llx\tPNTW SW ID: 0x%llx\n",
			pntw->pntw_id, pntw->swc_node.sw_id);

		buf_count = 0;
		ntw = pntw->ntw_list;
		if (ntw) {
			do {
				buf_count += ntw->num_buf;
				ntw = cve_dle_next(ntw, list);
			} while (ntw != pntw->ntw_list);
		}

		seq_printf(m, "Number of buffers = %d\t",
			buf_count);

		page_config = pntw->ntw_buf_page_config;
		seq_printf(m, "Network Size usage (Low, 32K, 16M, 32M) = (0x%llx, 0x%llx, 0x%llx, 0x%llx)\n",
		page_config[IOVA_PAGE_ALIGNMENT_LOW_32K],
		page_config[IOVA_PAGE_ALIGNMENT_32K],
		page_config[IOVA_PAGE_ALIGNMENT_16M],
		page_config[IOVA_PAGE_ALIGNMENT_32M]);

		inf_buf_count = 0;
		ntw = pntw->ntw_list;
		if (ntw) {
			do {
				inf_buf_count += ntw->infer_buf_count;
				ntw = cve_dle_next(ntw, list);
			} while (ntw != pntw->ntw_list);
		}

		seq_printf(m, "Number of Infer buffers = %d\t",
			inf_buf_count);

		page_config = pntw->infer_buf_page_config;
		seq_printf(m, "Inference Size usage (Low, 32K, 16M, 32M) = (0x%llx, 0x%llx, 0x%llx, 0x%llx)\n",
		page_config[IOVA_PAGE_ALIGNMENT_LOW_32K],
		page_config[IOVA_PAGE_ALIGNMENT_32K],
		page_config[IOVA_PAGE_ALIGNMENT_16M],
		page_config[IOVA_PAGE_ALIGNMENT_32M]);

		pntw = cve_dle_next(pntw, resource_list);
	} while (pntw != dg->pntw_with_resources);

out:
	cve_os_unlock(&g_cve_driver_biglock);

	return retval;
}

static int ice_counter_info_open(struct inode *inode, struct file *filp)
{
	return single_open(filp, ice_counter_info_show, inode->i_private);
}

static int ice_counter_info_show(struct seq_file *m, void *v)
{
	struct cve_device_group *dg;
	struct ice_pnetwork *pntw;
	struct cve_device *dev;

	int retval = CVE_DEFAULT_ERROR_CODE;

	retval = cve_os_lock(&g_cve_driver_biglock, CVE_INTERRUPTIBLE);
	if (retval != 0)
		return -ERESTARTSYS;

	dg = cve_dg_get();
	if (dg == NULL) {
		seq_puts(m, "No active ICEs\n");
		goto out;
	}

	pntw = dg->pntw_with_resources;
	if (pntw == NULL) {
		seq_puts(m, "No active ICEs\n");
		goto out;
	}

	do {
		dev = pntw->ice_list;
		do {
			seq_printf(m, "dev index = %d\tCurrent PNTW = 0x%llx\tPNTW SW ID: 0x%llx\tdb = %d",
				dev->dev_index, pntw->pntw_id,
				pntw->swc_node.sw_id,
				dev->db_cbd_id);

			seq_puts(m, "\tCold Run: ");
			seq_puts(m, dev->is_cold_run ? "Yes" : "No");
			seq_puts(m, "\tICE Error: ");
			seq_puts(m, is_cve_error(dev->interrupts_status) ?
					"Yes\n" : "No\n");
			dev = cve_dle_next(dev, owner_list);
		} while (dev != pntw->ice_list);

		pntw = cve_dle_next(pntw, resource_list);
	} while (pntw != dg->pntw_with_resources);

out:
	cve_os_unlock(&g_cve_driver_biglock);

	return retval;
}

static int ice_firmware_info_open(struct inode *inode, struct file *filp)
{
	return single_open(filp, ice_firmware_info_show, inode->i_private);
}

static int ice_firmware_info_show(struct seq_file *m, void *v)
{
	struct cve_device_group *dg;
	struct ice_pnetwork *pntw;
	struct cve_device *dev;
	struct cve_fw_loaded_sections *fw_loaded_head = NULL;
	struct cve_fw_loaded_sections *fw_loaded_curr = NULL;

	int retval = CVE_DEFAULT_ERROR_CODE;

	retval = cve_os_lock(&g_cve_driver_biglock, CVE_INTERRUPTIBLE);
	if (retval != 0)
		return -ERESTARTSYS;

	dg = cve_dg_get();
	if (dg == NULL) {
		seq_puts(m, "No active ICEs\n");
		goto out;
	}

	pntw = dg->pntw_with_resources;
	if (pntw == NULL) {
		seq_puts(m, "No active ICEs\n");
		goto out;
	}

	do {
		seq_printf(m, "PNTW ID: 0x%llx\tPNTW SW ID: 0x%llx\n",
			pntw->pntw_id, pntw->swc_node.sw_id);
		dev = pntw->ice_list;
		do {
			seq_printf(m, "dev index = 0x%x\n",
				dev->dev_index);

			fw_loaded_head = dev->fw_loaded_list;
			fw_loaded_curr = fw_loaded_head;

			do {
				if (fw_loaded_curr->sections) {
					seq_printf(m, "Sections = %d\tFW Type = ",
						fw_loaded_curr->sections_nr);

					seq_puts(m, get_fw_binary_type_str(
						fw_loaded_curr->fw_type));

					seq_printf(m, "\tSize = 0x%x\n",
						fw_loaded_curr->sections->
							size_bytes);
				}

				fw_loaded_curr = cve_dle_next(fw_loaded_curr,
									list);
			} while (fw_loaded_curr != fw_loaded_head);

			dev = cve_dle_next(dev, owner_list);
		} while (dev != pntw->ice_list);

		pntw = cve_dle_next(pntw, resource_list);
	} while (pntw != dg->pntw_with_resources);

out:
	cve_os_unlock(&g_cve_driver_biglock);

	return retval;
}
