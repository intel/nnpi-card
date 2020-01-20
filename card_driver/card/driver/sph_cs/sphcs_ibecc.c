/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#include "sphcs_ibecc.h"
#include "sph_log.h"
#include <linux/kernel.h>
#include <linux/debugfs.h>
#include <linux/pfn_t.h>
#include <linux/highmem.h>
#include <linux/cache.h>

/* Whether context scope error injection requested */
bool ibecc_error_injection_requested;

#ifdef CARD_PLATFORM_BR

#include <../drivers/edac/igen6_edac.h>
#include <linux/scatterlist.h>
#include <linux/ion_exp.h>
#include "sphcs_cs.h"
#include "sph_mem_alloc_defs.h"
#include "sph_ibecc.h"

static void __iomem *mchbar;

/* 0 - correctable, 1 - uncorrectable card */
static u8 ibecc_error_type;
/* 0 - os, 1 - ctxt */
static u8 ibecc_error_scope;
/* 0 - ctxt, 1 - card */
static u8 ibecc_error_uc_severity;

static struct dentry *debugfs_dir;
static u32 orig_value;

/* The error injection is pretty simple:
 * - the wrong syndrome is injected on write
 * - the error triggered on read
 *
 * When we write the data less than 64 byte (that is likely the case when we do it from CPU)
 * - if the data is cachable, the read will be issued on cache miss and the appropriate
 * bytes will be updated in the cacheline.
 * - if the data is uncachable, the partial write (read followed by the write)
 * will be executed.
 *
 * We need to be aware of the "hidden" reads as described above, once the error
 * injection is activated as read will cause the error indication
 *
 */
static void sphcs_ibecc_inject_os_err(void)
{
	struct page *page;
	void *vaddr;
	phys_addr_t addr;
	u32 val;
	size_t size;

	/* Allocate page */
	size = cache_line_size();
	page = alloc_page(GFP_KERNEL);
	vaddr = kmap(page);
	addr = pfn_t_to_phys(page_to_pfn_t(page));

	/* Zero page and initialize the EDSR data of the page */
	memset(vaddr, 0, size);
	clflush_cache_range(vaddr, size);

	/* Inject error */
	mb();
	sph_log_info(GENERAL_LOG, "Inject error: addr %pap\n", &addr);
	val = (ibecc_error_type == 0) ? ECC_ENJ_CONTROL_MODE_COR_ERR : ECC_ENJ_CONTROL_MODE_UC_ERR;
	writew(val, mchbar + IBECC_INJ_CONTROL_OFF);
	writeq(addr, mchbar + IBECC_INJ_ADDR_BASE_OFF);
	writeq(~(size - 1), mchbar + IBECC_INJ_ADDR_MASK_OFF);
	mb();
	*(u32 *)vaddr = 0;
	clflush_cache_range(vaddr, 4);

	/* Trigger error */
	mb();
	sph_log_info(GENERAL_LOG, "Trigger error: %u\n", *(u32 *)vaddr);

	/* Clean injected error */
	writew(0, mchbar + IBECC_INJ_CONTROL_OFF);
	writeq(0, mchbar + IBECC_INJ_ADDR_BASE_OFF);
	writeq(0, mchbar + IBECC_INJ_ADDR_MASK_OFF);
	mb();
	*(u32 *)vaddr = 0;
	clflush_cache_range(vaddr, 4);

	/* Release the page */
	kunmap(page);
	__free_page(page);
}

static ssize_t debugfs_inject_write(struct file *file,
				    const char __user *data,
				    size_t count,
				    loff_t *ppos)
{
	sph_log_info(GENERAL_LOG, "ibecc error injection triggered\n");

	if (ibecc_error_scope == 0)
		sphcs_ibecc_inject_os_err();
	else
		ibecc_error_injection_requested = true;

	return count;
}

static const struct file_operations debugfs_inject_fops = {
	.open = simple_open,
	.write = debugfs_inject_write,
};

/* IBECC error cb runs in process ctxt */
static int ibecc_error_cb(struct notifier_block *nb, unsigned long action, void *data)
{
	struct ibecc_err_info *err_info = (struct ibecc_err_info *)data;
	union sph_mem_protected_buff_attr buff_attr;

	int context_id = -1;
	uint16_t eventCode;
	int ret;
	bool corrected = (err_info->type == HW_EVENT_ERR_CORRECTED);

	sph_log_info(GENERAL_LOG, "IBECC error at addr 0x%llX corrected=%d\n",
		     err_info->sys_addr, corrected);

	/* Try to retrieve user assigned data */
	ret = ion_get_buf_user_data(err_info->sys_addr, &buff_attr.value);
	if (ret == 0) {
		/* This is an ion buffer */
		if (corrected)
			eventCode = SPH_IPC_ERROR_DRAM_ECC_CORRECTABLE;
		else {
			context_id = buff_attr.context_id;
			/* If either context or severity is not set */
			if ((buff_attr.context_id_valid != 1) || (buff_attr.uc_ecc_severity == 0))
				eventCode = SPH_IPC_ERROR_DRAM_ECC_UNCORRECTABLE_FATAL;
			else if (buff_attr.uc_ecc_severity == 2)
				eventCode = SPH_IPC_ERROR_DRAM_ECC_UNCORRECTABLE_FATAL;
			else
				eventCode = SPH_IPC_CTX_DRAM_ECC_UNCORRECTABLE;
		}
	} else {
		/* This is an OS managed buffer*/
		eventCode = corrected ?
				SPH_IPC_ERROR_DRAM_ECC_CORRECTABLE :
				SPH_IPC_ERROR_DRAM_ECC_UNCORRECTABLE_FATAL;
	}

	/* context_id is passed as objID in purpose! */
	sphcs_send_event_report(g_the_sphcs, eventCode, 0, -1, context_id);

	return NOTIFY_OK;
}

static struct notifier_block ibecc_errors_notifier = {
	.notifier_call = ibecc_error_cb,
};


int sphcs_ibecc_init(void)
{
	int rc;
	struct pci_dev *dev0 = NULL;

	/* IBECC enabled? */
	dev0 = is_ibecc_enabled();
	if (!dev0) {
		rc = 0;
		goto out;
	}

	/* Map mchbar */
	mchbar = ibecc_map_mchbar(dev0);
	if (!mchbar) {
		sph_log_err(START_UP_LOG, "Failed to map mchbar\n");
		rc = -EIO;
		goto out;
	}

	/* IBECC activated? */
	if (!is_ibecc_activated(mchbar)) {
		sph_log_info(START_UP_LOG, "IBECC disabled\n");
		rc = 0;
		goto unmap;
	}

	/* If IBECC exists, is enabled and activated create debugfs for error injection */
	debugfs_dir = debugfs_create_dir("ibecc", NULL);
	debugfs_create_u8("error_type", 0600, debugfs_dir, &ibecc_error_type);
	debugfs_create_u8("error_scope", 0600, debugfs_dir, &ibecc_error_scope);
	debugfs_create_u8("error_uc_severity", 0600, debugfs_dir, &ibecc_error_uc_severity);
	debugfs_create_file("inject", 0200, debugfs_dir, NULL, &debugfs_inject_fops);

	/* If IBECC exists, is enabled and activated register the callback */
	rc = ibecc_err_register_notifer(&ibecc_errors_notifier);
	if (rc) {
		sph_log_err(START_UP_LOG, "Failed to register callback\n");
		goto out;
	}

	return 0;

unmap:
	ibecc_unmap_mchbar(mchbar);
	mchbar = NULL;
out:
	return rc;
}

int sphcs_ibecc_fini(void)
{
	/* If IBECC is not enabled/ activated */
	if (!mchbar)
		return 0;

	ibecc_unmap_mchbar(mchbar);
	debugfs_remove_recursive(debugfs_dir);
	return ibecc_err_unregister_notifer(&ibecc_errors_notifier);
}

int sphcs_ibecc_inject_ctxt_err(phys_addr_t addr, void *vaddr)
{

	size_t size;
	u32 val;

	sph_log_info(GENERAL_LOG, "addr %pap, vaddr %px\n", &addr, vaddr);

	size = cache_line_size();
	orig_value = *(u32 *)vaddr;
	mb();

	val = (ibecc_error_type == 0) ? ECC_ENJ_CONTROL_MODE_COR_ERR : ECC_ENJ_CONTROL_MODE_UC_ERR;
	writew(val, mchbar + IBECC_INJ_CONTROL_OFF);
	writeq(addr, mchbar + IBECC_INJ_ADDR_BASE_OFF);
	writeq(~(size - 1), mchbar + IBECC_INJ_ADDR_MASK_OFF);
	mb();
	*(u32 *)vaddr = orig_value;
	clflush_cache_range(vaddr, sizeof(orig_value));

	return 0;
}

int sphcs_ibecc_clean_ctxt_err(void *vaddr)
{
	sph_log_info(GENERAL_LOG, "vaddr %px\n", vaddr);

	ibecc_error_injection_requested = false;

	/* Clean injected error */
	writew(0, mchbar + IBECC_INJ_CONTROL_OFF);
	writeq(0, mchbar + IBECC_INJ_ADDR_BASE_OFF);
	writeq(0, mchbar + IBECC_INJ_ADDR_MASK_OFF);
	mb();
	*(u32 *)vaddr = orig_value;
	clflush_cache_range(vaddr, sizeof(orig_value));

	return 0;
}

bool sphcs_ibecc_get_uc_severity_ctxt_requested(void)
{
	return (ibecc_error_uc_severity == 0);
}

bool sphcs_ibecc_correctable_error_requested(void)
{
	return (ibecc_error_type == 0);
}

#else
int sphcs_ibecc_init(void)
{
	return 0;
}

int sphcs_ibecc_fini(void)
{
	return 0;
}

bool sphcs_ibecc_get_uc_severity_ctxt_requested(void)
{
	return false;
}

bool sphcs_ibecc_correctable_error_requested(void)
{
	return false;
}

int sphcs_ibecc_inject_ctxt_err(phys_addr_t addr, void *vaddr)
{
	return 0;
}

int sphcs_ibecc_clean_ctxt_err(void *vaddr)
{
	return 0;
}

#endif
