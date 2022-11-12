/********************************************
 * Copyright (C) 2019-2021 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/stringify.h>
#include <linux/acpi.h>

#include "sphcs_pcie.h"
#include "sph_log.h"
#include "sphcs_cs.h"
#include "sphcs_genmsg.h"
#ifdef ULT
#include "sphcs_ult.h"
#endif
#include "sph_version.h"
#include "sphcs_maintenance.h"
#include "sphcs_trace.h"
#include "sphcs_p2p_test.h"

struct BDAT_HEADER_STRUCTURE {
	u8   BiosDataSignature[8];	// "BDATHEAD"
	u32  BiosDataStructSize;	// sizeof BDAT_STRUCTURE
	u16  Crc16;			// 16-bit CRC of BDAT_STRUCTURE (calculated with 0 in this field)
	u16  Reserved;
	u16  PrimaryVersion;		// Primary version
	u16  SecondaryVersion;	// Secondary version
	u32  OemOffset;		// Optional offset to OEM-defined structure
	u32  Reserved1;
	u32  Reserved2;
};

static void    *bdat_virt;
static uint32_t bdat_size;

static ssize_t bdat_read(struct file *filp,
			 struct kobject *kobj,
			 struct bin_attribute *attr,
			 char *buf,
			 loff_t offset,
			 size_t count)
{
	ssize_t ret;

	if (bdat_size > 0)
		ret = memory_read_from_buffer(buf,
					      count,
					      &offset,
					      bdat_virt,
					      bdat_size);
	else
		ret = 0;

	return ret;
}

static struct bin_attribute bdat_attr = {
	.attr = {
		.name = "bdat",
		.mode = 0400
	},
	.size = 0,
	.read = bdat_read,
	.write = NULL,
	.mmap = NULL,
	.private = (void *)0
};

int init_bdat_sysfs(void)
{
	struct acpi_table_header *table_header = NULL;
	int ret;
	uint64_t bdat_phys_addr;
	struct BDAT_HEADER_STRUCTURE *header;

	ret = acpi_get_table("BDAT", 0, &table_header);
	if (ACPI_FAILURE(ret)) {
		sph_log_err(GENERAL_LOG, "Failed to find BDAT acpi table\n");
		return -ENODEV;
	}

	if (table_header->length != 48) {
		sph_log_err(GENERAL_LOG, "Wrong BDAT table size %d instead of 48\n", table_header->length);
		ret = -EFAULT;
		goto done;
	}

	bdat_phys_addr = *((uint64_t *)(((uintptr_t)table_header) + 40));
	sph_log_info(GENERAL_LOG, "Found BDAT acpi table at=0x%llx\n", bdat_phys_addr);

	bdat_virt = memremap(bdat_phys_addr, PAGE_SIZE, MEMREMAP_WB);
	if (!bdat_virt) {
		sph_log_err(GENERAL_LOG, "Failed to map BDAT table\n");
		ret = -EFAULT;
		goto done;
	}

	header = (struct BDAT_HEADER_STRUCTURE *)bdat_virt;
	if (strncmp(header->BiosDataSignature, "BDATHEAD", 8) != 0) {
		sph_log_err(GENERAL_LOG, "BDAT wrong signature\n");
		ret = -EFAULT;
		goto done;
	}
	bdat_size = header->BiosDataStructSize;

	if (bdat_size > PAGE_SIZE) {
		memunmap(bdat_virt);
		bdat_virt = memremap(bdat_phys_addr, PAGE_ALIGN(bdat_size), MEMREMAP_WB);
		if (!bdat_virt) {
			sph_log_err(GENERAL_LOG, "Failed to map BDAT table size=%d\n", bdat_size);
			ret = -EFAULT;
			goto done;
		}
	}

	bdat_attr.size = bdat_size;

	ret = sysfs_create_bin_file(&THIS_MODULE->mkobj.kobj, &bdat_attr);
	if (ret) {
		sph_log_err(GENERAL_LOG, "Failed to create bdat sysfs file\n");
		memunmap(bdat_virt);
		bdat_virt = NULL;
		bdat_size = 0;
	}

done:
	acpi_put_table(table_header);

	return ret;
}

int sphcs_init_module(void)
{
	int ret = 0;

	sph_log_debug(START_UP_LOG, "module (version %s) started\n", NNP_VERSION);

	DO_TRACE(sphcs_trace_init());

	ret = sphcs_hw_init(&g_sphcs_pcie_callbacks);
	if (ret)
		sph_log_err(START_UP_LOG, "Failed to init hw layer\n");

	/* Initliaize general messaging interface character device */
	ret = sphcs_init_genmsg_interface();
	if (ret) {
		sph_log_err(START_UP_LOG, "Failed to init general messaging interface\n");
		ret = -ENODEV;
		goto pcie_cleanup;
	}

	/* Initialize maintenance interface character device */
	ret = sphcs_init_maint_interface();
	if (ret) {
		sph_log_err(START_UP_LOG, "Failed to init maintenance interface\n");
		ret = -ENODEV;
		goto sphcs_genmsg_cleanup;
	}
#ifdef ULT
	/* Initlize ULT module */
	ret = sphcs_init_ult_module();
	if (ret) {
		sph_log_err(START_UP_LOG, "Failed to init ult module\n");
		ret = -ENODEV;
		goto sphcs_maint_cleanup;
	}

	sphcs_p2p_test_init();
#endif

	init_bdat_sysfs();

	return 0;

#ifdef ULT
	sphcs_p2p_test_cleanup();
	sphcs_fini_ult_module();

sphcs_maint_cleanup:
#endif
	sphcs_release_maint_interface();
sphcs_genmsg_cleanup:
	sphcs_release_genmsg_interface();
pcie_cleanup:
	sphcs_hw_cleanup();

	return ret;
}

void sphcs_cleanup(void)
{
	sph_log_debug(GO_DOWN_LOG, "Cleaning Up the Module\n");
#ifdef ULT
	sphcs_p2p_test_cleanup();

	sphcs_fini_ult_module();
#endif
	sphcs_release_maint_interface();

	sphcs_release_genmsg_interface();

	sphcs_hw_cleanup();

	if (bdat_virt) {
		sysfs_remove_bin_file(&THIS_MODULE->mkobj.kobj, &bdat_attr);
		memunmap(bdat_virt);
	}
}

module_init(sphcs_init_module);
module_exit(sphcs_cleanup);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("SpringHill Card Driver");
MODULE_AUTHOR("Intel Corporation");
MODULE_VERSION(NNP_VERSION);
#ifdef DEBUG
MODULE_INFO(git_hash, SPH_GIT_HASH);
#endif
