/********************************************
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/err.h>
#include <linux/list.h>
#include <linux/highmem.h>
#include <linux/pfn.h>
#include <linux/vmalloc.h>
#include <asm/page.h>
#include <linux/pci.h>
#include <linux/pci_ids.h>
#include <asm/processor.h>
#include <linux/bitops.h>
#include <linux/workqueue.h>
#include <linux/cpumask.h>

#include "sph_log.h"
#include "sph_version.h"
#include "sph_mem_alloc_defs.h"
#include "sw_counters.h"

/* The sph_mem module parameter defines physically contiguous
 * memory regions that will be managed by Memory Allocator
 *
 * sph_mem=size@start,size@start, ...
 */
static char *sph_mem;
static int test;
module_param(sph_mem, charp, 0400);
module_param(test, int, 0400);

#ifdef CARD_PLATFORM_BR

#include <linux/ion_exp.h>

#define DID_ICLI_SKU8 0x4581
#define DID_ICLI_SKU10 0x4585
#define DID_ICLI_SKU11 0x4589
#define DID_ICLI_SKU12 0x458d
#define CAPID0_C_OFF 0xEC
#define MCHBAR_HI_OFF 0x4c
#define MCHBAR_LO_OFF 0x48
#define MCHBAR_EN BIT_ULL(0)
#define MCHBAR_MASK GENMASK_ULL(38, 16)
#define MCHBAR_SIZE BIT_ULL(16)

/* IBECC registers */
#define IBECC_BASE 0xd800
#define IBECC_ACTIVATE_OFF IBECC_BASE
#define IBECC_PROTECTED_RANGE_0_OFF (IBECC_BASE + 0xC)
#define IBECC_PROTECTED_RANGE_1_OFF (IBECC_BASE + 0x10)
#define IBECC_PROTECTED_RANGE_2_OFF (IBECC_BASE + 0x14)
#define IBECC_PROTECTED_RANGE_3_OFF (IBECC_BASE + 0x18)
#define IBECC_PROTECTED_RANGE_4_OFF (IBECC_BASE + 0x1C)
#define IBECC_PROTECTED_RANGE_5_OFF (IBECC_BASE + 0x20)
#define IBECC_PROTECTED_RANGE_6_OFF (IBECC_BASE + 0x24)
#define IBECC_PROTECTED_RANGE_7_OFF (IBECC_BASE + 0x28)

/* IBECC_PROTECTED_RANGE register layout */
#define IBECC_PROTECTED_RANGE_EN BIT(31)
#define IBECC_PROTECTED_RANGE_BASE_OFF 0
#define IBECC_PROTECTED_RANGE_BASE_MASK GENMASK(13, 0)
#define IBECC_PROTECTED_RANGE_MASK_OFF 16
#define IBECC_PROTECTED_RANGE_MASK_MASK GENMASK(29, 16)

/* SW counters */
static const struct sph_sw_counters_group_info sw_counters_groups_info[] = {
	{"device_memory", "group of device memory counters"}
};

/* Counter indices in the sw_counters_info array */
#define SW_COUNTER_BYTES_TOTAL_INDEX 0
#define SW_COUNTER_BYTES_BAD_INDEX 1
#define SW_COUNTER_PROT_BYTES_TOTAL_INDEX 2
#define SW_COUNTER_PROT_BYTES_BAD_INDEX 3

static const struct sph_sw_counter_info sw_counters_info[] = {
		{0, "non_protected.bytes.total", "Total number of bytes of device memory in the unprotected region"},
		{0, "non_protected.bytes.bad", "Number of bad bytes in the unprotected region (memory test failed)"},
		{0, "protected.bytes.total", "Total number of bytes of device memory in the protected region"},
		{0, "protected.bytes.bad", "Number of bad bytes in the protected region (memory test failed)"},
};

static const struct sph_sw_counters_set sw_counters_set = {
	"sw_counters",
	false,
	sw_counters_info,
	ARRAY_SIZE(sw_counters_info),
	sw_counters_groups_info,
	ARRAY_SIZE(sw_counters_groups_info)};

static void *sw_counters_handle;
static struct sph_sw_counters *sw_counters;

/* heap handles */
void *ecc_unprotected_heap_handle;
void *ecc_protected_heap_handle;

LIST_HEAD(protected_regions);
LIST_HEAD(unprotected_regions);
LIST_HEAD(managed_regions);
LIST_HEAD(protected_managed_regions);

/* Number of pages to test at once -
 * the total number of bytes should be greater than cache size ( L0 + L1 + LLC)
 */
#define NUM_OF_PAGES 32768
struct page *pages[NUM_OF_PAGES];

static struct workqueue_struct *wq;
static void do_mem_set_work(struct work_struct *work);

struct mem_work {
	struct work_struct work;
	uint64_t *buf;
	uint64_t value;
	uint64_t count;
	bool res;
};
static struct mem_work *mem_works;
static int num_of_mem_works;

static void do_mem_set_work(struct work_struct *work)
{
	struct mem_work *mem_set_work = container_of(work, struct mem_work, work);

	memset64(mem_set_work->buf, mem_set_work->value, mem_set_work->count);
	clflush_cache_range(mem_set_work->buf,  mem_set_work->count * sizeof(u64));
}

static bool memcmp64(u64 *buf, u64 value, u64 count)
{
	u64 i;

	for (i = 0; i < count; i++)
		if (buf[i] != value)
			return false;
	return true;
}

static void do_mem_cmp_work(struct work_struct *work)
{
	struct mem_work *mem_cmp_work = container_of(work, struct mem_work, work);

	mem_cmp_work->res = memcmp64(mem_cmp_work->buf, mem_cmp_work->value, mem_cmp_work->count);

}

static bool overlapped_region(struct mem_region *reg1, struct mem_region *reg2)
{
	if ((reg1->start + reg1->size - 1 < reg2->start) ||
		   (reg2->start + reg2->size - 1 < reg1->start))
		return false;

	return true;
}

static void release_list(struct list_head *head)
{
	struct mem_region *pos, *tmp;

	if (!list_empty(head)) {
		list_for_each_entry_safe(pos, tmp, head, list) {
			list_del(&pos->list);
			vfree(pos);
		}
	}


}

static void print_list(const char *headline, struct list_head *head)
{
	struct mem_region *pos;

	sph_log_info(GENERAL_LOG, "%s\n", headline);

	if (list_empty(head))
		sph_log_info(GENERAL_LOG, "\tempty\n");
	else
		list_for_each_entry(pos, head, list)
			sph_log_info(GENERAL_LOG, "\t%pad\t0x%zX\n", &pos->start, pos->size);

}
/*
 * This function updates the list of memory regions according to the bad page index.
 * As this function is called from within list_for_each_entry_safe saving the next
 * for safe node removing, adding the element is a little bit tricky: after
 * adding the element we need to update the saved next.
 */
static int update_regions(struct mem_region *reg, struct mem_region **tmp, u64 bad_page_index)
{
	u64 num_of_pages;
	struct mem_region *new_reg;

	num_of_pages = reg->size >> PAGE_SHIFT;

	/* One page region is entirely bad - remove it */
	if (num_of_pages == 1) {
		list_del(&reg->list);
		vfree(reg);
		return 0;
	}

	/* first page */
	if (bad_page_index == 0) {
		new_reg = vmalloc(sizeof(struct mem_region));
		if (new_reg == NULL)
			return -ENOMEM;
		new_reg->start = reg->start + PAGE_SIZE;
		new_reg->size = reg->size - PAGE_SIZE;
		list_add(&new_reg->list, &reg->list);
		list_del(&reg->list);
		vfree(reg);
		*tmp = new_reg;
	/* last page of the region */
	} else if (bad_page_index == num_of_pages - 1) {
		reg->size -= PAGE_SIZE;
	} else {
		reg->size = bad_page_index * PAGE_SIZE;
		new_reg = vmalloc(sizeof(struct mem_region));
		if (new_reg == NULL)
			return -ENOMEM;
		new_reg->start = reg->start + (bad_page_index + 1) * PAGE_SIZE;
		new_reg->size = (num_of_pages - (bad_page_index + 1)) * PAGE_SIZE;
		list_add(&new_reg->list, &reg->list);
		*tmp = new_reg;
	}
	return 0;
}

static void memset64_mt(u64 *buf, u64 value, u64 count)
{
	int cpu;
	u64 i;
	uint64_t count_per_thread = count / num_of_mem_works;

	i = 0;
	for_each_cpu(cpu, cpu_online_mask) {
		mem_works[i].value = value;
		mem_works[i].count = count_per_thread;
		mem_works[i].buf = buf + i*count_per_thread;
		INIT_WORK(&mem_works[i].work, do_mem_set_work);
		queue_work_on(cpu, wq,  &mem_works[i].work);
		i++;
	}

	flush_workqueue(wq);
}

static bool memcmp64_mt(u64 *buf, u64 value, u64 count)
{
	u64 i;
	int cpu;
	bool ret = true;
	uint64_t count_per_thread = count / num_of_mem_works;

	i = 0;
	for_each_cpu(cpu, cpu_online_mask) {
		mem_works[i].value = value;
		mem_works[i].count = count_per_thread;
		mem_works[i].buf = buf + i*count_per_thread;
		mem_works[i].res = false;
		INIT_WORK(&mem_works[i].work, do_mem_cmp_work);
		queue_work_on(cpu, wq,  &mem_works[i].work);
		i++;
	}

	flush_workqueue(wq);

	for (i = 0; i < num_of_mem_works; i++)
		ret = ret && mem_works[i].res;
	return ret;
}

static int test_list(struct list_head *head, bool is_protected)
{
	struct mem_region *reg, *tmp;
	u64 num_of_pages, num_of_tested_pages, pages_to_test;
	u32 i;
	void *reg_virt_addr;
	bool bad_page_detected;
	int rc;

#ifdef INJECT_ERR
	bool inject = true;
	bool inject_current_reg = false;
	u64 injected_bad_page_index;
	phys_addr_t injected_bad_page_addr = 0x20000F000;
#endif

	if (list_empty(head)) {
		sph_log_warn(GENERAL_LOG, "The list of regions is empty\n");
		return 0;
	}

	/* go over the memory regions */
	list_for_each_entry_safe(reg, tmp, head, list) {
		bad_page_detected = false;
		num_of_pages = reg->size >> PAGE_SHIFT;
		num_of_tested_pages = 0;

		sph_log_debug(GENERAL_LOG, "Start scan memory region %pad\t0x%zX\n", &reg->start, reg->size);

#ifdef INJECT_ERR
		if (inject) {
			if ((injected_bad_page_addr >= reg->start) && (injected_bad_page_addr < (reg->start + reg->size))) {
				injected_bad_page_index = (injected_bad_page_addr - reg->start) >> PAGE_SHIFT;
				sph_log_debug(GENERAL_LOG, "injected_bad_page_index = 0x%llX\n", injected_bad_page_index);
				inject_current_reg = true;
			} else
				inject_current_reg = false;
		}
#endif
		/* scan the region by segments of NUM_OF_PAGES pages */
		while ((num_of_pages > num_of_tested_pages) && (!bad_page_detected)) {

			pages_to_test = (num_of_pages - num_of_tested_pages > NUM_OF_PAGES) ? NUM_OF_PAGES : num_of_pages - num_of_tested_pages;
			for (i = 0; i < pages_to_test; i++)
				pages[i] = pfn_to_page(PHYS_PFN(reg->start + num_of_tested_pages*PAGE_SIZE + i*PAGE_SIZE));

			reg_virt_addr = vm_map_ram(pages, pages_to_test, -1, PAGE_KERNEL);
			if (reg_virt_addr == NULL) {
				sph_log_err(GENERAL_LOG, "Couldn't map the ram\n");
				rc = -ENOMEM;
				goto err;
			}

			memset64_mt(reg_virt_addr, 0, pages_to_test * PAGE_SIZE / sizeof(u64));
#ifdef INJECT_ERR
			if (inject_current_reg) {
				if (injected_bad_page_index >= num_of_tested_pages && injected_bad_page_index <= num_of_tested_pages + pages_to_test)
					memset(reg_virt_addr + (injected_bad_page_index - num_of_tested_pages)*PAGE_SIZE, 1, PAGE_SIZE);
			}
#endif
			/* More likely that there is no faulty pages, so we try to compare all in once */
			if (unlikely(!memcmp64_mt(reg_virt_addr, 0, pages_to_test * PAGE_SIZE / sizeof(u64)))) {
				/* Find the faulty page */
				for (i = 0; i < pages_to_test; i++) {
					if (!memcmp64_mt(reg_virt_addr + i*PAGE_SIZE, 0x0, PAGE_SIZE / sizeof(u64))) {
						sph_log_err(GENERAL_LOG, "Bad page detected - bad page index %llu\n", num_of_tested_pages + i);
						if (is_protected)
							SPH_SW_COUNTER_ADD(sw_counters, SW_COUNTER_PROT_BYTES_BAD_INDEX, PAGE_SIZE);
						else
							SPH_SW_COUNTER_ADD(sw_counters, SW_COUNTER_BYTES_BAD_INDEX, PAGE_SIZE);
						rc = update_regions(reg, &tmp, num_of_tested_pages + i);
						if (rc != 0)
							goto err;
						bad_page_detected = true;
						goto out;
					}

				}
			}

			memset64_mt(reg_virt_addr, -1ULL, pages_to_test * PAGE_SIZE / sizeof(u64));

			/* More likely that there is no faulty pages, so we try to compare all in once */
			if (unlikely(!memcmp64_mt(reg_virt_addr, -1ULL, pages_to_test * PAGE_SIZE / sizeof(u64)))) {
				/* Find the faulty page */
				for (i = 0; i < pages_to_test; i++) {
					if (!memcmp64(reg_virt_addr + i*PAGE_SIZE, -1ULL, PAGE_SIZE / sizeof(u64))) {
						sph_log_err(GENERAL_LOG, "Bad page detected - bad page index %llu\n", num_of_tested_pages + i);
						if (is_protected)
							SPH_SW_COUNTER_ADD(sw_counters, SW_COUNTER_PROT_BYTES_BAD_INDEX, PAGE_SIZE);
						else
							SPH_SW_COUNTER_ADD(sw_counters, SW_COUNTER_BYTES_BAD_INDEX, PAGE_SIZE);
						rc = update_regions(reg, &tmp, num_of_tested_pages + i);
						if (rc != 0)
							goto err;
						bad_page_detected = true;
						goto out;
					}

				}
			}

			num_of_tested_pages += pages_to_test;
out:
			vm_unmap_ram(reg_virt_addr, pages_to_test);
		}

	}
	return 0;
err:
	return rc;
}

static int create_unprotected_regions(void)
{
	struct mem_region *unprotected_region, *protected_region, *reg, *tmp;
	int rc = 0;

	/* Start with the unprotected_regions list identical to managed regions list */
	list_for_each_entry(tmp, &managed_regions, list) {
		reg = vmalloc(sizeof(struct mem_region));
		if (reg == NULL) {
			rc = -ENOMEM;
			goto err;
		}

		reg->start = tmp->start;
		reg->size = tmp->size;
		list_add(&reg->list, &unprotected_regions);
	}

	list_for_each_entry_safe(unprotected_region, tmp, &unprotected_regions, list)
		list_for_each_entry(protected_region, &protected_managed_regions, list) {

			/* Two regions does not overlap - skip it */
			if (!overlapped_region(unprotected_region, protected_region))
				continue;

			/* If two regions are the same - keep protected */
			if (unprotected_region->start == protected_region->start &&
				   unprotected_region->size == protected_region->size) {
				sph_log_debug(GENERAL_LOG, "Same region\n");
				list_del(&unprotected_region->list);
				vfree(unprotected_region);
			/* Two regions have the same start address */
			} else if (unprotected_region->start == protected_region->start &&
					unprotected_region->size > protected_region->size) {
				sph_log_debug(GENERAL_LOG, "Same start address\n");
				unprotected_region->start = unprotected_region->start + protected_region->size;
				unprotected_region->size = unprotected_region->size - protected_region->size;
			/* Two regions have the same end address */
			} else if ((protected_region->start + protected_region->size == unprotected_region->start + unprotected_region->size) &&
					(unprotected_region->start <= protected_region->start)) {
				sph_log_debug(GENERAL_LOG, "Same end address\n");
				unprotected_region->size = unprotected_region->size - protected_region->size;
			/* One region strictly contains the second one - need to split */
			} else  {
				reg = vmalloc(sizeof(struct mem_region));
				if (reg == NULL) {
					rc = -ENOMEM;
					goto err;
				}
				reg->start = protected_region->start + protected_region->size;
				reg->size = unprotected_region->start + unprotected_region->size - reg->start;
				list_add(&reg->list, &unprotected_regions);

				unprotected_region->size = protected_region->start - unprotected_region->start;

			}

	}
	return 0;

err:
	release_list(&unprotected_regions);
	return rc;
}

static int create_protected_managed_regions(void)
{
	struct mem_region *managed_region, *protected_region, *reg;
	int rc = 0;

	/* Go over all protected regions and create the list of protected managed regions */
	list_for_each_entry(protected_region, &protected_regions, list)
		list_for_each_entry(managed_region, &managed_regions, list) {

			/* Two regions does not overlap - skip it */
			if (!overlapped_region(protected_region, managed_region))
				continue;

			/* The newly created region is intersection with managed region */
			reg = vmalloc(sizeof(struct mem_region));
			if (reg == NULL) {
				rc = -ENOMEM;
				goto err;
			}
			list_add(&reg->list, &protected_managed_regions);

			reg->start = max(protected_region->start, managed_region->start);
			if (managed_region->start + managed_region->size >= protected_region->start + protected_region->size)
				reg->size = (protected_region->start + protected_region->size) - reg->start;
			else
				reg->size = (managed_region->start + managed_region->size) - reg->start;

	}
	return 0;

err:
	release_list(&protected_managed_regions);
	return rc;
}

static int create_protected_regions(void)
{
	u32 capid0;
	u32 mchbar_addr_lo;
	u32 mchbar_addr_hi;
	u64 mchbar_addr;
	struct pci_dev *dev0;
	u32 icli_dids[] = {DID_ICLI_SKU8, DID_ICLI_SKU10, DID_ICLI_SKU11, DID_ICLI_SKU12};
	u32 region_offs[] = {IBECC_PROTECTED_RANGE_0_OFF,
			     IBECC_PROTECTED_RANGE_1_OFF,
			     IBECC_PROTECTED_RANGE_2_OFF,
			     IBECC_PROTECTED_RANGE_3_OFF,
			     IBECC_PROTECTED_RANGE_4_OFF,
			     IBECC_PROTECTED_RANGE_5_OFF,
			     IBECC_PROTECTED_RANGE_6_OFF,
			     IBECC_PROTECTED_RANGE_7_OFF};
	u32 i;
	u32 val;
	u32 base_field, mask_field;
	void __iomem *mchbar;
	int rc;
	struct mem_region *reg;

	/* check stepping first */
	if (boot_cpu_data.x86_stepping < 1) {
		sph_log_info(START_UP_LOG, "IBECC is not supported in step A\n");
		goto out;
	}
	/* get device object of device 0 */
	i = 0;
	do {
		dev0 = pci_get_device(PCI_VENDOR_ID_INTEL, icli_dids[i], NULL);
		i++;
	} while ((dev0 == NULL) && (i < ARRAY_SIZE(icli_dids)));
	if (dev0 == NULL) {
		sph_log_err(START_UP_LOG, "DID isn't supported\n");
		rc = -ENODEV;
		goto err;
	}

	/* check that bit 15 of CAPID0 is 0 */
	pci_read_config_dword(dev0, CAPID0_C_OFF, &capid0);
	if (capid0 & BIT(15)) {
		sph_log_info(START_UP_LOG, "IBECC is not supported\n");
		goto out;
	}

	/* Map MCHBAR */
	pci_read_config_dword(dev0, MCHBAR_LO_OFF, &mchbar_addr_lo);
	pci_read_config_dword(dev0, MCHBAR_HI_OFF, &mchbar_addr_hi);

	mchbar_addr = ((u64)mchbar_addr_hi << 32) | mchbar_addr_lo;

	if (!(mchbar_addr & MCHBAR_EN)) {
		sph_log_info(START_UP_LOG, "MCHBAR is disabled\n");
		goto out;
	}

	mchbar = ioremap_nocache(mchbar_addr & MCHBAR_MASK, MCHBAR_SIZE);
	if (!mchbar) {
		sph_log_err(START_UP_LOG, "Failed to map mchbar\n");
		rc = -EIO;
		goto err;
	}

	/* Check whether IBECC is enabled */
	if (!(ioread32(mchbar + IBECC_ACTIVATE_OFF) & BIT(0))) {
		sph_log_info(START_UP_LOG, "IBECC disabled\n");
		goto unmap_and_out;
	}

	/* Read IBECC protected regions and create the list */
	i = 0;
	do {
		val = ioread32(mchbar + region_offs[i]);
		if ((val & IBECC_PROTECTED_RANGE_EN)) {

			reg = vmalloc(sizeof(struct mem_region));
			if (reg == NULL) {
				rc = -ENOMEM;
				goto failed_to_alloc;
			}

			list_add(&reg->list, &protected_regions);

			base_field = (val & IBECC_PROTECTED_RANGE_BASE_MASK) >> IBECC_PROTECTED_RANGE_BASE_OFF;
			mask_field = (val & IBECC_PROTECTED_RANGE_MASK_MASK) >> IBECC_PROTECTED_RANGE_MASK_OFF;

			/* The base field contains 14 MSB of 39 phys address */
			reg->start = (u64)base_field << 25;

			/* Size is deduced from the mask field */
			reg->size = BIT_ULL(ffs(mask_field) - 1 + 25);

			sph_log_debug(GENERAL_LOG, "prot reg %u start address %pad size 0x%zX\n", i, &reg->start, reg->size);

		}
		i++;

	} while (i < ARRAY_SIZE(region_offs));

unmap_and_out:
	iounmap(mchbar);
out:
	return 0;

failed_to_alloc:
	iounmap(mchbar);
	release_list(&protected_regions);
err:
	return rc;
}

static int parse_sph_mem(char *param)
{
	struct mem_region *reg;
	phys_addr_t start = 0;
	size_t size = 0;
	char *curr, *p, *pp;
	int rc;

	curr  = param;
	do {
		size = memparse(curr, &p);
		if (curr == p) {
			rc = -EINVAL;
			goto err;
		}

		if (*p == '@')
			start = memparse(p + 1, &pp);
		else {
			rc = -EINVAL;
			goto err;
		}

		if (p == pp) {
			rc = -EINVAL;
			goto err;
		}

		reg = vmalloc(sizeof(struct mem_region));
		if (reg == NULL) {
			rc = -ENOMEM;
			goto err;
		}

		reg->start = start;
		reg->size = size;
		list_add(&reg->list, &managed_regions);

		curr = strchr(curr, ',');
		if (!curr)
			break;
		curr++;
	} while (true);

	/* If no region provided */
	if (list_empty(&managed_regions)) {
		rc = -EINVAL;
		goto err;
	}

	return 0;
err:
	release_list(&managed_regions);
	return rc;

};

static int test_memory(void)
{
	int rc;

	num_of_mem_works = num_online_cpus();

	sph_log_info(START_UP_LOG, "Number of online cpus - %d\n", num_of_mem_works);

	mem_works = kmalloc_array(num_of_mem_works, sizeof(struct mem_work), GFP_KERNEL);
	if (mem_works == NULL) {
		rc = -ENOMEM;
		sph_log_err(START_UP_LOG, "Failed to create works\n");
		goto failed_to_create_works;
	}

	wq = create_workqueue("mem_set_wq");
	if (wq == NULL) {
		rc = -ENOMEM;
		sph_log_err(START_UP_LOG, "Failed to create wq\n");
		goto failed_to_create_wq;
	}

	rc = test_list(&unprotected_regions, false);
	if (rc != 0) {
		sph_log_err(START_UP_LOG, "Failed to test memory\n");
		goto failed_to_test_unprotected;
	}
	print_list("unprotected (after test)", &unprotected_regions);

	rc = test_list(&protected_managed_regions, true);
	if (rc != 0) {
		sph_log_err(START_UP_LOG, "Failed to test memory\n");
		goto failed_to_test_protected;
	}
	print_list("protected managed (after test)", &protected_managed_regions);

	destroy_workqueue(wq);
	kfree(mem_works);

	return 0;

failed_to_test_protected:
failed_to_test_unprotected:
	destroy_workqueue(wq);
failed_to_create_wq:
	kfree(mem_works);
failed_to_create_works:
	return rc;
}

int sph_memory_allocator_init_module(void)
{
	int rc;
	struct mem_region *reg;

	sph_log_debug(START_UP_LOG, "module (version %s) started\n", SPH_VERSION);

	if (sph_mem == NULL) {
		sph_log_err(START_UP_LOG, "sph_mem module parameter is empty\n");
		return -EINVAL;
	}

	rc = sph_create_sw_counters_info_node(NULL,
					       &sw_counters_set,
					       NULL,
					       &sw_counters_handle);
	if (rc) {
		sph_log_err(START_UP_LOG, "Failed to create sw counters info\n");
		goto failed_to_create_sw_counters_info;
	}

	rc = sph_create_sw_counters_values_node(sw_counters_handle,
						 0x0,
						 NULL,
						 &sw_counters);
	if (rc) {
		sph_log_err(START_UP_LOG, "Failed to create sw counters values\n");
		goto failed_to_create_sw_counters_values;
	}


	/* Parse module param and create list of managed memory regions */
	rc = parse_sph_mem(sph_mem);
	if (rc != 0) {
		sph_log_err(START_UP_LOG, "Failed to parse module param\n");
		goto failed_to_parse;
	};
	print_list("managed (module param)", &managed_regions);

	/* Read IBECC registers and create list of protected memory regions */
	rc = create_protected_regions();
	if (rc != 0) {
		sph_log_err(START_UP_LOG, "Failed to create protected regions\n");
		goto failed_to_create_protected;
	};
	print_list("protected (ibecc protected regions)", &protected_regions);

	/* create protected memory regions that are managed by memory allocator */
	rc = create_protected_managed_regions();
	if (rc != 0) {
		sph_log_err(START_UP_LOG, "Failed to create protected managed regions\n");
		goto failed_to_create_protected_managed;
	}
	print_list("protected & managed", &protected_managed_regions);

	/* Create unprotected managed memory regions */
	rc = create_unprotected_regions();
	if (rc != 0) {
		sph_log_err(START_UP_LOG, "Failed to create unprotected regions\n");
		goto failed_to_create_unprotected;
	}
	print_list("unprotected & managed", &unprotected_regions);

	/* test memory regions if requested */
	SPH_SW_COUNTER_SET(sw_counters, SW_COUNTER_BYTES_BAD_INDEX, 0);
	SPH_SW_COUNTER_SET(sw_counters, SW_COUNTER_PROT_BYTES_BAD_INDEX, 0);
	if (test) {
		rc = test_memory();
		if (rc != 0)
			goto failed_to_test_memory;
	}

	/* Create ion heap managing unprotected regions */
	SPH_SW_COUNTER_SET(sw_counters, SW_COUNTER_BYTES_TOTAL_INDEX, 0);
	if (!list_empty(&unprotected_regions)) {
		ecc_unprotected_heap_handle = ion_chunk_heap_setup(&unprotected_regions, ECC_NON_PROTECTED_HEAP_NAME);
		if (IS_ERR(ecc_unprotected_heap_handle)) {
			sph_log_err(START_UP_LOG, "Failed to create unprotected heap\n");
			rc = PTR_ERR(ecc_unprotected_heap_handle);
			ecc_unprotected_heap_handle = NULL;
			goto failed_to_create_unprotected_heap;
		} else
			sph_log_debug(START_UP_LOG, "unprotected heap successfully created\n");

		/* update s/w counter of total bytes in the unprotected regions */
		list_for_each_entry(reg, &unprotected_regions, list)
			SPH_SW_COUNTER_ADD(sw_counters, SW_COUNTER_BYTES_TOTAL_INDEX, reg->size);
	}

	/* If there are ecc protected regions, create ion heap managing them */
	SPH_SW_COUNTER_SET(sw_counters, SW_COUNTER_PROT_BYTES_TOTAL_INDEX, 0);
	if (!list_empty(&protected_managed_regions)) {
		ecc_protected_heap_handle = ion_chunk_heap_setup(&protected_managed_regions, ECC_PROTECTED_HEAP_NAME);
		if (IS_ERR(ecc_protected_heap_handle)) {
			sph_log_err(START_UP_LOG, "Failed to create protected heap\n");
			rc = PTR_ERR(ecc_protected_heap_handle);
			ecc_protected_heap_handle = NULL;
			goto failed_to_create_protected_heap;
		} else
			sph_log_debug(START_UP_LOG, "protected heap succesfully created\n");

		/* update s/w counter of total bytes in the protected regions */
		list_for_each_entry(reg, &protected_managed_regions, list)
			SPH_SW_COUNTER_ADD(sw_counters, SW_COUNTER_PROT_BYTES_TOTAL_INDEX, reg->size);
	}

	release_list(&managed_regions);
	release_list(&protected_regions);
	release_list(&protected_managed_regions);
	release_list(&unprotected_regions);

	return 0;

failed_to_create_protected_heap:
	ion_chunk_heap_remove(ecc_unprotected_heap_handle);
failed_to_create_unprotected_heap:
failed_to_test_memory:
	release_list(&unprotected_regions);
failed_to_create_unprotected:
	release_list(&protected_managed_regions);
failed_to_create_protected_managed:
	release_list(&protected_regions);
failed_to_create_protected:
	release_list(&managed_regions);
failed_to_parse:
	sph_remove_sw_counters_values_node(sw_counters);
failed_to_create_sw_counters_values:
	sph_remove_sw_counters_info_node(sw_counters_handle);
failed_to_create_sw_counters_info:
	return rc;
}

void sph_memory_allocator_cleanup(void)
{
	sph_log_debug(GO_DOWN_LOG, "Cleaning Up the Module\n");
	sph_remove_sw_counters_values_node(sw_counters);
	sph_remove_sw_counters_info_node(sw_counters_handle);
	if (ecc_unprotected_heap_handle)
		ion_chunk_heap_remove(ecc_unprotected_heap_handle);
	if (ecc_protected_heap_handle)
		ion_chunk_heap_remove(ecc_protected_heap_handle);
}
#else
int sph_memory_allocator_init_module(void)
{
	return 0;
}
void sph_memory_allocator_cleanup(void)
{

}
#endif
module_init(sph_memory_allocator_init_module);
module_exit(sph_memory_allocator_cleanup);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("SpringHill Card memory allocator");
MODULE_AUTHOR("Intel Corporation");
MODULE_VERSION(SPH_VERSION);
#ifdef DEBUG
MODULE_INFO(git_hash, SPH_GIT_HASH);
#endif
