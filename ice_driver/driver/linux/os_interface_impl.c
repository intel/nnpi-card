/*
 * NNP-I Linux Driver
 * Copyright (c) 2017-2019, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 */

#include <linux/device.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/fs.h>
#include <linux/printk.h>
#include <linux/jiffies.h>
#include <linux/timer.h>
#include <linux/workqueue.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/cdev.h>
#include <linux/dma-mapping.h>
#include <asm/cacheflush.h>
#include <linux/uaccess.h>
#include <asm/processor.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/miscdevice.h>
#include <linux/debugfs.h>
#include <asm/processor.h>
#include "os_interface.h"
#include "os_interface_impl.h"
#include "device_interface.h"
#include "cve_linux_internal.h"
#include "cve_project_internal.h"
#include "cve_driver_internal_funcs.h"
#include "cve_device.h"
#include "cve_driver_utils.h"
#include "cve_device_group.h"
#include "cve_context_process.h"
#include "cve_device_group.h"
#include "project_settings.h"
#include "version.h"
#include "ice_sw_counters.h"
#include "icedrv_sw_trace.h"
#include "ice_debug.h"
#include "project_device_interface.h"
#include "cve_firmware.h"

#ifdef IDC_ENABLE
/* For ssleep() */
#include <linux/delay.h>
#endif

#ifdef NULL_DEVICE_RING0
#include "dummy_icedc.h"
#endif

#include "ice_trace.h"
#include "ice_debug_event.h"
/* CONSTANTS */

#define CVE_DEVICE_INDEX_BASE 0
#define DEVICE_NAME MODULE_NAME"%d"
#define DISABLE_DEBUGFS_ICE_DUMP 1

/* DATA STRUCTURES */

struct cve_os_internal_timer_t {
	cve_os_timer_t handler;
	struct timer_list timer;
};

struct cve_dma_alloc_pages_desc {
	struct cve_dle_t list;
	struct page *page_addr;
	u32 order;
};

struct cve_dma_handle_private_data {
	u32 pages_nr;
	struct page **pages;
	struct cve_dma_alloc_pages_desc *desc_list;
};

/* STATIC FUNCTIONS PROTOTYPES */

static int cve_open_misc(struct inode *inode, struct file *file);
static int cve_close_misc(struct inode *inode, struct file *file);
static long cve_ioctl_misc(
		struct file *file, unsigned int cmd, unsigned long arg);

static int cve_dump_open(struct inode *inode, struct file *filp);
static ssize_t cve_dump_read(struct file *fp, char __user *user_buffer,
	size_t count, loff_t *position);
static int cve_dump_close(struct inode *inode, struct file *filp);


/* Module parameters */
int enable_llc;
u32 g_icemask;
u32 disable_embcb;
u32 core_mask;
u32 ice_fw_select;
u32 block_mmu;
u32 enable_b_step;
struct config cfg_default;

static u32 icemask_user;
static u32 enable_llc_config_via_axi_reg;
static u32 sph_soc;

static int ice_power_off_delay_ms = 1000;
static int enable_ice_drv_memleak;

module_param(enable_llc, int, 0);
MODULE_PARM_DESC(enable_llc, "Enable LLC usage in driver");

module_param(icemask_user, int, 0);
MODULE_PARM_DESC(icemask_user, "User provided ICE Mask");

module_param(disable_embcb, int, 0);
MODULE_PARM_DESC(disable_embcb, "Disable Embedded CB");

module_param(core_mask, int, 0);
MODULE_PARM_DESC(core_mask, "Disable TLC (0x1) | Disable IVP (0x2) | Disable ASIP0 (0x4) | Disable ASIP1 (0x8)");

module_param(enable_llc_config_via_axi_reg, int, 0);
MODULE_PARM_DESC(enable_llc_config_via_axi_reg, "Enable llc config via axi regsiter");

module_param(sph_soc, int, 0);
MODULE_PARM_DESC(sph_soc, "if set, means that driver is running on real SOC and not simulator");

module_param(ice_fw_select, int, 0);
MODULE_PARM_DESC(ice_fw_select, "Permit the use of rtl debug FW (0=rtl/release FW [default], 1=rtl/debug FW)");

module_param(ice_power_off_delay_ms, int, 0);
MODULE_PARM_DESC(ice_power_off_delay_ms, "Delay in ms to power off ICEs after WL completion(value less than 0 signifies no power off)");

module_param(block_mmu, int, 0);
MODULE_PARM_DESC(block_mmu, "Enables MMU Block/Unblock for each Doorbell");

module_param(enable_ice_drv_memleak, int, 0);
MODULE_PARM_DESC(enable_ice_drv_memleak, "If set to non-zero value memory leak detection in driver is enabled. Default is 0");

module_param(enable_b_step, int, 0);
MODULE_PARM_DESC(enable_b_step, "Enable B step flow in driver. Default 0 i.e disabled");

/* UITILITY FUNCTIONS */

/* MODULE LEVEL VARIABLES */

/* user interface functions */
static const struct file_operations m_cve_misc_fops = {
	.owner = THIS_MODULE,
	.open = cve_open_misc,
	.release = cve_close_misc,
	.unlocked_ioctl = cve_ioctl_misc,
#ifdef CONFIG_COMPAT
	.compat_ioctl = cve_ioctl_misc,
#endif
};

static struct miscdevice cve_misc_device = {
		.minor = MISC_DYNAMIC_MINOR,
		.name = "intel_misc_cve",
		.fops = &m_cve_misc_fops
};

static ssize_t show_misc_device_info(struct device *dev,
		struct device_attribute *attr,
		char *buf);
static DEVICE_ATTR(misc_device_info, S_IRUGO, show_misc_device_info, NULL);

static const struct file_operations fops_cve_dump = {
		.open = cve_dump_open,
		.read = cve_dump_read,
		.release =  cve_dump_close,
};

static int cve_dump_close(struct inode *inode, struct file *filp)
{
#ifndef DISABLE_DEBUGFS_ICE_DUMP
	struct di_cve_dump_buffer *cve_dump_buf = filp->private_data;

	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"[DUMP] Close Dump\n");
	cve_dump_buf->is_cve_dump_on_error = 0;
	module_put(THIS_MODULE);
#endif
	return 0;
}

static int cve_dump_open(struct inode *inode, struct file *filp)
{
#ifndef DISABLE_DEBUGFS_ICE_DUMP
	struct di_cve_dump_buffer *cve_dump_buf;
	int retval = 0;

	try_module_get(THIS_MODULE);

	filp->private_data = inode->i_private;
	cve_dump_buf = filp->private_data;
	cve_dump_buf->is_allowed_tlc_dump = 1;

	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"[DUMP] Wait Dump\n");

	/* wait dump content */
	retval = cve_os_block_interruptible_infinite(
			&cve_dump_buf->dump_wqs_que,
			(cve_dump_buf->is_cve_dump_on_error));
	if (retval == -ERESTARTSYS) {
		module_put(THIS_MODULE);
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"[DUMP] wait interrupted\n");
	goto out;

	}

	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"[DUMP] Wait Dump Done\n");
out:
	return retval;
#endif
	return 0;
}


/* read file operation */
static ssize_t cve_dump_read(struct file *fp,
	char __user *user_buffer, size_t count, loff_t *position)
{
#ifndef DISABLE_DEBUGFS_ICE_DUMP
	struct di_cve_dump_buffer *cve_dump_buf =
		fp->private_data;

	if (cve_dump_buf->cve_dump_buffer) {
		return simple_read_from_buffer(
			user_buffer, count, position,
			cve_dump_buf->cve_dump_buffer,
			cve_dump_buf->size_bytes);
	} else {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"[DUMP] Invalid cve dump buffer pointer\n");
		return -EINVAL;
	}
#endif
	return 0;
}

#define CLOS0_MSR 0xC90
#define CLOS1_MSR 0xC91
#define CLOS2_MSR 0xC92
#define PQR_ASSOC 0xC8F

void ice_os_read_clos(void *pmclos)
{
	struct clos_manager *mclos = (struct clos_manager *)pmclos;

	mclos->clos_default[ICE_CLOS_0] = native_read_msr(CLOS0_MSR);
	cve_os_log(CVE_LOGLEVEL_INFO, "CLOS0: 0x%llx\n",
		mclos->clos_default[ICE_CLOS_0]);
	mclos->clos_default[ICE_CLOS_1] = native_read_msr(CLOS1_MSR);
	cve_os_log(CVE_LOGLEVEL_INFO, "CLOS1: 0x%llx\n",
		mclos->clos_default[ICE_CLOS_1]);
	mclos->clos_default[ICE_CLOS_2] = native_read_msr(CLOS2_MSR);
	cve_os_log(CVE_LOGLEVEL_INFO, "CLOS2: 0x%llx\n",
		mclos->clos_default[ICE_CLOS_2]);
	mclos->pqr_default = native_read_msr(PQR_ASSOC);
	cve_os_log(CVE_LOGLEVEL_INFO, "PQR_ASSOC: 0x%llx\n",
		 mclos->pqr_default);
}

void ice_os_set_clos(void *pmclos)
{
	u32 lo, hi;
	u32 clos_shift;
	u64 val;
	struct clos_manager *mclos = (struct clos_manager *)pmclos;

	/* CLOS 0 */
	lo = (1 << mclos->clos_size[ICE_CLOS_0]) - 1;
	hi = 0;
	native_write_msr(CLOS0_MSR, lo, hi);
	val = native_read_msr(CLOS0_MSR);
	cve_os_log(CVE_LOGLEVEL_INFO, "CLOS0: Write=0x%x, Read=0x%llx\n",
		lo, val);

	/* CLOS 1 */
	clos_shift = (24 - mclos->clos_size[ICE_CLOS_1]);
	lo = ((1 << mclos->clos_size[ICE_CLOS_1]) - 1) << clos_shift;
	hi = 0;
	native_write_msr(CLOS1_MSR, lo, hi);
	val = native_read_msr(CLOS1_MSR);
	cve_os_log(CVE_LOGLEVEL_INFO, "CLOS1: Write=0x%x, Read=0x%llx\n",
		lo, val);

	/* CLOS 2 */
	clos_shift = mclos->clos_size[ICE_CLOS_0];
	lo = ((1 << mclos->clos_size[ICE_CLOS_2]) - 1) << clos_shift;
	hi = 0;
	native_write_msr(CLOS2_MSR, lo, hi);
	val = native_read_msr(CLOS2_MSR);
	cve_os_log(CVE_LOGLEVEL_INFO, "CLOS2: Write=0x%x, Read=0x%llx\n",
		lo, val);

	/* IA32_PQR_ASSOC.COS */
	lo = 0x0;
	hi = 0x0;
	native_write_msr(PQR_ASSOC, lo, hi);
	val = native_read_msr(PQR_ASSOC);
	cve_os_log(CVE_LOGLEVEL_INFO, "IA32_PQR_ASSOC=0x%llx\n",
		val);

}

void ice_os_reset_clos(void *pmclos)
{
	u32 lo, hi;
	u64 val;
	struct clos_manager *mclos = (struct clos_manager *)pmclos;

	lo = mclos->clos_default[ICE_CLOS_0] & 0xFFFFFFFF;
	hi = (mclos->clos_default[ICE_CLOS_0] >> 32) & 0xFFFFFFFF;
	native_write_msr(CLOS0_MSR, lo, hi);
	val = native_read_msr(CLOS0_MSR);
	cve_os_log(CVE_LOGLEVEL_INFO, "CLOS0: Write=0x%llx, Read=0x%llx\n",
		mclos->clos_default[ICE_CLOS_0], val);

	lo = mclos->clos_default[ICE_CLOS_1] & 0xFFFFFFFF;
	hi = (mclos->clos_default[ICE_CLOS_1] >> 32) & 0xFFFFFFFF;
	native_write_msr(CLOS1_MSR, lo, hi);
	val = native_read_msr(CLOS1_MSR);
	cve_os_log(CVE_LOGLEVEL_INFO, "CLOS1: Write=0x%llx, Read=0x%llx\n",
		mclos->clos_default[ICE_CLOS_1], val);

	lo = mclos->clos_default[ICE_CLOS_2] & 0xFFFFFFFF;
	hi = (mclos->clos_default[ICE_CLOS_2] >> 32) & 0xFFFFFFFF;
	native_write_msr(CLOS2_MSR, lo, hi);
	val = native_read_msr(CLOS2_MSR);
	cve_os_log(CVE_LOGLEVEL_INFO, "CLOS2: Write=0x%llx, Read=0x%llx\n",
		mclos->clos_default[ICE_CLOS_2], val);

	lo = mclos->pqr_default & 0xFFFFFFFF;
	hi = (mclos->pqr_default >> 32) & 0xFFFFFFFF;
	native_write_msr(PQR_ASSOC, lo, hi);
	val = native_read_msr(PQR_ASSOC);
	cve_os_log(CVE_LOGLEVEL_INFO,
		"IA32_PQR_ASSOC: Write=0x%llx, Read=0x%llx\n",
		mclos->pqr_default, val);
}

uint64_t get_llc_freq(void)
{
	return native_read_msr(LLC_FREQ_MSR);
}

int set_llc_freq(void *llc_freq_config)
{
	u32 lo, hi, msr, freq_min, freq_max, val_low, val_high;
	u64 val;
	int retval = 0;

	struct ice_hw_config_llc_freq *freq_config =
			(struct ice_hw_config_llc_freq *)llc_freq_config;

	msr = LLC_FREQ_MSR;
	val = native_read_msr(msr);
	val_high = val >> 32; /* higher 32 bits of msr */
	val_low = val & 0xFFFFFFFF; /* lower 32 bits of msr */

	/* llc freq msr bit config
	 * 0-6 -> max_ratio
	 * 7 ->reserved
	 * 8-14 -> min_ratio
	 * 15-63 reserved
	 */

	hi = val_high;

	if (freq_config->llc_freq_min > 0)
		freq_min = (freq_config->llc_freq_min /
				LLC_FREQ_DIVIDER_FACTOR);
	else
		freq_min = min_llc_ratio(val_low);

	if (freq_config->llc_freq_max > 0)
		freq_max = (freq_config->llc_freq_max /
				LLC_FREQ_DIVIDER_FACTOR);
	else
		freq_max = max_llc_ratio(val_low);

	val_low = val_low & LLC_MASK;

	if (freq_min > freq_max) {
		cve_os_log_default(CVE_LOGLEVEL_ERROR,
			"Failed to write llc_freq Min:%u MHz Max:%u MHz, Min freq should be less than or equal to Max freq\n ",
				(freq_min * LLC_FREQ_DIVIDER_FACTOR),
				(freq_max * LLC_FREQ_DIVIDER_FACTOR));
		retval = ICEDRV_KERROR_INVAL_LLC_FREQ;
		return retval;
	}

	lo = ((freq_min << 8 | freq_max) | val_low);
	native_write_msr(msr, lo, hi);

	val = native_read_msr(msr);
	val_low = val & 0xFFFFFFFF;

	if ((val_low & ~LLC_MASK) == (freq_min << 8 | freq_max)) {
		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"llc frequency set to Min:%u MHz Max:%u MHz ( msr: 0x%x)\n",
				(freq_min * LLC_FREQ_DIVIDER_FACTOR),
				(freq_max * LLC_FREQ_DIVIDER_FACTOR), msr);
		retval = 0;
	} else {
		retval = ICEDRV_KERROR_SET_LLC_HW;
		cve_os_log_default(CVE_LOGLEVEL_ERROR,
			"Failed to write llc_freq Min:%u MHz Max:%u MHz, readback value of msr:0x%x is 0x%llx\n ",
				(freq_min * LLC_FREQ_DIVIDER_FACTOR),
				(freq_max * LLC_FREQ_DIVIDER_FACTOR), msr, val);
	}
	return retval;
}

/* INTERFACE FUNCTIONS */
/* module init / cleanup */

u32 cve_os_cve_devices_nr(void)
{
#if defined(FPGA)
	/* FPGA has only 1 cve device */
	return 1;
#else
	return MAX_CVE_DEVICES_NR;
#endif
}

uint32_t get_process_pid(void)
{
	return current->pid;
}
int cve_os_interface_init(void)
{
	FUNC_ENTER();

	FUNC_LEAVE();
	return 0;
}

void cve_os_interface_cleanup(void)
{
	FUNC_ENTER();
	FUNC_LEAVE();
}

/* event */

int cve_os_init_wait_que(cve_os_wait_que_t *que)
{
	FUNC_ENTER();
	init_waitqueue_head(que);
	FUNC_LEAVE();
	return 0;
}

void cve_os_wakeup(cve_os_wait_que_t *que)
{
	FUNC_ENTER();
	wake_up_interruptible_all(que);
	FUNC_LEAVE();
}

/* semaphore */

int cve_os_lock_init(cve_os_lock_t *lock)
{
	FUNC_ENTER();
	sema_init(lock, 1);
	FUNC_LEAVE();
	return 0;
}

int cve_os_lock(cve_os_lock_t *lock, int is_interruptible)
{
	int ret = 0;

	FUNC_ENTER();

	if (is_interruptible)
		ret = down_interruptible(lock);
	else
		down(lock);

	FUNC_LEAVE();
	return ret;
}

void cve_os_unlock(cve_os_lock_t *lock)
{
	FUNC_ENTER();
	up(lock);
	FUNC_LEAVE();
}

void cve_os_print_user_buffer(void **pages,
		u32 pages_nr,
		void *buffer_addr,
		u32 size_bytes,
		const char *buf_name)
{
	void *vaddr;
	unsigned long offset = ((unsigned long)buffer_addr) & ~OS_PAGE_MASK;

	vaddr = vmap((struct page **)pages,
			pages_nr,
			VM_MAP,
			PAGE_KERNEL);

	if (vaddr == NULL) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"vmap failed cannot print user buffer\n");
		goto out;
	}

	cve_utils_print_buffer(vaddr + offset, size_bytes, buf_name,
			vaddr + offset);
	vunmap(vaddr);
out:
	return;
}

void cve_os_print_kernel_buffer(
		void *buffer_addr,
		u32 size_bytes,
		const char *buf_name)
{

	cve_utils_print_buffer(buffer_addr, size_bytes,
			buf_name, buffer_addr);
}

void cve_os_print_shared_buffer(
		void *buffer_addr,
		u32 size_bytes,
		const char *buf_name)
{

	cve_utils_print_buffer(buffer_addr, size_bytes,
			buf_name, buffer_addr);
}

/* timers. */

int cve_os_timer_create(cve_os_timer_function handler,
		cve_os_timer_t *out_timer)
{
	int retval = CVE_DEFAULT_ERROR_CODE;
	struct cve_os_internal_timer_t *timer = NULL;

	FUNC_ENTER();
	retval = OS_ALLOC_ZERO(sizeof(*timer), (void **)&timer);
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "kmalloc failed: %d\n", retval);
		goto out;
	}

	/* success */
	timer->handler = handler;
	*out_timer = timer;
	retval = 0;
out:
	FUNC_LEAVE();
	return retval;
}

#if 0
int cve_os_timer_set(cve_os_timer_t timer,
		cve_timer_period_t usecs,
		cve_timer_param_t param)
{
	struct cve_os_internal_timer_t *_t =
			(struct cve_os_internal_timer_t *)timer;
	struct timer_list *t = &_t->timer;

	FUNC_ENTER();
	if (usecs == 0) {
		/* deactivate the timer */
		del_timer(t);
	} else {
		init_timer(t);
		t->function = _t->handler;
		t->data = param;
		t->expires = usecs_to_jiffies(usecs);
		add_timer(t);
	}
	FUNC_LEAVE();
	return 0;
}

void cve_os_timer_remove(cve_os_timer_t timer)
{
	struct cve_os_internal_timer_t *t =
			(struct cve_os_internal_timer_t *)timer;

	FUNC_ENTER();
	del_timer(&t->timer);
	OS_FREE(t, sizeof(*t));
	FUNC_LEAVE();
}
#endif
/* access user memory */

int cve_os_read_user_memory(void *base_address,
		u32 size_bytes,
		void *kernel_copy)
{
	unsigned long remaining = copy_from_user(kernel_copy,
			base_address,
			size_bytes);
	return (remaining != 0) ? -EACCES : 0;
}

int cve_os_write_user_memory(void *base_address,
		u32 size_bytes,
		void *kernel_copy)
{
	unsigned long remaining = copy_to_user(base_address,
			kernel_copy,
			size_bytes);
	return (remaining != 0) ? -EACCES : 0;
}

int cve_os_read_user_memory_64(u64 *user_addr, u64 *val)
{
	return copy_from_user(val, user_addr, sizeof(*val)) ? -EACCES : 0;
}

int cve_os_write_user_memory_64(u64 *user_addr, u64 val)
{
	/* user_addr may be unaligned, put_user assumes aligned address */
	return copy_to_user(user_addr, &val, sizeof(val)) ? -EACCES : 0;
}

int cve_os_write_user_memory_32(u32 *user_addr, u32 val)
{
	/* user_addr may be unaligned, put_user assumes aligned address */
	return copy_to_user(user_addr, &val, sizeof(val)) ? -EACCES : 0;
}

/* memory allocation */
#ifdef ENABLE_MEM_DETECT
struct ice_drv_memleak *g_leak_list;
u32 mem_leak_count;
#endif

int __cve_os_malloc_zero(u32 size_bytes, void **out_ptr)
{
	void *p = NULL;

	FUNC_ENTER();
	p = kzalloc(size_bytes, GFP_KERNEL);
	*out_ptr = p;

#ifdef ENABLE_MEM_DETECT
	if (enable_ice_drv_memleak && p) {
		struct ice_drv_memleak *leak;

		leak = kzalloc(sizeof(struct ice_drv_memleak), GFP_KERNEL);
		if (leak) {
			leak->caller_fn = __builtin_return_address(0);
			leak->caller_fn2 = __builtin_return_address(1);
			leak->va = p;
			leak->size = size_bytes;
			cve_dle_add_to_list_before(g_leak_list, list, leak);
		} else {
			cve_os_log(CVE_LOGLEVEL_ERROR,
			   "##failed in allocating memory for book keeping\n");
		}
		mem_leak_count++;
	}
#endif

	FUNC_LEAVE();
	return (!p) ? -ENOMEM : 0;
}

int __cve_os_free(void *base_address,
		u32 size_bytes)
{
	FUNC_ENTER();

#ifdef ENABLE_MEM_DETECT
	if (enable_ice_drv_memleak) {
		struct ice_drv_memleak *leak;

		leak = cve_dle_lookup(g_leak_list, list, va, base_address);
		if (leak) {
			cve_dle_remove_from_list(g_leak_list, list, leak);
			kfree(leak);
			mem_leak_count--;
		} else {
			cve_os_log(CVE_LOGLEVEL_ERROR,
			   "##FATAL VA:0x%p not allocated\n", base_address);
		}
	}
#endif

	kfree(base_address);
	FUNC_LEAVE();

	return 0;
}

static void cve_os_clean_dma_sg_alloc_pages(
		struct cve_dma_alloc_pages_desc *allocs_descs)
{
	while (allocs_descs) {
		struct cve_dma_alloc_pages_desc *alloc_desc = allocs_descs;

		cve_dle_remove_from_list
			(allocs_descs, list, alloc_desc);
		__free_pages(alloc_desc->page_addr, alloc_desc->order);
		cve_os_log(CVE_LOGLEVEL_DEBUG,
				"free page %p with order %u\n",
				alloc_desc->page_addr,
				alloc_desc->order);
		OS_FREE(alloc_desc, sizeof(*alloc_desc));
	}
}

static int cve_os_alloc_non_ctg_pages(
		struct device *dev,
		u32 pages_nr,
		struct page **pages,
		struct cve_dma_alloc_pages_desc **out_desc_list)
{
	int ret = CVE_DEFAULT_ERROR_CODE;
	int order;
	struct page *page = NULL;
	struct cve_dma_alloc_pages_desc *desc_list = NULL;
	struct cve_dma_alloc_pages_desc *new_alloc = NULL;
	u64 dma_mask = dma_get_mask(dev);
	u32 cur_alloc_pages = 0;
	u32 remaining_pages = 0;
	int first_bit_location = 0;
	int i;

	/* ffs returns the least significant bit position in the given number.
	 * example: 0xA4 = 10100100, ffs(0xA4) = 3
	 */
	remaining_pages = pages_nr;
	first_bit_location = ffs(remaining_pages);
	order = min(first_bit_location - 1, MAX_ORDER - 1);

	/* DMA Bit mask is now 35 bits */
	if (dma_mask < DMA_BIT_MASK(35)) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"dma mask is lower than 35. Today we don't support this option\n");
		goto out;
	} else if (dma_mask > DMA_BIT_MASK(35)) {
		cve_os_log(CVE_LOGLEVEL_WARNING,
				"dma mask is higher than 35. Today we allocate only 35bit dma allocations\n");
	}

	/* The allocation algorithm will iterate over the least
	 * significant bits (LSB) of the pages_nr. on every iteration
	 * it will try to allocate the number of pages that
	 * represented by this bit.
	 * For example:
	 * - alloc_size=0X13340 => pages_nr=19 => 19=10011
	 * - iterations:
	 *   ffs(19) = 1 ==> alloc_pages(,,0)
	 *   ffs(19-1) = ffs(18) = 2 ==> alloc_pages(,,1)
	 *   ffs(18-2) = ffs(16) = 5 ==> alloc_pages(,,4)
	 * In case order(LSB) >= MAX_ORDER, MAX_ORDER will be allocated
	 */
	do {
		cur_alloc_pages = 1 << order;
		/* allocate pages using the kernel API.
		 * Note: there is no specific flag to allocate pages for device
		 * with irregular bit mask (bit mask != 16,32,64).
		 * Therefore we use 32 bit mask (GFP_DMA32).
		 */
		page = alloc_pages_node(dev_to_node(dev),
				GFP_DMA32,
				order);

		/* check if allocated pages chunk is valid.
		 * Today we are not checking that pages are dma-able as we alloc
		 * using the GFP_DMA32.
		 */
		if (!page) {
			cve_os_log(CVE_LOGLEVEL_WARNING,
					"alloc_pages_node failed for order :%d\n",
					order);
			order = order - 1;
		} else {
			/* create a new alloc metadata and add to list */
			ret = OS_ALLOC_ZERO(sizeof(*new_alloc),
					(void **)&new_alloc);
			if (ret != 0) {
				__free_pages(page, order);
				cve_os_log(CVE_LOGLEVEL_ERROR,
					"OS_ALLOC_ZERO failed %d\n", ret);
				goto alloc_failure;
			}

			new_alloc->order = order;
			new_alloc->page_addr = page;
			cve_dle_add_to_list_after(desc_list,
					list,
					new_alloc);

			/* set page addresses in list of pages.
			 * (pages_nr-remaining_pages) is the total number
			 * of pages that were allocated before the current
			 * allocation.
			 */
			for (i = 0 ; i < cur_alloc_pages ; ++i)
				pages[pages_nr - remaining_pages + i] =
						&page[i];

			remaining_pages = remaining_pages - cur_alloc_pages;
			cve_os_log(CVE_LOGLEVEL_DEBUG,
					"New pages were allocated. AllocatedPagesCount=%d RemainingPagesCount=%d page:%p order:%d\n",
					cur_alloc_pages,
					remaining_pages,
					page,
					order);
			if (remaining_pages > 0) {
				first_bit_location = ffs(remaining_pages);
				order = min(first_bit_location - 1,
						MAX_ORDER - 1);
			}
		}
	} while (remaining_pages > 0 && order >= 0);

	if (order < 0) {
		ret = -ENOMEM;
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"Failed to allocate %d pages\n",
				pages_nr);
		goto alloc_failure;
	}

	/* success */
	*out_desc_list = desc_list;

	ret = 0;
	goto out;

alloc_failure:
	cve_os_clean_dma_sg_alloc_pages(desc_list);

out:
	return ret;
}

/**/
static u32 align_to_nearest_power_of_2(u32 size)
{
	u32 aligned_size = 1;

	/* Size must be <= 2GB in order to be able to find nearest power of 2*/
	while ((aligned_size < size) && (aligned_size != (1 << 31)))
		aligned_size *= 2;

	ASSERT(aligned_size >= size);
	return aligned_size;
}

int __cve_os_alloc_dma_sg(struct cve_device *cve_dev,
		u32 size_of_elem,
		u32 num_of_elem,
		struct cve_dma_handle *out_dma_handle)
{
	int ret = CVE_DEFAULT_ERROR_CODE;
	struct sg_table *sgt = NULL;
	int r_nents;
	struct cve_dma_handle_private_data *priv_data = NULL;
	struct device *dev = to_cve_os_device(cve_dev)->dev;
	u32 alloc_size = size_of_elem * num_of_elem;
	u32 actual_size = size_of_elem * num_of_elem;
	u32 pages_nr, actual_page_nr;

#ifndef FPGA
	/* all allocations should be cache line aligned, if user
	 * request to allocate buffer that is not cache line aligned,
	 * we add some padding and allocate cache line aligned buffer.
	 * This operation is transparent to user, and intended
	 * only for cache maintenance operation of ARC processor
	 */
	alloc_size = (alloc_size + L2_CACHE_BYTES - 1) & L2_CACHE_LINE_MASK;
#endif
	/* Following 2 lines will find the nearest boundary of given PageSize */
	alloc_size += (1 << ICE_DEFAULT_PAGE_SHIFT);
	alloc_size = (alloc_size & ~((1 << OS_PAGE_SHIFT) - 1));
	/* Align size with nearest power of 2 so that SG list has one entry */
	alloc_size = align_to_nearest_power_of_2(alloc_size);

	pages_nr = bytes_to_os_pages(alloc_size);
	actual_page_nr = bytes_to_os_pages(actual_size);

#if !defined CONFIG_ARCH_HAS_SG_CHAIN && !defined FPGA
	/* Check if sg chaining is defined in kernel.
	 * if not there is limit of
	 * PAGE_SIZE/sizeof(struct scatterlist) entries on SGT.
	 * Which can lead to failures in page allocations.
	 */
#warning "CONFIG_ARCH_HAS_SG_CHAIN is not defined in kernel." \
		"it may lead to failures in allocations"
#endif
	/* allocate private data */
	ret = OS_ALLOC_ZERO(sizeof(*priv_data),
			(void **)&priv_data);
	if (ret != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"OS_ALLOC_ZERO failed %d\n", ret);
		goto out;
	}

	/* create a list of pages that is filled with pages that were
	 * allocated in cve_os_alloc_non_ctg_pages function
	 */
	ret = OS_ALLOC_ZERO(sizeof(*priv_data->pages) * pages_nr,
			(void **)&priv_data->pages);
	if (ret != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"OS_ALLOC_ZERO failed %d\n", ret);
		goto failed_to_alloc_pr_data_pages;
	}

	cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Try to allocate %u bytes\n",
			alloc_size);

	ret = cve_os_alloc_non_ctg_pages(
			dev,
			pages_nr,
			priv_data->pages,
			&priv_data->desc_list);
	if (ret != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"cve_os_alloc_non_ctg_pages failed %d\n",
				ret);
		goto failed_to_alloc_non_ctg_pages;
	}

	/* Ensure that Physical address is aligned with given Page size */
	ASSERT(!(page_to_phys(priv_data->pages[0]) &
			((1ULL << ICE_DEFAULT_PAGE_SHIFT) - 1)));

	priv_data->pages_nr = pages_nr;

	cve_os_log(CVE_LOGLEVEL_DEBUG,
			"PA=0x%llx, ActualPagesCount=%d, PagesCount=%d, ActualSize=%d, Size=%d\n",
			(page_to_phys(priv_data->pages[0])),
			 actual_page_nr, pages_nr,
			 actual_size, alloc_size);

	/* allocate sgt */
	ret = OS_ALLOC_ZERO(sizeof(*sgt), (void **)&sgt);
	if (ret != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"OS_ALLOC_ZERO failed %d\n", ret);
		goto failed_to_alloc_sgt;
	}

	cve_os_log(CVE_LOGLEVEL_DEBUG,
			"SGT was allocated sgt:%p, allocated_pages %d\n",
			sgt, pages_nr);

	/* create sgt from the pages */
	ret = sg_alloc_table_from_pages(sgt,
			priv_data->pages,
			actual_page_nr,
			0,
			actual_size,
			GFP_KERNEL);
	if (ret != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"sg_alloc_table_from_pages failed\n");
		goto failed_to_alloc_table_from_pages;
	}

	cve_os_log(CVE_LOGLEVEL_DEBUG,
			"DMA_SGT was allocated. PA=0x%llx\n",
			sgt->sgl->dma_address);

	/* map the sgt to device */
	r_nents = dma_map_sg(dev,
			sgt->sgl,
			sgt->nents,
			DMA_BIDIRECTIONAL);
	if (r_nents != sgt->nents) {
		ret = -EFAULT;
		cve_os_log(CVE_LOGLEVEL_ERROR, "dma_map_sg failed\n");
		goto failed_to_map_sg;
	}

	cve_os_log(CVE_LOGLEVEL_DEBUG,
			"dma_map_sg completed successfully\n");

	/* success */
	out_dma_handle->mem_type = CVE_MEMORY_TYPE_KERNEL_SG;
	out_dma_handle->mem_handle.sgt = sgt;
	out_dma_handle->priv = (void *)priv_data;

	ret = 0;
	goto out;

failed_to_map_sg:
	sg_free_table(sgt);
failed_to_alloc_table_from_pages:
	OS_FREE(sgt, sizeof(*sgt));
failed_to_alloc_sgt:
	cve_os_clean_dma_sg_alloc_pages(priv_data->desc_list);
failed_to_alloc_non_ctg_pages:
	OS_FREE(priv_data->pages, sizeof(*priv_data->pages) * pages_nr);
failed_to_alloc_pr_data_pages:
	OS_FREE(priv_data, sizeof(*priv_data));
out:
	return ret;
}

void __cve_os_free_dma_sg(struct cve_device *cve_dev,
		u32 size,
		struct cve_dma_handle *dma_handle)
{
	struct sg_table *sgt = dma_handle->mem_handle.sgt;
	struct cve_dma_handle_private_data *priv_data =
			(struct cve_dma_handle_private_data *)dma_handle->priv;

	/* unmap the sg that was already mapped to device */
	dma_unmap_sg(to_cve_os_device(cve_dev)->dev,
			sgt->sgl,
			sgt->nents,
			DMA_BIDIRECTIONAL);

	cve_os_log(CVE_LOGLEVEL_DEBUG,
				"dma_unmap_sg completed successfully\n");

	/* Remove all pages that were allocated for the SGT */
	cve_os_clean_dma_sg_alloc_pages(priv_data->desc_list);

	/* Release pages array */
	OS_FREE(priv_data->pages, sizeof(*priv_data->pages)
			* priv_data->pages_nr);

	/* release private data*/
	OS_FREE(priv_data, sizeof(*priv_data));

	/* remove the sgt */
	sg_free_table(sgt);
	OS_FREE(sgt, sizeof(*sgt));
	cve_os_log(CVE_LOGLEVEL_DEBUG,
			"free_sgt %p\n", sgt);
}

void *cve_os_vmap_dma_handle(struct cve_dma_handle *dma_handle)
{
	struct cve_dma_handle_private_data *priv_data =
			(struct cve_dma_handle_private_data *)dma_handle->priv;

	return vmap(priv_data->pages,
			priv_data->pages_nr,
			VM_MAP,
			PAGE_KERNEL);
}

void cve_os_vunmap_dma_handle(void *vaddr)
{
	vunmap(vaddr);
}

int cve_os_dma_copy_from_buffer(struct cve_dma_handle *dma_handle,
		void *buffer,
		u32 size_bytes)
{
	size_t copied_bytes;

	copied_bytes = sg_copy_from_buffer(
			dma_handle->mem_handle.sgt->sgl,
			dma_handle->mem_handle.sgt->nents,
			buffer, size_bytes);

	return (copied_bytes == size_bytes) ? 0 : CVE_DEFAULT_ERROR_CODE;
}

void cve_os_pause(void)
{
	cpu_relax();
}

/* mmio management and access */
u32 cve_os_read_icemask_bar0(struct idc_device *idc_dev, bool force_print)
{
	struct cve_os_device *os_dev;
	u32 *mmio_addr;
	u32 val, offset_bytes;

	offset_bytes = cfg_default.bar0_mem_icemasksts_offset;

	os_dev = container_of(idc_dev, struct cve_os_device, idc_dev);
	mmio_addr = os_dev->cached_mmio_base.iobase[0] + offset_bytes;

#ifdef NULL_DEVICE_RING0
	val = dummy_ioread32(mmio_addr);
#else
	val = ioread32(mmio_addr);
#endif

	cve_os_log(force_print ? CVE_LOGLEVEL_ERROR : CVE_LOGLEVEL_DEBUG,
		"[MMIO] ICEMASK reg:%s offset:0x%x value:0x%x mmio_addr=%p\n",
		get_idc_regs_str(offset_bytes),
		offset_bytes,
		val,
		mmio_addr);
	return val;
}

u32 cve_os_read_idc_mmio_bar_nr(struct cve_device *cve_dev,
		u32 bar_nr,
		u32 offset_bytes,
		bool force_print)
{
	struct cve_os_device *os_dev;
	u32 *mmio_addr;
	u32 val;

	os_dev = to_cve_os_device(cve_dev);
	mmio_addr = os_dev->cached_mmio_base.iobase[bar_nr] + offset_bytes;
#ifdef NULL_DEVICE_RING0
	val = dummy_ioread32(mmio_addr);
#else
	val = ioread32(mmio_addr);
#endif

	cve_os_log(force_print ? CVE_LOGLEVEL_ERROR : CVE_LOGLEVEL_DEBUG,
		"[MMIO] reading from BAR%d reg:%s offset:0x%x value:0x%x mmio_addr=%p\n",
		bar_nr,
		get_idc_regs_str(offset_bytes),
		offset_bytes,
		val,
		mmio_addr);
	return val;
}

u32 cve_os_read_mmio_32_bar_nr(struct cve_device *cve_dev,
		u32 bar_nr,
		u32 offset_bytes,
		bool force_print)
{
	struct cve_os_device *os_dev;
	u32 *mmio_addr;
	u32 val;

	os_dev = to_cve_os_device(cve_dev);
#ifdef IDC_ENABLE
	mmio_addr = os_dev->cached_mmio_base.iobase[bar_nr] +
				ICE_OFFSET(cve_dev->dev_index) + offset_bytes;
#else
	mmio_addr = os_dev->cached_mmio_base.iobase[bar_nr] + offset_bytes;
#endif

#ifdef NULL_DEVICE_RING0
	val = dummy_ioread32(mmio_addr);
#else
	val = ioread32(mmio_addr);
#endif

	cve_os_dev_log(force_print ? CVE_LOGLEVEL_ERROR : CVE_LOGLEVEL_DEBUG,
			cve_dev->dev_index,
		"[MMIO] reading from BAR%d reg:%s offset:0x%x value:0x%x mmio_addr=%p\n",
		bar_nr,
		get_regs_str(offset_bytes),
		offset_bytes,
		val,
		mmio_addr);
	return val;
}

void cve_os_write_idc_mmio_bar_nr(struct cve_device *cve_dev,
		u32 bar_nr,
		u32 offset_bytes,
		u64 value)
{
	struct cve_os_device *os_dev;
	u32 *mmio_addr;

	os_dev = to_cve_os_device(cve_dev);
	mmio_addr = os_dev->cached_mmio_base.iobase[bar_nr] + offset_bytes;

	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"[MMIO] writing to BAR%d reg:%s offset:0x%x value:0x%llx mmio_addr=%p\n",
		bar_nr,
		get_idc_regs_str(offset_bytes),
		offset_bytes,
		(unsigned long long)value,
		mmio_addr);

#ifdef NULL_DEVICE_RING0
	dummy_iowrite32(value, mmio_addr);
#else
	iowrite32(value, mmio_addr);
#endif
}

void cve_os_write_mmio_32_bar_nr(struct cve_device *cve_dev,
		u32 bar_nr,
		u32 offset_bytes,
		u32 value)
{
	struct cve_os_device *os_dev;
	u32 *mmio_addr;

	os_dev = to_cve_os_device(cve_dev);
#ifdef IDC_ENABLE
	mmio_addr = os_dev->cached_mmio_base.iobase[bar_nr] +
				ICE_OFFSET(cve_dev->dev_index) + offset_bytes;
#else
	mmio_addr = os_dev->cached_mmio_base.iobase[bar_nr] + offset_bytes;
#endif
	cve_os_dev_log(CVE_LOGLEVEL_DEBUG,
			cve_dev->dev_index,
		"[MMIO] writing to BAR%d reg:%s offset:0x%x value:0x%x mmio_addr=%p\n",
		bar_nr,
		get_regs_str(offset_bytes),
		offset_bytes,
		value,
		mmio_addr);

#ifdef NULL_DEVICE_RING0
	dummy_iowrite32(value, mmio_addr);
#else
	iowrite32(value, mmio_addr);
#endif
}

/* atomics */

u64 cve_os_atomic_increment_64(atomic64_t *n)
{
	return (u64)atomic64_inc_return(n);
}

/* misc memory utils */

void cve_os_memory_barrier(void)
{
	/*Full memory barrier*/
	mb();
}

/* clock */
u64 cve_os_get_time_stamp(void)
{
	return get_cycles();
}

/*
 * NOTE: although there is jiffies_to_usecs function
 * the resolution of jiffies is msec only
 */
u32 cve_os_get_msec_time_stamp(void)
{
	u32 msec_stamp;

	msec_stamp = jiffies_to_msecs(jiffies);

	return msec_stamp;
}

void cve_os_sync_sg_memory_to_device(struct cve_device *cve_dev,
		struct sg_table *sgt)
{
	dma_sync_sg_for_device(to_cve_os_device(cve_dev)->dev,
			sgt->sgl, sgt->nents, DMA_TO_DEVICE);
}

void cve_os_sync_sg_memory_to_host(struct cve_device *cve_dev,
		struct sg_table *sgt)
{
	dma_sync_sg_for_cpu(to_cve_os_device(cve_dev)->dev,
			sgt->sgl, sgt->nents, DMA_FROM_DEVICE);
}

int __cve_os_alloc_dma_contig(struct cve_device *cve_dev,
		u32 size_of_elem,
		u32 num_of_elem,
		void **out_vaddr,
		struct cve_dma_handle *out_dma_handle, int aligned)
{
	int retval = 0;
	int size = (size_of_elem * num_of_elem);

	FUNC_ENTER();

#ifdef NULL_DEVICE_RING0
	*out_vaddr = kzalloc(size, GFP_KERNEL);
	out_dma_handle->mem_handle.dma_address = 0x2000;
#else
	if (aligned)
		size += (1 << ICE_DEFAULT_PAGE_SHIFT);

	*out_vaddr = dmam_alloc_coherent(to_cve_os_device(cve_dev)->dev,
			size,
			&out_dma_handle->mem_handle.dma_address,
			GFP_KERNEL);
#endif
	if (!*out_vaddr) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "Failed to allocate\n");
		retval = -ENOMEM;
		goto out;
	}

	/* Ensure that Physical address is aligned with given Page size */
	if (aligned)
		ASSERT(!(out_dma_handle->mem_handle.dma_address &
				((1 << ICE_DEFAULT_PAGE_SHIFT) - 1)));

	out_dma_handle->mem_type = CVE_MEMORY_TYPE_KERNEL_CONTIG;

	cve_os_log(CVE_LOGLEVEL_DEBUG,
			"allocate dma_addr = %pad, virtual = %p, size = %d\n",
			(void *)(uintptr_t)
			&(out_dma_handle->mem_handle.dma_address),
			*out_vaddr,
			size);

out:
	FUNC_LEAVE();
	return retval;
}

void __cve_os_free_dma_contig(struct cve_device *cve_dev,
		u32 size,
		void *vaddr,
		struct cve_dma_handle *dma_handle,
		int aligned)
{
	FUNC_ENTER();
#ifdef NULL_DEVICE_RING0
	kfree(vaddr);
#else
	if (aligned)
		size += (1 << ICE_DEFAULT_PAGE_SHIFT);

	dmam_free_coherent(to_cve_os_device(cve_dev)->dev,
			size,
			vaddr, dma_handle->mem_handle.dma_address);
#endif
	cve_os_log(CVE_LOGLEVEL_DEBUG,
				"free virtual = 0x%p, size = %d\n",
				vaddr, size);
	FUNC_LEAVE();
}

#ifdef IDC_ENABLE
/* interrupts */

cve_isr_retval_t cve_os_interrupt_handler(int irq, void *os_dev)
{
	if (cve_di_interrupt_handler(
			&((struct cve_os_device *)os_dev)->idc_dev)) {
#ifdef NULL_DEVICE_RING0
	cve_di_interrupt_handler_deferred_proc(
			&((struct cve_os_device *)os_dev)->idc_dev);
		return IRQ_HANDLED;
#else
		return IRQ_WAKE_THREAD;
#endif
}
	return IRQ_HANDLED;
}

cve_isr_retval_t cve_os_interrupt_handler_bh(int irq, void *os_dev)
{

	cve_di_interrupt_handler_deferred_proc(
			&((struct cve_os_device *)os_dev)->idc_dev);
	return IRQ_HANDLED;
}

/* device probe/remove */
int cve_probe_common(struct cve_os_device *linux_device, int dev_ind)
{
	int i, retval = 0;
	u64 pe_reg_value;
	struct dentry *file;
	char dev_name[8];
	char file_name[30];
	u32 icemask_reg, active_ice;

	FUNC_ENTER();

	cve_os_log(CVE_LOGLEVEL_ERROR,
				"CVE KMD version: %s\n"
				, KMD_VERSION);
	if (ice_get_b_step_enable_flag()) {
		memcpy(&cfg_default, &cfg_b, sizeof(cfg_b));
		if (ice_fw_select == 1)
			ice_fw_update_path(RTL_DEBUG_B_STEP_FW_PATH);
		else
			ice_fw_update_path(RTL_RELEASE_B_STEP_FW_PATH);
		cve_os_log(CVE_LOGLEVEL_INFO, "B STEP ENABLED\n");
	} else {
		memcpy(&cfg_default, &cfg_a, sizeof(cfg_a));
		if (ice_fw_select == 1)
			ice_fw_update_path(RTL_DEBUG_A_STEP_FW_PATH);
		else
			ice_fw_update_path(RTL_RELEASE_A_STEP_FW_PATH);
		cve_os_log(CVE_LOGLEVEL_INFO, "B STEP DISABLED\n");
	}

	icemask_reg = ice_di_get_icemask(&linux_device->idc_dev);
	g_icemask = icemask_user | icemask_reg;

	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"UserConfig: ICEMASK_USER: 0x%x, ICEMASK_REG: 0x%x enable_llc_config_via_axi_reg:0x%x\n sph_soc:0x%x",
		icemask_user, icemask_reg, enable_llc_config_via_axi_reg,
		sph_soc);


	active_ice = (~g_icemask) & VALID_ICE_MASK;
	if (!active_ice) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "No Active ICE\n");
		goto out;
	}

	/* Keep only relevant bits */
	core_mask = (core_mask & 0xF);
	if (core_mask)
		disable_embcb = 1;

	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"DISABLE_EMBCB=%u, CORE_MASK=0x%x\n",
		disable_embcb, core_mask);
	pe_reg_value = cve_os_read_idc_mmio(
		&linux_device->idc_dev.cve_dev[0],
			cfg_default.bar0_mem_icepe_offset);
	/* Still not initializing all 12 ICE */
	while (active_ice) {
		i = __builtin_ctz(active_ice);
		CVE_CLEAR_BIT(active_ice, i);

		retval = cve_device_init(
				&linux_device->idc_dev.cve_dev[i],
				i, pe_reg_value);
		if (retval != 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
					"cve_device_init failed %d\n", retval);
			goto out;
		}
	}

	/* create cve_x directory */
	snprintf(dev_name,
			sizeof(dev_name),
			"idc");

	linux_device->dev_dir = debugfs_create_dir(dev_name, NULL);
	if (IS_ERR_OR_NULL(linux_device->dev_dir)) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"error creating IDC device debug directory\n");
		/* If debugfs API failed driver will continue without it*/
	}

	/* Set registers set*/
	linux_device->regset.base = linux_device->cached_mmio_base.iobase[0];
	cve_di_get_debugfs_regs_list(&linux_device->regset.regs,
			&linux_device->regset.nregs);

	file = debugfs_create_regset32("registers",
			S_IRUGO,
			linux_device->dev_dir,
			&linux_device->regset);
	if (IS_ERR_OR_NULL(file)) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"error creating regset\n");
		/* If debugfs API failed driver will continue without it*/
		debugfs_remove_recursive(linux_device->dev_dir);
	}

	active_ice = (~g_icemask) & VALID_ICE_MASK;
	while (active_ice) {
		i = __builtin_ctz(active_ice);
		CVE_CLEAR_BIT(active_ice, i);

		snprintf(file_name, sizeof(file_name),
			"enable_hw_counters_%d",
			linux_device->idc_dev.cve_dev[i].dev_index);

		file = debugfs_create_u32(file_name,
		 S_IRUGO | S_IWUGO, linux_device->dev_dir,
		 &linux_device->idc_dev.cve_dev[i].is_hw_counters_enabled);

		if (IS_ERR_OR_NULL(file)) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
					"error creating enable_hw_counters\n");
		/* If debugfs API failed driver will continue without it*/
		}

#ifndef DISABLE_DEBUGFS_ICE_DUMP
		snprintf(file_name, sizeof(file_name), "cveDumpBuffer_%d", i);

		file = debugfs_create_file(file_name,
			0644, linux_device->dev_dir,
			&linux_device->idc_dev.cve_dev[i].cve_dump_buf,
			&fops_cve_dump);

		if (IS_ERR_OR_NULL(file)) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
					"error creating cveDumpBuffer\n");
		/* If debugfs API failed driver will continue without it */
		}
#endif

	}

out:
	FUNC_LEAVE();
	return retval;
}

void cve_remove_common(struct cve_os_device *linux_device)
{
	int i;
	u32 active_ice;

FUNC_ENTER();

	active_ice = (~g_icemask) & VALID_ICE_MASK;
	while (active_ice) {
		i = __builtin_ctz(active_ice);
		CVE_CLEAR_BIT(active_ice, i);

		cve_os_log(CVE_LOGLEVEL_DEBUG,
				"Remove linux_device->cve_dev.dev_index = %d\n"
				, linux_device->idc_dev.cve_dev[i].dev_index);

		cve_device_clean(&linux_device->idc_dev.cve_dev[i]);
	}

	debugfs_remove_recursive(linux_device->dev_dir);

FUNC_LEAVE();
}
#else
/* interrupts */

cve_isr_retval_t cve_os_interrupt_handler(int irq, void *os_dev)
{
	if (cve_di_interrupt_handler(
			&((struct cve_os_device *)os_dev)->cve_dev))
		return IRQ_WAKE_THREAD;

	return IRQ_HANDLED;
}

cve_isr_retval_t cve_os_interrupt_handler_bh(int irq, void *os_dev)
{

	cve_di_interrupt_handler_deferred_proc(
			&((struct cve_os_device *)os_dev)->cve_dev);
	return IRQ_HANDLED;
}

/* device probe/remove */
int cve_probe_common(struct cve_os_device *linux_device, int dev_ind)
{	/* Changes will come because cve_os_device will now
	 * contain idc_dev and not cve_dev. Extract cve_dev
	 * using dev_ind.
	 */
	int retval = 0;
	struct dentry *file;
	char dev_name[8];
	u64 pe_reg_value = 0;

	FUNC_ENTER();

	cve_os_log(CVE_LOGLEVEL_ERROR,
				"CVE KMD version: %s\n"
				, KMD_VERSION);

	cve_os_log(CVE_LOGLEVEL_DEBUG,
			"adding device ID = %d\n", dev_ind);

	retval = cve_device_init(&linux_device->cve_dev, dev_ind, pe_reg_value);
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"cve_device_init failed %d\n", retval);
		goto out;
	}

	/* create cve_x directory */
	snprintf(dev_name,
			sizeof(dev_name),
			"cve_%d",
			linux_device->cve_dev.dev_index);

	linux_device->dev_dir = debugfs_create_dir(dev_name, NULL);
	if (IS_ERR_OR_NULL(linux_device->dev_dir)) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"error creating CVE device debug directory\n");
		/* If debugfs API failed driver will continue without it*/
		goto out;
	}

	/* Set registers set*/
	linux_device->regset.base = linux_device->cached_mmio_base.iobase[0];
	cve_di_get_debugfs_regs_list(&linux_device->regset.regs,
			&linux_device->regset.nregs);

	file = debugfs_create_regset32("registers",
			S_IRUGO,
			linux_device->dev_dir,
			&linux_device->regset);
	if (IS_ERR_OR_NULL(file)) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"error creating regset\n");
		/* If debugfs API failed driver will continue without it*/
		goto err;
	}

	file = debugfs_create_u32("enable_hw_counters",
			S_IRUGO | S_IWUGO,
			linux_device->dev_dir,
			&linux_device->cve_dev.is_hw_counters_enabled);

	if (IS_ERR_OR_NULL(file)) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"error creating enable_hw_counters\n");
		/* If debugfs API failed driver will continue without it*/
		goto err;
	}

	file = debugfs_create_file("cveDumpBuffer",
		0644, linux_device->dev_dir,
		&linux_device->cve_dev.cve_dump_buf,
		&fops_cve_dump);

	if (IS_ERR_OR_NULL(file)) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"error creating cveDumpBuffer\n");
		/* If debugfs API failed driver will continue without it*/
		goto err;
	}


out:
	FUNC_LEAVE();
	return retval;

err:
	debugfs_remove_recursive(linux_device->dev_dir);
	goto out;
}

void cve_remove_common(struct cve_os_device *linux_device)
{

FUNC_ENTER();

	cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Remove linux_device->cve_dev.dev_index = %d\n"
			, linux_device->cve_dev.dev_index);

	debugfs_remove_recursive(linux_device->dev_dir);

	cve_device_clean(&linux_device->cve_dev);

FUNC_LEAVE();
}
#endif


/* user interface */
static ssize_t show_misc_device_info(struct device *dev,
		struct device_attribute *attr,
		char *buf)
{
	ssize_t len = 0;
	struct cve_device_group *dg;
	struct cve_device *cve_dev;

	FUNC_ENTER();
	dg = cve_dg_get();
	cve_dev = dg->dev_info.icebo_list[0].dev_list;
	len = sprintf(buf, "Revision = %x.%x\n",
			cve_dev->version_info.major,
			cve_dev->version_info.minor);
	FUNC_LEAVE();
	return len;
}

static int cve_open_misc(struct inode *inode, struct file *file)
{
	int retval = CVE_DEFAULT_ERROR_CODE;
	cve_context_process_id_t context_pid =
				(cve_context_process_id_t)(uintptr_t)file;

	FUNC_ENTER();

	retval = cve_context_process_create(
			context_pid);
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"cve_ds_open_context_process failed %d\n",
				retval);
	}

	FUNC_LEAVE();

	return retval;
}

static int cve_close_misc(struct inode *inode, struct file *file)
{
	int retval = CVE_DEFAULT_ERROR_CODE;
	cve_context_process_id_t context_pid =
				(cve_context_process_id_t)(uintptr_t)file;

	FUNC_ENTER();

	retval = cve_context_process_destroy(
			context_pid);
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"cve_ds_close_context_process failed %d\n",
				retval);
	}

	FUNC_LEAVE();
	return retval;
}

static long cve_ioctl_misc(
		struct file *file, unsigned int cmd, unsigned long arg)
{
	int retval = CVE_DEFAULT_ERROR_CODE;
	cve_context_process_id_t context_pid =
				(cve_context_process_id_t)(uintptr_t)file;

	struct cve_ioctl_param __user *uparam =
			(struct cve_ioctl_param __user *)arg;
	struct cve_ioctl_param kparam;

	FUNC_ENTER();
	if (cmd & IOC_IN) {
		retval = cve_os_read_user_memory(uparam,
				sizeof(kparam),
				&kparam);
		if (retval != 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
					"cve_os_read_user_memory failed %d\n",
					retval);
			goto out;
		}
	}

	switch (cmd) {
	case CVE_IOCTL_CREATE_CONTEXT:
		{
			struct cve_create_context_params *p =
					&kparam.create_context;

			cve_os_log(CVE_LOGLEVEL_DEBUG,
					"CVE_IOCTL_CREATE_CONTEXT n/a\n");
			retval = cve_ds_open_context(context_pid, p->obj_id,
					&p->out_contextid);
		}
		break;
	case CVE_IOCTL_DESTROY_CONTEXT:
		{
			struct cve_destroy_context_params *p =
					&kparam.destroy_context;

			cve_os_log(CVE_LOGLEVEL_DEBUG,
					"CVE_IOCTL_DESTROY_CONTEXT n/a\n");
			retval = cve_ds_close_context(
					context_pid,
					p->contextid);
		}
		break;
	case CVE_IOCTL_CREATE_NETWORK:
		{
			/* TODO: Rename */
			struct cve_create_network *p = &kparam.create_network;

			cve_os_log(CVE_LOGLEVEL_DEBUG,
					"CVE_IOCTL_CREATE_NETWORK\n");
			retval = cve_ds_handle_create_network(context_pid,
					p->contextid,
					&p->network,
					&p->network.network_id);
		}
		break;
	case CVE_IOCTL_DESTROY_NETWORK:
		{
			struct cve_destroy_network *p = &kparam.destroy_network;

			cve_os_log(CVE_LOGLEVEL_DEBUG,
					"CVE_IOCTL_DESTROY_NETWORK\n");
			retval = cve_ds_handle_destroy_network(context_pid,
					p->contextid,
					p->networkid);
			break;
		}
	case CVE_IOCTL_CREATE_INFER:
		{
			struct cve_create_infer *p = &kparam.create_infer;

			cve_os_log(CVE_LOGLEVEL_DEBUG,
					"CVE_IOCTL_CREATE_INFER\n");
			retval = cve_ds_handle_create_infer(context_pid,
					p->contextid,
					p->networkid,
					&p->infer,
					&p->infer.infer_id);

		}
		break;
	case CVE_IOCTL_EXECUTE_INFER:
		{
			struct cve_execute_infer *p = &kparam.execute_infer;

			cve_os_log(CVE_LOGLEVEL_DEBUG,
					"CVE_IOCTL_EXECUTE_INFER\n");
			retval = cve_ds_handle_execute_infer(context_pid,
					p->contextid,
					p->networkid,
					p->inferid,
					&p->data);
			break;
		}
	case CVE_IOCTL_DESTROY_INFER:
		{
			struct cve_destroy_infer *p = &kparam.destroy_infer;

			cve_os_log(CVE_LOGLEVEL_DEBUG,
					"CVE_IOCTL_DESTROY_INFER\n");
			retval = cve_ds_handle_destroy_infer(context_pid,
					p->contextid,
					p->networkid,
					p->inferid);
			break;
		}
	case CVE_IOCTL_MANAGE_RESOURCE:
		{
			struct ice_manage_resource *p = &kparam.manage_resource;

			cve_os_log(CVE_LOGLEVEL_DEBUG,
					"CVE_IOCTL_MANAGE_RESOURCE\n");
			retval = cve_ds_handle_manage_resource(context_pid,
					p->contextid,
					p->networkid,
					&p->resource);
			break;
		}
	case CVE_IOCTL_LOAD_FIRMWARE:
		{
			struct cve_load_firmware_params *p =
					&kparam.load_firmware;

			cve_os_log(CVE_LOGLEVEL_DEBUG,
					"CVE_IOCTL_LOAD_FIRMWARE\n");
			cve_os_log(CVE_LOGLEVEL_DEBUG,
					"Got IOCTL for fw file %llx (%d) map file %llx (%d)\n",
					p->fw_image,
					p->fw_image_size_bytes,
					p->fw_binmap,
					p->fw_binmap_size_bytes);
#ifdef NULL_DEVICE_RING0
			retval = 0;
#else
			retval = cve_ds_handle_fw_loading(
					context_pid,
					p->contextid,
					p->fw_image,
					p->fw_binmap,
					p->fw_binmap_size_bytes);
#endif
		}
		break;
	case CVE_IOCTL_WAIT_FOR_EVENT:
		{
			struct cve_get_event *p = &kparam.get_event;

			cve_os_log(CVE_LOGLEVEL_DEBUG,
					"CVE_IOCTL_WAIT_FOR_EVENT\n");
			retval = cve_ds_wait_for_event(
					context_pid,
					p);
		}
		break;
	case CVE_IOCTL_GET_VERSION:
		{
			struct cve_get_version_params *p = &kparam.get_version;

			cve_os_log(CVE_LOGLEVEL_DEBUG,
					"CVE_IOCTL_GET_VERSION\n");
			retval = cve_ds_get_version(
				context_pid,
				p->contextid,
				&p->out_versions
				);
		}
		break;
	case CVE_IOCTL_GET_METADATA:
		{
			struct cve_get_metadata_params *p =
					&kparam.get_metadata;

			cve_os_log(CVE_LOGLEVEL_DEBUG,
					"CVE_IOCTL_GET_METADATA\n");
			retval = cve_ds_get_metadata(
					&p->icemask
					);
		}
		break;
	case ICE_IOCTL_HW_TRACE_CONFIG:
		{
			struct ice_hw_trace_config *p = &kparam.trace_cfg;

			cve_os_log(CVE_LOGLEVEL_DEBUG,
					    "ICE_IOCTL_HW_TRACE_CONFIG\n");
			retval = ice_trace_config(p);
		}
		break;
	case ICE_IOCTL_WAIT_FOR_DEBUG_EVENT:
		{
			struct ice_get_debug_event *p = &kparam.get_debug_event;

			cve_os_log(CVE_LOGLEVEL_DEBUG,
					    "ICE_IOCTL_WAIT_FOR_DEBUG_EVENT\n");
			retval = ice_debug_wait_for_event(p);
		}
		break;
	case ICE_IOCTL_DEBUG_CONTROL:
		{
			struct ice_debug_control_params *p =
							&kparam.debug_control;

			cve_os_log(CVE_LOGLEVEL_DEBUG,
					    "ICE_IOCTL_DEBUG_CONTROL\n");
			retval = ice_ds_debug_control(p);
		}
		break;
	case ICE_IOCTL_SET_HW_CONFIG:
		{
			struct ice_set_hw_config_params *p =
							&kparam.set_hw_config;

			cve_os_log(CVE_LOGLEVEL_DEBUG,
					    "ICE_IOCTL_SET_HW_CONFIG\n");
			retval = ice_set_hw_config(p);
		}
		break;
	default:
		retval = -ENOENT;
		goto out;
	}

	if (cmd & IOC_OUT) {
		if (cve_os_write_user_memory(
				uparam,
				sizeof(kparam),
				&kparam) != 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
					"cve_os_write_user_memory failed %d\n",
					retval);
			retval = -EFAULT;
		}
	}

out:
	cve_os_log(CVE_LOGLEVEL_DEBUG,
			"IOCTL accomplished\n");
	FUNC_LEAVE();
	return retval;
}

/* init/cleanup */

static int __init cve_init(void)
{
	int retval = CVE_DEFAULT_ERROR_CODE;
	struct ice_drv_config param;

	FUNC_ENTER();

	cve_os_log(CVE_LOGLEVEL_DEBUG,
			"CPU Family- %d, Vendor- %d, Model- %d, Stepping- %d\n",
			boot_cpu_data.x86,
			boot_cpu_data.x86_vendor,
			boot_cpu_data.x86_model,
			boot_cpu_data.x86_stepping);

	param.enable_sph_b_step = false;
	if (ice_is_soc()) { /* if silicon */
		if (boot_cpu_data.x86_stepping == 1)
			param.enable_sph_b_step = true;
	} else { /* simulation*/
		if (enable_b_step)
			param.enable_sph_b_step = true;
	}
	/* Configure the driver params*/
	param.sph_soc = sph_soc;
	param.enable_llc_config_via_axi_reg = enable_llc_config_via_axi_reg;
	param.ice_power_off_delay_ms = ice_power_off_delay_ms;
	ice_set_driver_config_param(&param);

	retval = ice_swc_init();
	if (retval < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"ice_swc_init failed %d\n", retval);
		goto out;
	}

	/* mis device initialization */
	retval = misc_register(&cve_misc_device);
	if (retval < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"misc_register failed %d\n", retval);
		goto out;
	}

	/*create sys/class/misc/intel_misc_cve/misc_device_info */
	retval = device_create_file(cve_misc_device.this_device,
			&dev_attr_misc_device_info);
	if (retval) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"device_create_file failed %d\n", retval);
		goto cleanup_misc;
	}

	DO_TRACE(icedrv_sw_trace_init());

	/* cve specific stuff */
	retval = cve_driver_init();
	if (retval) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"cve_driver_init failed %d\n", retval);
		goto cleanup_device_info;
	}

	/* platform specific part */
	retval = cve_register_driver();
	if (retval) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"register_driver failed %d\n", retval);
		goto cleanup_driver_init;
	}

	ice_di_activate_driver();

	/* success */
	retval = 0;
out:
	FUNC_LEAVE();
	return retval;

	/* errors */
cleanup_driver_init:
	cve_driver_cleanup();
cleanup_device_info:
	device_remove_file(cve_misc_device.this_device,
			&dev_attr_misc_device_info);
cleanup_misc:
	misc_deregister(&cve_misc_device);
	ice_swc_fini();
	goto out;
}

#ifdef ENABLE_MEM_DETECT
static void __dump_leak(void)
{
	struct ice_drv_memleak *head = g_leak_list;
	struct ice_drv_memleak *curr = NULL;
	struct ice_drv_memleak *next = NULL;
	int is_last = 0;

	if (!enable_ice_drv_memleak)
		return;

	cve_os_log(CVE_LOGLEVEL_INFO,
				"LEAKCOUNT:%u\n", mem_leak_count);
	/* try to destroy all networks within this workqueue */
	if (head == NULL)
		return;

	curr = head;
	do {
		next = cve_dle_next(curr, list);

		if (next == curr)
			is_last = 1;

		cve_os_log(CVE_LOGLEVEL_INFO,
			    "VA:0x%p size:%d Caller:%pS, Caller's caller:%pS\n",
				curr->va, curr->size, curr->caller_fn,
				curr->caller_fn2);
		cve_dle_remove_from_list(g_leak_list, list, curr);


		if (!is_last)
			curr = cve_dle_next(curr, list);
	} while (!is_last && curr);
}
#endif

static void __exit cve_exit(void)
{
	FUNC_ENTER();

	ice_di_deactivate_driver();

	cve_dg_stop_poweroff_thread();

	/* platform specific part */
	cve_unregister_driver();

	/* cleanup */
	cve_driver_cleanup();

	/*remove sys/class/misc/intel_misc_cve/misc_device_info */
	device_remove_file(cve_misc_device.this_device,
				&dev_attr_misc_device_info);

	/* unregister misc device */
	misc_deregister(&cve_misc_device);

	ice_swc_fini();
#ifdef ENABLE_MEM_DETECT
	__dump_leak();
#endif
	FUNC_LEAVE();
}


module_init(cve_init);
module_exit(cve_exit);

MODULE_AUTHOR("Surendra Singh <surendra.k.singh@intel.com>");
MODULE_AUTHOR("Anshuman Gaurav <anshuman.gaurav@intel.com>");
MODULE_AUTHOR("Priya Thakur <priya.thakur@intel.com>");
MODULE_AUTHOR("Amrutha Dontula <amrutha.dontula@intel.com>");
MODULE_AUTHOR("Bharat Jauhari <bharat.jauhari@intel.com>");
MODULE_AUTHOR("Subrata Chatterjee<subrata.chatterjee@intel.com>");
MODULE_AUTHOR("Intel");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Intel ICE driver");
MODULE_VERSION(KMD_VERSION);
MODULE_INFO(git_hash, KMD_GIT_HASH);

