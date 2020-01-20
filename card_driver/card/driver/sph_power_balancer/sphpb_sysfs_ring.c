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
#include <asm/msr.h>
#include <linux/sched/clock.h>
#include "sph_log.h"
#include "sphpb_bios_mailbox.h"

/* RING SYSFS */

/* uncore clock ticks msr's */
#define MSR_UNC_PERF_GLOBAL_CTRL 0xe01
#define MSR_UNC_PERF_FIXED_CTRL 0x394

/* power throttling threasholds*/
#define RING_FREQ_SETP 100llu //MHz
#define RING_THRESHOLD (400llu + RING_FREQ_SETP / 2u) //MHz
#define IA_FREQ_SETP 100000llu //KHz
#define IA_THRESHOLD (400000llu + IA_FREQ_SETP / 2u) //KHz
#define ICEBO_FREQ_SETP 25u //MHz
#define ICEBO_THRESHOLD (200u + ICEBO_FREQ_SETP / 2u) //MHz

/* sysfs related functions, structures */
static ssize_t show_ring_entry(struct kobject *kobj,
				struct kobj_attribute *attr,
				char *buf);

static ssize_t store_ring_entry(struct kobject *kobj,
				struct kobj_attribute *attr,
				const char *buf, size_t count);

static struct kobj_attribute ring_frequency_max_attr =
__ATTR(max_frequency, 0664, show_ring_entry, store_ring_entry);
static struct kobj_attribute ring_frequency_min_attr =
__ATTR(min_frequency, 0664, show_ring_entry, store_ring_entry);
static struct kobj_attribute ring_clock_en_attr =
__ATTR(clock_enable, 0664, show_ring_entry, store_ring_entry);
static struct kobj_attribute ring_clock_ticks_attr =
__ATTR(clock_ticks, 0664, show_ring_entry, NULL);

static struct attribute *ring_frequency_attrs[] = {
	&ring_frequency_max_attr.attr,
	&ring_frequency_min_attr.attr,
	&ring_clock_en_attr.attr,
	&ring_clock_ticks_attr.attr,
	NULL,	/* need to NULL terminate the list of attributes */
};

static struct attribute_group ring_attr_group = {
		.name = "ring",
		.attrs = ring_frequency_attrs,
};

bool is_ring_free_clock_enable(void)
{
	struct UNC_PERF_FIXED_CTRL_MSR fixed_ctl;
	struct UNC_PERF_GLOBAL_CTRL_MSR perf_global;

	fixed_ctl.value = native_read_msr(MSR_UNC_PERF_FIXED_CTRL);
	perf_global.value = native_read_msr(MSR_UNC_PERF_GLOBAL_CTRL);

	return (perf_global.BitField.en && fixed_ctl.BitField.cnt_en);
}


void set_ring_free_clock_enable(bool bEnable)
{
	struct UNC_PERF_FIXED_CTRL_MSR fixed_ctl;
	struct UNC_PERF_GLOBAL_CTRL_MSR perf_global;

	// bEnable == TRUE set en in MSR_UNC_PERF_GLOBAL_CTRL which enables all uncore counters
	// bEnable == FALSE unset en in MSR_UNC_PERF_GLOBAL_CTRL which disabled all uncore counters
	perf_global.value = native_read_msr(MSR_UNC_PERF_GLOBAL_CTRL);
	perf_global.BitField.en = bEnable;
	native_write_msr(MSR_UNC_PERF_GLOBAL_CTRL, perf_global.U64.low, perf_global.U64.high);

	// sets cnt_en in MSR_UNC_PERF_FIXED_CTRL which enables fixed uncore counter
	fixed_ctl.value = native_read_msr(MSR_UNC_PERF_FIXED_CTRL);
	fixed_ctl.BitField.cnt_en = bEnable;
	native_write_msr(MSR_UNC_PERF_FIXED_CTRL, fixed_ctl.U64.low, fixed_ctl.U64.high);
}


/* Function to show ring Min/Max Frequency */
static ssize_t show_ring_entry(struct kobject *kobj,
			       struct kobj_attribute *attr,
			       char *buf)
{
	struct RING_FREQUENCY_MSR ring_freq;
	uint64_t clock_ticks;

	ring_freq.value = native_read_msr(RING_FREQ_MSR);

	if (strcmp(attr->attr.name, "max_frequency") == 0x0)
		return sprintf((buf), "%d\n", ring_freq.BitField.MAX_RATIO * RING_FREQ_DIVIDER_FACTOR);
	else if (strcmp(attr->attr.name, "min_frequency") == 0x0)
		return sprintf((buf), "%d\n", ring_freq.BitField.MIN_RATIO * RING_FREQ_DIVIDER_FACTOR);
	else if (strcmp(attr->attr.name, "clock_enable") == 0x0) {
		return sprintf((buf), "%d\n", is_ring_free_clock_enable());
	} else if (strcmp(attr->attr.name, "clock_ticks") == 0x0) {
		rdmsrl(MSR_UNC_PERF_UNCORE_CLOCK_TICKS, clock_ticks);
		return sprintf((buf), "%llu\n", clock_ticks);
	}

	return 0;
}

/* Function to show ring Min/Max Frequency */
static ssize_t store_ring_entry(struct kobject *kobj,
				struct kobj_attribute *attr,
				const char *buf, size_t count)
{
	struct RING_FREQUENCY_MSR ring_freq;
	uint32_t input_value;
	uint32_t ring_value;
	int ret;


	ret = kstrtouint(buf, 10, &input_value);
	if (ret < 0)
		return ret;

	if (strcmp(attr->attr.name, "max_frequency") == 0x0) {
		ring_value = input_value / RING_FREQ_DIVIDER_FACTOR;
		ring_freq.value = native_read_msr(RING_FREQ_MSR);
		ring_freq.BitField.MAX_RATIO = ring_value;
		native_write_msr(RING_FREQ_MSR, ring_freq.U64.low, ring_freq.U64.high);
	} else if (strcmp(attr->attr.name, "min_frequency") == 0x0) {
		ring_value = input_value / RING_FREQ_DIVIDER_FACTOR;
		ring_freq.value = native_read_msr(RING_FREQ_MSR);
		ring_freq.BitField.MIN_RATIO = ring_value;
		native_write_msr(RING_FREQ_MSR, ring_freq.U64.low, ring_freq.U64.high);
	} else if (strcmp(attr->attr.name, "clock_enable") == 0x0)
		set_ring_free_clock_enable(input_value != 0x0);
	else
		return 0;

	return count;
}

int sphpb_ring_freq_sysfs_init(struct sphpb_pb *sphpb)
{
	int ret = 0;


	/* Create the ring files config kobject */
	ret = sysfs_create_group(sphpb->kobj, &ring_attr_group);
	if (ret) {
		sph_log_err(POWER_BALANCER_LOG, "ring sysfs group creation failed err(%d)\n", ret);
		return ret;
	}

	set_ring_free_clock_enable(true);


	return 0;
}

void sphpb_ring_freq_sysfs_deinit(struct sphpb_pb *sphpb)
{
	set_ring_free_clock_enable(false);
	/* Remove ring files config kobject */
	sysfs_remove_group(sphpb->kobj, &ring_attr_group);
}

