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
#include <linux/mutex.h>
#include <linux/anon_inodes.h>
#include <linux/uaccess.h>
#include <linux/fcntl.h>
#include <asm/msr.h>
#include <linux/sched/clock.h>
#include "sphpb_sw_counters.h"
#include "sphpb_trace.h"
#include "sph_log.h"
#include "sph_version.h"
#include "sphpb.h"
#include "sphpb_punit.h"
#include "sphpb_bios_mailbox.h"

struct sphpb_pb *g_the_sphpb;
void *g_hSwCountersInfo_global;
struct sph_sw_counters *g_sph_sw_pb_counters;

static ssize_t show_bios_mailbox_locked(struct kobject *kobj,
					struct kobj_attribute *attr,
					char *buf);

static ssize_t store_bios_mailbox_locked(struct kobject *kobj,
					 struct kobj_attribute *attr,
					 const char *buf, size_t count);

static ssize_t show_debug_log_value(struct kobject *kobj,
				    struct kobj_attribute *attr,
				    char *buf);

static ssize_t store_debug_log_value(struct kobject *kobj,
				     struct kobj_attribute *attr,
				     const char *buf, size_t count);


static struct kobj_attribute bios_mailbox_locked_attr =
__ATTR(bios_mailbox_locked, 0664, show_bios_mailbox_locked, store_bios_mailbox_locked);

static struct kobj_attribute debug_log_attr =
__ATTR(debug_log, 0664, show_debug_log_value, store_debug_log_value);



/* request to get a list of recommended ices to use when job starts */
static int sphpb_get_efficient_ice_list(uint64_t ice_mask,
					uint32_t ddr_bw,
					uint16_t ring_divisor_fx,
					uint16_t ratio_fx,
					uint8_t *o_ice_array,
					ssize_t array_size)
{
	int ret;

	if (g_the_sphpb->debug_log)
		sph_log_info(POWER_BALANCER_LOG,
			     "request list of ices - ice mask - %llu  ddr_bw = %uMB/s ring_divisor = 0x%x(U1.15) ratio = %u\n",
			     ice_mask, ddr_bw, ring_divisor_fx, ratio_fx);

	ret = sphpb_mng_get_efficient_ice_list(g_the_sphpb,
					       ice_mask,
					       ring_divisor_fx,
					       ratio_fx,
					       o_ice_array,
					       array_size);

	return ret;
}


/* request from sphpb to set ice to ring and ice ratio */
int sphpb_request_ice_dvfs_values(uint32_t ice_index,
				  uint32_t ddr_bw,
				  uint16_t ring_divisor_fx,
				  uint16_t ratio_fx)
{
	int ret;

	DO_TRACE(trace_power_request(ice_index,
				     ring_divisor_fx,
				     ddr_bw));

	if (g_the_sphpb->debug_log)
		sph_log_info(POWER_BALANCER_LOG,
			     "Got request for ICE %u - ddr_bw=%uMB/s ring_divisor=0x%x(U1.15) ratio=%u\n",
			     ice_index, ddr_bw, ring_divisor_fx, ratio_fx);

	ret = sphpb_mng_request_ice_dvfs_values(g_the_sphpb,
						ice_index,
						ddr_bw,
						ring_divisor_fx,
						ratio_fx);

	return ret;
}

/* set ice active state */
int sphpb_set_power_state(uint32_t ice_index, bool bOn)
{
	int ret;

	if (g_the_sphpb->debug_log)
		sph_log_info(POWER_BALANCER_LOG,
			     "set power state for ICE %u - Power State - %s\n",
			     ice_index, bOn ? "ON" : "OFF");

	ret = sphpb_mng_set_icebo_enable(g_the_sphpb,
					 ice_index,
					 bOn);

	return ret;
}

int sphpb_throttle_init(struct sphpb_pb *sphpb)
{
	int ret = 0;
	sphpb->throttle_data.curr_state = 0x0/*SPHPB_NO_THROTTLE*/;

	sphpb->throttle_data.cpu_stat = kmalloc_array(num_possible_cpus(), sizeof(struct cpu_perfstat), GFP_KERNEL);
	if (unlikely(sphpb->throttle_data.cpu_stat == NULL)) {
		ret = -ENOMEM;
		sph_log_err(POWER_BALANCER_LOG, "Throttling init failure: Out of memory.\n");
	}
	return ret;
}

void sphpb_throttle_deinit(struct sphpb_pb *sphpb)
{
	sphpb->throttle_data.curr_state = 0x0;
	kfree(sphpb->throttle_data.cpu_stat);
}

static void sphpb_throttle_prepare(void)
{
	uint32_t cpu;
	int ret;

	if (unlikely(g_the_sphpb->icedrv_cb == NULL ||
	    g_the_sphpb->icedrv_cb->set_clock_squash == NULL))
		goto err;

	ret = g_the_sphpb->icedrv_cb->set_clock_squash(0, g_the_sphpb->throttle_data.curr_state,
						       g_the_sphpb->throttle_data.curr_state != 0x0);
	if (unlikely(ret < 0))
		sph_log_err(POWER_BALANCER_LOG, "Throttling failure: Unable to disable ice throttling. Err(%d)\n", ret);

	if (g_the_sphpb->throttle_data.curr_state != 0x0)
		g_the_sphpb->request_ddr_value = SAGV_POLICY_FIXED_LOW;
	else
		g_the_sphpb->request_ddr_value = SAGV_POLICY_DYNAMIC;

	ret = set_sagv_freq(g_the_sphpb->request_ddr_value, SAGV_POLICY_DYNAMIC);

	if (unlikely(ret < 0))
		sph_log_err(POWER_BALANCER_LOG, "Throttling failure: Unable to set Dynamic DRAM frequency. Err(%d)\n", ret);

	g_the_sphpb->throttle_data.time_us = local_clock() / 1000u; //ns -> us
	rdmsrl(MSR_UNC_PERF_UNCORE_CLOCK_TICKS, g_the_sphpb->throttle_data.ring_clock_ticks);
	if (unlikely(g_the_sphpb->throttle_data.cpu_stat == NULL))
		return;
	for (cpu = 0; cpu < num_possible_cpus(); ++cpu)
		smp_call_function_single(cpu, aperfmperf_snapshot_khz, &g_the_sphpb->throttle_data.cpu_stat[cpu], true);
err:
	return;

}

static void sphpb_unregister_driver(void)
{
	if (!g_the_sphpb) {
		sph_log_err(POWER_BALANCER_LOG, "sph_power_balancer was failed to un-register");
		return;
	}

	if (g_the_sphpb->debug_log)
		sph_log_info(POWER_BALANCER_LOG, "got request to unregister_driver\n");


	mutex_lock(&g_the_sphpb->mutex_lock);

	g_the_sphpb->icedrv_cb = NULL;

	memset(&g_the_sphpb->icebo, 0x0, sizeof(*g_the_sphpb->icebo));

	mutex_unlock(&g_the_sphpb->mutex_lock);

	if (g_the_sphpb->debug_log)
		sph_log_info(POWER_BALANCER_LOG, "unregister_driver, completed - throttling is not active\n");
}

const struct sphpb_callbacks *sph_power_balancer_register_driver(const struct sphpb_icedrv_callbacks *drv_data)
{
	if (!g_the_sphpb || !drv_data) {
		sph_log_err(POWER_BALANCER_LOG, "sph_power_balancer was failed to register");
		return NULL;
	}

	if (g_the_sphpb->debug_log)
		sph_log_info(POWER_BALANCER_LOG, "got request to register driver\n");


	mutex_lock(&g_the_sphpb->mutex_lock);

	if (g_the_sphpb->icedrv_cb) {
		sph_log_err(POWER_BALANCER_LOG, "sph_power_balancer already registered");
		goto err;
	}

	g_the_sphpb->icedrv_cb = drv_data;

	sphpb_throttle_prepare();

	mutex_unlock(&g_the_sphpb->mutex_lock);

	if (g_the_sphpb->icedrv_cb->get_icebo_to_ring_ratio)
		g_the_sphpb->icedrv_cb->get_icebo_to_ring_ratio(&g_the_sphpb->orig_icebo_ring_divisor);

	g_the_sphpb->icebo_ring_divisor = SPHPB_MIN_RING_POSSIBLE_VALUE;

	if (g_the_sphpb->debug_log)
		sph_log_info(POWER_BALANCER_LOG, "register driver completed\n");

	return &g_the_sphpb->callbacks;
err:
	mutex_unlock(&g_the_sphpb->mutex_lock);

	if (g_the_sphpb->debug_log)
		sph_log_info(POWER_BALANCER_LOG, "register driver failed\n");

	return NULL;
}
EXPORT_SYMBOL(sph_power_balancer_register_driver);


static ssize_t show_bios_mailbox_locked(struct kobject *kobj,
					struct kobj_attribute *attr,
					char *buf)
{
	return sprintf(buf, "%d\n", g_the_sphpb->bios_mailbox_locked);
}

static ssize_t store_bios_mailbox_locked(struct kobject *kobj,
					 struct kobj_attribute *attr,
					 const char *buf, size_t count)
{
	int ret = count;
	unsigned long val;

	if (kstrtoul(buf, 0, &val) < 0)
		return -EINVAL;

	mutex_lock(&g_the_sphpb->mutex_lock);

	if (val != 0 && g_the_sphpb->bios_mailbox_locked)
		ret = -EBUSY;
	else if (val == 0 && !g_the_sphpb->bios_mailbox_locked)
		ret = -EINVAL;
	else
		g_the_sphpb->bios_mailbox_locked = val;

	mutex_unlock(&g_the_sphpb->mutex_lock);

	return ret;
}

static ssize_t show_debug_log_value(struct kobject *kobj,
				    struct kobj_attribute *attr,
				    char *buf)
{
	return sprintf(buf, "%d\n", g_the_sphpb->debug_log);
}

static ssize_t store_debug_log_value(struct kobject *kobj,
				     struct kobj_attribute *attr,
				     const char *buf, size_t count)
{
	int ret = count;
	unsigned long val;

	if (kstrtoul(buf, 0, &val) < 0)
		return -EINVAL;

	g_the_sphpb->debug_log = (val != 0) ? 1 : 0;

	return ret;
}

static int sphpb_sw_counters_init(void)
{
	int ret;

	ret = sph_create_sw_counters_info_node(NULL,
					       &g_sw_counters_set_global,
					       NULL,
					       &g_hSwCountersInfo_global);
	if (ret) {
		sph_log_err(START_UP_LOG, "Failed to initialize sw counters nodes\n");
		return ret;
	}

	ret = sph_create_sw_counters_values_node(g_hSwCountersInfo_global,
						 0x0,
						 NULL,
						 &g_sph_sw_pb_counters);
	if (ret) {
		sph_log_err(START_UP_LOG, "Failed to initialize sw counters values\n");
		goto free_counters_info_global;
	}

	return ret;

free_counters_info_global:
	sph_remove_sw_counters_info_node(g_hSwCountersInfo_global);

	return ret;
}

static void sphpb_sw_counters_fini(void)
{
	sph_remove_sw_counters_values_node(g_sph_sw_pb_counters);
	sph_remove_sw_counters_info_node(g_hSwCountersInfo_global);
}

int create_sphpb(void)
{
	struct sphpb_pb *sphpb;
	int icebo;
	int ret = 0;

	g_the_sphpb = NULL;

	/* allocate global sph power balancer object */
	sphpb = kzalloc(sizeof(struct sphpb_pb), GFP_KERNEL);
	if (!sphpb)
		return -ENOMEM;

	mutex_init(&sphpb->mutex_lock);

	sphpb->callbacks.get_efficient_ice_list		= sphpb_get_efficient_ice_list;
	sphpb->callbacks.request_ice_dvfs_values	= sphpb_request_ice_dvfs_values;
	sphpb->callbacks.set_power_state		= sphpb_set_power_state;
	sphpb->callbacks.unregister_driver		= sphpb_unregister_driver;

	for (icebo = 0; icebo < SPHPB_MAX_ICEBO_COUNT; icebo++)
		sphpb->icebo[icebo].ring_divisor_idx = -1;

	sphpb->kobj = kobject_create_and_add("sphpb", kernel_kobj);
	if (unlikely(sphpb->kobj == NULL)) {
		sph_log_err(POWER_BALANCER_LOG, "sphpb kboj creation failed");
		ret = -ENOMEM;
		goto err;
	}

	ret = sysfs_create_file(sphpb->kobj, &bios_mailbox_locked_attr.attr);
	if (ret) {
		sph_log_err(POWER_BALANCER_LOG, "sphpb bios mailbox attr failed - err(%d)\n", ret);
		goto cleanup_kobj;
	}

	ret = sysfs_create_file(sphpb->kobj, &debug_log_attr.attr);
	if (ret) {
		sph_log_err(POWER_BALANCER_LOG, "sphpb bios mailbox attr failed - err(%d)\n", ret);
		goto cleanup_bios_mailbox_attr;
	}

	ret = sphpb_ring_freq_sysfs_init(sphpb);
	if (ret)
		goto cleanup_debug_log_attr;

	ret = sphpb_ia_cycles_sysfs_init(sphpb);
	if (ret)
		goto cleanup_ring_freq_sysfs;

	ret = sphpb_sw_counters_init();
	if (ret)
		goto cleanup_ia_cycles_sysfs;

	ret = sphpb_map_bios_mailbox(sphpb);
	if (ret) {
		sph_log_err(POWER_BALANCER_LOG, "sphpb_map_bios_mailbox failed with err: %d.\n", ret);
		goto cleanup_counters;
	}

	ret = sphpb_power_overshoot_sysfs_init(sphpb);
	if (ret) {
		sph_log_err(POWER_BALANCER_LOG, "sphpb_power_overshoot_sysfs_init failed with err: %d.\n", ret);
		goto cleanup_map_bios_mailbox_sysfs;

	}

	ret = sphpb_throttle_init(sphpb);
	if (ret) {
		sph_log_err(POWER_BALANCER_LOG, "sphpb_throttle_init failed with err: %d.\n", ret);
		goto cleanup_power_overshoot_sysfs;
	}

	sphpb_trace_init();

	g_the_sphpb = sphpb;

	return 0;
cleanup_power_overshoot_sysfs:
	sphpb_power_overshoot_sysfs_deinit(sphpb);

cleanup_map_bios_mailbox_sysfs:
	sphpb_unmap_bios_mailbox(sphpb);

cleanup_counters:
	sphpb_sw_counters_fini();

cleanup_ia_cycles_sysfs:
	sphpb_ia_cycles_sysfs_deinit(sphpb);

cleanup_ring_freq_sysfs:
	sphpb_ring_freq_sysfs_deinit(sphpb);

cleanup_debug_log_attr:
	sysfs_remove_file(sphpb->kobj, &debug_log_attr.attr);

cleanup_bios_mailbox_attr:
	sysfs_remove_file(sphpb->kobj, &bios_mailbox_locked_attr.attr);

cleanup_kobj:
	kobject_put(sphpb->kobj);
err:
	mutex_destroy(&sphpb->mutex_lock);

	kfree(sphpb);

	return ret;
}


void destroy_sphpb(void)
{
	if (unlikely(g_the_sphpb == NULL))
		return;

	sphpb_throttle_deinit(g_the_sphpb);

	sphpb_power_overshoot_sysfs_deinit(g_the_sphpb);

	sphpb_unmap_bios_mailbox(g_the_sphpb);

	sphpb_sw_counters_fini();

	sphpb_ia_cycles_sysfs_deinit(g_the_sphpb);

	sphpb_ring_freq_sysfs_deinit(g_the_sphpb);

	sysfs_remove_file(g_the_sphpb->kobj, &bios_mailbox_locked_attr.attr);

	sysfs_remove_file(g_the_sphpb->kobj, &debug_log_attr.attr);

	kobject_put(g_the_sphpb->kobj);

	mutex_destroy(&g_the_sphpb->mutex_lock);

	kfree(g_the_sphpb);

	g_the_sphpb = NULL;
}

int sph_power_balancer_init_module(void)
{
	return create_sphpb();
}

void sph_power_balancer_cleanup(void)
{
	destroy_sphpb();
}

module_init(sph_power_balancer_init_module);
module_exit(sph_power_balancer_cleanup);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("SpringHill power balancer");
MODULE_AUTHOR("Intel Corporation");
MODULE_VERSION(SPH_VERSION);
