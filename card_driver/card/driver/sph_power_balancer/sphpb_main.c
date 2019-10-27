/********************************************
 * Copyright (C) 2019 Intel Corporation
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
#include "sph_version.h"
#include "sphpb.h"
#include "sphpb_punit.h"
#include "sphpb_icedriver.h"

struct sphpb_pb *g_the_sphpb;



/* request to get a list of recommended ices to use when job starts */
static int sphpb_get_efficient_ice_list(uint64_t ice_mask,
					enum SPHPB_DDR_REQUEST ddr,
					uint16_t ring_divisor_fx,
					uint16_t ratio_fx,
					uint8_t *o_ice_array,
					ssize_t array_size)
{
	int ret;

	/*
	 * first time call to set initial ring divisor value
	 */
	if (g_the_sphpb->icedrv_cb->get_icebo_to_ring_ratio &&
	    !g_the_sphpb->icebo_ring_divisor)
		ret = g_the_sphpb->icedrv_cb->get_icebo_to_ring_ratio(&g_the_sphpb->icebo_ring_divisor);


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
				  enum SPHPB_DDR_REQUEST ddr,
				  uint16_t ring_divisor_fx,
				  uint16_t ratio_fx)
{
	int ret;

	ret = sphpb_mng_request_ice_dvfs_values(g_the_sphpb,
					    ice_index,
					    ring_divisor_fx,
					    ratio_fx);

	return ret;
}

/* set ice active state */
int sphpb_set_power_state(uint32_t ice_index, bool bOn)
{
	int ret;

	/*
	 * first time call to set initial ring divisor value
	 */
	if (g_the_sphpb->icedrv_cb->get_icebo_to_ring_ratio &&
	    !g_the_sphpb->icebo_ring_divisor)
		ret = g_the_sphpb->icedrv_cb->get_icebo_to_ring_ratio(&g_the_sphpb->icebo_ring_divisor);


	ret = sphpb_mng_set_icebo_enable(g_the_sphpb,
					 ice_index,
					 bOn);

	return ret;
}


void sphpb_unregister_driver(void)
{
	if (!g_the_sphpb) {
		sph_log_err(POWER_BALANCER_LOG, "sph_power_balancer was failed to register");
		return;
	}

	SPH_SPIN_LOCK(&g_the_sphpb->lock);

	g_the_sphpb->icedrv_cb = NULL;

	memset(&g_the_sphpb->icebo, 0x0, sizeof(*g_the_sphpb->icebo));

	SPH_SPIN_UNLOCK(&g_the_sphpb->lock);
}

const struct sphpb_callbacks *sph_power_balancer_register_driver(const struct sphpb_icedrv_callbacks *drv_data)
{
	if (!g_the_sphpb || !drv_data) {
		sph_log_err(POWER_BALANCER_LOG, "sph_power_balancer was failed to register");
		return NULL;
	}

	SPH_SPIN_LOCK(&g_the_sphpb->lock);

	if (g_the_sphpb->icedrv_cb) {
		sph_log_err(POWER_BALANCER_LOG, "sph_power_balancer already registered");
		SPH_SPIN_UNLOCK(&g_the_sphpb->lock);
		return NULL;
	}
	g_the_sphpb->icedrv_cb = drv_data;

	SPH_SPIN_UNLOCK(&g_the_sphpb->lock);

	return &g_the_sphpb->callbacks;
}
EXPORT_SYMBOL(sph_power_balancer_register_driver);

int create_sphbp(void)
{
	struct sphpb_pb *sphpb;
	int icebo;
	int ret = 0;

	g_the_sphpb = NULL;

	/* allocate global sph power balancer object */
	sphpb = kzalloc(sizeof(struct sphpb_pb), GFP_KERNEL);
	if (!sphpb)
		return -ENOMEM;

	sphpb->callbacks.get_efficient_ice_list		= sphpb_get_efficient_ice_list;
	sphpb->callbacks.request_ice_dvfs_values	= sphpb_request_ice_dvfs_values;
	sphpb->callbacks.set_power_state		= sphpb_set_power_state;
	sphpb->callbacks.unregister_driver		= sphpb_unregister_driver;

	sphpb->max_ring_divisor_ice_num = -1;
	for (icebo = 0; icebo < SPHPB_MAX_ICEBO_COUNT; icebo++)
		sphpb->icebo[icebo].ring_divisor_idx = -1;

	sphpb->kobj = kobject_create_and_add("sphpb", kernel_kobj);
	if (unlikely(sphpb->kobj == NULL)) {
		sph_log_err(POWER_BALANCER_LOG, "sphpb kboj creation failed");
		ret = -ENOMEM;
		goto err;
	}

	ret = sphpb_iccp_table_sysfs_init(sphpb);
	if (ret)
		goto cleanup_kobj;

	ret = sphpb_ring_freq_sysfs_init(sphpb);
	if (ret)
		goto cleanup_iccp_table;

	ret = sphpb_ia_cycles_sysfs_init(sphpb);
	if (ret)
		goto cleanup_iccp_table;

	ret = sphpb_icebo_sysfs_init(sphpb);
	if (ret)
		goto cleanup_ia_table;


	spin_lock_init(&sphpb->lock);

	sphpb_map_idc_mailbox_base_registers(sphpb);

	g_the_sphpb = sphpb;

	return ret;

cleanup_ia_table:
	sphpb_ia_cycles_sysfs_deinit(sphpb);

cleanup_iccp_table:
	sphpb_iccp_table_sysfs_deinit(sphpb);

cleanup_kobj:
	kobject_put(sphpb->kobj);
err:
	kfree(sphpb);

	return ret;
}


void destroy_sphpb(void)
{
	if (!g_the_sphpb)
		return;

	sphpb_icebo_sysfs_deinit(g_the_sphpb);

	sphpb_ia_cycles_sysfs_deinit(g_the_sphpb);

	sphpb_ring_freq_sysfs_deinit(g_the_sphpb);

	sphpb_iccp_table_sysfs_deinit(g_the_sphpb);

	sphpb_unmap_idc_mailbox_base_registers(g_the_sphpb);

	kobject_put(g_the_sphpb->kobj);

	kfree(g_the_sphpb);

}

int sph_power_balancer_init_module(void)
{
	int ret = 0;

	ret = create_sphbp();
	if (ret)
		return ret;

	return 0;
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
