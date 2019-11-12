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

#include "cve_device_group.h"
#include "cve_driver_internal_macros.h"
#include "os_interface.h"
#include "cve_linux_internal.h"
#include "dispatcher.h"
#include "device_interface.h"

#include "ice_sw_counters.h"
#ifndef RING3_VALIDATION
#include "intel_sphpb.h"
#else
#include "dummy_intel_sphpb.h"
#endif

#define LLC_PMON_HIT_ICE_0 0x17663B88
#define LLC_PMON_HIT_ICE_1 0x17663B90

static struct cve_device_groups_config config_param_single_dg_all_dev =
		DG_CONFIG_SINGLE_GROUP_ALL_DEVICES;

struct cve_device_group *g_cve_dev_group_list;

/* Consolidated structure to encapsulate all driver dyanmic configurations */
static struct ice_drv_config drv_config_param = {
	.enable_llc_config_via_axi_reg = 0,
	.sph_soc = 0,
	.ice_power_off_delay_ms = 1000,
	.enable_sph_b_step = false,
	.ice_sch_preemption = 1,
	.iccp_throttling = 1,
	.initial_iccp_config[0] = INITIAL_CDYN_VAL,
	.initial_iccp_config[1] = RESET_CDYN_VAL,
	.initial_iccp_config[2] = BLOCKED_CDYN_VAL
};


static struct cve_device_group *__get_ref_to_dg(void)
{
	return g_cve_dev_group_list;
}
static int cve_dg_add_hw_counter(struct cve_device_group *p)
{
	int retval = CVE_DEFAULT_ERROR_CODE;
	uint16_t i;
	uint32_t sz;
	struct cve_hw_cntr_descriptor *hw_cntr_list;

	sz = (sizeof(*hw_cntr_list) * NUM_COUNTER_REG);
	retval = OS_ALLOC_ZERO(sz, (void **)&hw_cntr_list);
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"cve_dg_add_hw_counter failed %d\n",
			retval);
		goto out;
	}
	for (i = 0; i < NUM_COUNTER_REG; i++) {
		hw_cntr_list[i].hw_cntr_id = i;
		hw_cntr_list[i].in_free_pool = true;
		hw_cntr_list[i].cntr_ntw_id = INVALID_NETWORK_ID;

		cve_dle_add_to_list_before(p->hw_cntr_list, list,
			&hw_cntr_list[i]);

		cve_os_log(CVE_LOGLEVEL_DEBUG,
		"CntrHwID=%d added to the DeviceGroup=0x%lx. CounterIAVA=0x%lx\n",
		hw_cntr_list[i].hw_cntr_id,
		(uintptr_t)p, (uintptr_t)&hw_cntr_list[i]);
	}
	p->num_avl_cntr = NUM_COUNTER_REG;
	p->num_nonres_cntr = NUM_COUNTER_REG;
	p->base_addr_hw_cntr = hw_cntr_list;
	/* indicate success */
	retval = 0;

out:
	return retval;
}

static void cve_dg_remove_hw_counter(struct cve_device_group *p)
{
	struct cve_hw_cntr_descriptor *cntr = p->base_addr_hw_cntr;

	while (p->hw_cntr_list) {
		struct cve_hw_cntr_descriptor *cur_cntr = p->hw_cntr_list;

		cve_dle_remove_from_list(p->hw_cntr_list, list, cur_cntr);
	}

	OS_FREE(cntr, sizeof(*cntr) * NUM_COUNTER_REG);
	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"SUCCESS> DG:%p, CountersNr:%d removed from the DG\n",
		p, p->num_avl_cntr);

	p->hw_cntr_list = NULL;
	p->num_avl_cntr = 0;
	p->num_nonres_cntr = 0;
}

static int __add_icebo_list(struct cve_device_group *dg)
{
	int retval = 0;
	uint32_t sz, i;
	struct icebo_desc *bo_list;

	sz = (sizeof(*bo_list) * MAX_NUM_ICEBO);
	retval = OS_ALLOC_ZERO(sz, (void **)&bo_list);
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"__add_icebo_list failed %d\n", retval);
		goto out;
	}
	for (i = 0; i < MAX_NUM_ICEBO; i++) {
		bo_list[i].bo_id = i;
		bo_list[i].bo_curr_state = NO_ICE;
		bo_list[i].bo_init_state = NO_ICE;
		bo_list[i].dev_list = NULL;
	}
	dg->dev_info.icebo_list = bo_list;
	dg->dev_info.picebo_list = NULL;
	dg->dev_info.sicebo_list = NULL;
	dg->dev_info.dicebo_list = NULL;
	dg->dev_info.num_avl_picebo = 0;
	dg->dev_info.num_avl_sicebo = 0;
	dg->dev_info.num_avl_dicebo = 0;
	/* indicate success */
	retval = 0;

out:
	return retval;
}

static void __remove_icebo_list(struct cve_device_group *dg)
{
	OS_FREE(dg->dev_info.icebo_list,
		sizeof(*dg->dev_info.icebo_list) * MAX_NUM_ICEBO);
	dg->dev_info.picebo_list = NULL;
	dg->dev_info.sicebo_list = NULL;
	dg->dev_info.dicebo_list = NULL;
	dg->dev_info.icebo_list = NULL;
	dg->dev_info.num_avl_picebo = 0;
	dg->dev_info.num_avl_sicebo = 0;
	dg->dev_info.num_avl_dicebo = 0;
}

static int cve_ds_create_ds_dev_data(
		struct cve_device_group *dg)
{
	struct ds_dev_data *data;
	int retval = OS_ALLOC_ZERO(sizeof(struct ds_dev_data),
			(void **)&data);
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"cve_ds_create_ds_dev_data failed %d\n",
				retval);
		return retval;
	}

	/*Assign to device*/
	dg->ds_data = data;

	return retval;
}

static void cve_ds_release_ds_dev_data(
		struct cve_device_group *dg)
{
	struct ds_dev_data *ds_dev_data = dg->ds_data;

	OS_FREE(ds_dev_data,
			sizeof(struct ds_dev_data));
}

struct cve_device *cve_device_get(
		u32 dev_index)
{
	struct cve_device *device = NULL;
	struct cve_device_group *tmp = g_cve_dev_group_list;
	int bo_id = dev_index / 2;

	/* find the contex_pid to remove */
	device = cve_dle_lookup(
			tmp->dev_info.icebo_list[bo_id].dev_list,
			bo_list, dev_index, dev_index);

	return device;
}

struct cve_device_group *cve_dg_get(void)
{
	struct cve_device_group *device_group = NULL;

	device_group = __get_ref_to_dg();
	if (!device_group) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"failed to get ice list\n");
	}

	return device_group;
}


static void update_dg_config(void)
{
	g_driver_settings.config = &config_param_single_dg_all_dev;
}

/* Return time diff in usec */
u32 ice_get_usec_timediff(struct timespec *time1, struct timespec *time2)
{
	struct timespec time_out;
	/* time_out = time1 - time2 */
	u32 ret = 0;

	if ((time1->tv_sec < time2->tv_sec) ||
	((time1->tv_sec == time2->tv_sec) &&
	(time1->tv_nsec <= time2->tv_nsec))) {
		time_out.tv_sec = time_out.tv_nsec = 0;
		ret = 0;
		ASSERT(false);
	} else {
		time_out.tv_sec = time1->tv_sec - time2->tv_sec;
		if (time1->tv_nsec < time2->tv_nsec) {
			time_out.tv_nsec = time1->tv_nsec +
				 NSEC_PER_SEC - time2->tv_nsec;
			time_out.tv_sec--;
		} else {
			time_out.tv_nsec = time1->tv_nsec - time2->tv_nsec;
		}
		ret = (time_out.tv_sec * USEC_PER_SEC) +
				(time_out.tv_nsec / NSEC_PER_USEC);
	}

	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"Elapsed time = %u usec\n",
		ret);
	return ret;
}


/* Return time diff in msec */
static u32 __timespec_diff(struct timespec *time1, struct timespec *time2,
		struct timespec *time_out)
{
	/* time_out = time1 - time2 */
	u32 ret = 0;

	if ((time1->tv_sec < time2->tv_sec) ||
	((time1->tv_sec == time2->tv_sec) &&
	(time1->tv_nsec <= time2->tv_nsec))) {
		time_out->tv_sec = time_out->tv_nsec = 0;
		ret = 0;
		ASSERT(false);
	} else {
		time_out->tv_sec = time1->tv_sec - time2->tv_sec;
		if (time1->tv_nsec < time2->tv_nsec) {
			time_out->tv_nsec = time1->tv_nsec +
				 1000000000L - time2->tv_nsec;
			time_out->tv_sec--;
		} else {
			time_out->tv_nsec = time1->tv_nsec - time2->tv_nsec;
		}
		ret = (time_out->tv_sec * 1000) +
				(time_out->tv_nsec / 1000000);
	}

	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"Elapsed time since Power Off request = %u msec\n",
		ret);
	return ret;
}

#ifdef RING3_VALIDATION
static void *ice_pm_monitor_task(void *data)
#else
static int ice_pm_monitor_task(void *data)
#endif
{
	int ret = 0, wq_status;
	u32 icemask;
	u32 configured_timeout_ms = (u32)ice_get_power_off_delay_param();
	u32 time_60sec = 60000;
	u32 timeout_msec = time_60sec;
	struct timespec curr_ts, out_ts;
	struct cve_device *head;
	struct cve_device_group *device_group = (struct cve_device_group *)data;
	const struct sphpb_callbacks *sphpb_cbs;
#ifdef RING3_VALIDATION
	void *retval = NULL;
	u32 factor = 1;
#else
	int retval = 0;
	/* TODO: Simics clock is 20 times fast [ICE-9296] */
	/* u32 factor = 20; */
	u32 factor = 1;
#endif

	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"Power Off thread started\n");
	sphpb_cbs = device_group->sphpb.sphpb_cbs;

	while (1) {

		wq_status = cve_os_block_interruptible_timeout(
				&device_group->power_off_wait_queue,
				device_group->start_poweroff_thread,
				(timeout_msec * factor));
		if (wq_status == -ERESTARTSYS) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
				"cve_os_block_interruptible_timeout error\n");
			/* TODO: Must stop Driver flow [ICE-9539] */
			goto out;
		}

		ret = cve_os_lock(&device_group->poweroff_dev_list_lock,
				CVE_INTERRUPTIBLE);
		if (ret != 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
				"cve_os_lock error\n");
			/* TODO: Must stop Driver flow [ICE-9539] */
			goto out;
		}

		getnstimeofday(&curr_ts);

		head = device_group->poweroff_dev_list;
		if (!head)
			goto out_null_list;

		icemask = 0;
		timeout_msec = __timespec_diff(&curr_ts,
					 &head->poweroff_ts, &out_ts);

		while (timeout_msec >= configured_timeout_ms) {
			if (head->power_state == ICE_POWER_OFF_INITIATED) {

				icemask |= (1 << head->dev_index);
				ice_dev_set_power_state(head, ICE_POWER_OFF);
				ice_swc_counter_set(head->hswc,
					ICEDRV_SWC_DEVICE_COUNTER_POWER_STATE,
					ice_dev_get_power_state(head));

				if (sphpb_cbs && sphpb_cbs->set_power_state) {
					ret = sphpb_cbs->set_power_state(
							head->dev_index, false);
					if (ret) {
						cve_os_dev_log(
							CVE_LOGLEVEL_ERROR,
							head->dev_index,
							"failed setting OFF power state OFF with power balancer (%d)\n",
							ret);
					}
				}

			} else {
				cve_os_log(CVE_LOGLEVEL_DEBUG,
					"ICE-%d allocated to Ntw. Power Off aborted.\n",
					head->dev_index);
			}

			cve_dle_remove_from_list(
				device_group->poweroff_dev_list,
				poweroff_list,
				head);

			head = device_group->poweroff_dev_list;
			if (!head)
				break;

			timeout_msec = __timespec_diff(&curr_ts,
						&head->poweroff_ts, &out_ts);
		}

		if (icemask)
			unset_idc_registers_multi(icemask, false);

out_null_list:

		device_group->start_poweroff_thread = 0;
		cve_os_unlock(&device_group->poweroff_dev_list_lock);

		if (head)
			timeout_msec = (configured_timeout_ms - timeout_msec);
		else {
			timeout_msec = time_60sec;

			if (terminate_thread(device_group))
				break;
		}

		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Thread will wake up in %u msec\n", timeout_msec);
	}

out:
	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"Power Off thread stopped\n");

	return retval;
}

int ice_kmd_create_dg(void)
{
	int retval = CVE_DEFAULT_ERROR_CODE;
	uint32_t i = 0;
	struct cve_device_groups_config *config;
	struct cve_device_group *device_group = NULL;

	/* update device group config parameters */
	update_dg_config();

	config = g_driver_settings.config;

	/* Create a device group and associate all the devices with it*/
	retval = OS_ALLOC_ZERO(sizeof(*device_group),
			(void **)&device_group);
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"Allocation failed(%d) for dg control block\n",
					 retval);
		goto out;
	}

	/* Power off wait queue Initialization */
	retval = cve_os_init_wait_que(&device_group->power_off_wait_queue);
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"events_wait_queue init failed  %d\n", retval);
		goto out_dev_data_fail;
	}

	/* initialize dispatcher data */
	retval = cve_ds_create_ds_dev_data(device_group);
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"failed to created ds data %d\n",
				retval);
		goto out_dev_data_fail;
	}

	/* add hw counters to the device group */
	retval = cve_dg_add_hw_counter(device_group);
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"failed to add hw counter to the device group %d\n",
			retval);
		goto out_hw_counter_fail;
	}

	retval = __add_icebo_list(device_group);
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"failed to add ICEBO list to the device group %d\n",
			retval);
		goto out_add_icebo_fail;
	}

	device_group->dg_id = i;
	device_group->expected_devices_nr =
			config->groups[i].devices_nr;
	device_group->dev_info.active_device_nr = 0;
	device_group->icedc_state = ICEDC_STATE_NO_ERROR;
#ifdef _DEBUG
	device_group->dg_exe_order = 0;
#endif
	device_group->num_avl_pool = MAX_IDC_POOL_NR;
	device_group->num_nonres_pool = MAX_IDC_POOL_NR;
	device_group->ntw_with_resources = NULL;
	device_group->num_running_ntw = 0;

	device_group->dg_clos_manager.size = MAX_CLOS_SIZE_MB;
	ice_os_read_clos((void *)&device_group->dg_clos_manager);

	for (i = 0; i < MAX_CVE_DEVICES_NR; i++)
		device_group->dice_res_status[i] = 0;

	cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Added device group %d\n",
			device_group->dg_id);

	device_group->sphpb.sphpb_cbs = NULL;
	/* Add the device_group to the global list */
	cve_dle_add_to_list_before(g_cve_dev_group_list,
			list, device_group);

	/* success */
	return 0;

out_add_icebo_fail:
	cve_dg_remove_hw_counter(device_group);
out_hw_counter_fail:
	cve_ds_release_ds_dev_data(device_group);
out_dev_data_fail:
	OS_FREE(device_group, sizeof(*device_group));
out:
	return retval;
}

int ice_kmd_destroy_dg(void)
{
	int retval = CVE_DEFAULT_ERROR_CODE;

	/* free the ICE device list */
	while (g_cve_dev_group_list) {
		struct cve_device_group *device_group = g_cve_dev_group_list;

		ice_os_reset_clos((void *)&device_group->dg_clos_manager);

		cve_dle_remove_from_list(
				g_cve_dev_group_list, list, device_group);

		cve_os_log(CVE_LOGLEVEL_DEBUG,
				"Remove device group %d\n",
				device_group->dg_id);

		cve_ds_release_ds_dev_data(device_group);

		cve_dg_remove_hw_counter(device_group);

		__remove_icebo_list(device_group);

		OS_FREE(device_group, sizeof(*device_group));
	}

	/* success */
	retval = 0;

	return retval;
}


int cve_dg_add_device(struct cve_device *cve_dev)
{
	int retval = CVE_DEFAULT_ERROR_CODE;
	struct cve_device_group *curr = g_cve_dev_group_list;
	struct cve_device_group *p = curr;
	struct icebo_desc *bo = &p->dev_info.icebo_list[cve_dev->dev_index / 2];

	do {
		/* if the device group does not complete
		 * add this device to this group
		 */
		if (p->expected_devices_nr != p->dev_info.active_device_nr) {
			cve_os_log(CVE_LOGLEVEL_DEBUG,
					"Add device %d to device group %d\n",
					cve_dev->dev_index,
					p->dg_id);

			p->dev_info.active_device_nr++;

			cve_dle_add_to_list_before(bo->dev_list,
					bo_list, cve_dev);

			if (bo->bo_init_state == NO_ICE) {

				cve_dle_add_to_list_before(
					p->dev_info.dicebo_list, owner_list,
					bo);
				p->dev_info.num_avl_dicebo++;
				bo->bo_init_state = ONE_ICE;
				bo->bo_curr_state = ONE_ICE;
				bo->llc_pmon_cfg.disable_llc_pmon = false;
				bo->iccp_init_done = false;
				bo->llc_pmon_cfg.pmon0_cfg = LLC_PMON_HIT_ICE_0;
				bo->llc_pmon_cfg.pmon1_cfg = LLC_PMON_HIT_ICE_1;

			} else if (bo->bo_init_state == ONE_ICE) {

				cve_dle_move(p->dev_info.picebo_list,
					p->dev_info.dicebo_list, owner_list,
					bo);
				p->dev_info.num_avl_dicebo--;
				p->dev_info.num_avl_picebo++;
				bo->bo_init_state = TWO_ICE;
				bo->bo_curr_state = TWO_ICE;
			} else
				ASSERT(false);

			p->num_nonres_picebo = p->dev_info.num_avl_picebo;
			p->num_nonres_dicebo = p->dev_info.num_avl_dicebo;

			cve_dev->dg = p;
			cve_dev->in_free_pool = true;

			ice_swc_counter_set(g_sph_swc_global,
				ICEDRV_SWC_GLOBAL_ACTIVE_ICE_COUNT,
				p->dev_info.active_device_nr);

			/* indicate success */
			retval = 0;

			break;
		}
		p = cve_dle_next(p, list);
	} while (curr != p);

	return retval;
}

int cve_dg_remove_device(struct cve_device *cve_dev)
{
	int retval = CVE_DEFAULT_ERROR_CODE;
	struct cve_device_group *curr = g_cve_dev_group_list;
	struct cve_device_group *p = curr;
	int bo_id = cve_dev->dev_index / 2;

	do {
		struct cve_device *dev;

		dev = cve_dle_lookup(p->dev_info.icebo_list[bo_id].dev_list,
				bo_list, dev_index, cve_dev->dev_index);

		if (dev) {
			cve_os_log(CVE_LOGLEVEL_DEBUG,
				"Remove device %d from device group %d\n",
				cve_dev->dev_index,
				p->dg_id);

			p->dev_info.active_device_nr--;

			cve_dle_remove_from_list(
					p->dev_info.icebo_list[bo_id].dev_list,
					bo_list, cve_dev);
			/* indicate success */
			retval = 0;
			break;
		}

		p = cve_dle_next(p, list);
	} while (curr != p);

	return retval;
}

static void print_wq_ds_data(struct cve_device_group *dg)
{
	struct cve_workqueue *curr = dg->ds_data->ready_workqueues;
	struct cve_workqueue *p = curr;

	cve_os_log(CVE_LOGLEVEL_DEBUG, "DISPATCH DATA\n");

	if (curr) {
		do {
			cve_os_log(CVE_LOGLEVEL_DEBUG,
					"READY wq_id=%lld\n", p->wq_id);
			p = cve_dle_next(p, list);
		} while (curr != p);
	}

	curr = dg->ds_data->idle_workqueues;
	p = curr;

	if (curr) {
		do {
			cve_os_log(CVE_LOGLEVEL_DEBUG,
					"IDLE wq_id=%lld\n", p->wq_id);
			p = cve_dle_next(p, list);
		} while (curr != p);
	}

	curr = dg->ds_data->dispatch_workqueues;
	p = curr;

	if (curr) {
		do {
			cve_os_log(CVE_LOGLEVEL_DEBUG,
					"DISPATCH wq_id=%lld\n",
					p->wq_id);
			p = cve_dle_next(p, list);
		} while (curr != p);
	}
}

void cve_dg_print(struct cve_device_group *group)
{
	/* print group attributes */
	cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Device Group: id=%d\n",
			group->dg_id);
	cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Device Group: active_devices_nr=%d\n",
			group->dev_info.active_device_nr);
	cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Device Group: llc_size=%d\n",
			group->dg_clos_manager.size);

	/* print dispatch data lists */
	print_wq_ds_data(group);
}

int cve_dg_start_poweroff_thread(void)
{
	int retval;
	struct cve_device_group *device_group = g_cve_dev_group_list;

	device_group->poweroff_dev_list = NULL;
	device_group->start_poweroff_thread = 0;
	retval = cve_os_lock_init(&device_group->poweroff_dev_list_lock);
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"cve_os_lock_init failed %d\n", retval);
		goto out;
	}

	if (ice_get_power_off_delay_param() < 0) {
		cve_os_log(CVE_LOGLEVEL_INFO,
				"Power off thead creation skipped\n");
		goto out;
	}

#ifdef RING3_VALIDATION
	device_group->terminate_thread = 0;
	pthread_create(&device_group->thread,
				NULL, ice_pm_monitor_task, device_group);
#else
	device_group->thread = kthread_run(ice_pm_monitor_task,
				device_group, "icedrv_LPM");
#endif

out:
	return retval;
}

void cve_dg_stop_poweroff_thread(void)
{
	struct cve_device_group *device_group = g_cve_dev_group_list;

	if (ice_get_power_off_delay_param() < 0) {
		cve_os_log(CVE_LOGLEVEL_DEBUG,
				"power of thread was not created\n");
		return;
	}

	device_group->start_poweroff_thread = 1;

	/* Blocking call till the thread is terminated */
#ifdef RING3_VALIDATION
	device_group->terminate_thread = 1;
	cve_os_wakeup(&device_group->power_off_wait_queue);

	if (pthread_join(device_group->thread, NULL) != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"ice_pm_monitor_task termination error\n");
	}
#else
	cve_os_wakeup(&device_group->power_off_wait_queue);
	kthread_stop(device_group->thread);
#endif
}

void ice_set_driver_config_param(struct ice_drv_config *param)
{
	drv_config_param.enable_llc_config_via_axi_reg =
			param->enable_llc_config_via_axi_reg;
	drv_config_param.sph_soc = param->sph_soc;
	drv_config_param.ice_power_off_delay_ms = param->ice_power_off_delay_ms;
	drv_config_param.enable_sph_b_step = param->enable_sph_b_step;
	drv_config_param.ice_sch_preemption = param->ice_sch_preemption;
	drv_config_param.iccp_throttling = param->iccp_throttling;
	drv_config_param.initial_iccp_config[0] = param->initial_iccp_config[0];
	drv_config_param.initial_iccp_config[1] = param->initial_iccp_config[1];
	drv_config_param.initial_iccp_config[2] = param->initial_iccp_config[2];

	cve_os_log(CVE_LOGLEVEL_INFO,
			"DriverConfig: enable_llc_config_via_axi_reg:%d sph_soc:%d ice_power_off_delay_ms:%d, is_b_step_enabled: %d Preemption:%d is_iccp_throttling_enabled:%d initial_cdyn:0x%x reset_cdyn:0x%x blocked_cdyn:0x%x\n",
			drv_config_param.enable_llc_config_via_axi_reg,
			drv_config_param.sph_soc,
			drv_config_param.ice_power_off_delay_ms,
			drv_config_param.enable_sph_b_step,
			drv_config_param.ice_sch_preemption,
			drv_config_param.iccp_throttling,
			drv_config_param.initial_iccp_config[0],
			drv_config_param.initial_iccp_config[1],
			drv_config_param.initial_iccp_config[2]);
}

struct ice_drv_config *ice_get_driver_config_param(void)
{
	return &drv_config_param;
}

u8 ice_enable_llc_config_via_axi_reg(void)
{
	return drv_config_param.enable_llc_config_via_axi_reg;
}

int ice_get_power_off_delay_param(void)
{
	return drv_config_param.ice_power_off_delay_ms;
}

int ice_get_b_step_enable_flag(void)
{
	return drv_config_param.enable_sph_b_step;
}

int ice_get_iccp_throttling_flag(void)
{
	return drv_config_param.iccp_throttling;
}

u32 ice_get_initial_cdyn_val(void)
{
	return drv_config_param.initial_iccp_config[0];
}

u32 ice_get_reset_cdyn_val(void)
{
	return drv_config_param.initial_iccp_config[1];
}

u32 ice_get_blocked_cdyn_val(void)
{
	return drv_config_param.initial_iccp_config[2];
}

struct cve_device *ice_get_first_dev(void)
{
	struct cve_device *dev = NULL;
	struct cve_device_group *dg = g_cve_dev_group_list;
	int i;

	for (i = 0; i < MAX_NUM_ICEBO; i++) {
		dev = dg->dev_info.icebo_list[i].dev_list;
		if (!dev)
			continue;
		break;
	}

	return dev;
}

u8 ice_is_soc(void)
{
	return drv_config_param.sph_soc;
}

u8 ice_sch_allow_preemption(void)
{
	return drv_config_param.ice_sch_preemption;
}
