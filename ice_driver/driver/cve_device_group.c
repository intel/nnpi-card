/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/



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
	.ice_power_off_delay_ms = 0,
	.enable_sph_b_step = false,
	.enable_sph_c_step = false,
	.ice_sch_preemption = 1,
	.iccp_throttling = 1,
	.initial_iccp_config[0] = INITIAL_CDYN_VAL,
	.initial_iccp_config[1] = RESET_CDYN_VAL,
	.initial_iccp_config[2] = BLOCKED_CDYN_VAL,
};

static struct cve_device_group *__get_ref_to_dg(void)
{
	return g_cve_dev_group_list;
}

static int cve_dg_add_hw_counter(struct cve_device_group *p)
{
	int retval = CVE_DEFAULT_ERROR_CODE;
	uint16_t i;
	size_t sz;
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
		hw_cntr_list[i].cntr_pntw_id = INVALID_NETWORK_ID;
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
	size_t sz;
	uint32_t i;
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
		bo_list[i].dev_list = NULL;
		bo_list[i].in_pool_ice = NO_ICE;
		bo_list[i].non_res_ice = NO_ICE;
	}
	dg->dev_info.icebo_list = bo_list;
	dg->dev_info.picebo_list = NULL;
	dg->dev_info.dicebo_list = NULL;
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
	dg->dev_info.dicebo_list = NULL;
	dg->dev_info.icebo_list = NULL;
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

/* Return true if time1 > time2 else false */
static u32 __is_time_greater(const u64 t1, const u64 t2)
{
	if (t1 < t2)
		return 0;
	else
		return 1;
}

#ifdef RING3_VALIDATION
static void *ice_pm_monitor_task(void *data)
#else
static int ice_pm_monitor_task(void *data)
#endif
{
	int ret = 0, wq_status;
	u32 icemask;
	u32 configured_timeout_ms;
	u32 time_60sec = 60000;
	u32 timeout_msec = time_60sec;
	unsigned long cur_jiffy;
	struct cve_device *head;
	struct cve_device_group *dg = (struct cve_device_group *)data;
	const struct sphpb_callbacks *sphpb_cbs;
	u64 t;

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

	while (1) {

		wq_status = cve_os_block_interruptible_timeout(
				&dg->power_off_wait_queue,
				dg->start_poweroff_thread,
				(timeout_msec * factor));
		if (wq_status == -ERESTARTSYS) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
				"cve_os_block_interruptible_timeout error\n");
			/* TODO: Must stop Driver flow [ICE-9539] */
			goto out;
		}

		ret = cve_os_lock(&dg->poweroff_dev_list_lock,
				CVE_INTERRUPTIBLE);
		if (ret != 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
				"cve_os_lock error\n");
			/* TODO: Must stop Driver flow [ICE-9539] */
			goto out;
		}

		/* Value can be changed dynamically through sysfs */
		configured_timeout_ms = (u32)ice_get_power_off_delay_param();
		cur_jiffy = ice_os_get_current_jiffy();

		head = dg->poweroff_dev_list;
		if (!head)
			goto out_null_list;

		icemask = 0;
		t = trace_clock_global();

		while (jiffies_to_msecs(cur_jiffy - head->poff_jiffy) >=
				configured_timeout_ms) {

			/* The ICEs can be in either ON or INITIATED state
			 * because maybe power-off thread started after
			 * executing some tests.
			 */
			ASSERT((head->power_state == ICE_POWER_OFF_INITIATED) ||
				(head->power_state == ICE_POWER_ON));

			icemask |= (1 << head->dev_index);
			ice_dev_set_power_state(head, ICE_POWER_OFF);
			ice_swc_counter_set(head->hswc,
					ICEDRV_SWC_DEVICE_COUNTER_POWER_STATE,
					ice_dev_get_power_state(head));

			if (!__is_time_greater(head->idle_start_time,
						head->busy_start_time)) {
				head->idle_start_time = t;
				ice_swc_counter_set(head->hswc,
				ICEDRV_SWC_DEVICE_COUNTER_IDLE_START_TIME,
				nsec_to_usec(head->idle_start_time));
			}

			sphpb_cbs = dg->sphpb.sphpb_cbs;
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

			cve_dle_remove_from_list(
				dg->poweroff_dev_list,
				poweroff_list,
				head);

			head = dg->poweroff_dev_list;
			if (!head)
				break;
		}

		if (icemask)
			unset_idc_registers_multi(icemask, false);

out_null_list:

		dg->start_poweroff_thread = 0;
		cve_os_unlock(&dg->poweroff_dev_list_lock);

		if (head) {
			/* For how long (in msec) the head is in queue */
			u32 time_spent = jiffies_to_msecs(cur_jiffy -
							head->poff_jiffy);

			timeout_msec = (configured_timeout_ms - time_spent);
		} else {
			timeout_msec = time_60sec;

			if (terminate_thread(dg))
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
#ifdef RING3_VALIDATION
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"events_wait_queue init failed  %d\n", retval);
		goto out_dev_data_fail;
	}
#endif

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

	device_group->dump_conf.pt_dump = 0;
#ifdef _DEBUG
	device_group->dg_exe_order = 0;
#endif
	device_group->num_avl_pool = MAX_IDC_POOL_NR;
	device_group->num_nonres_pool = MAX_IDC_POOL_NR;
	device_group->pntw_with_resources = NULL;
	device_group->num_running_ntw = 0;
	device_group->clos_state = CLOS_STATE_DEFAULT;
	device_group->total_pbo = 0;
	device_group->in_pool_pbo = 0;
	device_group->non_res_pbo = 0;
	device_group->total_dice = 0;
	device_group->in_pool_dice = 0;
	device_group->non_res_dice = 0;
	device_group->poweroff_dev_list = NULL;

	cve_os_lock_init(&device_group->poweroff_dev_list_lock);

	device_group->dg_clos_manager.size = MAX_CLOS_SIZE_MB;
	ice_os_read_clos((void *)&device_group->dg_clos_manager);

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

			if (bo->in_pool_ice == NO_ICE) {

				cve_dle_add_to_list_before(
					p->dev_info.dicebo_list, owner_list,
					bo);
				bo->llc_pmon_cfg.disable_llc_pmon = false;
				bo->iccp_init_done = false;
				bo->llc_pmon_cfg.pmon0_cfg = LLC_PMON_HIT_ICE_0;
				bo->llc_pmon_cfg.pmon1_cfg = LLC_PMON_HIT_ICE_1;
				bo->in_pool_ice = ONE_ICE;
				bo->non_res_ice = ONE_ICE;

				p->total_dice++;
				p->in_pool_dice++;
				p->non_res_dice++;

			} else if (bo->in_pool_ice == ONE_ICE) {

				cve_dle_move(p->dev_info.picebo_list,
					p->dev_info.dicebo_list, owner_list,
					bo);
				bo->in_pool_ice = TWO_ICE;
				bo->non_res_ice = TWO_ICE;

				p->total_dice--;
				p->in_pool_dice--;
				p->non_res_dice--;

				p->total_pbo++;
				p->in_pool_pbo++;
				p->non_res_pbo++;
			} else
				ASSERT(false);

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
	struct cve_device_group *device_group = g_cve_dev_group_list;

	/* To turn off any devices already in queue */
	device_group->start_poweroff_thread = 1;

	if (!ice_get_power_off_delay_param()) {
		cve_os_log(CVE_LOGLEVEL_INFO,
				"Power off thread creation skipped\n");
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
	return 0;
}

void cve_dg_stop_poweroff_thread(void)
{
	struct cve_device_group *device_group = g_cve_dev_group_list;

	if (!ice_get_power_off_delay_param()) {
		/*
		 * If here, it means Power-off thread was never started and
		 * ICEDrv is about to be unloaded. Not reporting to PB because
		 * anyways it will reset its status when ICEDrv is unregistered
		 */
		cve_os_log(CVE_LOGLEVEL_DEBUG,
				"Power off thread was not created. Forcing all ICEs off\n");
		unset_idc_registers_multi(0xFFF, true);

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
	drv_config_param.enable_sph_b_step = param->enable_sph_b_step;
	drv_config_param.enable_sph_c_step = param->enable_sph_c_step;
	drv_config_param.ice_sch_preemption = param->ice_sch_preemption;
	drv_config_param.iccp_throttling = param->iccp_throttling;
	drv_config_param.initial_iccp_config[0] = param->initial_iccp_config[0];
	drv_config_param.initial_iccp_config[1] = param->initial_iccp_config[1];
	drv_config_param.initial_iccp_config[2] = param->initial_iccp_config[2];
	ice_set_power_off_delay_param(param->ice_power_off_delay_ms);

	cve_os_log(CVE_LOGLEVEL_INFO,
			"DriverConfig: enable_llc_config_via_axi_reg:%d sph_soc:%d ice_power_off_delay_ms:%d, is_b_step_enabled: %d is_c_step_enabled: %d Preemption:%d is_iccp_throttling_enabled:%d initial_cdyn:0x%x reset_cdyn:0x%x blocked_cdyn:0x%x\n",
			drv_config_param.enable_llc_config_via_axi_reg,
			drv_config_param.sph_soc,
			drv_config_param.ice_power_off_delay_ms,
			drv_config_param.enable_sph_b_step,
			drv_config_param.enable_sph_c_step,
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

void ice_set_power_off_delay_param(int time_ms)
{
	drv_config_param.ice_power_off_delay_ms = time_ms;
}

int ice_get_power_off_delay_param(void)
{
	int delay = drv_config_param.ice_power_off_delay_ms;

	if (delay <= 0)
		return 0;
	else
		return drv_config_param.ice_power_off_delay_ms;
}

int ice_get_a_step_enable_flag(void)
{
	if (drv_config_param.enable_sph_c_step ||
		drv_config_param.enable_sph_b_step)
		return false;
	else
		return true;
}

int ice_get_b_step_enable_flag(void)
{
	return drv_config_param.enable_sph_b_step;
}

int ice_get_c_step_enable_flag(void)
{
	return drv_config_param.enable_sph_c_step;
}

int ice_check_b_or_c_step_enable_flag(void)
{
	if (drv_config_param.enable_sph_c_step ||
		drv_config_param.enable_sph_b_step)
		return true;
	else
		return false;
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

enum resource_status ice_dg_check_resource_availability(
		struct ice_pnetwork *pntw)
{
	/* TODO: Add debug logs */
	struct cve_device_group *dg = cve_dg_get();
	u32 count = 0;
	enum resource_status tmp_status;
	enum resource_status status = RESOURCE_INSUFFICIENT;

	if (pntw->temp_icebo_req != ICEBO_DEFAULT) {

		int in_pool_dice = 2 * (dg->in_pool_pbo - pntw->temp_pbo_req) +
				dg->in_pool_dice;
		int non_res_dice = 2 * (dg->non_res_pbo - pntw->temp_pbo_req) +
				dg->non_res_dice;

		if ((pntw->temp_pbo_req <= dg->in_pool_pbo) &&
			(pntw->temp_dice_req <= in_pool_dice))

			tmp_status = RESOURCE_OK;

		else if ((pntw->temp_pbo_req <= dg->non_res_pbo) &&
			(pntw->temp_dice_req <= non_res_dice))

			tmp_status = RESOURCE_BUSY;

		else
			goto out;

	} else {

		int num_ice_req = (2 * pntw->temp_pbo_req) +
					pntw->temp_dice_req;
		int num_ice_pool = (2 * dg->in_pool_pbo) +
					dg->in_pool_dice;
		int num_ice_non_res = (2 * dg->non_res_pbo) +
					dg->non_res_dice;

		if (num_ice_req <= num_ice_pool)
			tmp_status = RESOURCE_OK;
		else if (num_ice_req <= num_ice_non_res)
			tmp_status = RESOURCE_BUSY;
		else
			goto out;

	}

	__local_builtin_popcount(pntw->cntr_bitmap, count);
	if (count <= dg->num_avl_cntr)
		status = tmp_status;
	else if (count <= dg->num_nonres_cntr)
		status = RESOURCE_BUSY;

out:
	if (status != RESOURCE_OK) {
		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"PNtwID=0x%lx. PNtw_pBO=%d, PNtw_dICE=%d, DG_ippBO=%d, DG_ipdICE=%d, DG_nrpBO=%d, DG_nrdICE=%d\n",
			(uintptr_t)pntw,
			pntw->temp_pbo_req, pntw->temp_dice_req,
			dg->in_pool_pbo, dg->in_pool_dice,
			dg->non_res_pbo, dg->non_res_dice);

		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"PNtwID=0x%lx. PNtw_Cntr=%d, DG_ipCntr=%d, DG_nrCntr=%d\n",
			(uintptr_t)pntw, count, dg->num_avl_cntr,
			dg->num_nonres_cntr);
	}

	return status;
}

bool ice_dg_can_lazy_capture_ice(struct ice_pnetwork *pntw)
{
	u32 i, no_prev_dev = 1;
	bool lazy_capture = true;
	struct cve_device *dev;

	if (pntw->temp_icebo_req != pntw->given_icebo_req) {
		lazy_capture = false;
		cve_os_log(CVE_LOGLEVEL_INFO,
			"Lazy False PNtwID=0x%lx pntw->temp_icebo_req:%d pntw->given_icebo_req:%d\n",
			(uintptr_t)pntw,
			pntw->temp_icebo_req,
			pntw->given_icebo_req);
		goto out;
	}

	/* Check if previous ICEs are still available */
	for (i = 0; i < pntw->num_ice; i++) {

		if (pntw->cur_ice_map[i] < 0)
			continue;

		no_prev_dev = 0;
		dev = cve_device_get(pntw->cur_ice_map[i]);

		/* ICE must be
		 *	1. Powered on
		 *	2. In free list
		 *	3. Last executing Ntw must be same as this
		 */
		if (!dev) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
				"cve dev is NULL");
			ASSERT(false);
		}
		if ((dev->power_state == ICE_POWER_OFF) ||
			(dev->dev_pntw_id != pntw->pntw_id) ||
			!dev->in_free_pool) {

			cve_os_log(CVE_LOGLEVEL_INFO,
					"Lazy False PNtwID=0x%lx ICE%d dev->dev_pntw_id:0x%llx pntw->pntw_id:0x%llx dev->in_free_pool:%u\n",
					(uintptr_t)pntw,
					dev->dev_index,
					dev->dev_pntw_id,
					pntw->pntw_id,
					dev->in_free_pool);
			lazy_capture = false;
			break;
		}
	}

	if (no_prev_dev) {
		lazy_capture = false;
			cve_os_log(CVE_LOGLEVEL_INFO,
					"Lazy False PNtwID=0x%lx No prev Dev\n",
					(uintptr_t)pntw);

	}
out:
	return lazy_capture;
}

void ice_dg_borrow_this_ice(struct ice_pnetwork *pntw,
		struct cve_device *dev, bool lazy)
{
	struct cve_device_group *dg = cve_dg_get();
	struct icebo_desc *bo = &dg->dev_info.icebo_list[dev->dev_index / 2];

	if (dev->dev_ctx_id != pntw->wq->context->context_id) {

		cve_di_set_device_reset_flag(dev, CVE_DI_RESET_DUE_CTX_SWITCH);
		dev->dev_ctx_id = pntw->wq->context->context_id;
	}

	dev->dev_pntw_id = pntw->pntw_id;
	if (pntw->curr_ntw)
		dev->dev_ntw_id = pntw->curr_ntw->network_id;

	cve_os_log(CVE_LOGLEVEL_INFO,
			"PNtwID:0x%llx Reserved ICE%d power_status:%d\n",
			pntw->pntw_id, dev->dev_index,
			ice_dev_get_power_state(dev));

	if (!lazy)
		cve_di_set_device_reset_flag(dev, CVE_DI_RESET_DUE_PNTW_SWITCH);

	cve_dle_add_to_list_before(pntw->ice_list, owner_list, dev);
	dev->in_free_pool = false;

	if (dev->power_state == ICE_POWER_OFF_INITIATED) {

		ice_dev_set_power_state(dev, ICE_POWER_ON);

		cve_dle_remove_from_list(dg->poweroff_dev_list,
			poweroff_list, dev);

		ice_swc_counter_set(dev->hswc,
			ICEDRV_SWC_DEVICE_COUNTER_POWER_STATE,
			ice_dev_get_power_state(dev));
	}

	if (bo->in_pool_ice == TWO_ICE) {

		ASSERT(dg->in_pool_pbo);

		dg->in_pool_pbo--;
		dg->in_pool_dice++;

		cve_dle_move(dg->dev_info.dicebo_list,
			dg->dev_info.picebo_list, owner_list, bo);

	} else if (bo->in_pool_ice == ONE_ICE) {

		ASSERT(dg->in_pool_dice);

		dg->in_pool_dice--;

		cve_dle_remove_from_list(dg->dev_info.dicebo_list,
			owner_list, bo);

	} else
		ASSERT(false);

	bo->in_pool_ice--;
}

void ice_dg_borrow_next_pbo(struct ice_pnetwork *pntw,
		struct cve_device **ice0,
		struct cve_device **ice1)
{
	struct cve_device_group *dg = cve_dg_get();
	struct icebo_desc *bo = dg->dev_info.picebo_list;
	struct cve_device *dev;

	/* add first device of BOn to ntw ice list */
	dev = bo->dev_list;
	ice_dg_borrow_this_ice(pntw, dev, false);
	*ice0 = dev;

	dev = cve_dle_next(dev, bo_list);
	ice_dg_borrow_this_ice(pntw, dev, false);
	*ice1 = dev;
}

void ice_dg_borrow_next_dice(struct ice_pnetwork *pntw,
		struct cve_device **ice0)
{
	struct cve_device_group *dg = cve_dg_get();
	struct icebo_desc *bo;
	struct cve_device *dev;

	if (dg->dev_info.dicebo_list) {
		bo = dg->dev_info.dicebo_list;
		dev = bo->dev_list;

		if (!dev->in_free_pool)
			dev = cve_dle_next(dev, bo_list);

	} else {
		bo = dg->dev_info.picebo_list;
		ASSERT(bo);
		dev = bo->dev_list;

	}

	ASSERT(dev);
	ice_dg_borrow_this_ice(pntw, dev, false);
	*ice0 = dev;
}

void ice_dg_reserve_this_ice(struct cve_device *dev)
{
	struct cve_device_group *dg = cve_dg_get();
	struct icebo_desc *bo = &dg->dev_info.icebo_list[dev->dev_index / 2];

	if (bo->non_res_ice == TWO_ICE) {

		ASSERT(dg->non_res_pbo);

		dg->non_res_pbo--;
		dg->non_res_dice++;

	} else if (bo->non_res_ice == ONE_ICE) {

		ASSERT(dg->non_res_dice);

		dg->non_res_dice--;

	} else
		ASSERT(false);

	bo->non_res_ice--;
}

void ice_dg_release_this_ice(struct cve_device *dev)
{
	struct cve_device_group *dg = cve_dg_get();
	struct icebo_desc *bo = &dg->dev_info.icebo_list[dev->dev_index / 2];

	if (bo->non_res_ice == ONE_ICE) {

		dg->non_res_pbo++;
		dg->non_res_dice--;

	} else if (bo->non_res_ice == NO_ICE) {

		dg->non_res_dice++;

	} else
		ASSERT(false);

	bo->non_res_ice++;
}

void ice_dg_return_this_ice(struct ice_pnetwork *pntw,
		struct cve_device *dev)
{
	struct cve_device_group *dg = cve_dg_get();
	struct icebo_desc *bo = &dg->dev_info.icebo_list[dev->dev_index / 2];

	/* Forced release will ensure correct state */
	dev->state = CVE_DEVICE_IDLE;

	cve_dle_remove_from_list(pntw->ice_list, owner_list, dev);

	/*Invalidate the ICE ID */
	ice_swc_counter_set(dev->hswc_infer,
			ICEDRV_SWC_INFER_DEVICE_COUNTER_ID,
			0xFFFF);
	dev->hswc_infer = NULL;
	cve_os_log(CVE_LOGLEVEL_INFO,
			"PNtwID:0x%llx ICEBO:%d released ICE%d\n",
			pntw->pntw_id, bo->bo_id, dev->dev_index);

	dev->in_free_pool = true;

	if (bo->in_pool_ice == ONE_ICE) {

		dg->in_pool_pbo++;
		dg->in_pool_dice--;

		cve_dle_move(dg->dev_info.picebo_list,
			dg->dev_info.dicebo_list, owner_list, bo);

	} else if (bo->in_pool_ice == NO_ICE) {

		dg->in_pool_dice++;

		cve_dle_add_to_list_before(dg->dev_info.dicebo_list,
			owner_list, bo);
	} else
		ASSERT(false);

	bo->in_pool_ice++;
}

#if 0

/*
 * TODO: Enable in future. Not blocking.
 * https://jira.devtools.intel.com/browse/ICE-26298
 */

ice_dg_can_lazy_capture_cntr()
ice_dg_borrow_next_cntr()
ice_dg_borrow_this_cntr()
ice_dg_reserve_this_cntr()
ice_dg_release_this_cntr()
ice_dg_return_this_cntr()
#endif
