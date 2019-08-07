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

#include "scheduler.h"
#include "cve_device_group.h"
#include "dispatcher.h"
#include "memory_manager.h"
#include "ice_debug.h"
#include "dev_context.h"

#ifdef RING3_VALIDATION
#include "coral.h"
#else
#include "icedrv_sw_trace.h"
#endif
#include "ice_debug_event.h"

static struct ice_network *scheduled_ntw_list;

/* return 1 iff job is marked as finished */
static inline int is_jobgroup_finished(struct jobgroup_descriptor *jobgroup)
{
	return (jobgroup->ended_jobs_nr == jobgroup->submitted_jobs_nr);
}

void ice_schedule_network(struct ice_network *ntw)
{
	if (!ntw->ntw_queued) {

		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Adding NtwID:0x%llx to Scheduler List\n",
			ntw->network_id);

		ntw->ntw_queued = true;
		cve_dle_add_to_list_before(scheduled_ntw_list,
				exe_list, ntw);

	} else if (ntw->ntw_running) {
		/* Since this Ntw is running, scheduler will be
		 * automatically invoked once the Ntw is over.
		 */

		goto exit;
	}

	ice_scheduler_engine(ntw);

#ifdef RING3_VALIDATION
	cve_os_log(CVE_LOGLEVEL_DEBUG, "Execute ICEs\n");
	coral_trigger_simulation();
#endif

exit:
	return;
}

static void __reset_scheduler_param(void)
{
	struct ice_network *head_ntw, *ntw;

	head_ntw = scheduled_ntw_list;
	ntw = head_ntw;

	if (!ntw)
		goto end;

	do {
		ntw->handled_by_sch = 0;

		ntw = cve_dle_next(ntw, exe_list);
	} while (head_ntw != ntw);

end:
	return;
}

struct ice_infer *ice_sch_get_next_ntw_infer(struct ice_network *ntw)
{
	struct ice_infer *inf = NULL;
	enum ice_execute_infer_priority pr;

	for (pr = EXE_INF_PRIORITY_0; pr < EXE_INF_PRIORITY_MAX; pr++) {

		inf = ntw->inf_exe_list[pr];
		if (inf)
			break;
	}

	return inf;
}

struct ice_infer *ice_sch_get_next_sch_infer(void)
{
	u64 min_exe_order = EXE_ORDER_MAX;
	struct ice_network *head_ntw, *ntw;
	struct ice_infer *inf, *next_inf = NULL;
	enum ice_execute_infer_priority min_pr = EXE_INF_PRIORITY_MAX;

	head_ntw = scheduled_ntw_list;
	ntw = head_ntw;

	if (!ntw)
		goto end;

	do {
		if (ntw->ntw_running || ntw->ntw_aborted || ntw->handled_by_sch)
			goto skip_ntw;

		inf = ice_sch_get_next_ntw_infer(ntw);
		if (!inf)
			goto skip_ntw;

		if (inf->inf_pr < min_pr) {

			min_pr = inf->inf_pr;
			min_exe_order = inf->inf_exe_order;
			next_inf = inf;
		} else if ((inf->inf_pr == min_pr) &&
			(inf->inf_exe_order < min_exe_order)) {

			min_exe_order = inf->inf_exe_order;
			next_inf = inf;
		}

skip_ntw:
		ntw = cve_dle_next(ntw, exe_list);
	} while (head_ntw != ntw);

end:
	return next_inf;
}

static void ice_schedule_list(struct ice_network *ntw)
{
	int retval = CVE_DEFAULT_ERROR_CODE;
	bool multi_ntw = true;
	struct ice_infer *inf = NULL;
	struct jobgroup_descriptor *cur_jg;
#ifdef _DEBUG
	struct cve_device *head, *next;
	u32 ices_bitmap = 0;
	struct ice_debug_event_info_power_on evt_info;
#endif

	if (ntw) {
		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Running specific Ntw. NtwID=0x%lx\n",
			(uintptr_t)ntw);

		multi_ntw = false;
		inf = ice_sch_get_next_ntw_infer(ntw);
	} else {

		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Running generic Scheduler\n");

		__reset_scheduler_param();

		/* Return next valid inference that can be executed */
		inf = ice_sch_get_next_sch_infer();
	}

	if (!inf) {

		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"No Infer for execution\n");
		goto exit;
	}

	do {
		ntw = inf->ntw;
		ntw->handled_by_sch = 1;

		/* NWA is must have */
		ASSERT(ntw->num_ice > 0);

		/* TODO: Segregate into Get and Reserve resource */
		retval = ice_ds_ntw_resource_reserve(ntw);
		if (retval < 0)
			goto skip_ntw;

		ntw->curr_exe = inf;
		ntw->ntw_running = true;
		inf->inf_running = true;

		cve_os_log(CVE_LOGLEVEL_INFO,
			"Scheduling Infer Request. NtwID=0x%llx, InfID=0x%lx, Order=%llu\n",
			ntw->network_id, (uintptr_t)inf, inf->inf_exe_order);

		/* Strictly 1 Ntw 1 JG */
		ASSERT(ntw->num_jg == 1);
		cur_jg = ntw->jg_list;

		/* ICEs must be enough to schedule all Jobs */
		ASSERT(cur_jg->submitted_jobs_nr <= ntw->num_ice);
		cur_jg->next_dispatch = cur_jg->jobs;

		retval = ice_ds_dispatch_jg(cur_jg);
		if (retval < 0) {
			cve_os_log_default(CVE_LOGLEVEL_ERROR,
					"Unable to Schedule JG_ID=0x%lx. Error=%d\n",
					(uintptr_t)cur_jg, retval);

			/* Schedule failed. So this network will be aborted */
			if (retval == -ICEDRV_KERROR_ICE_DOWN)
				cur_jg->aborted_jobs_nr++;
		}

		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Scheduling Infer Request completed. NtwID:0x%llx, InfID:0x%lx\n",
			ntw->network_id, (uintptr_t)inf);

#ifdef _DEBUG
		head = ntw->ice_list;
		next = head;
		if (next) {
			do {
				if (next->power_state == ICE_POWER_ON)
					ices_bitmap |=
						(1 << next->dev_index);
				next = cve_dle_next(next, owner_list);
			} while (next != head);
		}

		evt_info.network_id = ntw->network_id;
		evt_info.powered_on_ices = ices_bitmap;

		/* Send Ice debug event (ICE_POWER_ON) */
		ice_debug_wake_up_event(ICE_DEBUG_EVENT_ICE_POWERED_ON,
					&evt_info);
#endif

		cve_dle_remove_from_list(ntw->inf_exe_list[inf->inf_pr],
			exe_list, inf);
		inf->inf_queued = false;

skip_ntw:
		inf = ice_sch_get_next_sch_infer();

	} while (inf && multi_ntw);

exit:
	return;
}

void ice_deschedule_network(struct ice_network *ntw)
{
	if (ntw->ntw_queued) {
		cve_dle_remove_from_list(scheduled_ntw_list, exe_list, ntw);
		ntw->ntw_queued = false;
	}
}

void ice_scheduler_engine(struct ice_network *ntw)
{
	if (ntw) {
		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Scheduling NtwID=0x%lx\n", (uintptr_t)ntw);
		ice_schedule_list(ntw);
		return;
	}

	/* Priority networks are scheduled first */
	if (scheduled_ntw_list) {
		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Scheduling Networks\n");
		ice_schedule_list(NULL);
	}
}

static void __reset_exe_order(u64 offset)
{
	struct ice_infer *head_inf, *inf;
	struct ice_network *head_ntw, *ntw;
	enum ice_execute_infer_priority pr;

	head_ntw = scheduled_ntw_list;
	ntw = head_ntw;

	if (!ntw)
		goto end;

	do {
		for (pr = EXE_INF_PRIORITY_0; pr < EXE_INF_PRIORITY_MAX; pr++) {

			head_inf = ntw->inf_exe_list[pr];
			inf = head_inf;

			if (!inf)
				continue;

			do {
				inf->inf_exe_order -= offset;

				inf = cve_dle_next(inf, exe_list);
			} while (head_inf != inf);
		}

		ntw = cve_dle_next(ntw, exe_list);
	} while (head_ntw != ntw);

end:
	return;
}

static u64 __get_min_order(void)
{
	u64 min_exe_order = EXE_ORDER_MAX;
	struct ice_network *head_ntw, *ntw;
	struct ice_infer *inf;
	enum ice_execute_infer_priority pr;

	head_ntw = scheduled_ntw_list;
	ntw = head_ntw;

	if (!ntw)
		goto end;

	do {
		for (pr = EXE_INF_PRIORITY_0; pr < EXE_INF_PRIORITY_MAX; pr++) {

			inf = ntw->inf_exe_list[pr];
			if (inf && (inf->inf_exe_order < min_exe_order))
				min_exe_order = inf->inf_exe_order;
		}

		ntw = cve_dle_next(ntw, exe_list);
	} while (head_ntw != ntw);

end:
	return min_exe_order;
}

void ice_sch_reset_exe_order(void)
{
	u64 min_exe_order = EXE_ORDER_MAX;
	struct cve_device_group *dg = cve_dg_get();

	min_exe_order = __get_min_order();

	__reset_exe_order(min_exe_order);

	dg->dg_exe_order -= min_exe_order;
}

