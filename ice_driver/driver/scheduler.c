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

static struct ice_network *scheduled_ntw_list[NTW_PRIORITY_MAX];

/* return 1 iff job is marked as finished */
static inline int is_jobgroup_finished(struct jobgroup_descriptor *jobgroup)
{
	return (jobgroup->ended_jobs_nr == jobgroup->submitted_jobs_nr);
}

static inline u32 available_llc_count(struct cve_device_group *dg)
{
	return dg->available_llc;
}

static inline u32 available_hw_counters(struct cve_device_group *dg)
{
	return dg->counters_nr;
}

void ice_schedule_network(struct ice_network *ntw)
{
	if (ntw->exe_status == NTW_EXE_STATUS_IDLE) {

		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Adding NtwID:0x%llx to Scheduler List\n",
			ntw->network_id);

		ntw->exe_status = NTW_EXE_STATUS_QUEUED;
		cve_dle_add_to_list_before(scheduled_ntw_list[ntw->p_type],
				exe_list, ntw);

		if (ntw->p_type == NTW_PRIORITY_0) {
			cve_os_log(CVE_LOGLEVEL_DEBUG,
					"This is a Priority Network\n");
		} else {
			cve_os_log(CVE_LOGLEVEL_DEBUG,
					"This is Not a Priority Network\n");
		}

	} else if (ntw->exe_status == NTW_EXE_STATUS_RUNNING) {
		/* Since this Ntw is running, scheduler will be
		 * automatically invoked once the Ntw is over.
		 */

		goto exit;
	}

	ice_scheduler_engine();

#ifdef RING3_VALIDATION
	cve_os_log(CVE_LOGLEVEL_DEBUG, "Execute ICEs\n");
	coral_trigger_simulation();
#endif

exit:
	return;
}

static int ice_schedule_list(u8 list_idx)
{
	int retval = CVE_DEFAULT_ERROR_CODE;
	struct ice_network *ntw;
	struct ice_infer *inf;
	struct jobgroup_descriptor *cur_jg;
#ifdef _DEBUG
	struct cve_device *head, *next;
	u32 ices_bitmap = 0;
	struct ice_debug_event_info_power_on evt_info;
#endif

	ntw = scheduled_ntw_list[list_idx];

	if (!ntw)
		goto exit;

	do {
		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Checking if NtwID:0x%llx can be Scheduled\n",
			ntw->network_id);

		/* NWA is must have */
		ASSERT(ntw->num_ice > 0);

		/* Ntw remains in Scheduler Queue unless it is Destroyed.
		 * There can be cases where Ntw is in queue but no Execute Inf
		 * was requested.
		 */
		inf = ntw->inf_exe_list;
		if (!inf)
			goto skip_ntw;

		/* Managing Ntw state */
		if (ntw->exe_status == NTW_EXE_STATUS_QUEUED) {

			retval = ice_ds_ntw_resource_reserve(ntw);
			if (retval < 0)
				goto skip_ntw;

			ntw->exe_status = NTW_EXE_STATUS_RUNNING;
		} else {

			/* Do not schedule if Ntw is Aborted */
			/* Do not schedule if Ntw is already Running */
			goto skip_ntw;
		}

		ntw->curr_exe = inf;
		inf->exe_status = INF_EXE_STATUS_RUNNING;

		cve_os_log(CVE_LOGLEVEL_INFO,
			"Scheduling Infer Request. NtwID:0x%llx, InfID:0x%lx\n",
			ntw->network_id, (uintptr_t)inf);

		/* Strictly 1 Ntw 1 JG */
		ASSERT(ntw->num_jg == 1);
		cur_jg = ntw->jg_list;

		/* ICEs must be enough to schedule all Jobs */
		ASSERT(cur_jg->submitted_jobs_nr <= ntw->num_ice);
		cur_jg->next_dispatch = cur_jg->jobs;

		retval = ice_ds_dispatch_jg(cur_jg);
		if (retval < 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
					"Unable to Schedule JG_ID=0x%lx. Error=%d\n",
					(uintptr_t)cur_jg, retval);

			/* Schedule failed. So this network will be aborted */
			if (retval == -ICEDRV_KERROR_ICE_DOWN)
				cur_jg->aborted_jobs_nr++;
		}

		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Scheduling Infer Request completed. NtwID:0x%llx, InfID:%lx\n",
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

		cve_dle_remove_from_list(ntw->inf_exe_list,
			exe_list, inf);

skip_ntw:
		ntw = cve_dle_next(ntw, exe_list);
	} while (ntw != scheduled_ntw_list[list_idx]);

	retval = 0;
exit:
	return retval;
}

void ice_deschedule_network(struct ice_network *ntw)
{
	cve_dle_remove_from_list(scheduled_ntw_list[ntw->p_type],
		exe_list, ntw);
}

void ice_scheduler_engine(void)
{
	/* Priority networks are scheduled first */
	if (scheduled_ntw_list[NTW_PRIORITY_0]) {
		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Scheduling Priority Networks\n");
		ice_schedule_list(0);
	}

	/* Now Normal networks will be scheduled */
	if (scheduled_ntw_list[NTW_PRIORITY_1]) {
		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Scheduling Normal Networks\n");
		ice_schedule_list(1);
	}
}

