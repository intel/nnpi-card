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

/*
 * Find an idle device.
 * If ctx_id is given, prefer to select a device which
 * its last execute job is from the same context.
 */
static struct cve_device *
find_idle_device(
		struct cve_device_group *dg,
		cve_context_id_t ctx_id)
{
	struct cve_device *cve_dev = NULL;
	struct cve_device *head, *next;
	int i;

	for (i = 0; i < MAX_NUM_ICEBO; i++) {
		head = dg->dev_info.icebo_list[i].dev_list;
		next = head;
		if (!head)
			continue;
		do {
			if ((next->state == CVE_DEVICE_IDLE) &&
				(next->pnetwork_id == INVALID_NETWORK_ID)) {
				if (ctx_id == INVALID_CONTEXT_ID ||
					ctx_id == next->last_context_id) {
					cve_dev = next;
					goto out;
				} else if (!cve_dev)
					cve_dev = next;
			}
			next = cve_dle_next(next, bo_list);
		} while (head != next);
	}
out:
	return cve_dev;
}

static struct cve_device *
find_idle_device_for_next_job(
		struct cve_device_group *dg,
		struct jobgroup_descriptor *jobgroup)
{
	struct ice_network *ntw;
	struct job_descriptor *job;
	struct cve_device *cve_dev = NULL;
	struct cve_device *head, *next;
	int is_complete_bo_required = 0, bo_id = 0;
	int  temp, ice_id = NUM_ICE_UNIT;

	ntw = jobgroup->network;
	job = jobgroup->next_dispatch;

	/* If persistent Job and mapping exist then
	 * pick that particular ICE else select new
	 */
	if ((job->graph_ice_id < NUM_ICE_UNIT) &&
		(ntw->pjob_info.ice_id_map[job->graph_ice_id] < NUM_ICE_UNIT)) {

		cve_dev = cve_device_get(
				ntw->pjob_info.ice_id_map[job->graph_ice_id]);

		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"ICE_SwID=%u already Mapped to ICE_HwID=%u. NtwID=%lx\n",
			job->graph_ice_id, cve_dev->dev_index, (uintptr_t)ntw);

		/* If this device is busy => do not schedule */
		if (cve_dev->state == CVE_DEVICE_BUSY) {
			/* PJob = Persistent Job */
			cve_os_log(CVE_LOGLEVEL_DEBUG,
				"but Device is Busy.\n");
			cve_dev = NULL;
		}

		goto out;
	}
	if (job->graph_ice_id < NUM_ICE_UNIT)
		bo_id = job->graph_ice_id / 2;
	if ((job->graph_ice_id < NUM_ICE_UNIT) &&
		(ntw->icebo_req == ICEBO_MANDATORY) &&
		ntw->pjob_info.num_pjob[2 * bo_id] &&
		ntw->pjob_info.num_pjob[2 * bo_id + 1]) {
		/* If here then complete ICEBOn is required based on current
		 * jobs graph_ice_id hence if any one of the graph_ice_id is
		 * already mapped to driver_ice_id then pick from same ICEBO
		 */
		is_complete_bo_required = 1;
		if (ntw->pjob_info.ice_id_map[2 * bo_id] < NUM_ICE_UNIT) {
			temp = ntw->pjob_info.ice_id_map[2 * bo_id];
			ice_id = (temp % 2 == 1) ? (temp - 1) : (temp + 1);
			cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Picking ICE_HwID=%u for ICE_SwID=%u because ICE_SwID=%u already Mapped to ICE_HwID=%u. NtwID=%lx\n",
			ice_id, job->graph_ice_id, 2 * bo_id, temp,
			(uintptr_t)ntw);
		} else if (ntw->pjob_info.ice_id_map[2 * bo_id + 1] <
			NUM_ICE_UNIT) {
			temp = ntw->pjob_info.ice_id_map[2 * bo_id + 1];
			ice_id = (temp % 2 == 1) ? (temp - 1) : (temp + 1);
			cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Picking ICE_HwID=%u for ICE_SwID=%u because ICE_SwID=%u already Mapped to ICE_HwID=%u. NtwID=%lx\n",
			ice_id, job->graph_ice_id, 2 * bo_id + 1, temp,
			(uintptr_t)ntw);
		}
		if (ice_id < NUM_ICE_UNIT) {
			cve_dev = cve_device_get(ice_id);
			if (cve_dev->state == CVE_DEVICE_BUSY) {
				cve_os_log(CVE_LOGLEVEL_DEBUG,
					"but Device is Busy.\n");
				cve_dev = NULL;
			}
			goto out;
		}
	}


	head = ntw->ice_list;
	next = head;
	do {
		if (next->state == CVE_DEVICE_IDLE) {
			if ((ntw->icebo_req == ICEBO_MANDATORY) &&
			(is_complete_bo_required == 1) &&
		(ntw->pjob_info.picebo[next->dev_index / 2] == 1)) {
				cve_dev = next;
				goto out;
			} else if ((ntw->icebo_req == ICEBO_MANDATORY)
			&& (is_complete_bo_required == 0) &&
			ntw->pjob_info.sicebo[next->dev_index / 2] ==
			next->dev_index) {
				cve_dev = next;
				goto out;
			} else if (ntw->icebo_req != ICEBO_MANDATORY) {
				cve_dev = next;
				goto out;
			}
		}
		next = cve_dle_next(next, owner_list);
	} while (head != next);

out:
	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"JobID=0x%lx, SCB_Status=%s\n",
		(uintptr_t)job, get_SCB_STATE_str(job->scb_state));

	return cve_dev;
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
			"Adding NtwID=0x%lx to Scheduler List\n",
			(uintptr_t)ntw->network_id);

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

int ice_schedule_jg(struct jobgroup_descriptor *jobgroup)
{
	u32 i;
	struct cve_device *dev;
	int retval = 0;
	struct cve_device_group *dg = jobgroup->wq->dg;
	struct ice_network *ntw;
	struct job_descriptor *job;

	for (i = 0; i < jobgroup->submitted_jobs_nr; i++) {

		job = jobgroup->next_dispatch;

		/* If next Job is persistent then scheduler should pick
		 * the ICE with proper graph_ice_id
		 */
		dev = find_idle_device_for_next_job(dg, jobgroup);
		/* At this point it is guaranteed that device will be found */
		if (dev == NULL) {

			if (job->graph_ice_id < NUM_ICE_UNIT) {
				retval = -EBUSY;
				cve_os_log(CVE_LOGLEVEL_ERROR,
					"ERROR:%d JG:0x%p No ice is Free\n",
					retval, jobgroup);
				goto exit;
			} else {
				ASSERT(dev != NULL);
			}
		} else {
			cve_os_log(CVE_LOGLEVEL_DEBUG,
				"Idle device found: ICE-%u\n",
				dev->dev_index);
		}

		if (job->cntr_patch_points_nr > 0) {

			cve_os_log(CVE_LOGLEVEL_DEBUG,
				COLOR_YELLOW(
					"Patching %u CounterPP. JobID=%lx\n"
				),
				job->cntr_patch_points_nr, (uintptr_t)job);

			ntw = jobgroup->network;

			/* Patch Counters */
			retval = ice_mm_patch_cntrs(ntw->buf_list,
				job, dev);
			if (retval < 0) {
				cve_os_log(CVE_LOGLEVEL_ERROR,
				"ERROR: %d, ice_mm_patch_cntrs() failed\n",
				retval);
				goto exit;
			}
		}

		if (!jobgroup->scheduled) {
			jobgroup->scheduled = 1;
			jobgroup->network->num_jg_scheduled++;
		}

		/*TODO: This call should never fail because of resource */
		retval = cve_ds_dispatch_single_job(dev, jobgroup);
		if (retval)
			goto exit;
	}

exit:
	return retval;
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
			"Checking if NtwID=0x%lx can be Scheduled\n",
			(uintptr_t)ntw);

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

		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Scheduling Infer Request. NtwID=0x%lx, InfID=0x%lx\n",
			(uintptr_t)ntw, (uintptr_t)inf);

		/* Strictly 1 Ntw 1 JG */
		ASSERT(ntw->num_jg == 1);
		cur_jg = ntw->jg_list;

		/* ICEs must be enough to schedule all Jobs */
		ASSERT(cur_jg->submitted_jobs_nr <= ntw->num_ice);
		cur_jg->next_dispatch = cur_jg->jobs;

		retval = ice_schedule_jg(cur_jg);
		if (retval < 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
					"Unable to Schedule JG_ID=0x%lx. Error=%d\n",
					(uintptr_t)cur_jg, retval);

			/* Schedule failed. So this network will be aborted */
			if (retval == -ICEDRV_KERROR_ICE_DOWN)
				cur_jg->aborted_jobs_nr++;
		}

		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Error:%d Scheduling Infer Request completed. NtwID=0x%lx, InfID=%lx\n",
			retval, (uintptr_t)ntw, (uintptr_t)inf);
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

int ice_schedule_is_dev_free(struct ice_network *ntw)
{
	int status = 0;
	struct cve_device *dev;
	struct ds_context *ctx = ntw->wq->context;
	struct cve_device_group *dg = ntw->wq->dg;

	dev = find_idle_device(dg, ctx->context_id);
	if (dev == NULL) {
		status = 0;
		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"CTX:0x%p NTW:0x%p No ice is Free\n", ctx, ntw);
	} else {
		status = 1;
		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"CTX:0x%p NTW:0x%p atleast 1 ice is Free\n", ctx, ntw);
	}
	return status;
}

