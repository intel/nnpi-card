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
#include <icedrv_sw_trace_stub.h>
#else
#include "icedrv_sw_trace.h"
#endif
#include "ice_debug_event.h"

static void __del_rr_from_queue(struct execution_node *node);

/* Each scheduler queue is associated with Priority */
static struct execution_node *sch_queue[EXE_INF_PRIORITY_MAX];

/* return 1 iff job is marked as finished */
static inline int is_jobgroup_finished(struct jobgroup_descriptor *jobgroup)
{
	return (jobgroup->ended_jobs_nr == jobgroup->submitted_jobs_nr);
}

enum sch_status {
	SCH_STATUS_DONE,
	SCH_STATUS_WAIT,
	SCH_STATUS_DISCARD
};

/* Wait, Discard or push to Ntw queue */
static enum sch_status __schedule_node(struct execution_node *node)
{
	int ret;
	enum resource_status res_status;
	enum sch_status status;
	struct ice_infer *inf = node->inf;
	struct ice_network *ntw = inf->ntw;
	struct jobgroup_descriptor *cur_jg;
#ifdef _DEBUG
	struct cve_device *head, *next;
	u32 ices_bitmap = 0;
	struct ice_debug_event_info_power_on evt_info;
#endif

	if (ntw->ntw_running) {
		/* If Ntw is already running then scheduler will mark it for
		 * execution once the previous infer is complete. When an Infer
		 * execution completes, priority is given to the pending
		 * inferences of same Ntw.
		 */

		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Queuing this Inference. NtwID=0x%lx, InfID=0x%lx\n",
			(uintptr_t)ntw, (uintptr_t)inf);

		inf->inf_sch_node.ready_to_run = true;

		cve_dle_remove_from_list(sch_queue[inf->inf_pr],
			sch_list[inf->inf_pr], &inf->inf_sch_node);

		status = SCH_STATUS_DONE;
		goto out;
	}

	res_status = ice_ds_ntw_borrow_resource(ntw);
	if (res_status == RESOURCE_BUSY) {
		/* Wait */

		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Inference must wait. NtwID=0x%lx, InfID=0x%lx\n",
			(uintptr_t)ntw, (uintptr_t)inf);

		status = SCH_STATUS_WAIT;
		goto out;

	} else if (res_status == RESOURCE_INSUFFICIENT) {
		/* Discard */

		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Inference will be discarded. NtwID=0x%lx, InfID=0x%lx\n",
			(uintptr_t)ntw, (uintptr_t)inf);

		ice_sch_del_inf_from_queue(inf);

		/* Aborting Network without giving reason :( */
		cur_jg = ntw->jg_list;
		cur_jg->aborted_jobs_nr++;

		ntw->curr_exe = inf;

		ice_ds_raise_event(ntw, false);

		status = SCH_STATUS_DISCARD;
		goto out;
	}

	/* Got the resources. Run it. */
	ntw->curr_exe = inf;

	cve_os_log(CVE_LOGLEVEL_INFO,
		"Scheduling Infer Request. NtwID=0x%llx, InfID=0x%lx, Order=%llu\n",
		ntw->network_id, (uintptr_t)inf, inf->inf_exe_order);

	/* Strictly 1 Ntw 1 JG */
	ASSERT(ntw->num_jg == 1);
	cur_jg = ntw->jg_list;

	DO_TRACE(trace_icedrvExecuteNetwork(
				SPH_TRACE_OP_STATE_START,
				ntw->wq->context->swc_node.sw_id,
				ntw->swc_node.parent_sw_id,
				ntw->swc_node.sw_id, ntw->network_id,
				inf->swc_node.sw_id,
				SPH_TRACE_OP_STATUS_ICE,
				ntw->ntw_icemask));

	/* ICEs must be enough to schedule all Jobs */
	ASSERT(cur_jg->submitted_jobs_nr <= ntw->num_ice);
	cur_jg->next_dispatch = cur_jg->jobs;

	ret = ice_ds_dispatch_jg(cur_jg);
	if (ret < 0) {

		cve_os_log_default(CVE_LOGLEVEL_ERROR,
				"Unable to Schedule JG_ID=0x%lx. Error=%d\n",
				(uintptr_t)cur_jg, ret);

		/* Schedule failed. So this network will be aborted */
		if (ret == -ICEDRV_KERROR_ICE_DOWN)
			cur_jg->aborted_jobs_nr++;
	}

	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"Scheduling Infer Request completed. NtwID:0x%llx, InfID:0x%lx\n",
		ntw->network_id, (uintptr_t)inf);

	ice_sch_del_inf_from_queue(inf);

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

	status = SCH_STATUS_DONE;
out:
	return status;
}

static enum sch_status __schedule_rr_node(
	struct execution_node *node)
{
	enum sch_status status = SCH_STATUS_DONE;
	enum resource_status res_status;
	struct ice_network *ntw = node->ntw;

	if (ntw->ntw_running) {

		node->ready_to_run = true;
		status = SCH_STATUS_WAIT;
		goto out;
	}

	ASSERT(node->ntype != NODE_TYPE_INFERENCE);

	/* Reserve or Release as per node */
	if (node->ntype == NODE_TYPE_RESERVE) {

		res_status = ice_ds_ntw_reserve_resource(node->ntw);
		if (res_status == RESOURCE_BUSY) {
			cve_os_log(CVE_LOGLEVEL_DEBUG,
				"Waiting for resource availability\n");
			status = SCH_STATUS_WAIT;
			goto out;
		} else if (res_status == RESOURCE_INSUFFICIENT) {
			cve_os_log(CVE_LOGLEVEL_DEBUG,
				"Cannot reserve resource\n");
			status = SCH_STATUS_DISCARD;
			node->is_success = false;
		} else {
			cve_os_log(CVE_LOGLEVEL_DEBUG,
				"Reserved resource\n");
			status = SCH_STATUS_DONE;
			node->is_success = true;
		}

		node->ntw->rr_node =  &node->ntw->ntw_res_node;
		cve_os_wakeup(&node->ntw->rr_wait_queue);

	} else {
		/* node->ntype == NODE_TYPE_RELEASE */

		ice_ds_ntw_release_resource(node->ntw);
		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Released resource\n");
	}

	__del_rr_from_queue(node);

out:
	return status;
}

void ice_sch_engine(struct ice_network *ntw)
{
	enum sch_status status;
	struct execution_node *head, *pr0_head, *pr1_head;
	bool pr0_head_rdy = false, pr1_head_rdy = false;

	if (ntw) {
		/* If any request pending in this Ntw then run it, else
		 * trigger a generic scheduler.
		 */
		pr0_head = ntw->sch_queue[EXE_INF_PRIORITY_0];
		if (pr0_head) {

			pr0_head_rdy = (ntw->res_resource) ?
					true : pr0_head->ready_to_run;
		}

		pr1_head = ntw->sch_queue[EXE_INF_PRIORITY_1];
		if (pr1_head) {

			pr1_head_rdy = (ntw->res_resource) ?
					true : pr1_head->ready_to_run;
		}

		if (ntw->res_resource) {
			cve_os_log(CVE_LOGLEVEL_DEBUG,
				"In reserved Ntw path. NtwID=0x%lx\n",
				(uintptr_t)ntw);
		} else {
			cve_os_log(CVE_LOGLEVEL_DEBUG,
				"In non-reserved Ntw path. NtwID=0x%lx\n",
				(uintptr_t)ntw);
		}

		if (pr0_head_rdy && (pr0_head->ntype == NODE_TYPE_INFERENCE)) {

			__schedule_node(pr0_head);
			goto scheduler_beginning;
		}

		if (pr1_head_rdy && (pr1_head->ntype == NODE_TYPE_INFERENCE)) {

			__schedule_node(pr1_head);
			goto scheduler_beginning;
		}

		if (pr0_head_rdy && pr1_head_rdy) {

			ASSERT(pr0_head == pr1_head);
			if (ntw->res_resource) {
				ASSERT(pr0_head->ntype ==
						NODE_TYPE_RELEASE);
			} else {
				ASSERT(pr0_head->ntype ==
						NODE_TYPE_RESERVE);
			}
			status = __schedule_rr_node(pr0_head);
			if (status == SCH_STATUS_DONE) {

				if (pr0_head->ntype == NODE_TYPE_RESERVE)
					ice_sch_engine(pr0_head->ntw);
				else
					ice_sch_engine(NULL);

			} else if (status == SCH_STATUS_DISCARD)
				ice_sch_engine(NULL);

			return;
		}

		ice_ds_ntw_return_resource(ntw);
	}

	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"In generic path\n");

scheduler_beginning:

	while (sch_queue[EXE_INF_PRIORITY_0]) {

		if (sch_queue[EXE_INF_PRIORITY_0]->ntype != NODE_TYPE_INFERENCE)
			break;

		status = __schedule_node(sch_queue[EXE_INF_PRIORITY_0]);
		if (status == SCH_STATUS_WAIT) {
			cve_os_log(CVE_LOGLEVEL_DEBUG, "Waiting\n");
			goto out;
		}
	};

	while (sch_queue[EXE_INF_PRIORITY_1]) {

		if (sch_queue[EXE_INF_PRIORITY_1]->ntype != NODE_TYPE_INFERENCE)
			break;

		status = __schedule_node(sch_queue[EXE_INF_PRIORITY_1]);
		if (status == SCH_STATUS_WAIT) {
			cve_os_log(CVE_LOGLEVEL_DEBUG, "Waiting\n");
			goto out;
		}
	};

	if (!sch_queue[EXE_INF_PRIORITY_0] && !sch_queue[EXE_INF_PRIORITY_1])
		return;

	ASSERT(sch_queue[EXE_INF_PRIORITY_0]);
	ASSERT(sch_queue[EXE_INF_PRIORITY_0] == sch_queue[EXE_INF_PRIORITY_1]);
	ASSERT(sch_queue[EXE_INF_PRIORITY_0]->ntype != NODE_TYPE_INFERENCE);

	head = sch_queue[EXE_INF_PRIORITY_0];

	status = __schedule_rr_node(head);
	if (status == SCH_STATUS_DONE) {

		if (head->ntype == NODE_TYPE_RESERVE)
			ice_sch_engine(head->ntw);
		else
			ice_sch_engine(NULL);

	} else if (status == SCH_STATUS_DISCARD)
		ice_sch_engine(NULL);

out:
	return;
}

void ice_sch_add_inf_to_queue(struct ice_infer *inf)
{
	struct ice_network *ntw = inf->ntw;

	ASSERT(!inf->inf_sch_node.is_queued);

	inf->inf_sch_node.is_queued = true;
	inf->inf_sch_node.ready_to_run = false;

	cve_dle_add_to_list_before(sch_queue[inf->inf_pr],
		sch_list[inf->inf_pr], &inf->inf_sch_node);

	cve_dle_add_to_list_before(ntw->sch_queue[inf->inf_pr],
		ntw_queue[inf->inf_pr], &inf->inf_sch_node);

	inf->ntw->sch_queued_inf_count++;

	ice_sch_engine(NULL);

#ifdef RING3_VALIDATION
	cve_os_log(CVE_LOGLEVEL_DEBUG, "Execute ICEs\n");
	coral_trigger_simulation();
#endif

}

void ice_sch_del_inf_from_queue(struct ice_infer *inf)
{
	struct ice_network *ntw = inf->ntw;

	ASSERT(inf->inf_sch_node.is_queued);

	inf->inf_sch_node.is_queued = false;

	cve_dle_remove_from_list(sch_queue[inf->inf_pr],
		sch_list[inf->inf_pr], &inf->inf_sch_node);

	cve_dle_remove_from_list(ntw->sch_queue[inf->inf_pr],
		ntw_queue[inf->inf_pr], &inf->inf_sch_node);

	inf->ntw->sch_queued_inf_count--;
}

void ice_sch_add_rr_to_queue(struct execution_node *node)
{
	node->ready_to_run = false;

	cve_dle_add_to_list_before(sch_queue[EXE_INF_PRIORITY_0],
		sch_list[EXE_INF_PRIORITY_0], node);
	cve_dle_add_to_list_before(sch_queue[EXE_INF_PRIORITY_1],
		sch_list[EXE_INF_PRIORITY_1], node);
	cve_dle_add_to_list_before(node->ntw->sch_queue[EXE_INF_PRIORITY_0],
		ntw_queue[EXE_INF_PRIORITY_0], node);
	cve_dle_add_to_list_before(node->ntw->sch_queue[EXE_INF_PRIORITY_1],
		ntw_queue[EXE_INF_PRIORITY_1], node);

	node->is_success = false;

	ice_sch_engine(NULL);
}

static void __del_rr_from_queue(struct execution_node *node)
{
	cve_dle_remove_from_list(sch_queue[EXE_INF_PRIORITY_0],
		sch_list[EXE_INF_PRIORITY_0], node);
	cve_dle_remove_from_list(sch_queue[EXE_INF_PRIORITY_1],
		sch_list[EXE_INF_PRIORITY_1], node);
	cve_dle_remove_from_list(node->ntw->sch_queue[EXE_INF_PRIORITY_0],
		ntw_queue[EXE_INF_PRIORITY_0], node);
	cve_dle_remove_from_list(node->ntw->sch_queue[EXE_INF_PRIORITY_1],
		ntw_queue[EXE_INF_PRIORITY_1], node);
}

int ice_sch_del_rr_from_queue(struct execution_node *node)
{
	int ret = -1;
	/* Dispatcher will delete only reservation node.
	 * If it is reserved by now then node is already deleted.
	 */
	if (!node->ntw->res_resource) {

		__del_rr_from_queue(node);
		ret = 0;
	}

	return ret;
}

