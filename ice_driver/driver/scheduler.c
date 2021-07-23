/********************************************
 * Copyright (C) 2019-2021 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/



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

enum sch_status {
	/* Ok */
	SCH_STATUS_DONE,
	/* Do not proceed. Try again later.*/
	SCH_STATUS_WAIT,
	/* Request is discarded */
	SCH_STATUS_DISCARD,
	/* Run it Later. Proceed with other nodes. */
	SCH_STATUS_DEFER,
	/* Invalid */
	SCH_STATUS_MAX
};

/* Each scheduler queue is associated with Priority */
static struct execution_node *sch_queue[EXE_INF_PRIORITY_MAX];
/* Network to be deleted during next Scheduler cycle */
static struct ice_pnetwork *sch_del_pntw;

int ice_sch_init(void)
{
	int ret = 0;

	return ret;
}

static struct execution_node *__get_next_exe_node(struct ice_pnetwork *pntw)
{
	struct execution_node *p0_head = NULL, *p1_head = NULL;
	struct execution_node *p0_node = NULL, *p1_node = NULL;
	struct execution_node *node = NULL;
	bool p0_node_rdy = false, p1_node_rdy = false;

	/* Finding next P0 node */
	if (pntw) {

		p0_head = pntw->sch_queue[EXE_INF_PRIORITY_0];
		if (p0_head) {
			ASSERT(pntw->res_resource);
			p0_node = p0_head;
			p0_node_rdy = true;
		}

	} else {

		p0_head = sch_queue[EXE_INF_PRIORITY_0];
		if (p0_head) {

			p0_node = p0_head;
			do {
				if ((p0_node->ntype == NODE_TYPE_INFERENCE) &&
					(!p0_node->pntw->pntw_running)) {

					p0_node_rdy = true;
					break;
				} else if (p0_node->ntype !=
						NODE_TYPE_INFERENCE) {

					/* If not Inf Node ==> Break now*/
					break;
				}

				p0_node = cve_dle_next(p0_node,
						sch_list[EXE_INF_PRIORITY_0]);
			} while (p0_node != p0_head);
		}
	}

	if (p0_node_rdy && (p0_node->ntype == NODE_TYPE_INFERENCE)) {

		/* P0 Inference nodes, if any, will be served here */
		node = p0_node;
		goto out;
	}

	/* Finding next P1 node */
	if (pntw) {

		p1_head = pntw->sch_queue[EXE_INF_PRIORITY_1];
		if (p1_head) {
			ASSERT(pntw->res_resource);
			p1_node = p1_head;
			p1_node_rdy = true;
		}

	} else {
		p1_head = sch_queue[EXE_INF_PRIORITY_1];
		if (p1_head) {

			p1_node = p1_head;
			do {
				if ((p1_node->ntype == NODE_TYPE_INFERENCE) &&
					(!p1_node->pntw->pntw_running)) {

					p1_node_rdy = true;
					break;
				} else if (p1_node->ntype !=
						NODE_TYPE_INFERENCE) {

					/* If not Inf Node ==> Break now*/
					break;
				}

				p1_node = cve_dle_next(p1_node,
						sch_list[EXE_INF_PRIORITY_1]);
			} while (p1_node != p1_head);
		}
	}

	if (p1_node_rdy && (p1_node->ntype == NODE_TYPE_INFERENCE)) {
		/* P1 Inference nodes, if any, will be served here */
		node = p1_node;
	} else if ((p0_head != NULL) && (p0_head == p1_head)) {
		/* Node must be related to Reserve/Release */
		node = p0_head;
	}

out:
	return node;
}

static enum sch_status __process_inf_node(struct execution_node *node)
{
	struct ice_infer *inf = node->inf;
	struct ice_network *ntw = inf->ntw;
	struct ice_pnetwork *pntw = ntw->pntw;
	enum resource_status res_status;
	enum sch_status status = SCH_STATUS_DONE;
	struct cve_device_group *dg = cve_dg_get();

	ASSERT(!ntw->ntw_running);

	if ((dg->icedc_state == ICEDC_STATE_CARD_RESET_REQUIRED) ||
		(ntw->reset_ntw)) {

		cve_os_log(CVE_LOGLEVEL_INFO,
			"Inference will be discarded. CardReset=%d, NtwReset=%d, NtwID=0x%lx, InfID=0x%lx\n",
			(dg->icedc_state == ICEDC_STATE_CARD_RESET_REQUIRED),
			ntw->reset_ntw, (uintptr_t)ntw, (uintptr_t)inf);

		ntw->curr_exe = inf;

		ice_ds_raise_event(ntw, CVE_JOBSGROUPSTATUS_ERROR, false);

		status = SCH_STATUS_DISCARD;
		goto del_and_exit;

	/* TODO: Clear ntw->reset_ntw must be done by Scheduler */
	}

	res_status = ice_ds_ntw_borrow_resource(pntw);
	if (res_status == RESOURCE_BUSY) {
		/* Wait */

		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Inference must wait. PNTWID:0x%lx, NtwID=0x%lx, InfID=0x%lx\n",
			(uintptr_t)pntw, (uintptr_t)ntw, (uintptr_t)inf);

		status = SCH_STATUS_WAIT;
		goto out;

	} else if (res_status == RESOURCE_INSUFFICIENT) {
		/* Discard */

		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Out of resource. Inference will be discarded. PNTWID:0x%lx NtwID=0x%lx, InfID=0x%lx\n",
			(uintptr_t)pntw, (uintptr_t)ntw, (uintptr_t)inf);

		ntw->curr_exe = inf;

		ice_ds_raise_event(ntw, CVE_JOBSGROUPSTATUS_NORESOURCE, false);

		status = SCH_STATUS_DISCARD;
	}

del_and_exit:
	ice_lsch_del_inf_from_queue(inf, false);

out:
	return status;
}

static enum sch_status __process_rr_node(struct execution_node *node)
{
	enum sch_status status = SCH_STATUS_DONE;
	enum resource_status res_status;

	/* Reserve or Release as per node */
	if (node->ntype == NODE_TYPE_RESERVE) {

		res_status = ice_ds_ntw_reserve_resource(node->pntw);
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

			status = SCH_STATUS_DONE;
			node->is_success = true;
		}

		node->pntw->rr_node =  &node->pntw->pntw_res_node;
		cve_os_wakeup(&node->pntw->rr_wait_queue);

	} else {
		/* node->ntype == NODE_TYPE_RELEASE */

		ASSERT(!node->pntw->pntw_running);
		ice_ds_ntw_release_resource(node->pntw);
	}

	ice_lsch_del_rr_from_queue(node, false);

out:
	return status;
}

static void __process_destroy_network(struct ice_network *ntw)
{
	struct ice_infer *head, *next;
	u32 inf_count = 0;

	if (!ntw)
		goto out;

	head = ntw->inf_list;
	next = head;

	if (next) {
		do {

			ice_lsch_del_inf_from_queue(next, false);
			inf_count++;
			next = cve_dle_next(next, ntw_list);
		} while (head != next);
	}

	cve_os_log(CVE_LOGLEVEL_INFO,
		"Descheduling PNTW:0x%llx NtwId=0x%lx InferCount:%u\n",
		ntw->pntw->pntw_id, (uintptr_t)ntw, inf_count);

	ntw->reset_ntw = false;

out:
	return;
}

static void __process_pntw_del_request(struct ice_pnetwork *pntw,
		struct ice_network **curr_sched_ntw,
		bool *is_ntw_over)
{
	struct ice_network *next;

	next = pntw->ntw_list;
	do {
		/* DestroyNetwork is requested. Remove all pending
		 * requests from queue
		 */

		__process_destroy_network(next);
		if (*curr_sched_ntw && (next == *curr_sched_ntw)) {

			/* If this Ntw was destroyed then Sch should
			 * not entertain this node anymore
			 */
			*curr_sched_ntw = NULL;
			*is_ntw_over = false;
		}

		next = cve_dle_next(next, del_list);

	} while (next != pntw->ntw_list);

	ice_lsch_del_rr_from_queue(&pntw->pntw_res_node, false);
	ice_lsch_del_rr_from_queue(&pntw->pntw_rel_node, false);

	cve_os_log(CVE_LOGLEVEL_INFO,
		"Descheduling. Parent NtwId=0x%lx\n", (uintptr_t)pntw);

	pntw->reset_ntw = false;

	/* All resource must be released */
	if (pntw->res_resource)
		ice_ds_ntw_release_resource(pntw);
	else
		ice_ds_ntw_return_resource(pntw);

}


/*
 * This function will definitely return the next eligible node, if exists.
 * RES/REL nodes will be executed here itself and status will be returned
 * INF nodes will try to borrow resource and return its status.
*/
static enum sch_status __l_process_next_exe_node(struct ice_pnetwork *pntw,
	bool is_ntw_over, struct execution_node **ret_node)
{
	enum sch_status status = SCH_STATUS_MAX;
	struct execution_node *node = NULL;
	struct ice_network *ntw = NULL;

	if (pntw)
		ntw = pntw->curr_ntw;

	if (is_ntw_over) {
		ASSERT(ntw);
		ntw->ntw_running = false;
		pntw->pntw_running = false;
		ntw->curr_exe->inf_running = false;
	}

	/* Due to global lock, sch_del_pntw has always has only one entry*/
	if (sch_del_pntw) {
		/* DestroyNetwork is requested. Remove all pending
		 * requests from queue
		 */
		__process_pntw_del_request(sch_del_pntw, &ntw, &is_ntw_over);
		sch_del_pntw = NULL;
	}

	if (pntw && pntw->res_resource && !pntw->pntw_running) {
		/* When resources are reserved, pick node from Ntw's queue */
		node = __get_next_exe_node(pntw);
	}

	if (node) {

		/* REL nodes will only be served through NTW's queue */
		if (node->ntype == NODE_TYPE_RELEASE) {
			status = __process_rr_node(node);
			goto out;
		}

	} else {

		/* Pick from Sch's queue if nothing picked from Ntw's queue */
		node = __get_next_exe_node(NULL);
	}

	if (node) {

		if (is_ntw_over && (node->pntw != pntw)) {
			/* Return the resources of previous Ntw because
			 * a different Ntw was selected for execution.
			 */
			ASSERT(pntw);
			ice_ds_ntw_return_resource(pntw);
		}
	} else {

		if (is_ntw_over)
			ice_ds_ntw_return_resource(pntw);

		goto out;
	}

	if (node->ntype == NODE_TYPE_INFERENCE) {
		/* Temp assignment of Requesting Network as current network
		 * in parent structure. If request fails, its assigned back
		 * to NULL. If successful, reassigned again inside
		 * if condition
		 */
		node->pntw->curr_ntw = node->ntw;
		status = __process_inf_node(node);
		node->pntw->curr_ntw = NULL;
		if (status == SCH_STATUS_DONE) {
			node->ntw->ntw_running = true;
			node->pntw->pntw_running = true;
			node->inf->inf_running = true;
			node->pntw->curr_ntw = node->ntw;
		}
	} else if (node->ntype == NODE_TYPE_RESERVE) {

		/* Only RES nodes will be served here*/
		status = __process_rr_node(node);
	} else {

		/* REL can only happen from Ntw's queue. Sch must wait now. */
		status = SCH_STATUS_WAIT;
	}

out:
	*ret_node = node;

	return status;
}

/* Wait, Discard or push to Ntw queue */
static enum sch_status __schedule_node(struct execution_node *node)
{
	int ret;
	enum sch_status status;
	struct ice_infer *inf = node->inf;
	struct ice_network *ntw = inf->ntw;
	struct jobgroup_descriptor *cur_jg;
#ifdef _DEBUG
	struct cve_device *head, *next;
	u32 ices_bitmap = 0;
#endif

	ntw->curr_exe = inf;
	/* time stamp to capture start of inference for network busy time*/
	inf->busy_start_time = trace_clock_global();
	cve_os_log(CVE_LOGLEVEL_INFO,
		"Scheduling Infer Request. PNTW:0x%llx NtwID=0x%llx, InfID=0x%lx\n",
		ntw->pntw->pntw_id, ntw->network_id, (uintptr_t)inf);

	/* Strictly 1 Ntw 1 JG */
	ASSERT(ntw->num_jg == 1);
	cur_jg = ntw->jg_list;

	DO_TRACE(trace_icedrvExecuteNetwork(
				SPH_TRACE_OP_STATE_START,
				ntw->pntw->wq->context->swc_node.sw_id,
				ntw->pntw->swc_node.sw_id,
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

#ifdef _DEBUG
	head = ntw->pntw->ice_list;
	next = head;
	if (next) {
		do {
			if (next->power_state == ICE_POWER_ON)
				ices_bitmap |=
					(1 << next->dev_index);
			next = cve_dle_next(next, owner_list);
		} while (next != head);
	}
#endif

	status = SCH_STATUS_DONE;
	return status;
}

void ice_sch_engine(struct ice_pnetwork *pntw, bool is_ntw_over)
{
	enum sch_status status;
	struct execution_node *node = NULL;

	status = __l_process_next_exe_node(pntw, is_ntw_over, &node);

	while (node) {

		if (status == SCH_STATUS_DONE) {

			if (node->ntype == NODE_TYPE_RESERVE) {
				ice_sch_engine(node->pntw, false);
				return;
			} else if (node->ntype == NODE_TYPE_INFERENCE) {
				__schedule_node(node);
			}
			/* If Released => Goto generic scheduler. */

		} else if (status == SCH_STATUS_WAIT) {

			cve_os_log(CVE_LOGLEVEL_DEBUG, "Waiting\n");
			return;
		}

		status = __l_process_next_exe_node(NULL, false, &node);
	};
}

bool ice_lsch_add_inf_to_queue(struct ice_infer *inf,
	enum ice_execute_infer_priority pr, bool enable_bp)
{
	bool ret = true;
	struct ice_network *ntw = inf->ntw;
	struct ice_pnetwork *pntw = inf->ntw->pntw;

	if (inf->inf_sch_node.is_queued || inf->inf_running) {
		ret = false;
		goto out;
	}

	inf->inf_pr = pr;
	inf->inf_sch_node.is_queued = true;
	inf->inf_sch_node.ready_to_run = false;
	inf->ntw->ntw_enable_bp = enable_bp;


	if (pntw->res_resource &&
		(pntw->last_request_type == NODE_TYPE_RESERVE)) {

		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Adding Inf Node to Parent Ntw Queue. PNTW=0x%lx, NtwId=0x%lx, InfId=0x%lx, Pr=%d\n",
			(uintptr_t)pntw,
			(uintptr_t)inf->ntw,
			(uintptr_t)inf,
			inf->inf_pr);

		/* These nodes will be executed when resources are reserved */
		cve_dle_add_to_list_before(ntw->pntw->sch_queue[inf->inf_pr],
			pntw_queue[inf->inf_pr], &inf->inf_sch_node);

		inf->inf_sch_node.in_pntw_queue = true;
	} else {

		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Adding Inf Node to Sch Queue. PNTW=0x%lx, NtwId=0x%lx, InfId=0x%lx, Pr=%d\n",
			(uintptr_t)pntw,
			(uintptr_t)inf->ntw,
			(uintptr_t)inf,
			inf->inf_pr);

		cve_dle_add_to_list_before(sch_queue[inf->inf_pr],
			sch_list[inf->inf_pr], &inf->inf_sch_node);

		inf->inf_sch_node.in_pntw_queue = false;
	}

out:

	if (ret) {

		ice_sch_engine(ntw->pntw, false);

#ifdef RING3_VALIDATION
		cve_os_log(CVE_LOGLEVEL_DEBUG, "Execute ICEs\n");
		coral_trigger_simulation();
#endif
	}

	return ret;
}

bool ice_lsch_del_inf_from_queue(struct ice_infer *inf,
	bool lock)
{
	bool ret = true;
	struct ice_network *ntw = inf->ntw;
	struct ice_pnetwork *pntw = ntw->pntw;

	if (lock) {

		if (inf->inf_running) {
			ret = false;
			goto out;
		}
	}

	if (inf->inf_sch_node.is_queued) {

		inf->inf_sch_node.is_queued = false;

		if (inf->inf_sch_node.in_pntw_queue) {

			cve_os_log(CVE_LOGLEVEL_DEBUG,
				"Removing Inf Node from PNtw Queue. Pntw=0x%lx NtwId=0x%lx, InfId=0x%lx, Pr=%d\n",
				(uintptr_t)pntw,
				(uintptr_t)inf->ntw, (uintptr_t)inf,
				inf->inf_pr);


			ASSERT(inf->inf_pr < EXE_INF_PRIORITY_MAX);

			cve_dle_remove_from_list(
				pntw->sch_queue[inf->inf_pr],
				pntw_queue[inf->inf_pr], &inf->inf_sch_node);
		} else {

			cve_os_log(CVE_LOGLEVEL_DEBUG,
				"Removing Inf Node from Sch Queue. PNTW=0x%lx, NtwId=0x%lx, InfId=0x%lx, Pr=%d\n",
				(uintptr_t)pntw,
				(uintptr_t)inf->ntw, (uintptr_t)inf,
				inf->inf_pr);

			ASSERT(inf->inf_pr < EXE_INF_PRIORITY_MAX);

			cve_dle_remove_from_list(
				sch_queue[inf->inf_pr],
				sch_list[inf->inf_pr], &inf->inf_sch_node);
		}
	}

out:

	return ret;
}

bool ice_lsch_add_rr_to_queue(struct execution_node *node)
{
	bool ret = true;

	node->ready_to_run = false;
	node->is_success = false;

	if (node->is_queued) {
		ret = false;
		goto out;
	}

	node->is_queued = true;

	if (node->ntype == NODE_TYPE_RELEASE) {

		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Adding Rel Node to Queue. PNtwId=0x%lx\n",
			(uintptr_t)node->pntw);

		cve_dle_add_to_list_before(
			sch_queue[EXE_INF_PRIORITY_0],
			sch_list[EXE_INF_PRIORITY_0], node);
		cve_dle_add_to_list_before(
			sch_queue[EXE_INF_PRIORITY_1],
			sch_list[EXE_INF_PRIORITY_1], node);
		cve_dle_add_to_list_before(
			node->pntw->sch_queue[EXE_INF_PRIORITY_0],
			pntw_queue[EXE_INF_PRIORITY_0], node);
		cve_dle_add_to_list_before(
			node->pntw->sch_queue[EXE_INF_PRIORITY_1],
			pntw_queue[EXE_INF_PRIORITY_1], node);
	} else {

		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Adding Res Node to Queue. PNtwId=0x%lx\n",
			(uintptr_t)node->pntw);

		cve_dle_add_to_list_before(
			sch_queue[EXE_INF_PRIORITY_0],
			sch_list[EXE_INF_PRIORITY_0], node);
		cve_dle_add_to_list_before(
			sch_queue[EXE_INF_PRIORITY_1],
			sch_list[EXE_INF_PRIORITY_1], node);
	}

out:
	/*
	 * If REL => It should first check Ntw's Queue
	 * If RES => It will anyways pick from Sch Queue
	 */
	ice_sch_engine(node->pntw, false);

	return ret;
}

bool ice_lsch_del_rr_from_queue(struct execution_node *node,
	bool lock)
{
	bool ret = true;

	if (!node->is_queued) {
		ret = false;
		goto out;
	}

	node->is_queued = false;

	if (node->ntype == NODE_TYPE_RELEASE) {

		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Removing Rel Node from Queue. PNtwId=0x%lx\n",
			(uintptr_t)node->pntw);

		cve_dle_remove_from_list(
			sch_queue[EXE_INF_PRIORITY_0],
			sch_list[EXE_INF_PRIORITY_0], node);
		cve_dle_remove_from_list(
			sch_queue[EXE_INF_PRIORITY_1],
			sch_list[EXE_INF_PRIORITY_1], node);
		cve_dle_remove_from_list(
			node->pntw->sch_queue[EXE_INF_PRIORITY_0],
			pntw_queue[EXE_INF_PRIORITY_0], node);
		cve_dle_remove_from_list(
			node->pntw->sch_queue[EXE_INF_PRIORITY_1],
			pntw_queue[EXE_INF_PRIORITY_1], node);
	} else {

		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Removing Res Node from Queue. PNtwId=0x%lx\n",
			(uintptr_t)node->pntw);

		cve_dle_remove_from_list(
			sch_queue[EXE_INF_PRIORITY_0],
			sch_list[EXE_INF_PRIORITY_0], node);
		cve_dle_remove_from_list(
			sch_queue[EXE_INF_PRIORITY_1],
			sch_list[EXE_INF_PRIORITY_1], node);
	}

out:

	return ret;
}

void ice_lsch_destroy_pnetwork(struct ice_pnetwork *pntw)
{
	ASSERT(sch_del_pntw == NULL);
	sch_del_pntw = pntw;

	ice_sch_engine(NULL, false);
}

