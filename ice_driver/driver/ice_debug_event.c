/*
 * NNP-I Linux Driver
 * Copyright (c) 2019, Intel Corporation.
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

#ifndef RING3_VALIDATION
#include <linux/printk.h>
#endif

#include "cve_linux_internal.h"
#include "cve_device.h"
#include "cve_driver_internal.h"

#include "ice_debug_event.h"

/* Ice debug event wait queue */
static cve_os_wait_que_t ice_debug_events_wait_queue;
/*FixMe: Avoid using global variables.*/
static u32 ice_debug_events_count;
static enum ice_debug_event_type  icedebug_event_type;
static struct ice_debug_event_info_power_on g_po_evt_info;
/* list of break point debug completion events */
struct ice_debug_event_bp *g_bp_evt;

int init_icedrv_debug_event(void)
{
	int retval;

	retval = cve_os_init_wait_que(&ice_debug_events_wait_queue);
	if (retval != 0)
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"events_wait_queue init failed  %d\n", retval);
	ice_debug_events_count = 0;

	return retval;

}

void term_icedrv_debug_event(void)
{
}

int ice_debug_wake_up_event(enum ice_debug_event_type event, void *event_info)
{
	icedebug_event_type = event;
	if (event == ICE_DEBUG_EVENT_ICE_POWERED_ON) {
		memcpy(&g_po_evt_info,
			(struct ice_debug_event_info_power_on *) event_info,
			sizeof(g_po_evt_info));

		cve_os_log(CVE_LOGLEVEL_DEBUG,
				"event:%d, NtwID:0x%llx, devmask:0x%x\n",
						event,
						g_po_evt_info.network_id,
						g_po_evt_info.powered_on_ices);
		ice_debug_events_count++;
		goto out;
	}

	if (event == ICE_DEBUG_EVENT_TLC_BP)
		goto out;

	return -EINVAL;
out:
	cve_os_wakeup(&ice_debug_events_wait_queue);
	return 0;
}

static int __update_debug_event_status(struct ice_get_debug_event *debug_event,
		int retval)
{
	if (retval == 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "Timeout\n");
		debug_event->debug_wait_status = CVE_WAIT_EVENT_TIMEOUT;
		return retval;
	} else if (retval == -ERESTARTSYS) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "Error\n");
		debug_event->debug_wait_status = CVE_WAIT_EVENT_ERROR;
		return retval;
	}
	debug_event->debug_wait_status = CVE_WAIT_EVENT_COMPLETE;
	return 1;

}

static void __cp_debug_event_and_remove(struct ice_get_debug_event *data,
			struct ice_debug_event_bp *debug_event)
{
	data->bp_evt_info.network_id = debug_event->network_id;
	data->bp_evt_info.ice_index = debug_event->ice_index;

	cve_dle_remove_from_list(g_bp_evt, list, debug_event);
	OS_FREE(debug_event, sizeof(*debug_event));
}

int ice_debug_wait_for_event(struct ice_get_debug_event *debug_event)
{
	int retval = 0;

	/*in case debug enabled don't timeout (~1000hours)*/
	if (unlikely(cve_debug_get(DEBUG_TENS_EN)))
		debug_event->timeout_msec = 0xFFFFFFFF;

	/* Wait for events objects to be available. This functions returns:
	 * -ERESTARTSYS, if interrupted
	 * 0 on timeout
	 * >0 condition evaluated to true before timeout is elapsed
	 */
	if (debug_event->debug_event & ICE_DEBUG_EVENT_ICE_POWERED_ON) {
		retval = cve_os_block_interruptible_timeout(
			&ice_debug_events_wait_queue,
			ice_debug_events_count,
			debug_event->timeout_msec);
		retval = __update_debug_event_status(debug_event, retval);
		if (retval != 0)
			goto out;
		retval = cve_os_lock(&g_cve_driver_biglock, CVE_INTERRUPTIBLE);
		if (retval <= 0) {
			retval = -ERESTARTSYS;
			goto out;
		}
		/*Fixme: Concurrency issue?*/
		ice_debug_events_count--;
		debug_event->power_on_evt_info.powered_on_ices =
						g_po_evt_info.powered_on_ices;
		debug_event->power_on_evt_info.network_id =
						g_po_evt_info.network_id;
		debug_event->debug_event = ICE_DEBUG_EVENT_ICE_POWERED_ON;
		cve_os_unlock(&g_cve_driver_biglock);
	}
	if (debug_event->debug_event & ICE_DEBUG_EVENT_TLC_BP) {
		retval = cve_os_block_interruptible_timeout(
			&ice_debug_events_wait_queue,
			g_bp_evt,
			debug_event->timeout_msec);
		retval = __update_debug_event_status(debug_event, retval);
		if (retval <= 0)
			goto out;
		retval = cve_os_lock(&g_cve_driver_biglock, CVE_INTERRUPTIBLE);
		if (retval != 0) {
			retval = -ERESTARTSYS;
			goto out;
		}
		__cp_debug_event_and_remove(debug_event, g_bp_evt);
		cve_os_unlock(&g_cve_driver_biglock);
	}



out:
	return retval;

}

void ice_debug_create_event_node(struct cve_device *dev,
	cve_ds_job_handle_t ds_job_handle)
{
	struct jobgroup_descriptor *jobgroup;
	struct job_descriptor *job;
	struct ice_network *ntw;
	struct ice_debug_event_bp *evt_info;
	struct ice_debug_event_info_bp evt;
	int retval;

	job = (struct job_descriptor *)ds_job_handle;
	jobgroup = job->jobgroup;
	ntw = jobgroup->network;

	if (ntw->ntw_enable_bp) {
		retval = OS_ALLOC_ZERO(sizeof(struct ice_debug_event_bp),
			(void **)&evt_info);
		if (retval != 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
				"ice debug event bp failed %d\n", retval);
			return;
		}
		evt_info->network_id = ntw->network_id;
		evt_info->ice_index = dev->dev_index;

		/* add to the end of debug events list */
		cve_dle_add_to_list_before(g_bp_evt,
				list, evt_info);

		evt.network_id = evt_info->network_id;
		evt.ice_index = evt_info->ice_index;

		/* Send Ice debug event (ICE_TLC_BP) */
		ice_debug_wake_up_event(ICE_DEBUG_EVENT_TLC_BP, &evt);
	}
}
