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
#ifndef _ICE_DEBUG_EVENT_H_
#define _ICE_DEBUG_EVENT_H_

int ice_debug_wait_for_event(struct ice_get_debug_event *debug_event);
int init_icedrv_debug_event(void);
void term_icedrv_debug_event(void);
int ice_debug_wake_up_event(enum ice_debug_event_type event, void *event_info);
void ice_debug_create_event_node(struct cve_device *dev,
					cve_ds_job_handle_t ds_job_handle);
#endif

