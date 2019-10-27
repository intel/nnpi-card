/********************************************
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#ifndef _SPH_KERNEL_DEBUG_WATCH_H
#define _SPH_KERNEL_DEBUG_WATCH_H

#ifdef _DEBUG

#include <linux/hw_breakpoint.h>
#include <linux/slab.h>

struct sph_watchpoint {
	struct perf_event_attr bp_attr;
	struct perf_event * __percpu *bp_event;
};

static void sph_watchpoint_handler(struct perf_event       *bp_event,
				   struct perf_sample_data *data,
				   struct pt_regs          *regs)
{
	pr_err("sph_watchpoint hit\n");
	dump_stack();
}

static struct sph_watchpoint *sph_debug_add_watchpoint(void *addr)
{
	struct sph_watchpoint *wp;

	wp = kzalloc(sizeof(*wp), GFP_KERNEL);
	if (!wp)
		return NULL;

	hw_breakpoint_init(&wp->bp_attr);
	wp->bp_attr.bp_addr = (uintptr_t)addr;
	wp->bp_attr.bp_len = HW_BREAKPOINT_LEN_4;
	wp->bp_attr.bp_type = HW_BREAKPOINT_W;
	wp->bp_event =
		register_wide_hw_breakpoint(&wp->bp_attr,
					    sph_watchpoint_handler,
					    NULL);
	return wp;
}

static void sph_debug_remove_watchpoint(struct sph_watchpoint *wp)
{
	if (wp) {
		unregister_wide_hw_breakpoint(wp->bp_event);
		kfree(wp);
	}
}

#else

#define sph_debug_add_watchpoint(addr)  NULL
#define sph_debug_remove_watchpoint(wp)

#endif //_DEBUG

#endif
