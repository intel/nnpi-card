/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#include "inf_exec_req.h"
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/atomic.h>


void inf_req_try_execute(struct inf_exec_req *req)
{
	int err;
	unsigned long flags;
	u32 curr_sched_tick;

	SPH_ASSERT(req != NULL);

	SPH_SPIN_LOCK_IRQSAVE(&req->lock_irq, flags);
	curr_sched_tick = atomic_read(&req->context->sched_tick);
	if (req->in_progress || req->last_sched_tick == curr_sched_tick) {
		SPH_SPIN_UNLOCK_IRQRESTORE(&req->lock_irq, flags);
		return;
	}
	req->last_sched_tick = curr_sched_tick;
	SPH_SPIN_UNLOCK_IRQRESTORE(&req->lock_irq, flags);

	if (!req->f->is_ready(req))
		return;

	SPH_SPIN_LOCK_IRQSAVE(&req->lock_irq, flags);
	if (req->in_progress) {
		SPH_SPIN_UNLOCK_IRQRESTORE(&req->lock_irq, flags);
		return;
	}
	req->in_progress = true;
	SPH_SPIN_UNLOCK_IRQRESTORE(&req->lock_irq, flags);

	err = req->f->execute(req);

	if (unlikely(err < 0))
		req->f->complete(req, err);

}

int inf_exec_req_get(struct inf_exec_req *req)
{
	return kref_get_unless_zero(&req->in_use);
}

int inf_exec_req_put(struct inf_exec_req *req)
{
	return kref_put(&req->in_use, req->f->release);
}

int inf_update_priority(struct inf_exec_req *req,
			uint8_t priority,
			bool card2host,
			dma_addr_t lli_addr)
{
	unsigned long flags;
	int ret = 0;

	SPH_SPIN_LOCK_IRQSAVE(&req->lock_irq, flags);
	if (!req->in_progress) {
		//Request didn't reached HW yet , just update priority here
		req->priority = priority;
	} else {
		//Call Dma scheduler for update
		ret = sphcs_dma_sched_update_priority(g_the_sphcs->dmaSched,
							sph_dma_direction(card2host),
							req->priority,
							sph_dma_priority(priority),
							lli_addr);
		if (ret == 0)
			req->priority = priority;
	}
	SPH_SPIN_UNLOCK_IRQRESTORE(&req->lock_irq, flags);

	return ret;
}
