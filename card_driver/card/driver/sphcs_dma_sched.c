/********************************************
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/
#include "sphcs_dma_sched.h"
#include <linux/module.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/interrupt.h>
#include <linux/slab.h>
#include <linux/workqueue.h>
#include <linux/completion.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include "sph_types.h"
#include "sph_log.h"
#include "sph_debug.h"
#include "sphcs_trace.h"
#include "sphcs_sw_counters.h"

#define SPHCS_NUM_OF_DMA_RETRIES 3
#define SPHCH_DMA_CHANNEL_0 BIT(0)
#define SPHCH_DMA_CHANNEL_1 BIT(1)
#define SPHCH_DMA_CHANNEL_2 BIT(2)
#define SPHCH_DMA_CHANNEL_3 BIT(3)

#define SPHCS_DMA_NUM_HW_CHANNELS 4

#define SPHCH_DMA_CHANNEL_ANY GEN_MASK(SPHCS_DMA_NUM_HW_CHANNELS - 1, 0)

#define SPH_DMA_COMPLETION_TIME_OUT_MS 3000

#define MAX_SKIPPED_SERIAL 5

// Disable use of C2H DMA channel 1 due since it getting hang after FLR reset.
#define DMA_DISABLE_C2H_CHANNEL_1_WA

const struct sphcs_dma_desc g_dma_desc_h2c_low = {
	.dma_direction  = SPHCS_DMA_DIRECTION_HOST_TO_CARD,
	.dma_priority   = SPHCS_DMA_PRIORITY_LOW,
	.serial_channel = 0,
	.flags          = 0
};

const struct sphcs_dma_desc g_dma_desc_h2c_normal = {
	.dma_direction  = SPHCS_DMA_DIRECTION_HOST_TO_CARD,
	.dma_priority   = SPHCS_DMA_PRIORITY_NORMAL,
	.serial_channel = 0,
	.flags          = 0
};

const struct sphcs_dma_desc g_dma_desc_h2c_high = {
	.dma_direction  = SPHCS_DMA_DIRECTION_HOST_TO_CARD,
	.dma_priority   = SPHCS_DMA_PRIORITY_HIGH,
	.serial_channel = 0,
	.flags          = 0
};

const struct sphcs_dma_desc g_dma_desc_h2c_high_nowait = {
	.dma_direction  = SPHCS_DMA_DIRECTION_HOST_TO_CARD,
	.dma_priority   = SPHCS_DMA_PRIORITY_HIGH,
	.serial_channel = 0,
	.flags          = SPHCS_DMA_START_XFER_COMPLETION_NO_WAIT
};

const struct sphcs_dma_desc g_dma_desc_c2h_low = {
	.dma_direction  = SPHCS_DMA_DIRECTION_CARD_TO_HOST,
	.dma_priority   = SPHCS_DMA_PRIORITY_LOW,
	.serial_channel = 0,
	.flags          = 0
};

const struct sphcs_dma_desc g_dma_desc_c2h_normal = {
	.dma_direction  = SPHCS_DMA_DIRECTION_CARD_TO_HOST,
	.dma_priority   = SPHCS_DMA_PRIORITY_NORMAL,
	.serial_channel = 0,
	.flags          = 0
};

const struct sphcs_dma_desc g_dma_desc_c2h_high = {
	.dma_direction  = SPHCS_DMA_DIRECTION_CARD_TO_HOST,
	.dma_priority   = SPHCS_DMA_PRIORITY_HIGH,
	.serial_channel = 0,
	.flags          = 0
};

const struct sphcs_dma_desc g_dma_desc_c2h_high_nowait = {
	.dma_direction  = SPHCS_DMA_DIRECTION_CARD_TO_HOST,
	.dma_priority   = SPHCS_DMA_PRIORITY_HIGH,
	.serial_channel = 0,
	.flags          = SPHCS_DMA_START_XFER_COMPLETION_NO_WAIT
};

struct sphcs_dma_request_callback_wq {
	struct work_struct work;
	struct sphcs_dma_sched *dmaSched;
	struct sphcs_dma_req *req;
};

struct sphcs_dma_sched_priority_queue {
	struct list_head reqList;
	struct workqueue_struct *req_callbacks_wq;
	u32 allowed_hw_channels;
	u32 reqList_size;
	u32 reqList_max_size;
	spinlock_t lock_irq;
};

struct spch_dma_hw_channels {
	u32 busy_mask;
	struct sphcs_dma_req *inflight_req[SPHCS_DMA_NUM_HW_CHANNELS];
	spinlock_t lock_irq;
};

enum SPHCS_DMA_ENGINE_STATE {
	SPHCS_DMA_ENGINE_STATE_ENABLED = 0,
	SPHCS_DMA_ENGINE_STATE_DISABLING,
};

struct reset_work {
	struct work_struct work;
	void (*reset)(void *hw_handle);
	void *hw_handle;
};

struct spcs_dma_direction_info {
	struct sphcs_dma_sched_priority_queue reqQueue[SPHCS_DMA_NUM_PRIORITIES];
	struct spch_dma_hw_channels hw_channels;
	enum SPHCS_DMA_ENGINE_STATE dma_engine_state;
	spinlock_t lock_irq;
	struct completion dma_engine_idle;
	struct reset_work reset_work;
};

#define MAX_USER_DATA_SIZE 64

struct sphcs_dma_sched {
	const struct sphcs_dma_hw_ops *hw_ops;
	void *hw_handle;
	struct sphcs *sphcs;
	u32 serial_channel;
	struct spcs_dma_direction_info direction[SPHCS_DMA_NUM_DIRECTIONS];
	spinlock_t lock;
	struct kmem_cache *slab_cache_ptr;
};

struct sphcs_dma_req {
	struct list_head node;
	sphcs_dma_sched_completion_callback callback;
	void *callback_ctx;

	dma_addr_t src;
	dma_addr_t dst;
	u32 size;
	uint64_t transfer_size;
	int status;
	u32 timeUS;
	u32 priority;
	u32 direction;
	u32 flags;
	u32 serial_channel;
	u32 retry_counter;

	u8 is_slab_cache_alloc;
	unsigned char user_data[1]; /* actual array size is varible - must be last member */
};


static void reset_handler(struct work_struct *work)
{
	struct reset_work *reset_work = container_of(work, struct reset_work, work);
	struct spcs_dma_direction_info *dir_info = container_of(reset_work, struct spcs_dma_direction_info, reset_work);
	unsigned long flags;

	wait_for_completion(&dir_info->dma_engine_idle);

	reset_work->reset(reset_work->hw_handle);

	sph_log_err(EXECUTE_COMMAND_LOG, "DMA failed - reset issued\n");

	/* enable DMA engine */
	SPH_SPIN_LOCK_IRQSAVE(&dir_info->lock_irq, flags);
	dir_info->dma_engine_state = SPHCS_DMA_ENGINE_STATE_ENABLED;
	SPH_SPIN_UNLOCK_IRQRESTORE(&dir_info->lock_irq, flags);
}

/* MACROS */
#define DMA_DIRECTION_INFO(dma_schedualer, dma_direction) ((dma_schedualer)->direction[(dma_direction)])

#define DMA_DIRECTION_INFO_PTR(dma_schedualer, dma_direction) (&DMA_DIRECTION_INFO(dma_schedualer, dma_direction))

#define DMA_QUEUE_INFO(dma_schedualer, dma_direction, dma_priority) ((dma_schedualer)->direction[(dma_direction)].reqQueue[dma_priority])

#define DMA_QUEUE_INFO_PTR(dma_schedualer, dma_direction, dma_priority) (&DMA_QUEUE_INFO(dma_schedualer, dma_direction, dma_priority))

#define DMA_HW_CHANNEL(dma_schedualer, dma_direction) (DMA_DIRECTION_INFO(dma_schedualer, dma_direction).hw_channels)

#define DMA_HW_CHANNEL_PTR(dma_schedualer, dma_direction) (&DMA_HW_CHANNEL(dma_schedualer, dma_direction))

#define DMA_QUEUE_WORKQUEUE(dma_schedualer, dma_direction, dma_priority) (DMA_QUEUE_INFO(dma_schedualer, dma_direction, dma_priority).req_callbacks_wq)

#define DMA_QUEUE_WORKQUEUE_PTR(dma_schedualer, dma_direction, dma_priority) (&DMA_QUEUE_INFO(dma_schedualer, dma_direction, dma_priority).req_callbacks_wq)

/* free hw channel request */

void free_dma_hw_channel(struct sphcs_dma_sched *dmaSched,
			 enum sphcs_dma_direction direction,
			 u32 channel)
{
	unsigned long flags;

	SPH_SPIN_LOCK_IRQSAVE(&(DMA_HW_CHANNEL(dmaSched, direction).lock_irq), flags);

	DMA_HW_CHANNEL(dmaSched, direction).busy_mask &= ~(0x1 << channel);
	DMA_HW_CHANNEL(dmaSched, direction).inflight_req[channel] = NULL;

	SPH_SPIN_UNLOCK_IRQRESTORE(&(DMA_HW_CHANNEL(dmaSched, direction).lock_irq), flags);
}

/* check if there is a free hw channel for dma, if so, it will be reserved for current request */

bool select_available_dma_hw_channel(struct sphcs_dma_sched *dmaSched,
				     enum sphcs_dma_direction direction,
				     u32 queueChannelMask,
				     u32 *selectedChannel,
				     struct sphcs_dma_req *req)
{
	unsigned long flags;
	u32 assign_dma_channel_mask = 0x0;
	bool ret = false;

	SPH_SPIN_LOCK_IRQSAVE(&(DMA_HW_CHANNEL(dmaSched, direction).lock_irq), flags);

	assign_dma_channel_mask = (queueChannelMask & ~(DMA_HW_CHANNEL(dmaSched, direction).busy_mask));

	if (assign_dma_channel_mask != 0x0) {
		ret = true;
		*selectedChannel = ffs(assign_dma_channel_mask) - 1;

		DMA_HW_CHANNEL(dmaSched, direction).inflight_req[*selectedChannel] = req;

		DMA_HW_CHANNEL(dmaSched, direction).busy_mask |= 0x1 << *selectedChannel;
	}

	SPH_SPIN_UNLOCK_IRQRESTORE(&(DMA_HW_CHANNEL(dmaSched, direction).lock_irq), flags);

	return ret;
}

/* check if we have an infligh request with the same serial channel value */
/* if serialChannel is set to 0 - function will return false */

bool is_serial_channel_in_use(struct sphcs_dma_sched *dmaSched,
			      enum sphcs_dma_direction direction,
			      u32 serialChannel)
{
	unsigned long flags;
	u32 dma_channel_mask = 0x0;
	bool ret = false;

	if (serialChannel == 0)
		return false;

	SPH_SPIN_LOCK_IRQSAVE(&(DMA_HW_CHANNEL(dmaSched, direction).lock_irq), flags);

	dma_channel_mask = (DMA_HW_CHANNEL(dmaSched, direction).busy_mask);

	while (dma_channel_mask) {
		u32 channel = ffs(dma_channel_mask) - 1;

		if (DMA_HW_CHANNEL(dmaSched, direction).inflight_req[channel]->serial_channel == serialChannel) {
			ret = true;
			break;
		}

		dma_channel_mask &= ~(1 << channel);
	}

	SPH_SPIN_UNLOCK_IRQRESTORE(&(DMA_HW_CHANNEL(dmaSched, direction).lock_irq), flags);

	return ret;
}

static inline int convert_dma_sched_prio_to_hw(u32 prio)
{
	switch (prio) {
	case SPHCS_DMA_PRIORITY_HIGH:
	case SPHCS_DMA_PRIORITY_DTF:
		return SPHCS_DMA_HW_PRIORITY_HIGH;
	case SPHCS_DMA_PRIORITY_NORMAL:
		return SPHCS_DMA_HW_PRIORITY_MEDIUM;
	case SPHCS_DMA_PRIORITY_LOW:
		return SPHCS_DMA_HW_PRIORITY_LOW;
	default:
		return SPHCS_DMA_HW_PRIORITY_LOW;
	}
}

/* submit dma request to hw layer */

static void start_request(struct sphcs_dma_sched *dmaSched,
			  struct sphcs_dma_req *req,
			  u32 hw_channel)
{

	req->status = 0;

	DO_TRACE(trace_dma(SPH_TRACE_OP_STATUS_START, req->direction == SPHCS_DMA_DIRECTION_CARD_TO_HOST,
			req->transfer_size, hw_channel, req->priority, (uint64_t)(uintptr_t)req));

	switch (req->direction) {
	case SPHCS_DMA_DIRECTION_CARD_TO_HOST:
		if (req->size) {
			dmaSched->hw_ops->start_xfer_c2h_single(dmaSched->hw_handle,
								hw_channel,
								convert_dma_sched_prio_to_hw(req->priority),
								req->src,
								req->dst,
								req->size);
		} else {
			dmaSched->hw_ops->start_xfer_c2h(dmaSched->hw_handle,
							 hw_channel,
							 convert_dma_sched_prio_to_hw(req->priority),
							 req->src);
		}
		break;
	case SPHCS_DMA_DIRECTION_HOST_TO_CARD:
		if (req->size) {
			dmaSched->hw_ops->start_xfer_h2c_single(dmaSched->hw_handle,
								hw_channel,
								convert_dma_sched_prio_to_hw(req->priority),
								req->src,
								req->dst,
								req->size);
		} else {
			dmaSched->hw_ops->start_xfer_h2c(dmaSched->hw_handle,
							 hw_channel,
							 convert_dma_sched_prio_to_hw(req->priority),
							 req->src);
		}
		break;
	}
}


static void do_schedule(struct sphcs_dma_sched *dmaSched,
			enum sphcs_dma_direction direction)
{
	unsigned long flags;
	u32 priority_queue = 0;

	/* lock current request type schedualer */
	SPH_SPIN_LOCK_IRQSAVE(&DMA_DIRECTION_INFO(dmaSched, direction).lock_irq, flags);

	if (DMA_DIRECTION_INFO(dmaSched, direction).dma_engine_state == SPHCS_DMA_ENGINE_STATE_ENABLED) {

		for (priority_queue = 0; priority_queue < SPHCS_DMA_NUM_PRIORITIES; priority_queue++) {
			struct sphcs_dma_sched_priority_queue *q = DMA_QUEUE_INFO_PTR(dmaSched, direction, priority_queue);
			unsigned long queue_flags;
			u32 hw_channel = 0;
			struct sphcs_dma_req *req, *tmpReq;
			u32 skipped_serial_channels[MAX_SKIPPED_SERIAL];
			u32 s, num_skipped_serial = 0;

			/* lock current queue */
			SPH_SPIN_LOCK_IRQSAVE(&q->lock_irq, queue_flags);

			list_for_each_entry_safe(req, tmpReq, &q->reqList, node) {


				if (req->serial_channel != 0) {
					/*
					 * First check if this serial channel
					 * has been skipped before during this
					 * scheduling loop, if it does, need to
					 * skip this one as well. After skipping
					 * MAX_SKIPPED_SERIAL channels we skip
					 * all.
					 */
					if (num_skipped_serial == MAX_SKIPPED_SERIAL) {
						continue;
					} else {
						bool skipped = false;
						for (s = 0; s < num_skipped_serial; s++)
							if (skipped_serial_channels[s] == req->serial_channel) {
								skipped = true;
								break;
							}

						if (skipped)
							continue;
					}

					/*
					 * The channel has not skipped before -
					 * skip only if currently running
					 */
					if (is_serial_channel_in_use(dmaSched, direction, req->serial_channel)) {
						skipped_serial_channels[num_skipped_serial++] = req->serial_channel;
						continue;
					}
				}


				/* check for available hw channel for submitting a request */
				if (!select_available_dma_hw_channel(dmaSched,
								     direction,
								     q->allowed_hw_channels,
								     &hw_channel,
								     req)) {
					/* if no available channels for request - break current queue request processing and proceed to next queue check */
					break;
				}
				/* remove from the queue and send the request */
				list_del(&req->node);
				start_request(dmaSched, req, hw_channel);
				q->reqList_size--;
			}
			SPH_SPIN_UNLOCK_IRQRESTORE(&q->lock_irq, queue_flags);
		}
	}

	SPH_SPIN_UNLOCK_IRQRESTORE(&DMA_DIRECTION_INFO(dmaSched, direction).lock_irq, flags);
}

static bool is_dma_engine_idle(struct sphcs_dma_sched *dmaSched,
			       enum sphcs_dma_direction dir)
{
	unsigned long flags;
	u32 busy_mask;

	SPH_SPIN_LOCK_IRQSAVE(&(DMA_HW_CHANNEL(dmaSched, dir).lock_irq), flags);
	busy_mask = DMA_HW_CHANNEL(dmaSched, dir).busy_mask;
	SPH_SPIN_UNLOCK_IRQRESTORE(&(DMA_HW_CHANNEL(dmaSched, dir).lock_irq), flags);

	if (busy_mask != 0)
		return false;
	else
		return true;

}

int sphcs_dma_sched_create(struct sphcs *sphcs,
			   const struct sphcs_dma_hw_ops *hw_ops,
			   void *hw_handle,
			   struct sphcs_dma_sched **out_dmaSched)
{
	struct sphcs_dma_sched *dmaSched;
	u32 direction_index = 0x0;

	/* reset output of new dma schedualer to NULL */
	*out_dmaSched = NULL;

	/* allocate a new dma schedualer instance */

	dmaSched = kzalloc(sizeof(*dmaSched), GFP_KERNEL);
	if (!dmaSched) {
		sph_log_err(START_UP_LOG, "Failed to allocate memory for dma_sched struct\n");
		return -ENOMEM;
	}

	dmaSched->slab_cache_ptr = kmem_cache_create("dma_scheduler_slabCache", sizeof(struct sphcs_dma_req) + MAX_USER_DATA_SIZE,
													 0, SLAB_HWCACHE_ALIGN, NULL);
	if (!dmaSched->slab_cache_ptr) {
		sph_log_err(START_UP_LOG, "failed to create dma scheduler slab cache\n");
		kfree(dmaSched);
		return -ENOMEM;
	}

	/* save in current instance input schedualer variables */
	dmaSched->hw_ops = hw_ops;
	dmaSched->hw_handle = hw_handle;
	dmaSched->sphcs = sphcs;
	dmaSched->serial_channel = 0;
	spin_lock_init(&dmaSched->lock);

	DMA_DIRECTION_INFO(dmaSched, SPHCS_DMA_DIRECTION_CARD_TO_HOST).reset_work.reset = hw_ops->reset_wr_dma_engine;
	DMA_DIRECTION_INFO(dmaSched, SPHCS_DMA_DIRECTION_HOST_TO_CARD).reset_work.reset = hw_ops->reset_rd_dma_engine;

	/* initialize request type structure */
	for (direction_index = 0; direction_index < SPHCS_DMA_NUM_DIRECTIONS; direction_index++) {
		u32 idxPriority = 0x0;

		spin_lock_init(&DMA_DIRECTION_INFO(dmaSched, direction_index).lock_irq);

		DMA_DIRECTION_INFO(dmaSched, direction_index).dma_engine_state = SPHCS_DMA_ENGINE_STATE_ENABLED;
		DMA_DIRECTION_INFO(dmaSched, direction_index).reset_work.hw_handle = hw_handle;

		/* reset busy hw channels mask */
		DMA_HW_CHANNEL(dmaSched, direction_index).busy_mask = 0x0;

		/* dma hw channel spin lock init */
		spin_lock_init(&DMA_HW_CHANNEL(dmaSched, direction_index).lock_irq);

		/* initialize priority request queues */
		for (idxPriority = 0; idxPriority < SPHCS_DMA_NUM_PRIORITIES; idxPriority++) {
			struct sphcs_dma_sched_priority_queue *q = DMA_QUEUE_INFO_PTR(dmaSched, direction_index, idxPriority);

			/* initialize requrest list for every priority */

			INIT_LIST_HEAD(&q->reqList);
			q->reqList_size = 0;
			q->reqList_max_size = 0;

			/* queue spin lock init */
			spin_lock_init(&q->lock_irq);


			/* create a single threaded work queue for each priority queue */

			DMA_QUEUE_WORKQUEUE(dmaSched, direction_index, idxPriority) =
				create_singlethread_workqueue("work queue for request callback");

			if (DMA_QUEUE_WORKQUEUE(dmaSched, direction_index, idxPriority) == NULL) {
				sphcs_dma_sched_destroy(dmaSched);
				sph_log_err(START_UP_LOG, "Failed to create work queue for request callbacks\n");
				return -ENOMEM;
			}


			/* set the channels allowed for every priority request */

			switch (idxPriority) {
			case SPHCS_DMA_PRIORITY_HIGH:
				q->allowed_hw_channels = (SPHCH_DMA_CHANNEL_0 |
						SPHCH_DMA_CHANNEL_1 |
						SPHCH_DMA_CHANNEL_3);
				break;
			case SPHCS_DMA_PRIORITY_NORMAL:
			case SPHCS_DMA_PRIORITY_LOW:
				q->allowed_hw_channels = (SPHCH_DMA_CHANNEL_1 |
						SPHCH_DMA_CHANNEL_2 |
						SPHCH_DMA_CHANNEL_3);
				break;
			case SPHCS_DMA_PRIORITY_DTF:
				q->allowed_hw_channels = (SPHCH_DMA_CHANNEL_3);
				break;
			}

#ifdef DMA_DISABLE_C2H_CHANNEL_1_WA
			if (direction_index == SPHCS_DMA_DIRECTION_CARD_TO_HOST)
				q->allowed_hw_channels &= ~(SPHCH_DMA_CHANNEL_1);
#endif
		}
	}

	*out_dmaSched = dmaSched;

	return 0;
}

/* free all allocated data and clear all pending requests from the queue */

void sphcs_dma_sched_destroy(struct sphcs_dma_sched *dmaSched)
{
	u32 direction_index;

	for (direction_index = 0; direction_index < SPHCS_DMA_NUM_DIRECTIONS; direction_index++) {

		unsigned long flags;
		u32 idxPriority = 0x0;

		SPH_SPIN_LOCK_IRQSAVE(&DMA_DIRECTION_INFO(dmaSched, direction_index).lock_irq, flags);

		for (idxPriority = 0; idxPriority < SPHCS_DMA_NUM_PRIORITIES; idxPriority++) {

			struct sphcs_dma_sched_priority_queue *q = DMA_QUEUE_INFO_PTR(dmaSched, direction_index, idxPriority);
			unsigned long queue_flags;
			struct sphcs_dma_req *req, *tmpReq;

			/* empty work queue and release */

			if (DMA_QUEUE_WORKQUEUE(dmaSched, direction_index, idxPriority) != NULL) {
				SPH_SPIN_UNLOCK_IRQRESTORE(&DMA_DIRECTION_INFO(dmaSched, direction_index).lock_irq, flags);
				flush_workqueue(DMA_QUEUE_WORKQUEUE(dmaSched, direction_index, idxPriority));
				destroy_workqueue(DMA_QUEUE_WORKQUEUE(dmaSched, direction_index, idxPriority));
				SPH_SPIN_LOCK_IRQSAVE(&DMA_DIRECTION_INFO(dmaSched, direction_index).lock_irq, flags);
				DMA_QUEUE_WORKQUEUE(dmaSched, direction_index, idxPriority) = NULL;
			}

			/* remove all pending requests from queue */

			SPH_SPIN_LOCK_IRQSAVE(&q->lock_irq, queue_flags);

			list_for_each_entry_safe(req, tmpReq, &q->reqList, node) {
				list_del(&req->node);

				if (req->is_slab_cache_alloc)
					kmem_cache_free(dmaSched->slab_cache_ptr, req);
				else
					kfree(req);
			}
			q->reqList_size = 0;

			SPH_SPIN_UNLOCK_IRQRESTORE(&q->lock_irq, queue_flags);

		}

		/* need to handle requests that are currently submitted to dma hw channel */
		SPH_ASSERT(DMA_HW_CHANNEL(dmaSched, direction_index).busy_mask == 0);

		SPH_SPIN_UNLOCK_IRQRESTORE(&DMA_DIRECTION_INFO(dmaSched, direction_index).lock_irq, flags);
	}

	kmem_cache_destroy(dmaSched->slab_cache_ptr);

	kfree(dmaSched);
}

/* create a handle for serialize channel, this value is incremented, no need for release */
u32 sphcs_dma_sched_create_serial_channel(struct sphcs_dma_sched *dmaSched)
{
	u32 ret;

	SPH_SPIN_LOCK(&dmaSched->lock);
	ret = ++dmaSched->serial_channel;
	if (ret == 0)
		ret = 1;
	SPH_SPIN_UNLOCK(&dmaSched->lock);

	return ret;
}

/* reserve SPHCH_DMA_CHANNEL_3 for dtf usage only, enable/disable flag */
int sphcs_dma_sched_reserve_channel_for_dtf(struct sphcs_dma_sched *dmaSched,
					   bool lock_dtf_channel)
{
	unsigned long flags;
	u32 idxPriority = 0x0;

	SPH_SPIN_LOCK_IRQSAVE(&DMA_DIRECTION_INFO(dmaSched, SPHCS_DMA_DIRECTION_CARD_TO_HOST).lock_irq, flags);

	for (idxPriority = 0; idxPriority < SPHCS_DMA_NUM_PRIORITIES; idxPriority++) {
		struct sphcs_dma_sched_priority_queue *q;
		unsigned long queue_flags;

		//Forbid channel 3 from all priority queues, need to skip the DTF priority queue .
		if (idxPriority == SPHCS_DMA_PRIORITY_DTF)
			continue;

		q = DMA_QUEUE_INFO_PTR(dmaSched, SPHCS_DMA_DIRECTION_CARD_TO_HOST, idxPriority);

		SPH_SPIN_LOCK_IRQSAVE(&q->lock_irq, queue_flags);

		if (lock_dtf_channel)
			q->allowed_hw_channels &= ~(SPHCH_DMA_CHANNEL_3);
		else
			q->allowed_hw_channels |= SPHCH_DMA_CHANNEL_3;

		SPH_SPIN_UNLOCK_IRQRESTORE(&q->lock_irq, queue_flags);
	}

	SPH_SPIN_UNLOCK_IRQRESTORE(&DMA_DIRECTION_INFO(dmaSched, SPHCS_DMA_DIRECTION_CARD_TO_HOST).lock_irq, flags);

	return 0;
}

int sphcs_dma_sched_stop_and_xfer(struct sphcs_dma_sched *dmaSched,
				      dma_addr_t src,
				      dma_addr_t dst,
				      u32 size,
				      int *dma_status,
				      u32 *time_us)
{
	/* Transfer on channel 0 with High priority */
	dmaSched->hw_ops->xfer_c2h_single(dmaSched->hw_handle,
			src,
			dst,
			size,
			SPH_DMA_COMPLETION_TIME_OUT_MS,
			dma_status,
			time_us);

	return 0;

}

inline void inc_reqSize(struct sphcs_dma_sched_priority_queue *q)
{
	q->reqList_size++;
	if (q->reqList_size > q->reqList_max_size)
		q->reqList_max_size = q->reqList_size;
}

int sphcs_dma_sched_start_xfer_single(struct sphcs_dma_sched *dmaSched,
				      const struct sphcs_dma_desc *desc,
				      dma_addr_t src,
				      dma_addr_t dst,
				      u32 size,
				      sphcs_dma_sched_completion_callback callback,
				      void *callback_ctx,
				      const void *user_data,
				      u32 user_data_size)
{
	struct sphcs_dma_req *req;
	unsigned long lock_flags;
	bool cache_alloc = user_data_size <= MAX_USER_DATA_SIZE;

	if (unlikely(desc == NULL))
		return -EINVAL;

	SPH_ASSERT(desc->dma_direction < SPHCS_DMA_NUM_DIRECTIONS);
	SPH_ASSERT(desc->dma_priority < SPHCS_DMA_NUM_PRIORITIES);

	if (cache_alloc) {
		req = kmem_cache_alloc(dmaSched->slab_cache_ptr, GFP_NOWAIT);
	} else {
		sph_log_debug(DMA_LOG, "Warning: user_data_size (%d) is greater than slab cache max size(%d)\n", user_data_size, MAX_USER_DATA_SIZE);
		req = kzalloc(sizeof(*req) + (user_data_size - 1), GFP_NOWAIT);
	}
	if (unlikely(req == NULL)) {
		sph_log_err(EXECUTE_COMMAND_LOG, "FATAL: Failed to allocate DMA req start\n");
		return -ENOMEM;
	}

	req->is_slab_cache_alloc = cache_alloc;

	/* initizalize request parameters */
	req->callback = callback;
	req->callback_ctx = callback_ctx;
	req->direction = desc->dma_direction;
	req->src = src;

	req->dst = dst;
	req->size = size;
	req->transfer_size = size;
	req->timeUS = 0;
	req->priority = desc->dma_priority;
	req->flags = desc->flags;
	req->serial_channel = desc->serial_channel;	/* if serial_channel is not equal to 0 - it will serialize the requests */
						/* from the current serial_channel number. */

	if (user_data_size > 0)
		memcpy(&req->user_data[0], user_data, user_data_size);

	/* lock queue and add new request to the end for the list */

	SPH_SPIN_LOCK_IRQSAVE(&DMA_QUEUE_INFO(dmaSched, desc->dma_direction,
					      desc->dma_priority).lock_irq, lock_flags);
	list_add_tail(&req->node, &DMA_QUEUE_INFO(dmaSched, desc->dma_direction,
						  desc->dma_priority).reqList);
	inc_reqSize(&DMA_QUEUE_INFO(dmaSched, desc->dma_direction, desc->dma_priority));

	DO_TRACE(trace_dma(SPH_TRACE_OP_STATUS_QUEUED, req->direction == SPHCS_DMA_DIRECTION_CARD_TO_HOST,
			req->transfer_size, req->serial_channel, req->priority, (uint64_t)(uintptr_t)req));
	SPH_SPIN_UNLOCK_IRQRESTORE(&DMA_QUEUE_INFO(dmaSched,
						   desc->dma_direction,
						   desc->dma_priority).lock_irq, lock_flags);

	/* once a new request was submited we will try to schedual requests from the queue */
	do_schedule(dmaSched, desc->dma_direction);

	return 0;
}

int sphcs_dma_sched_start_xfer(struct sphcs_dma_sched      *dmaSched,
			       const struct sphcs_dma_desc *desc,
			       dma_addr_t                   lli,
			       uint64_t                     transfer_size,
			       sphcs_dma_sched_completion_callback callback,
			       void                        *callback_ctx,
			       const void                  *user_data,
			       u32                          user_data_size)
{
	struct sphcs_dma_req *req;
	unsigned long lock_flags;

	/* slab cache objects have size req+MAX_USER_DATA_SIZE, otherwise allocate normally */
	if (user_data_size > MAX_USER_DATA_SIZE) {
		sph_log_debug(DMA_LOG, "Warning: user_data_size (%d) is greater than slab cache max size(%d)\n", user_data_size, MAX_USER_DATA_SIZE);
		req = kzalloc(sizeof(*req) + (user_data_size > 0 ? user_data_size - 1 : 0), GFP_NOWAIT);
		req->is_slab_cache_alloc = 0;
	} else {
		req = kmem_cache_alloc(dmaSched->slab_cache_ptr, GFP_NOWAIT);
		req->is_slab_cache_alloc = 1;
	}
	if (!req) {
		sph_log_err(EXECUTE_COMMAND_LOG, "FATAL: Failed to allocate DMA req start\n");
		return -ENOMEM;
	}

	req->retry_counter = 0;
	req->callback = callback;
	req->callback_ctx = callback_ctx;
	req->src = lli;
	req->size = 0;
	req->transfer_size = transfer_size;
	req->timeUS = 0;
	req->direction = desc->dma_direction;
	req->priority = desc->dma_priority;
	req->flags = desc->flags;
	req->serial_channel = desc->serial_channel; /* if serial_channel is not equal to 0 - it will serialize the requests */
					      /* from the current serial_channel number. */

	if (user_data_size > 0)
		memcpy(&req->user_data[0], user_data, user_data_size);

	SPH_SPIN_LOCK_IRQSAVE(&DMA_QUEUE_INFO(dmaSched,
					      desc->dma_direction,
					      desc->dma_priority).lock_irq,
			      lock_flags);
	list_add_tail(&req->node, &DMA_QUEUE_INFO(dmaSched, desc->dma_direction,
						  desc->dma_priority).reqList);
	inc_reqSize(&DMA_QUEUE_INFO(dmaSched, desc->dma_direction, desc->dma_priority));
	DO_TRACE(trace_dma(SPH_TRACE_OP_STATUS_QUEUED, req->direction == SPHCS_DMA_DIRECTION_CARD_TO_HOST,
			req->transfer_size, req->serial_channel, req->priority, (uint64_t)(uintptr_t)req));

	SPH_SPIN_UNLOCK_IRQRESTORE(&DMA_QUEUE_INFO(dmaSched, desc->dma_direction,
						   desc->dma_priority).lock_irq,
				   lock_flags);

	do_schedule(dmaSched, desc->dma_direction);

	return 0;
}

static void request_callback_handler(struct work_struct *work)
{
	struct sphcs_dma_request_callback_wq *cb_work = (struct sphcs_dma_request_callback_wq *)work;
	struct sphcs_dma_sched *dmaSched = cb_work->dmaSched;
	struct sphcs_dma_req *req = cb_work->req;

	DO_TRACE(trace_dma(SPH_TRACE_OP_STATUS_CB_START, req->direction == SPHCS_DMA_DIRECTION_CARD_TO_HOST,
			req->transfer_size, -1, req->priority, (uint64_t)(uintptr_t)req));

	req->callback(dmaSched->sphcs, req->callback_ctx, &req->user_data[0], req->status, req->timeUS);

	DO_TRACE(trace_dma(SPH_TRACE_OP_STATUS_CB_COMPLETE, req->direction == SPHCS_DMA_DIRECTION_CARD_TO_HOST,
			req->transfer_size, -1, req->priority, (uint64_t)(uintptr_t)req));

	if (req->is_slab_cache_alloc)
		kmem_cache_free(dmaSched->slab_cache_ptr, req);
	else
		kfree(req);

	kfree(cb_work);
}

static int sphcs_dma_sched_xfer_complete_int(struct sphcs_dma_sched *dmaSched,
					     int channel,
					     enum sphcs_dma_direction dma_direction,
					     int status,
					     int recovery_action,
					     u32 xferTimeUS)
{
	struct spcs_dma_direction_info *dir_info;
	unsigned long flags;
	struct sphcs_dma_req *req = DMA_HW_CHANNEL(dmaSched, dma_direction).inflight_req[channel];

	DO_TRACE(trace_dma(SPH_TRACE_OP_STATUS_COMPLETE, req->direction == SPHCS_DMA_DIRECTION_CARD_TO_HOST,
			req->transfer_size, channel, req->priority, (uint64_t)(uintptr_t)req));

	/* If retry is requested, no more than SPHCS_NUM_OF_DMA_RETRIES allowed */
	if (req->retry_counter < SPHCS_NUM_OF_DMA_RETRIES &&
			recovery_action == SPHCS_RA_RETRY_DMA) {
		sph_log_err(EXECUTE_COMMAND_LOG, "DMA failed - retry issued\n");
		req->retry_counter++;
		start_request(dmaSched, req, channel);
	} else {
		req->status = status;
		req->timeUS = xferTimeUS;

		free_dma_hw_channel(dmaSched, req->direction, channel);

		if (SPH_SW_GROUP_IS_ENABLE(g_sph_sw_counters, SPHCS_SW_COUNTERS_GROUP_DMA)) {
			switch (dma_direction) {
			case SPHCS_DMA_DIRECTION_HOST_TO_CARD:
				SPH_SW_COUNTER_INC(g_sph_sw_counters, SPHCS_SW_DMA_GLOBAL_COUNTER_H2C_COUNT(channel));
				SPH_SW_COUNTER_ADD(g_sph_sw_counters, SPHCS_SW_DMA_GLOBAL_COUNTER_H2C_BYTES(channel), req->transfer_size);
				SPH_SW_COUNTER_ADD(g_sph_sw_counters, SPHCS_SW_DMA_GLOBAL_COUNTER_H2C_BUSY(channel), xferTimeUS);
				break;
			case SPHCS_DMA_DIRECTION_CARD_TO_HOST:
				SPH_SW_COUNTER_INC(g_sph_sw_counters, SPHCS_SW_DMA_GLOBAL_COUNTER_C2H_COUNT(channel));
				SPH_SW_COUNTER_ADD(g_sph_sw_counters, SPHCS_SW_DMA_GLOBAL_COUNTER_C2H_BYTES(channel), req->transfer_size);
				SPH_SW_COUNTER_ADD(g_sph_sw_counters, SPHCS_SW_DMA_GLOBAL_COUNTER_C2H_BUSY(channel), xferTimeUS);
				break;
			default:
				break;
			}
		}

		dir_info = DMA_DIRECTION_INFO_PTR(dmaSched, dma_direction);

		if ((recovery_action == SPHCS_RA_RESET_DMA) ||
				(req->retry_counter == SPHCS_NUM_OF_DMA_RETRIES &&
				recovery_action == SPHCS_RA_RETRY_DMA)) {

			SPH_SPIN_LOCK_IRQSAVE(&(DMA_DIRECTION_INFO(dmaSched, dma_direction).lock_irq), flags);

			/* If DMA engine isn't already disabled*/
			if (dir_info->dma_engine_state != SPHCS_DMA_ENGINE_STATE_DISABLING) {

				/* disable DMA engine */
				dir_info->dma_engine_state = SPHCS_DMA_ENGINE_STATE_DISABLING;

				/* Wait for all channels of the DMa engine to be idle */
				init_completion(&dir_info->dma_engine_idle);
				INIT_WORK(&dir_info->reset_work.work, reset_handler);
				schedule_work(&dir_info->reset_work.work);
			}

			SPH_SPIN_UNLOCK_IRQRESTORE(&(DMA_DIRECTION_INFO(dmaSched, dma_direction).lock_irq), flags);
		} else
			do_schedule(dmaSched, req->direction);

		/* Once all channels of the DMA engine are idle and DMA engine recovery flow has been started  */
		SPH_SPIN_LOCK_IRQSAVE(&(DMA_DIRECTION_INFO(dmaSched, dma_direction).lock_irq), flags);
		if ((dir_info->dma_engine_state == SPHCS_DMA_ENGINE_STATE_DISABLING) &&
				(is_dma_engine_idle(dmaSched, dma_direction)))
			complete(&dir_info->dma_engine_idle);
		SPH_SPIN_UNLOCK_IRQRESTORE(&(DMA_DIRECTION_INFO(dmaSched, dma_direction).lock_irq), flags);

		if (req->callback) {
			if (req->flags & SPHCS_DMA_START_XFER_COMPLETION_NO_WAIT) {
				req->callback(dmaSched->sphcs,
					      req->callback_ctx,
					      &req->user_data[0],
					      req->status,
					      req->timeUS);

				DO_TRACE(trace_dma(SPH_TRACE_OP_STATUS_CB_NW_COMPLETE, req->direction == SPHCS_DMA_DIRECTION_CARD_TO_HOST,
						req->transfer_size, channel, req->priority, (uint64_t)(uintptr_t)req));

				if (req->is_slab_cache_alloc)
					kmem_cache_free(dmaSched->slab_cache_ptr, req);
				else
					kfree(req);
			} else {
				/* assume M_WAITOK */
				struct sphcs_dma_request_callback_wq *cb_work = kzalloc(sizeof(*cb_work), GFP_NOWAIT);

				if (cb_work) {
					INIT_WORK(&cb_work->work, request_callback_handler);
					cb_work->dmaSched = dmaSched;
					cb_work->req = req;
					queue_work(DMA_QUEUE_WORKQUEUE(dmaSched,
								       req->direction,
								       req->priority),
						   &cb_work->work);
				} else {
					/* in case cb_work was not allocated */
				}
			}
		}
	}
	return 0;
}


int sphcs_dma_sched_h2c_xfer_complete_int(struct sphcs_dma_sched *dmaSched,
					  int channel,
					  int status,
					  int recovery_action,
					  u32 xferTimeUS)
{
	sphcs_dma_sched_xfer_complete_int(dmaSched,
					  channel,
					  SPHCS_DMA_DIRECTION_HOST_TO_CARD,
					  status,
					  recovery_action,
					  xferTimeUS);
	return 0;
}

int sphcs_dma_sched_c2h_xfer_complete_int(struct sphcs_dma_sched *dmaSched,
					  int channel,
					  int status,
					  int recovery_action,
					  u32 xferTimeUS)
{
	sphcs_dma_sched_xfer_complete_int(dmaSched,
					  channel,
					  SPHCS_DMA_DIRECTION_CARD_TO_HOST,
					  status,
					  recovery_action,
					  xferTimeUS);
	return 0;
}

static int debug_direction_show(struct seq_file *m, void *v)
{
	struct spcs_dma_direction_info *dir_info = m->private;
	unsigned long flags;
	int i;

	if (unlikely(dir_info == NULL))
		return -EINVAL;

	SPH_SPIN_LOCK_IRQSAVE(&dir_info->lock_irq, flags);

	if (dir_info->dma_engine_state == SPHCS_DMA_ENGINE_STATE_ENABLED)
		seq_puts(m, "State: Enabled\n");
	else
		seq_puts(m, "State: Disabling\n");

	seq_puts(m, "HW Channels:\n");
	for (i = 0; i < SPHCS_DMA_NUM_HW_CHANNELS; i++) {
		if (dir_info->hw_channels.busy_mask & BIT(i)) {
			const struct sphcs_dma_req *req = dir_info->hw_channels.inflight_req[i];

			seq_printf(m, "\tchan%d: busy req=0x%lx xfer_size=0x%llx pri=%u status=%u flags=0x%x serial=%u\n",
				   i,
				   (uintptr_t)req,
				   req->transfer_size,
				   req->priority,
				   req->status,
				   req->flags,
				   req->serial_channel);
		} else {
			seq_printf(m, "\tchan%d: idle\n", i);
		}
	}

	seq_puts(m, "Request Queues\n");
	for (i = 0; i < SPHCS_DMA_NUM_PRIORITIES; i++) {
		struct sphcs_dma_sched_priority_queue *q = &dir_info->reqQueue[i];
		unsigned long queue_flags;

		SPH_SPIN_LOCK_IRQSAVE(&q->lock_irq, queue_flags);
		seq_printf(m, "\tprio%d: qsize=%u max_qsize=%u allowed_channels_mask=0x%x\n",
			   i,
			   q->reqList_size,
			   q->reqList_max_size,
			   q->allowed_hw_channels);
		SPH_SPIN_UNLOCK_IRQRESTORE(&q->lock_irq, queue_flags);
	}

	SPH_SPIN_UNLOCK_IRQRESTORE(&dir_info->lock_irq, flags);

	return 0;
}

static int debug_direction_open(struct inode *inode, struct file *filp)
{
	return single_open(filp, debug_direction_show, inode->i_private);
}

static const struct file_operations debug_direction_stats_fops = {
	.open		= debug_direction_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

void sphcs_dma_sched_init_debugfs(struct sphcs_dma_sched *dmaSched,
				  struct dentry          *parent,
				  const char             *dirname)
{
	struct dentry *dir, *f;
	int i;
	char allowed_mask_name[32];

	if (!parent)
		return;

	dir = debugfs_create_dir(dirname, parent);
	if (IS_ERR_OR_NULL(dir))
		return;

	f = debugfs_create_file("h2c_stats",
				0444,
				dir,
				&dmaSched->direction[SPHCS_DMA_DIRECTION_HOST_TO_CARD],
				&debug_direction_stats_fops);
	if (IS_ERR_OR_NULL(f))
		goto err;

	f = debugfs_create_file("c2h_stats",
				0444,
				dir,
				&dmaSched->direction[SPHCS_DMA_DIRECTION_CARD_TO_HOST],
				&debug_direction_stats_fops);
	if (IS_ERR_OR_NULL(f))
		goto err;

	for (i = 0; i < SPHCS_DMA_NUM_PRIORITIES; i++) {
		snprintf(allowed_mask_name, 32, "h2c_pri%d_allowed_hw_channels", i);
		f = debugfs_create_u32(allowed_mask_name,
				       0644,
				       dir,
				       &dmaSched->direction[SPHCS_DMA_DIRECTION_HOST_TO_CARD].reqQueue[i].allowed_hw_channels);
		if (IS_ERR_OR_NULL(f))
			goto err;

		snprintf(allowed_mask_name, 32, "c2h_pri%d_allowed_hw_channels", i);
		f = debugfs_create_u32(allowed_mask_name,
				       0644,
				       dir,
				       &dmaSched->direction[SPHCS_DMA_DIRECTION_CARD_TO_HOST].reqQueue[i].allowed_hw_channels);
		if (IS_ERR_OR_NULL(f))
			goto err;
	}

	return;

err:
	debugfs_remove(dir);
}
