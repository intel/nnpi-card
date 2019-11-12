/********************************************
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#include "inf_context.h"
#include <linux/kernel.h>
#include <linux/slab.h>
#include "inf_devres.h"
#include "inf_devnet.h"
#include "inf_copy.h"
#include "ioctl_inf.h"
#include "inf_subresload.h"
#include "inf_req.h"
#include "sph_time.h"
#include "periodic_timer.h"
#include "sph_error.h"

struct inf_sync_point {
	struct list_head node;
	u32              seq_id;
	u16              host_sync_id;
};

static void update_sw_counters(void *ctx)
{
	struct inf_context *context = (struct inf_context *)ctx;
	u64 current_time;
	unsigned long flags;

	SPH_SPIN_LOCK_IRQSAVE(&context->sw_counters_lock_irq, flags);
	if (context->infreq_counter > 0 &&
	    SPH_SW_GROUP_IS_ENABLE(context->sw_counters,
				   CTX_SPHCS_SW_COUNTERS_GROUP_INFERENCE)) {
		current_time = sph_time_us();
		if (context->runtime_busy_starttime) {
			SPH_SW_COUNTER_ADD(context->sw_counters,
					   CTX_SPHCS_SW_COUNTERS_INFERENCE_RUNTIME_BUSY_TIME,
					   current_time - context->runtime_busy_starttime);
		}
		context->runtime_busy_starttime = current_time;
	} else {
		context->runtime_busy_starttime = 0;
	}
	SPH_SPIN_UNLOCK_IRQRESTORE(&context->sw_counters_lock_irq, flags);
}

int inf_context_create(uint16_t             protocolID,
		       struct sphcs_cmd_chan *chan,
		       struct inf_context **out_context)
{
	struct inf_context *context;
	struct periodic_timer_data periodic_timer_data;
	char slab_name[16];
	int ret;

	context = kzalloc(sizeof(*context), GFP_KERNEL);
	if (unlikely(context == NULL))
		return -ENOMEM;

	snprintf(slab_name, sizeof(slab_name), "sph_ctxslab%03d", protocolID);
	context->exec_req_slab_cache = kmem_cache_create(slab_name,
							 sizeof(struct inf_exec_req),
							 0, SLAB_HWCACHE_ALIGN, NULL);
	if (unlikely(context->exec_req_slab_cache == NULL)) {
		sph_log_err(CREATE_COMMAND_LOG, "failed to create context slab cache\n");
		ret = -ENOMEM;
		goto freeCtx;
	}

	kref_init(&context->ref);
	context->chan = chan;
	context->magic = inf_context_create;
	context->protocolID = protocolID;
	context->state = CONTEXT_OK;
	context->attached = 0;
	context->destroyed = 0;
	spin_lock_init(&context->lock);
	spin_lock_init(&context->sync_lock_irq);
	spin_lock_init(&context->sw_counters_lock_irq);
	inf_cmd_queue_init(&context->cmdq);
	hash_init(context->cmd_hash);
	hash_init(context->devres_hash);
	hash_init(context->copy_hash);
	hash_init(context->devnet_hash);

	INIT_LIST_HEAD(&context->sync_points);
	INIT_LIST_HEAD(&context->active_seq_list);
	INIT_LIST_HEAD(&context->subresload_sessions);

	ret = sph_create_sw_counters_values_node(g_hSwCountersInfo_context,
						 (u32)protocolID,
						 g_sph_sw_counters,
						 &context->sw_counters);
	if (unlikely(ret < 0))
		goto free_kmem_cache;

	//Init periodic timer
	periodic_timer_data.timer_callback = update_sw_counters;
	periodic_timer_data.timer_callback_ctx = (void *)context;

	context->counters_cb_data_handler = periodic_timer_add_data(&g_the_sphcs->periodic_timer, &periodic_timer_data);
	if (unlikely(context->counters_cb_data_handler == 0)) {
		ret = -ENOMEM;
		goto free_counters;
	}

	if (!context->chan) {
		context->wq = create_singlethread_workqueue("sph_ctx_wq");
		if (unlikely(context->wq == NULL)) {
			ret = -ENOMEM;
			goto freeCb;
		}
	}

	*out_context = context;
	SPH_SW_COUNTER_ATOMIC_INC(g_sph_sw_counters, SPHCS_SW_COUNTERS_INFERENCE_NUM_CONTEXTS);
	return 0;

freeCb:
	periodic_timer_remove_data(&g_the_sphcs->periodic_timer, context->counters_cb_data_handler);
free_counters:
	sph_remove_sw_counters_values_node(context->sw_counters);
free_kmem_cache:
	kmem_cache_destroy(context->exec_req_slab_cache);
freeCtx:
	kfree(context);
	return ret;
}

int inf_context_runtime_attach(struct inf_context *context)
{
	SPH_SPIN_LOCK(&context->lock);
	if (unlikely(context->attached != 0)) {
		SPH_SPIN_UNLOCK(&context->lock);
		return -EBUSY;
	}
	if (unlikely(context->destroyed)) {
		SPH_SPIN_UNLOCK(&context->lock);
		return -EPERM;
	}
	context->attached = 1;
	SPH_SPIN_UNLOCK(&context->lock);

	return 0;
}

void inf_context_runtime_detach(struct inf_context *context)
{
	int ret;

	/*
	 * insert an EOF command to the runtime to cause it to exit.
	 * If failed to insert EOF command (should not happen) then signal
	 * an immediate hangup which will make the runtime ignore any pending
	 * commadns.
	 */
	ret = inf_cmd_queue_add(&context->cmdq,
				SPHCS_CMD_EOF,
				NULL,
				0,
				NULL, NULL);
	if (unlikely(ret < 0))
		inf_cmd_queue_hangup(&context->cmdq);
}

int is_inf_context_ptr(void *ptr)
{
	struct inf_context *context = (struct inf_context *)ptr;

	return (context &&
		context->magic == inf_context_create);
}

static void release_context(struct kref *kref)
{
	struct inf_context *context = container_of(kref,
						   struct inf_context,
						   ref);
	struct inf_devres *devres;
	struct inf_copy *copy;
	struct inf_sync_point *sync_point;
	struct inf_sync_point *n;
	struct inf_subres_load_session *subresload_sessions;
	struct inf_subres_load_session *m;
	int i;

	if (!context->chan) {
		drain_workqueue(context->wq);
		destroy_workqueue(context->wq);
	} else {
		context->chan->destroy_cb = NULL;
	}

	inf_cmd_queue_fini(&context->cmdq);

	SPH_ASSERT(hash_empty(context->copy_hash));
	hash_for_each(context->copy_hash, i, copy, hash_node) {
		inf_copy_put(copy);
	}
	SPH_ASSERT(hash_empty(context->devres_hash));
	hash_for_each(context->devres_hash, i, devres, hash_node) {
		inf_devres_put(devres);
	}
	list_for_each_entry_safe(sync_point, n, &context->sync_points, node) {
		list_del(&sync_point->node);
		kfree(sync_point);
	}
	list_for_each_entry_safe(subresload_sessions, m, &context->subresload_sessions, node) {
		list_del(&subresload_sessions->node);
		kfree(subresload_sessions);
	}
	SPH_SW_COUNTER_ATOMIC_DEC(g_sph_sw_counters, SPHCS_SW_COUNTERS_INFERENCE_NUM_CONTEXTS);

	sph_remove_sw_counters_values_node(context->sw_counters);

	periodic_timer_remove_data(&g_the_sphcs->periodic_timer, context->counters_cb_data_handler);

	SPH_ASSERT(context->attached != 1);

	kmem_cache_destroy(context->exec_req_slab_cache);

	if (context->chan != NULL)
		sphcs_cmd_chan_put(context->chan);
	else if (likely(context->destroyed))
		sphcs_send_event_report(g_the_sphcs,
					SPH_IPC_CONTEXT_DESTROYED,
					0,
					context->protocolID,
					-1);

	kfree(context);
}

void inf_context_destroy_objects(struct inf_context *context)
{
	struct inf_devres *devres;
	struct inf_copy *copy;
	struct inf_devnet *devnet;
	struct inf_cmd_list *cmd;
	struct inf_sync_point *sync_point;
	int i;
	bool found = true;
	unsigned long flags;

	do {
		found = false;
		SPH_SPIN_LOCK(&context->lock);
		hash_for_each(context->cmd_hash, i, cmd, hash_node) {
			SPH_SPIN_LOCK_IRQSAVE(&cmd->lock_irq, flags);
			if (cmd->destroyed == 0)
				found = true;
			cmd->destroyed = -1;
			SPH_SPIN_UNLOCK_IRQRESTORE(&cmd->lock_irq, flags);

			if (found) {
				SPH_SPIN_UNLOCK(&context->lock);
				inf_cmd_put(cmd);
				break;
			}
		}
	} while (found);
	SPH_SPIN_UNLOCK(&context->lock);

	do {
		found = false;
		SPH_SPIN_LOCK(&context->lock);
		hash_for_each(context->copy_hash, i, copy, hash_node) {
			if (copy->destroyed == 0) {
				copy->destroyed = -1;
				hash_del(&copy->hash_node);
				SPH_SPIN_UNLOCK(&context->lock);
				inf_copy_put(copy);
				found = true;
				break;
			}
			copy->destroyed = -1;
		}
	} while (found);
	SPH_SPIN_UNLOCK(&context->lock);

	do {
		found = false;
		SPH_SPIN_LOCK(&context->lock);
		hash_for_each(context->devnet_hash, i, devnet, hash_node) {
			SPH_SPIN_LOCK(&devnet->lock);
			if (devnet->destroyed == 0)
				found = true;
			devnet->destroyed = -1;
			SPH_SPIN_UNLOCK(&devnet->lock);

			if (found) {
				SPH_SPIN_UNLOCK(&context->lock);
				inf_devnet_destroy_all_infreq(devnet);
				inf_devnet_put(devnet);
				break;
			}
		}
	} while (found);
	SPH_SPIN_UNLOCK(&context->lock);


	do {
		found = false;
		SPH_SPIN_LOCK(&context->lock);
		hash_for_each(context->devres_hash, i, devres, hash_node) {
			SPH_SPIN_LOCK_IRQSAVE(&devres->lock_irq, flags);
			if (devres->destroyed == 0)
				found = true;
			devres->destroyed = -1;
			SPH_SPIN_UNLOCK_IRQRESTORE(&devres->lock_irq, flags);

			if (found) {
				SPH_SPIN_UNLOCK(&context->lock);
				inf_devres_put(devres);
				break;
			}
		}
	} while (found);
	SPH_SPIN_UNLOCK(&context->lock);

	do {
		found = false;
		SPH_SPIN_LOCK(&context->lock);
		if (!list_empty(&context->sync_points)) {
			sync_point = list_first_entry(&context->sync_points,
						      struct inf_sync_point,
						      node);
			list_del(&sync_point->node);
			SPH_SPIN_UNLOCK(&context->lock);
			kfree(sync_point);
			found = true;
			break;
		}
	} while (found);
	SPH_SPIN_UNLOCK(&context->lock);
}

inline void inf_context_get(struct inf_context *context)
{
	int ret;

	ret = kref_get_unless_zero(&context->ref);
	SPH_ASSERT(ret != 0);
};

inline int inf_context_put(struct inf_context *context)
{
	return kref_put(&context->ref, release_context);
}

/* This function evaluates if a sync point has reached and send out
 * a message to host when needed, as well as removing done sync points
 * from the list.
 * the function must be called while the context lock is held!
 */
static void evaluate_sync_points(struct inf_context *context)
{
	struct inf_sync_point *sync_point;
	struct inf_req_sequence *oldest;

	oldest = list_first_entry_or_null(&context->active_seq_list,
					  struct inf_req_sequence,
					  node);

	while (!list_empty(&context->sync_points)) {
		sync_point = list_first_entry(&context->sync_points,
					      struct inf_sync_point,
					      node);

		if (oldest != NULL && sync_point->seq_id >= oldest->seq_id)
			break; /* no need to test rest of sync points */

		if (context->chan == NULL) {
			union c2h_SyncDone msg;

			msg.value = 0;
			msg.opcode = SPH_IPC_C2H_OP_SYNC_DONE;
			msg.contextID = context->protocolID;
			msg.syncSeq = sync_point->host_sync_id;

			sphcs_msg_scheduler_queue_add_msg(g_the_sphcs->public_respq,
							  &msg.value, 1);
		} else {
			union c2h_ChanSyncDone msg;

			msg.value = 0;
			msg.opcode = SPH_IPC_C2H_OP_CHAN_SYNC_DONE;
			msg.chanID = context->chan->protocolID;
			msg.syncSeq = sync_point->host_sync_id;

			sphcs_msg_scheduler_queue_add_msg(context->chan->respq,
							  &msg.value, 1);
		}

		list_del(&sync_point->node);
		kfree(sync_point);
	}
}

static void handle_seq_id_wrap(struct inf_context    *context)
{
	struct inf_req_sequence *oldest;

	/* report back completed sync points */
	if (!list_empty(&context->sync_points))
		evaluate_sync_points(context);

	oldest = list_first_entry_or_null(&context->active_seq_list,
					  struct inf_req_sequence,
					  node);

	if (oldest) {
		struct inf_req_sequence *req = NULL;
		struct inf_sync_point *sync_point;
		u16 min_seq_id = oldest->seq_id;
		u16 max_seq_id;

		list_for_each_entry(req, &context->active_seq_list, node) {
			SPH_ASSERT(req->seq_id >= min_seq_id);
			req->seq_id -= min_seq_id;
		}

		list_for_each_entry(sync_point, &context->sync_points, node) {
			SPH_ASSERT(sync_point->seq_id >= min_seq_id);
			sync_point->seq_id -= min_seq_id;
		}

		max_seq_id = list_last_entry(&context->active_seq_list,
					     struct inf_req_sequence,
					     node)->seq_id;
		SPH_ASSERT(max_seq_id + 2 > max_seq_id + 1);
		context->next_seq_id = max_seq_id + 1;
	} else {
		/* if no active requests are in flight, all sync points must
		 * have been completed as well.
		 * safe to reset the seq_id counter
		 */
		SPH_ASSERT(list_empty(&context->sync_points));
		context->next_seq_id = 0;
	}
}

void inf_context_seq_id_init(struct inf_context      *context,
			     struct inf_req_sequence *seq)
{
	unsigned long flags;

	SPH_SPIN_LOCK_IRQSAVE(&context->sync_lock_irq, flags);

	if (context->next_seq_id + 1 < context->next_seq_id)
		handle_seq_id_wrap(context);

	seq->seq_id = context->next_seq_id++;
	list_add_tail(&seq->node, &context->active_seq_list);
	SPH_SPIN_UNLOCK_IRQRESTORE(&context->sync_lock_irq, flags);
}

void inf_context_seq_id_fini(struct inf_context      *context,
			     struct inf_req_sequence *seq)
{
	unsigned long flags;

	SPH_SPIN_LOCK_IRQSAVE(&context->sync_lock_irq, flags);
	list_del(&seq->node);
	if (!list_empty(&context->sync_points))
		evaluate_sync_points(context);
	SPH_SPIN_UNLOCK_IRQRESTORE(&context->sync_lock_irq, flags);
}


/*
 * This function cancels all the infer request (of a specific context) which
 * are active during "runtime died" event (further details: these requests were added
 * to the cmdq) so they were expected to be handled by the runtime, but this function is
 * called when runtime died, so runtime cannot handle these request).
 * For each devnet, iterate over its infer requests.
 * If the infer request's "active_req" is null, only one of the following is true:
 * 1. The request was completed or is currently in completing phase. OR
 * 3. The request was not added to the cmdq (and therefore didn't even start).
 * Case 1 is ok, because after the request is completed it will clean itself.
 * Case 2 is fine also because:
 *    a. The request failed to be added to cmdq because the context is broken, and
 *       inf_req_complete will be called with relevant error. or
 *    b. The request still didn't try to be added to cmdq. When it will try, it wil fail
 *       because the context is broken (similar to #a).
 *
 * Here we will cancel all the infer request in which their active_req is not null,
 * because no other flow will cancel them.
 *
 */
void del_all_active_create_and_inf_requests(struct inf_context *context)
{
	struct inf_devnet *devnet;
	struct inf_devres *devres;
	struct inf_req *infreq;
	struct inf_exec_req *active_req;
	int i, j;
	unsigned long flags;
	bool found;

	SPH_SPIN_LOCK(&context->lock);
	hash_for_each(context->devnet_hash, i, devnet, hash_node) {
		SPH_SPIN_LOCK(&devnet->lock);
		// Complete all active infreq
		do {
			found = false;
			hash_for_each(devnet->infreq_hash, j, infreq, hash_node) {
				SPH_SPIN_LOCK_IRQSAVE(&infreq->lock_irq, flags);
				if (infreq->active_req != NULL) {
					SPH_ASSERT(infreq->status == CREATED);
					active_req = infreq->active_req;
					infreq->active_req = NULL;
					SPH_SPIN_UNLOCK_IRQRESTORE(&infreq->lock_irq, flags);
					SPH_SPIN_UNLOCK(&devnet->lock);
					found = true;
					inf_req_complete(active_req,
							 -SPHER_CONTEXT_BROKEN);
					SPH_SPIN_LOCK(&devnet->lock);
					break;
				}
				SPH_SPIN_UNLOCK_IRQRESTORE(&infreq->lock_irq, flags);
			}
		} while (found);
		// Destroy not fully created infreqs
		do {
			found = false;
			hash_for_each(devnet->infreq_hash, j, infreq, hash_node) {
				if (infreq->status != CREATED) {
					SPH_SPIN_UNLOCK(&devnet->lock);
					found = true;
					destroy_infreq_on_create_failed(infreq);
					SPH_SPIN_LOCK(&devnet->lock);
					break;
				}
			}
		} while (found);
		SPH_SPIN_UNLOCK(&devnet->lock);
	}
	// Destroy not fully created devnets
	do {
		found = false;
		hash_for_each(context->devnet_hash, i, devnet, hash_node) {
			if (devnet->edit_status != CREATED) {
				SPH_SPIN_UNLOCK(&context->lock);
				found = true;
				destroy_devnet_on_create_failed(devnet);
				SPH_SPIN_LOCK(&context->lock);
				break;
			}
		}
	} while (found);
	// Destroy not fully created devreses
	do {
		found = false;
		hash_for_each(context->devres_hash, i, devres, hash_node) {
			if (devres->status != CREATED) {
				SPH_SPIN_UNLOCK(&context->lock);
				found = true;
				destroy_devres_on_create_failed(devres);
				SPH_SPIN_LOCK(&context->lock);
				break;
			}
		}
	} while (found);
	SPH_SPIN_UNLOCK(&context->lock);
}

void inf_context_set_state(struct inf_context *context, enum context_state state)
{
	unsigned long flags;

	SPH_ASSERT(state >= CONTEXT_STATE_MIN && state <= CONTEXT_STATE_MAX); //check range

	SPH_SPIN_LOCK_IRQSAVE(&context->sync_lock_irq, flags);

	if (context->state == state) // nothing to change: return
		goto unlock;

	// if non recoverable state: return
	if (context->state == CONTEXT_BROKEN_NON_RECOVERABLE)
		goto unlock;

	sph_log_info(CONTEXT_STATE_LOG, "modifying context state, old: %d, new: %d\n", context->state, state);

	context->state = state;

unlock:
	SPH_SPIN_UNLOCK_IRQRESTORE(&context->sync_lock_irq, flags);
}

enum context_state inf_context_get_state(struct inf_context *context)
{
	return context->state;
}

void inf_context_add_sync_point(struct inf_context *context,
				u16                 host_sync_id)
{
	struct inf_sync_point *sync_point;
	unsigned long flags;

	sync_point = kzalloc(sizeof(*sync_point), GFP_NOWAIT);
	if (!sync_point) {
		sphcs_send_event_report(g_the_sphcs,
					SPH_IPC_CREATE_SYNC_FAILED,
					SPH_IPC_NO_MEMORY,
					context->protocolID,
					host_sync_id);
		return;
	}

	sync_point->host_sync_id = host_sync_id;
	SPH_SPIN_LOCK_IRQSAVE(&context->sync_lock_irq, flags);
	sync_point->seq_id = context->next_seq_id > 0 ? context->next_seq_id - 1 : 0;
	list_add_tail(&sync_point->node, &context->sync_points);
	evaluate_sync_points(context);
	SPH_SPIN_UNLOCK_IRQRESTORE(&context->sync_lock_irq, flags);
}

int inf_context_create_devres(struct inf_context *context,
			      uint16_t            protocolID,
			      uint64_t            byte_size,
			      uint8_t             depth,
			      uint32_t            usage_flags,
			      struct inf_devres **out_devres)
{
	struct inf_create_resource cmd_args;
	struct inf_devres *devres;
	int ret;

	ret = inf_devres_create(protocolID,
				context,
				byte_size,
				depth,
				usage_flags,
				&devres);
	if (unlikely(ret < 0))
		return ret;

	/* place a create device resource command for the runtime */
	cmd_args.drv_handle = (uint64_t)(uintptr_t)devres;
	cmd_args.size = byte_size * depth;
	cmd_args.usage_flags = usage_flags;

	SPH_SPIN_LOCK(&context->lock);
	hash_add(context->devres_hash,
		 &devres->hash_node,
		 devres->protocolID);

	SPH_ASSERT(devres->status == CREATE_STARTED);
	devres->status = DMA_COMPLETED; //sent to rt
	// get kref to prevent the devres to be destroyed,
	// when it is waiting for response from runtime
	inf_devres_get(devres);
	SPH_SPIN_UNLOCK(&context->lock);

	ret = inf_cmd_queue_add(&context->cmdq,
				SPHCS_RUNTIME_CMD_CREATE_RESOURCE,
				&cmd_args,
				sizeof(cmd_args),
				NULL, NULL);

	if (unlikely(ret < 0)) {
		destroy_devres_on_create_failed(devres);
		return ret;
	}

	*out_devres = devres;
	return 0;
}

int inf_context_find_and_destroy_devres(struct inf_context *context,
					uint16_t            devresID)
{
	struct inf_devres *iter, *devres = NULL;
	unsigned long flags;

	SPH_SPIN_LOCK(&context->lock);
	hash_for_each_possible(context->devres_hash, iter, hash_node, devresID)
		if (iter->protocolID == devresID) {
			devres = iter;
			break;
		}

	if (unlikely(devres == NULL)) {
		SPH_SPIN_UNLOCK(&context->lock);
		return -ENXIO;
	}

	SPH_SPIN_LOCK_IRQSAVE(&devres->lock_irq, flags);
	if (unlikely(devres->destroyed != 0)) {
		SPH_SPIN_UNLOCK_IRQRESTORE(&devres->lock_irq, flags);
		SPH_SPIN_UNLOCK(&context->lock);
		return -ENXIO;
	}

	devres->destroyed = 1;
	SPH_SPIN_UNLOCK_IRQRESTORE(&devres->lock_irq, flags);
	SPH_SPIN_UNLOCK(&context->lock);

	// kref for host
	inf_devres_put(devres);

	return 0;
}

struct inf_devres *inf_context_find_devres(struct inf_context *context,
					   uint16_t            protocolID)
{
	struct inf_devres *devres;

	SPH_SPIN_LOCK(&context->lock);
	hash_for_each_possible(context->devres_hash,
			       devres,
			       hash_node,
			       protocolID)
		if (devres->protocolID == protocolID) {
			SPH_ASSERT(devres->status == CREATED);
			SPH_ASSERT(!devres->destroyed);
			SPH_SPIN_UNLOCK(&context->lock);
			return devres;
		}
	SPH_SPIN_UNLOCK(&context->lock);

	return NULL;
}

int inf_context_create_cmd(struct inf_context   *context,
			   uint16_t              protocolID,
			   struct inf_cmd_list **out_cmd)
{
	struct inf_cmd_list *cmd;
	int ret;

	ret = inf_cmd_create(protocolID,
			     context,
			     &cmd);
	if (unlikely(ret < 0))
		return ret;

	*out_cmd = cmd;
	return 0;
}

int inf_context_find_and_destroy_cmd(struct inf_context *context,
				     uint16_t            cmdID)
{
	struct inf_cmd_list *iter, *cmd = NULL;
	unsigned long flags;

	SPH_SPIN_LOCK(&context->lock);
	hash_for_each_possible(context->cmd_hash, iter, hash_node, cmdID)
		if (iter->protocolID == cmdID) {
			cmd = iter;
			break;
		}

	if (unlikely(cmd == NULL)) {
		SPH_SPIN_UNLOCK(&context->lock);
		return -ENXIO;
	}

	SPH_SPIN_LOCK_IRQSAVE(&cmd->lock_irq, flags);
	if (unlikely(cmd->destroyed != 0)) {
		SPH_SPIN_UNLOCK_IRQRESTORE(&cmd->lock_irq, flags);
		SPH_SPIN_UNLOCK(&context->lock);
		return -ENXIO;
	}

	cmd->destroyed = 1;
	SPH_SPIN_UNLOCK_IRQRESTORE(&cmd->lock_irq, flags);
	SPH_SPIN_UNLOCK(&context->lock);

	// kref for host
	inf_cmd_put(cmd);

	return 0;
}

struct inf_cmd_list *inf_context_find_cmd(struct inf_context *context,
					  uint16_t            protocolID)
{
	struct inf_cmd_list *cmd;

	SPH_SPIN_LOCK(&context->lock);
	hash_for_each_possible(context->cmd_hash, cmd, hash_node, protocolID)
		if (cmd->protocolID == protocolID) {
			SPH_ASSERT(cmd->status == CREATED);
			SPH_ASSERT(!cmd->destroyed);
			SPH_SPIN_UNLOCK(&context->lock);
			return cmd;
		}
	SPH_SPIN_UNLOCK(&context->lock);

	return NULL;
}

int inf_context_create_devnet(struct inf_context *context,
			      uint16_t protocolID,
			      struct inf_devnet **out_devnet)
{
	struct inf_devnet *devnet;
	int ret;

	ret = inf_devnet_create(protocolID, context, &devnet);
	if (unlikely(ret < 0))
		return ret;

	*out_devnet = devnet;

	return 0;
}

int inf_context_find_and_destroy_devnet(struct inf_context *context,
					uint16_t            devnetID)
{
	struct inf_devnet *iter, *devnet = NULL;

	SPH_SPIN_LOCK(&context->lock);
	hash_for_each_possible(context->devnet_hash, iter, hash_node, devnetID)
		if (iter->protocolID == devnetID) {
			devnet = iter;
			break;
		}

	if (unlikely(devnet == NULL)) {
		SPH_SPIN_UNLOCK(&context->lock);
		return -ENXIO;
	}

	SPH_SPIN_LOCK(&devnet->lock);
	if (unlikely(devnet->destroyed != 0)) {
		SPH_SPIN_UNLOCK(&devnet->lock);
		SPH_SPIN_UNLOCK(&context->lock);
		return -ENXIO;
	}

	devnet->destroyed = 1;
	SPH_SPIN_UNLOCK(&devnet->lock);
	SPH_SPIN_UNLOCK(&context->lock);

	// kref for host
	inf_devnet_put(devnet);

	return 0;
}

struct inf_devnet *inf_context_find_devnet(struct inf_context *context, uint16_t protocolID)
{
	struct inf_devnet *devnet;

	SPH_SPIN_LOCK(&context->lock);
	hash_for_each_possible(context->devnet_hash, devnet, hash_node, protocolID)
		if (devnet->protocolID == protocolID) {
			SPH_ASSERT(devnet->created);
			SPH_ASSERT(devnet->destroyed == 0);
			SPH_SPIN_UNLOCK(&context->lock);
			return devnet;
		}
	SPH_SPIN_UNLOCK(&context->lock);

	return NULL;
}

struct inf_copy *inf_context_find_copy(struct inf_context *context, uint16_t protocolID)
{
	struct inf_copy *copy;

	SPH_SPIN_LOCK(&context->lock);
	hash_for_each_possible(context->copy_hash, copy, hash_node, protocolID) {
		if (copy->protocolID == protocolID) {
			SPH_ASSERT(copy->destroyed == 0);
			SPH_SPIN_UNLOCK(&context->lock);
			return copy;
		}
	}
	SPH_SPIN_UNLOCK(&context->lock);

	return NULL;
}

/* This function is called only when creation is failed,
 * to destroy already created part
 */
void destroy_copy_on_create_failed(struct inf_copy *copy)
{
	SPH_SPIN_LOCK(&copy->context->lock);
	if (copy->destroyed) {
		SPH_SPIN_UNLOCK(&copy->context->lock);
		return;
	}
	hash_del(&copy->hash_node);
	SPH_SPIN_UNLOCK(&copy->context->lock);

	inf_copy_put(copy);
}

int inf_context_find_and_destroy_copy(struct inf_context *context,
				      uint16_t            copyID)
{
	struct inf_copy *iter, *copy = NULL;

	SPH_SPIN_LOCK(&context->lock);
	hash_for_each_possible(context->copy_hash, iter, hash_node, copyID) {
		if (iter->protocolID == copyID) {
			copy = iter;
			break;
		}
	}

	if (unlikely(copy == NULL)) {
		SPH_SPIN_UNLOCK(&context->lock);
		return -ENXIO;
	}

	SPH_ASSERT(!copy->destroyed);
	copy->destroyed = 1;
	hash_del(&copy->hash_node);
	SPH_SPIN_UNLOCK(&copy->context->lock);

	inf_copy_put(copy);

	return 0;
}

void inf_req_try_execute(struct inf_exec_req *req)
{
	bool ready;
	int err;
	unsigned long flags;

	SPH_ASSERT(req != NULL);

	if (req->is_copy)
		ready = inf_copy_req_ready(req);
	else
		ready = inf_req_ready(req);

	if (!ready)
		return;

	SPH_SPIN_LOCK_IRQSAVE(&req->lock_irq, flags);
	if (req->in_progress) {
		SPH_SPIN_UNLOCK_IRQRESTORE(&req->lock_irq, flags);
		return;
	}
	req->in_progress = true;
	SPH_SPIN_UNLOCK_IRQRESTORE(&req->lock_irq, flags);

	if (req->is_copy) {
		err = inf_copy_req_execute(req);
	} else {
		err = inf_req_execute(req);
	}

	if (unlikely(err < 0)) {
		if (req->is_copy)
			inf_copy_req_complete(req, err, 0);
		else
			inf_req_complete(req, err);
	}

}

static struct inf_subres_load_session *create_subres_load_session(struct inf_context *context, uint16_t sessionID, struct inf_devres *devres)
{
	struct inf_subres_load_session *session;

	session = kzalloc(sizeof(*session), GFP_KERNEL);
	if (!session) {
		sph_log_err(CREATE_COMMAND_LOG, "Failed to create subres_load session object\n");
		return NULL;
	}

	memset(session, 0, sizeof(*session));
	session->sessionID = sessionID;
	session->devres = devres;
	session->lli_size = SPH_PAGE_SIZE;
	session->lli_buf = dma_alloc_coherent(g_the_sphcs->hw_device, session->lli_size, &session->lli_addr, GFP_KERNEL);
	INIT_LIST_HEAD(&session->lli_space_list);
	spin_lock_init(&session->lock);
	init_waitqueue_head(&session->lli_waitq);

	return session;
}

struct inf_subres_load_session *inf_context_create_subres_load_session(struct inf_context *context,
								       struct inf_devres *devres,
								       union h2c_SubResourceLoadCreateRemoveSession *cmd)
{
	struct inf_subres_load_session *session;

	session = inf_context_get_subres_load_session(context, cmd->sessionID);
	if (session != NULL) {
		sph_log_err(CREATE_COMMAND_LOG, "WARNING: session id %hu allready exist\n", cmd->sessionID);
		return session;
	}
	session = create_subres_load_session(context, cmd->sessionID, devres);

	SPH_SPIN_LOCK(&context->lock);
	list_add_tail(&session->node, &context->subresload_sessions);
	SPH_SPIN_UNLOCK(&context->lock);

	return session;
}

struct inf_subres_load_session *inf_context_get_subres_load_session(struct inf_context *context, uint16_t sessionID)
{
	struct inf_subres_load_session *session;

	SPH_SPIN_LOCK(&context->lock);
	list_for_each_entry(session, &context->subresload_sessions, node) {
		if (session->sessionID == sessionID)
			break;
	}
	// Check if nothing found
	if (&session->node == &context->subresload_sessions)
		session = NULL;
	SPH_SPIN_UNLOCK(&context->lock);

	return session;
}

static void delete_session(struct inf_subres_load_session *session)
{
	//All session delete operations are here
	inf_subresload_delete_lli_space_list(session);
	dma_free_coherent(g_the_sphcs->hw_device, session->lli_size, session->lli_buf, session->lli_addr);
	kfree(session);
}

void inf_context_remove_subres_load_session(struct inf_context *context, uint16_t sessionID)
{
	struct inf_subres_load_session *session = NULL;

	SPH_SPIN_LOCK(&context->lock);
	list_for_each_entry(session, &context->subresload_sessions, node) {
		if (session->sessionID == sessionID) {
			list_del(&session->node);
			SPH_SPIN_UNLOCK(&context->lock);
			delete_session(session);
			return;
		}
	}
	SPH_SPIN_UNLOCK(&context->lock);
}

int inf_exec_req_get(struct inf_exec_req *req)
{
	return kref_get_unless_zero(&req->in_use);
}

int inf_exec_req_put(struct inf_exec_req *req)
{
	if (req->is_copy)
		return kref_put(&req->in_use, inf_copy_req_release);
	else
		return kref_put(&req->in_use, inf_req_release);
}
