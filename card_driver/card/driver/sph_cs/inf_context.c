/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#include "inf_context.h"
#include <linux/kernel.h>
#include <linux/hashtable.h>
#include <linux/slab.h>
#include "inf_devres.h"
#include "inf_devnet.h"
#include "inf_copy.h"
#include "ioctl_inf.h"
#include "inf_req.h"
#include "nnp_time.h"
#include "periodic_timer.h"
#include "nnp_error.h"
#include "sphcs_inf.h"
#include "inf_ptr2id.h"

static void update_sw_counters(void *ctx)
{
	struct inf_context *context = (struct inf_context *)ctx;
	u64 current_time;
	unsigned long flags;

	NNP_SPIN_LOCK_IRQSAVE(&context->sw_counters_lock_irq, flags);
	if (context->infreq_counter > 0 &&
	    NNP_SW_GROUP_IS_ENABLE(context->sw_counters,
				   CTX_SPHCS_SW_COUNTERS_GROUP_INFERENCE)) {
		current_time = nnp_time_us();
		if (context->runtime_busy_starttime) {
			NNP_SW_COUNTER_ADD(context->sw_counters,
					   CTX_SPHCS_SW_COUNTERS_INFERENCE_RUNTIME_BUSY_TIME,
					   current_time - context->runtime_busy_starttime);
		}
		context->runtime_busy_starttime = current_time;
	} else {
		context->runtime_busy_starttime = 0;
	}
	NNP_SPIN_UNLOCK_IRQRESTORE(&context->sw_counters_lock_irq, flags);
}

int inf_context_create(uint16_t             protocol_id,
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

	snprintf(slab_name, sizeof(slab_name), "sph_ctxslab%03d", protocol_id);
	context->exec_req_slab_cache = kmem_cache_create(slab_name,
							 sizeof(struct inf_exec_req),
							 0, SLAB_HWCACHE_ALIGN, NULL);
	if (unlikely(context->exec_req_slab_cache == NULL)) {
		sph_log_err(CREATE_COMMAND_LOG, "failed to create context slab cache\n");
		ret = -ENOMEM;
		goto freeCtx;
	}

	atomic_set(&context->ref, 1);
	context->chan = chan;
	context->magic = inf_context_create;
	context->protocol_id = protocol_id;
	context->state = CONTEXT_OK;
	context->attached = 0;
	context->destroyed = 0;
	context->runtime_detach_sent = false;
	atomic_set(&context->sched_tick, 1);
	spin_lock_init(&context->lock);
	spin_lock_init(&context->sync_lock_irq);
	spin_lock_init(&context->sw_counters_lock_irq);
	inf_cmd_queue_init(&context->cmdq);
	hash_init(context->cmd_hash);
	hash_init(context->devres_hash);
	hash_init(context->copy_hash);
	hash_init(context->devnet_hash);
	context->daemon_ref_released = true;
	INIT_LIST_HEAD(&context->sync_points);
	INIT_LIST_HEAD(&context->active_seq_list);
	init_waitqueue_head(&context->sched_waitq);

	inf_exec_error_list_init(&context->error_list, context);

	ret = nnp_create_sw_counters_values_node(g_hSwCountersInfo_context,
						 (u32)protocol_id,
						 g_nnp_sw_counters,
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

	NNP_SPIN_LOCK_BH(&g_the_sphcs->inf_data->lock_bh);
	hash_add(g_the_sphcs->inf_data->context_hash,
		 &context->hash_node,
		 context->protocol_id);
	NNP_SPIN_UNLOCK_BH(&g_the_sphcs->inf_data->lock_bh);

	*out_context = context;
	SPH_SW_COUNTER_ATOMIC_INC(g_nnp_sw_counters, SPHCS_SW_COUNTERS_INFERENCE_NUM_CONTEXTS);
	return 0;

free_counters:
	nnp_remove_sw_counters_values_node(context->sw_counters);
free_kmem_cache:
	kmem_cache_destroy(context->exec_req_slab_cache);
freeCtx:
	kfree(context);
	return ret;
}

int inf_context_runtime_attach(struct inf_context *context)
{
	NNP_SPIN_LOCK_BH(&g_the_sphcs->inf_data->lock_bh);
	if (unlikely(context->destroyed)) {
		NNP_SPIN_UNLOCK_BH(&g_the_sphcs->inf_data->lock_bh);
		return -EPERM;
	}
	NNP_SPIN_LOCK(&context->lock);
	if (unlikely(context->attached != 0)) {
		NNP_SPIN_UNLOCK(&context->lock);
		NNP_SPIN_UNLOCK_BH(&g_the_sphcs->inf_data->lock_bh);
		return -EBUSY;
	}
	context->attached = 1;
	NNP_SPIN_UNLOCK(&context->lock);
	NNP_SPIN_UNLOCK_BH(&g_the_sphcs->inf_data->lock_bh);

	/* Take kref, dedicated to runtime */
	inf_context_get(context);

	return 0;
}

static void inf_context_runtime_detach(struct inf_context *context)
{
	int ret;

	NNP_ASSERT(context->runtime_detach_sent);

	if (context->attached <= 0)
		return;
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

static void release_context(struct inf_context *context)
{
	struct inf_devres *devres;
	struct inf_copy *copy;
	struct inf_sync_point *sync_point;
	struct inf_sync_point *n;
	int i;

	NNP_SPIN_LOCK_BH(&g_the_sphcs->inf_data->lock_bh);
	hash_del(&context->hash_node);
	context->chan->destroy_cb = NULL;
	NNP_SPIN_UNLOCK_BH(&g_the_sphcs->inf_data->lock_bh);

	inf_cmd_queue_fini(&context->cmdq);

	NNP_ASSERT(hash_empty(context->copy_hash));
	hash_for_each(context->copy_hash, i, copy, hash_node) {
		inf_copy_put(copy);
	}
	NNP_ASSERT(hash_empty(context->devres_hash));
	hash_for_each(context->devres_hash, i, devres, hash_node) {
		inf_devres_put(devres);
	}
	list_for_each_entry_safe(sync_point, n, &context->sync_points, node) {
		list_del(&sync_point->node);
		kfree(sync_point);
	}
	SPH_SW_COUNTER_ATOMIC_DEC(g_nnp_sw_counters, SPHCS_SW_COUNTERS_INFERENCE_NUM_CONTEXTS);

	nnp_remove_sw_counters_values_node(context->sw_counters);

	periodic_timer_remove_data(&g_the_sphcs->periodic_timer, context->counters_cb_data_handler);

	NNP_ASSERT(context->attached != 1);

	kmem_cache_destroy(context->exec_req_slab_cache);

	inf_exec_error_list_fini(&context->error_list);

	if (likely(context->destroyed == 1))
		sphcs_send_event_report(g_the_sphcs,
					NNP_IPC_CONTEXT_DESTROYED,
					0,
					context->chan->respq,
					context->protocol_id,
					-1);

	sphcs_cmd_chan_put(context->chan);

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
	bool connected, found;
	unsigned long flags;

	do {
		found = false;
		NNP_SPIN_LOCK(&context->lock);
		hash_for_each(context->cmd_hash, i, cmd, hash_node) {
			NNP_SPIN_LOCK_IRQSAVE(&cmd->lock_irq, flags);
			if (cmd->destroyed == 0)
				found = true;
			cmd->destroyed = -1;
			NNP_SPIN_UNLOCK_IRQRESTORE(&cmd->lock_irq, flags);

			if (found) {
				NNP_SPIN_UNLOCK(&context->lock);
				inf_cmd_put(cmd);
				break;
			}
		}
	} while (found);
	NNP_SPIN_UNLOCK(&context->lock);

	do {
		found = false;
		NNP_SPIN_LOCK(&context->lock);
		hash_for_each(context->copy_hash, i, copy, hash_node) {
			if (copy->destroyed == 0) {
				copy->destroyed = -1;
				NNP_SPIN_UNLOCK(&context->lock);
				inf_copy_put(copy);
				found = true;
				break;
			}
			copy->destroyed = -1;
		}
	} while (found);
	NNP_SPIN_UNLOCK(&context->lock);

	do {
		found = false;
		NNP_SPIN_LOCK(&context->lock);
		hash_for_each(context->devnet_hash, i, devnet, hash_node) {
			NNP_SPIN_LOCK(&devnet->lock);
			if (devnet->destroyed == 0)
				found = true;
			devnet->destroyed = -1;
			NNP_SPIN_UNLOCK(&devnet->lock);

			NNP_SPIN_UNLOCK(&context->lock);
			inf_devnet_destroy_all_infreq(devnet);
			if (found) {
				inf_devnet_put(devnet);
				break;
			}
			NNP_SPIN_LOCK(&context->lock);
		}
	} while (found);
	NNP_SPIN_UNLOCK(&context->lock);


	do {
		found = false;
		NNP_SPIN_LOCK(&context->lock);
		hash_for_each(context->devres_hash, i, devres, hash_node) {
			if (devres->is_p2p_dst) {
				NNP_SPIN_LOCK_IRQSAVE(&devres->lock_irq, flags);
				if (!devres->is_dirty) {
					found = true;
					inf_devres_set_dirty(devres, true);
					devres->p2p_buf.ready = true;

					NNP_SPIN_UNLOCK_IRQRESTORE(&devres->lock_irq, flags);
					NNP_SPIN_UNLOCK(&context->lock);
					/* advance sched tick and try execute next requests */
					atomic_add(2, &context->sched_tick);
					inf_devres_try_execute(devres);
					break;
				}
				NNP_SPIN_UNLOCK_IRQRESTORE(&devres->lock_irq, flags);
			}
		}
	} while (found);
	NNP_SPIN_UNLOCK(&context->lock);

	do {
		connected = false;
		found = false;
		NNP_SPIN_LOCK(&context->lock);
		hash_for_each(context->devres_hash, i, devres, hash_node) {
			NNP_SPIN_LOCK_IRQSAVE(&devres->lock_irq, flags);
			if (devres->destroyed == 0)
				found = true;
			if (devres->destroyed != -1 &&
			    devres->is_p2p_dst &&
			    devres->p2p_buf.peer_dev != NULL) // connected
				connected = true;
			devres->destroyed = -1;
			NNP_SPIN_UNLOCK_IRQRESTORE(&devres->lock_irq, flags);
			if (connected || found) {
				NNP_SPIN_UNLOCK(&context->lock);
				if (connected)
					inf_devres_put(devres);
				if (found)
					inf_devres_put(devres);
				break;
			}
		}
	} while (connected || found);
	NNP_SPIN_UNLOCK(&context->lock);

	do {
		found = false;
		NNP_SPIN_LOCK(&context->lock);
		if (!list_empty(&context->sync_points)) {
			sync_point = list_first_entry(&context->sync_points,
						      struct inf_sync_point,
						      node);
			list_del(&sync_point->node);
			NNP_SPIN_UNLOCK(&context->lock);
			kfree(sync_point);
			found = true;
			break;
		}
	} while (found);
	NNP_SPIN_UNLOCK(&context->lock);
}

int inf_context_get(struct inf_context *context)
{
	return atomic_inc_not_zero(&context->ref);
}

int inf_context_put(struct inf_context *context)
{
	bool send_runtime = false;
	int usage_count;

	if (!context)
		return 0;

	usage_count = atomic_dec_if_positive(&context->ref);
	NNP_ASSERT(usage_count >= 0);

	/*
	 * send runtime detach request to runtime
	 * if only runtime and daemon remained attached after the put
	 */
	NNP_SPIN_LOCK(&context->lock);
	if (context->attached > 0 &&
	    !context->runtime_detach_sent)
		send_runtime = context->runtime_detach_sent = (usage_count <= (context->daemon_ref_released ? 1 : 2));
	NNP_SPIN_UNLOCK(&context->lock);

	if (send_runtime)
		inf_context_runtime_detach(context);

	if (usage_count == 0) {
		release_context(context);

		return 1;
	}

	return 0;
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
	union c2h_ChanSyncDone msg;

	oldest = list_first_entry_or_null(&context->active_seq_list,
					  struct inf_req_sequence,
					  node);

	while (!list_empty(&context->sync_points)) {
		sync_point = list_first_entry(&context->sync_points,
					      struct inf_sync_point,
					      node);

		if (oldest != NULL && sync_point->seq_id >= oldest->seq_id)
			break; /* no need to test rest of sync points */

		msg.value = 0;
		msg.opcode = NNP_IPC_C2H_OP_CHAN_SYNC_DONE;
		msg.chan_id = context->chan->protocol_id;
		msg.syncSeq = sync_point->host_sync_id;

		sphcs_msg_scheduler_queue_add_msg(context->chan->respq,
						  &msg.value, 1);

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
			NNP_ASSERT(req->seq_id >= min_seq_id);
			req->seq_id -= min_seq_id;
		}

		list_for_each_entry(sync_point, &context->sync_points, node) {
			NNP_ASSERT(sync_point->seq_id >= min_seq_id);
			sync_point->seq_id -= min_seq_id;
		}

		max_seq_id = list_last_entry(&context->active_seq_list,
					     struct inf_req_sequence,
					     node)->seq_id;
		NNP_ASSERT(max_seq_id + 2 > max_seq_id + 1);
		context->next_seq_id = max_seq_id + 1;
	} else {
		/* if no active requests are in flight, all sync points must
		 * have been completed as well.
		 * safe to reset the seq_id counter
		 */
		NNP_ASSERT(list_empty(&context->sync_points));
		context->next_seq_id = 0;
	}
}

void inf_context_seq_id_init(struct inf_context      *context,
			     struct inf_req_sequence *seq)
{
	unsigned long flags;

	NNP_SPIN_LOCK_IRQSAVE(&context->sync_lock_irq, flags);

	if (context->next_seq_id + 1 < context->next_seq_id)
		handle_seq_id_wrap(context);

	seq->seq_id = context->next_seq_id++;
	list_add_tail(&seq->node, &context->active_seq_list);
	NNP_SPIN_UNLOCK_IRQRESTORE(&context->sync_lock_irq, flags);
}

void inf_context_seq_id_fini(struct inf_context      *context,
			     struct inf_req_sequence *seq)
{
	unsigned long flags;

	NNP_SPIN_LOCK_IRQSAVE(&context->sync_lock_irq, flags);
	list_del(&seq->node);
	if (!list_empty(&context->sync_points))
		evaluate_sync_points(context);
	NNP_SPIN_UNLOCK_IRQRESTORE(&context->sync_lock_irq, flags);
	wake_up_all(&context->sched_waitq);
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

	sph_log_info(CONTEXT_STATE_LOG, "contextID: %u\n", context->protocol_id);

	do {
		found = false;
		NNP_SPIN_LOCK(&context->lock);
		hash_for_each(context->devnet_hash, i, devnet, hash_node) {
			NNP_SPIN_LOCK(&devnet->lock);
			hash_for_each(devnet->infreq_hash, j, infreq, hash_node) {
				NNP_SPIN_LOCK_IRQSAVE(&infreq->lock_irq, flags);
				// Complete active infreq
				if (infreq->active_req != NULL) {
					NNP_ASSERT(infreq->status == CREATED);
					active_req = infreq->active_req;
					infreq->active_req = NULL;
					NNP_SPIN_UNLOCK_IRQRESTORE(&infreq->lock_irq, flags);
					NNP_SPIN_UNLOCK(&devnet->lock);
					NNP_SPIN_UNLOCK(&context->lock);
					found = true;
					inf_req_complete(active_req,
							 -NNPER_CONTEXT_BROKEN,
							 NULL,
							 0);
					break;
				// Destroy not fully created infreqs
				} else if (infreq->status == DMA_COMPLETED ||
					   (infreq->status != CREATED && infreq->destroyed == 0)) {
					NNP_SPIN_UNLOCK_IRQRESTORE(&infreq->lock_irq, flags);
					NNP_SPIN_UNLOCK(&devnet->lock);
					NNP_SPIN_UNLOCK(&context->lock);
					found = true;
					sphcs_send_event_report_ext(g_the_sphcs,
						NNP_IPC_CREATE_INFREQ_FAILED,
						NNP_IPC_RUNTIME_FAILED,
						context->chan->respq,
						context->protocol_id,
						infreq->protocol_id,
						devnet->protocol_id);
					destroy_infreq_on_create_failed(infreq);
					break;
				}
				NNP_SPIN_UNLOCK_IRQRESTORE(&infreq->lock_irq, flags);
			}
			if (found)
				break;
			NNP_SPIN_UNLOCK(&devnet->lock);
		}
	} while (found);
	NNP_SPIN_UNLOCK(&context->lock);

	// Destroy not fully created devnets / devnets with not added resources
	do {
		found = false;
		NNP_SPIN_LOCK(&context->lock);
		hash_for_each(context->devnet_hash, i, devnet, hash_node) {
			if (devnet->edit_status == DMA_COMPLETED ||
			    (!devnet->created && devnet->destroyed == 0)) {
				NNP_SPIN_UNLOCK(&context->lock);
				found = true;
				inf_devnet_on_create_or_add_res_failed(devnet);
				break;
			}
		}
	} while (found);
	NNP_SPIN_UNLOCK(&context->lock);

	// Destroy not fully created devreses
	do {
		found = false;
		NNP_SPIN_LOCK(&context->lock);
		hash_for_each(context->devres_hash, i, devres, hash_node) {
			if (devres->status == DMA_COMPLETED ||
			    (devres->status != CREATED && devres->destroyed == 0)) {
				NNP_SPIN_UNLOCK(&context->lock);
				found = true;
				destroy_devres_on_create_failed(devres);
				break;
			}
		}
	} while (found);
	NNP_SPIN_UNLOCK(&context->lock);
}

void inf_context_set_state(struct inf_context *context, enum context_state state)
{
	unsigned long flags;

	NNP_ASSERT(state >= CONTEXT_STATE_MIN && state <= CONTEXT_STATE_MAX); //check range

	NNP_SPIN_LOCK_IRQSAVE(&context->sync_lock_irq, flags);

	if (context->state == state) // nothing to change: return
		goto unlock;

	// if non recoverable state: return
	if (context->state == CONTEXT_BROKEN_NON_RECOVERABLE)
		goto unlock;

	sph_log_info(CONTEXT_STATE_LOG, "modifying context state, old: %d, new: %d\n", context->state, state);

	context->state = state;

unlock:
	NNP_SPIN_UNLOCK_IRQRESTORE(&context->sync_lock_irq, flags);
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
					NNP_IPC_CREATE_SYNC_FAILED,
					NNP_IPC_NO_MEMORY,
					context->chan->respq,
					context->protocol_id,
					host_sync_id);
		return;
	}

	sync_point->host_sync_id = host_sync_id;
	NNP_SPIN_LOCK_IRQSAVE(&context->sync_lock_irq, flags);
	sync_point->seq_id = context->next_seq_id > 0 ? context->next_seq_id - 1 : 0;
	list_add_tail(&sync_point->node, &context->sync_points);
	evaluate_sync_points(context);
	NNP_SPIN_UNLOCK_IRQRESTORE(&context->sync_lock_irq, flags);
}

int inf_context_create_devres(struct inf_context *context,
			      uint16_t            protocol_id,
			      uint64_t            byte_size,
			      uint8_t             depth,
			      uint64_t            align,
			      uint32_t            usage_flags,
			      struct inf_devres **out_devres)
{
	struct inf_create_resource cmd_args;
	struct inf_devres *devres;
	int ret;

	ret = inf_devres_create(protocol_id,
				context,
				byte_size,
				depth,
				align,
				usage_flags,
				&devres);
	if (unlikely(ret < 0))
		return ret;

	/* place a create device resource command for the runtime */
	cmd_args.drv_handle = devres->ptr2id;
	cmd_args.size = byte_size * depth;
	cmd_args.align = align;
	cmd_args.usage_flags = usage_flags;

	NNP_SPIN_LOCK(&context->lock);
	hash_add(context->devres_hash,
		 &devres->hash_node,
		 devres->protocol_id);

	NNP_ASSERT(devres->status == CREATE_STARTED);
	devres->status = DMA_COMPLETED; //sent to rt
	// get kref to prevent the devres to be destroyed,
	// when it is waiting for response from runtime
	inf_devres_get(devres);
	NNP_SPIN_UNLOCK(&context->lock);

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

	NNP_SPIN_LOCK(&context->lock);
	hash_for_each_possible(context->devres_hash, iter, hash_node, devresID)
		if (iter->protocol_id == devresID) {
			devres = iter;
			break;
		}

	if (unlikely(devres == NULL)) {
		NNP_SPIN_UNLOCK(&context->lock);
		return -ENXIO;
	}

	NNP_SPIN_LOCK_IRQSAVE(&devres->lock_irq, flags);
	if (unlikely(devres->destroyed != 0)) {
		NNP_SPIN_UNLOCK_IRQRESTORE(&devres->lock_irq, flags);
		NNP_SPIN_UNLOCK(&context->lock);
		return -ENXIO;
	}

	devres->destroyed = 1;
	NNP_SPIN_UNLOCK_IRQRESTORE(&devres->lock_irq, flags);
	NNP_SPIN_UNLOCK(&context->lock);

	// kref for host
	inf_devres_put(devres);

	return 0;
}

struct inf_devres *inf_context_find_devres(struct inf_context *context,
					   uint16_t            protocol_id)
{
	struct inf_devres *devres;

	NNP_SPIN_LOCK(&context->lock);
	hash_for_each_possible(context->devres_hash,
			       devres,
			       hash_node,
			       protocol_id)
		if (devres->protocol_id == protocol_id) {
			NNP_ASSERT(devres->status == CREATED);
			NNP_SPIN_UNLOCK(&context->lock);
			return devres;
		}
	NNP_SPIN_UNLOCK(&context->lock);

	return NULL;
}

struct inf_devres *inf_context_find_and_get_devres(struct inf_context *context,
						   uint16_t            protocol_id)
{
	struct inf_devres *devres;

	NNP_SPIN_LOCK(&context->lock);
	hash_for_each_possible(context->devres_hash,
			       devres,
			       hash_node,
			       protocol_id)
		if (devres->protocol_id == protocol_id) {
			NNP_ASSERT(devres->status == CREATED);
			if (unlikely(devres->destroyed || inf_devres_get(devres) == 0))
				break; //destroyed
			NNP_SPIN_UNLOCK(&context->lock);
			return devres;
		}
	NNP_SPIN_UNLOCK(&context->lock);

	return NULL;
}

int inf_context_create_cmd(struct inf_context   *context,
			   uint16_t              protocol_id,
			   struct inf_cmd_list **out_cmd)
{
	struct inf_cmd_list *cmd;
	int ret;

	ret = inf_cmd_create(protocol_id,
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

	NNP_SPIN_LOCK(&context->lock);
	hash_for_each_possible(context->cmd_hash, iter, hash_node, cmdID)
		if (iter->protocol_id == cmdID) {
			cmd = iter;
			break;
		}

	if (unlikely(cmd == NULL)) {
		NNP_SPIN_UNLOCK(&context->lock);
		return -ENXIO;
	}

	NNP_SPIN_LOCK_IRQSAVE(&cmd->lock_irq, flags);
	if (unlikely(cmd->destroyed != 0)) {
		NNP_SPIN_UNLOCK_IRQRESTORE(&cmd->lock_irq, flags);
		NNP_SPIN_UNLOCK(&context->lock);
		return -ENXIO;
	}

	cmd->destroyed = 1;
	NNP_SPIN_UNLOCK_IRQRESTORE(&cmd->lock_irq, flags);
	NNP_SPIN_UNLOCK(&context->lock);

	// kref for host
	inf_cmd_put(cmd);

	return 0;
}

struct inf_cmd_list *inf_context_find_cmd(struct inf_context *context,
					  uint16_t            protocol_id)
{
	struct inf_cmd_list *cmd;

	NNP_SPIN_LOCK(&context->lock);
	hash_for_each_possible(context->cmd_hash, cmd, hash_node, protocol_id)
		if (cmd->protocol_id == protocol_id) {
			if (cmd->destroyed)
				break; //destroyed
			NNP_SPIN_UNLOCK(&context->lock);
			return cmd;
		}
	NNP_SPIN_UNLOCK(&context->lock);

	return NULL;
}

int inf_context_find_and_destroy_devnet(struct inf_context *context,
					uint16_t            devnetID)
{
	struct inf_devnet *iter, *devnet = NULL;

	NNP_SPIN_LOCK(&context->lock);
	hash_for_each_possible(context->devnet_hash, iter, hash_node, devnetID)
		if (iter->protocol_id == devnetID) {
			devnet = iter;
			break;
		}

	if (unlikely(devnet == NULL)) {
		NNP_SPIN_UNLOCK(&context->lock);
		return -ENXIO;
	}

	NNP_SPIN_LOCK(&devnet->lock);
	if (unlikely(devnet->destroyed != 0)) {
		NNP_SPIN_UNLOCK(&devnet->lock);
		NNP_SPIN_UNLOCK(&context->lock);
		return -ENXIO;
	}

	devnet->destroyed = 1;
	NNP_SPIN_UNLOCK(&devnet->lock);
	NNP_SPIN_UNLOCK(&context->lock);

	// kref for host
	inf_devnet_put(devnet);

	return 0;
}

struct inf_devnet *inf_context_find_devnet(struct inf_context *context, uint16_t protocol_id)
{
	struct inf_devnet *devnet;

	NNP_SPIN_LOCK(&context->lock);
	hash_for_each_possible(context->devnet_hash, devnet, hash_node, protocol_id)
		if (devnet->protocol_id == protocol_id) {
			NNP_SPIN_UNLOCK(&context->lock);
			return devnet;
		}
	NNP_SPIN_UNLOCK(&context->lock);

	return NULL;
}

struct inf_devnet *inf_context_find_and_get_devnet(struct inf_context *context, uint16_t protocol_id, bool alive, bool created)
{
	struct inf_devnet *devnet;

	NNP_SPIN_LOCK(&context->lock);
	hash_for_each_possible(context->devnet_hash, devnet, hash_node, protocol_id)
		if (devnet->protocol_id == protocol_id) {
			if (created && !devnet->created)
				break;
			if (alive && devnet->destroyed)
				break;
			if (unlikely(inf_devnet_get(devnet) == 0))
				break;
			NNP_SPIN_UNLOCK(&context->lock);
			return devnet;
		}
	NNP_SPIN_UNLOCK(&context->lock);

	return NULL;
}

struct inf_copy *inf_context_find_copy(struct inf_context *context, uint16_t protocol_id)
{
	struct inf_copy *copy;

	NNP_SPIN_LOCK(&context->lock);
	hash_for_each_possible(context->copy_hash, copy, hash_node, protocol_id) {
		if (copy->protocol_id == protocol_id) {
			NNP_SPIN_UNLOCK(&context->lock);
			return copy;
		}
	}
	NNP_SPIN_UNLOCK(&context->lock);

	return NULL;
}

struct inf_copy *inf_context_find_and_get_copy(struct inf_context *context, uint16_t protocol_id)
{
	struct inf_copy *copy;

	NNP_SPIN_LOCK(&context->lock);
	hash_for_each_possible(context->copy_hash, copy, hash_node, protocol_id) {
		if (copy->protocol_id == protocol_id) {
			if (unlikely(copy->destroyed || inf_copy_get(copy) == 0))
				break;
			NNP_SPIN_UNLOCK(&context->lock);
			return copy;
		}
	}
	NNP_SPIN_UNLOCK(&context->lock);

	return NULL;
}

/* This function is called only when creation is failed,
 * to destroy already created part
 */
void destroy_copy_on_create_failed(struct inf_copy *copy)
{
	NNP_SPIN_LOCK(&copy->context->lock);
	if (copy->destroyed) {
		NNP_SPIN_UNLOCK(&copy->context->lock);
		return;
	}
	NNP_SPIN_UNLOCK(&copy->context->lock);

	inf_copy_put(copy);
}

int inf_context_find_and_destroy_copy(struct inf_context *context,
				      uint16_t            copyID)
{
	struct inf_copy *iter, *copy = NULL;

	NNP_SPIN_LOCK(&context->lock);
	hash_for_each_possible(context->copy_hash, iter, hash_node, copyID) {
		if (iter->protocol_id == copyID) {
			copy = iter;
			break;
		}
	}

	if (unlikely(copy == NULL)) {
		NNP_SPIN_UNLOCK(&context->lock);
		return -ENXIO;
	} else if (copy->destroyed) {
		NNP_SPIN_UNLOCK(&context->lock);
		return -ENXIO;
	}

	copy->destroyed = 1;
	NNP_SPIN_UNLOCK(&copy->context->lock);

	inf_copy_put(copy);

	return 0;
}

