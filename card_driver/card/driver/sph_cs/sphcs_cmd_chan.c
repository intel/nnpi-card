/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#include "sphcs_cmd_chan.h"
#include <linux/kernel.h>
#include <linux/slab.h>
#include "ipc_protocol.h"
#include "sph_log.h"
#include "sphcs_cs.h"

static void sphcs_host_rb_init(struct sphcs_host_rb *rb,
			       struct sg_table      *host_sgt,
			       uint64_t              size);

int sphcs_cmd_chan_create(uint16_t                protocol_id,
			  uint32_t                uid,
			  bool                    privileged,
			  struct sphcs_cmd_chan **out_cmd_chan)
{
	struct sphcs_cmd_chan *cmd_chan;
	struct sphcs_cmd_chan *iter;
	bool found = false;

	cmd_chan = kzalloc(sizeof(struct sphcs_cmd_chan), GFP_KERNEL);
	if (unlikely(cmd_chan == NULL)) {
		sph_log_err(CREATE_COMMAND_LOG, "FATAL: %s():%u failed to allocate command channel object\n", __func__, __LINE__);
		return NNP_IPC_NO_MEMORY;
	}

	kref_init(&cmd_chan->ref);
	cmd_chan->magic = sphcs_cmd_chan_create;
	cmd_chan->protocol_id = protocol_id;
	cmd_chan->uid = uid;
	cmd_chan->privileged = privileged;
	cmd_chan->destroyed = false;

	spin_lock_init(&cmd_chan->lock_bh);
	hash_init(cmd_chan->hostres_hash);

	cmd_chan->c2h_dma_desc.dma_direction = SPHCS_DMA_DIRECTION_CARD_TO_HOST;
	cmd_chan->c2h_dma_desc.dma_priority = SPHCS_DMA_PRIORITY_LOW;
	cmd_chan->c2h_dma_desc.flags = 0;
	cmd_chan->c2h_dma_desc.serial_channel =
		sphcs_dma_sched_create_serial_channel(g_the_sphcs->dmaSched);

	cmd_chan->h2c_dma_desc.dma_direction = SPHCS_DMA_DIRECTION_HOST_TO_CARD;
	cmd_chan->h2c_dma_desc.dma_priority = SPHCS_DMA_PRIORITY_LOW;
	cmd_chan->h2c_dma_desc.flags = 0;
	cmd_chan->h2c_dma_desc.serial_channel =
		sphcs_dma_sched_create_serial_channel(g_the_sphcs->dmaSched);

	cmd_chan->wq = create_singlethread_workqueue("chan_wq");
	if (!cmd_chan->wq) {
		sph_log_err(CREATE_COMMAND_LOG, "Failed to initialize channel workqueue\n");
		kfree(cmd_chan);
		return NNP_IPC_NO_MEMORY;
	}

	cmd_chan->respq = sphcs_create_response_queue(g_the_sphcs, 1);
	if (!cmd_chan->respq) {
		sph_log_err(START_UP_LOG, "Failed to create channel response q\n");
		destroy_workqueue(cmd_chan->wq);
		kfree(cmd_chan);
		return NNP_IPC_NO_MEMORY;
	}

	if (protocol_id < 256) { //for context
		cmd_chan->h2c_dma_exec_desc.dma_direction = SPHCS_DMA_DIRECTION_HOST_TO_CARD;
		cmd_chan->h2c_dma_exec_desc.dma_priority = SPHCS_DMA_PRIORITY_NORMAL;
		cmd_chan->h2c_dma_exec_desc.flags = 0;
		cmd_chan->h2c_dma_exec_desc.serial_channel =
			sphcs_dma_sched_create_serial_channel(g_the_sphcs->dmaSched);

		atomic_set(&cmd_chan->sched_queued, 0);
		cmd_chan->wq_exec = create_singlethread_workqueue("chan_wq_exec");
		if (!cmd_chan->wq_exec) {
			sph_log_err(CREATE_COMMAND_LOG, "Failed to initialize channel execution workqueue\n");
			sphcs_destroy_response_queue(g_the_sphcs, cmd_chan->respq);
			destroy_workqueue(cmd_chan->wq);
			kfree(cmd_chan);
			return NNP_IPC_NO_MEMORY;
		}
	}

	//
	// Add channel to the channel hash - if protocol ID not already exist
	//
	NNP_SPIN_LOCK_BH(&g_the_sphcs->lock_bh);
	hash_for_each_possible(g_the_sphcs->cmd_chan_hash,
			       iter,
			       hash_node,
			       protocol_id)
		if (iter->protocol_id == protocol_id) {
			found = true;
			break;
		}

	if (!found)
		hash_add(g_the_sphcs->cmd_chan_hash,
			 &cmd_chan->hash_node,
			 cmd_chan->protocol_id);
	NNP_SPIN_UNLOCK_BH(&g_the_sphcs->lock_bh);

	if (found) {
		if (protocol_id < 256)
			destroy_workqueue(cmd_chan->wq_exec);
		destroy_workqueue(cmd_chan->wq);
		sphcs_destroy_response_queue(g_the_sphcs, cmd_chan->respq);
		kfree(cmd_chan);
		return NNP_IPC_ALREADY_EXIST;
	}

	*out_cmd_chan = cmd_chan;

	return 0;
}

static void cmd_chan_release(struct work_struct *work)
{
	struct sphcs_cmd_chan *cmd_chan;
	int i;

	cmd_chan = container_of(work, struct sphcs_cmd_chan, work);

	if (cmd_chan->protocol_id < 256) { //for context
		drain_workqueue(cmd_chan->wq_exec);
		destroy_workqueue(cmd_chan->wq_exec);
	}
	drain_workqueue(cmd_chan->wq);
	destroy_workqueue(cmd_chan->wq);
	sphcs_destroy_response_queue(g_the_sphcs, cmd_chan->respq);

	for (i = 0; i < NNP_IPC_MAX_CHANNEL_RINGBUFS; i++) {
		sphcs_host_rb_init(&cmd_chan->h2c_rb[i], NULL, 0);
		sphcs_host_rb_init(&cmd_chan->c2h_rb[i], NULL, 0);
	}

	sphcs_send_event_report(g_the_sphcs,
				NNP_IPC_CHANNEL_DESTROYED,
				0,
				NULL,
				-1,
				cmd_chan->protocol_id);

	kfree(cmd_chan);
}

static void sched_cmd_chan_release(struct kref *kref)
{
	struct sphcs_cmd_chan *cmd_chan;

	cmd_chan = container_of(kref, struct sphcs_cmd_chan, ref);
	INIT_WORK(&cmd_chan->work, cmd_chan_release);
	queue_work(system_wq, &cmd_chan->work);
}

int is_cmd_chan_ptr(void *ptr)
{
	struct sphcs_cmd_chan *cmd_chan = (struct sphcs_cmd_chan *)ptr;

	return (ptr != NULL && cmd_chan->magic == sphcs_cmd_chan_create);
}

void sphcs_cmd_chan_get(struct sphcs_cmd_chan *cmd_chan)
{
	int ret;

	ret = kref_get_unless_zero(&cmd_chan->ref);
	NNP_ASSERT(ret != 0);
}

int sphcs_cmd_chan_put(struct sphcs_cmd_chan *cmd_chan)
{
	return kref_put(&cmd_chan->ref, sched_cmd_chan_release);
}

void sphcs_cmd_chan_update_cmd_head(struct sphcs_cmd_chan *chan, uint16_t rb_id, uint32_t size)
{
	union c2h_ChanRingBufUpdate cmd;

	if (rb_id < NNP_IPC_MAX_CHANNEL_RINGBUFS &&
	    chan->h2c_rb[rb_id].host_sgt.sgl) {
		cmd.opcode = NNP_IPC_C2H_OP_CHANNEL_RB_UPDATE;
		cmd.chan_id = chan->protocol_id;
		cmd.rb_id = rb_id;
		cmd.size = size;
		sphcs_msg_scheduler_queue_add_msg(chan->respq, (u64 *)&cmd.value, 1);
	}
}

static void sphcs_host_rb_init(struct sphcs_host_rb *rb,
			       struct sg_table      *host_sgt,
			       uint64_t              size)
{
	if (rb->host_sgt.sgl && (!host_sgt || host_sgt->sgl != rb->host_sgt.sgl)) {
		sg_free_table(&rb->host_sgt);
		memset(&rb->host_sgt, 0, sizeof(rb->host_sgt));
	}

	if (host_sgt)
		memcpy(&rb->host_sgt, host_sgt, sizeof(struct sg_table));

	rb->size = (uint32_t)size;
	rb->head = 0;
	rb->tail = 0;
	rb->is_full = false;
	rb->disconnected = false;
	init_waitqueue_head(&rb->waitq);
	spin_lock_init(&rb->lock_bh);
}

dma_addr_t host_rb_get_addr(struct    sphcs_host_rb *rb,
			    uint32_t  offset,
			    uint32_t *out_cont_size)
{
	struct scatterlist *sgl = rb->host_sgt.sgl;
	uint32_t curr_offset = 0;
	dma_addr_t ret = 0;

	while (sgl &&
	       curr_offset + sgl->length <= offset) {
		curr_offset += sgl->length;
		sgl = sg_next(sgl);
	}

	if (sgl != NULL) {
		ret = sgl->dma_address + (offset - curr_offset);
		*out_cont_size = sgl->length - (offset - curr_offset);
	}

	return ret;
}

int host_rb_get_addr_range(struct    sphcs_host_rb *rb,
			   uint32_t  offset,
			   uint32_t  size,
			   uint32_t  array_size,
			   dma_addr_t *addr_array,
			   uint32_t   *size_array,
			   uint32_t   *out_left)
{
	struct scatterlist *sgl = rb->host_sgt.sgl;
	uint32_t curr_offset = 0;
	uint32_t idx = 0;
	uint32_t sz = 0;
	uint32_t left = size;
	bool allow_cyc = true;

	if (array_size < 1)
		return -EINVAL;

	while (sgl &&
	       curr_offset + sgl->length <= offset) {
		curr_offset += sgl->length;
		sgl = sg_next(sgl);
	}

	while (sgl &&
	       left > 0 &&
	       idx < array_size) {
		sz = sgl->length - (offset - curr_offset);
		addr_array[idx] = sgl->dma_address + (offset - curr_offset);
		size_array[idx] = sz > left ? left : sz;
		offset = curr_offset = 0;
		left -= size_array[idx];
		idx++;
		sgl = sg_next(sgl);

		if (!sgl && left > 0 && idx < array_size && allow_cyc) {
			sgl = rb->host_sgt.sgl;
			allow_cyc = false;
		}
	}

	*out_left = left;

	return idx;
}

int host_rb_wait_free_space(struct sphcs_host_rb *rb,
			    uint32_t              size,
			    uint32_t              array_size,
			    dma_addr_t           *addr_array,
			    uint32_t             *size_array)
{
	int ret;
	u32 left = 0;
	int n;

	ret = wait_event_interruptible(rb->waitq,
				       host_rb_free_bytes(rb) >= size || rb->disconnected);
	if (ret != 0)
		return -EINTR;

	if (rb->disconnected)
		return -EFAULT;

	n = host_rb_get_addr_range(rb,
				   rb->tail,
				   size,
				   array_size,
				   addr_array,
				   size_array,
				   &left);

	if (left != 0)
		return -EFAULT;

	return n;
}

void host_rb_update_free_space(struct sphcs_host_rb *rb,
			       uint32_t              size)
{
	NNP_SPIN_LOCK_BH(&rb->lock_bh);
	rb->tail = (rb->tail + size) % rb->size;
	if (rb->tail == rb->head)
		rb->is_full = true;
	NNP_SPIN_UNLOCK_BH(&rb->lock_bh);
}

int host_rb_get_avail_space(struct sphcs_host_rb *rb,
			    uint32_t              size,
			    uint32_t              array_size,
			    dma_addr_t           *addr_array,
			    uint32_t             *size_addr)
{
	u32 avail = host_rb_avail_bytes(rb);
	u32 left = 0;
	int n;

	if (avail < size)
		return -EBUSY;

	n = host_rb_get_addr_range(rb,
				   rb->head,
				   size,
				   array_size,
				   addr_array,
				   size_addr,
				   &left);

	if (left != 0)
		return -EFAULT;

	return n;
}

void host_rb_update_avail_space(struct sphcs_host_rb *rb,
				uint32_t              size)
{
	NNP_SPIN_LOCK_BH(&rb->lock_bh);
	rb->head = (rb->head + size) % rb->size;
	rb->is_full = false;
	NNP_SPIN_UNLOCK_BH(&rb->lock_bh);
	wake_up_all(&rb->waitq);
}

struct channel_rb_op_work {
	struct work_struct  work;
	struct sphcs_cmd_chan *chan;
	union h2c_channel_data_ringbuf_op cmd;
};

static void rb_hostres_pagetable_complete_cb(void                  *cb_ctx,
					     int                    status,
					     struct sg_table       *host_sgt,
					     uint64_t               total_size)
{
	struct channel_rb_op_work *op = (struct channel_rb_op_work *)cb_ctx;

	if (status == 0) {
		if (op->cmd.h2c)
			sphcs_host_rb_init(&op->chan->h2c_rb[op->cmd.rb_id],
					   host_sgt,
					   total_size);
		else
			sphcs_host_rb_init(&op->chan->c2h_rb[op->cmd.rb_id],
					   host_sgt,
					   total_size);

		sphcs_send_event_report_ext(g_the_sphcs,
					    NNP_IPC_CHANNEL_SET_RB_SUCCESS,
					    0,
					    NULL,
					    -1,
					    op->cmd.chan_id,
					    op->cmd.rb_id);
	} else {
		sphcs_send_event_report_ext(g_the_sphcs,
					    NNP_IPC_CHANNEL_SET_RB_FAILED,
					    status,
					    NULL,
					    -1,
					    op->cmd.chan_id,
					    op->cmd.rb_id);
	}

	sphcs_cmd_chan_put(op->chan);
	kfree(op);
}

static void channel_rb_op_work_handler(struct work_struct *work)
{
	struct channel_rb_op_work *op = container_of(work,
						     struct channel_rb_op_work,
						     work);
	struct sphcs *sphcs = g_the_sphcs;
	struct sphcs_cmd_chan *chan = op->chan;
	int ret;


	if (op->cmd.destroy) {
		if (op->cmd.h2c && chan->h2c_rb[op->cmd.rb_id].host_sgt.sgl != NULL)
			sphcs_host_rb_init(&chan->h2c_rb[op->cmd.rb_id], NULL, 0);
		else if (!op->cmd.h2c && chan->c2h_rb[op->cmd.rb_id].host_sgt.sgl != NULL)
			sphcs_host_rb_init(&chan->c2h_rb[op->cmd.rb_id], NULL, 0);

		sphcs_send_event_report_ext(sphcs,
					    NNP_IPC_CHANNEL_SET_RB_SUCCESS,
					    0,
					    NULL,
					    -1,
					    op->cmd.chan_id,
					    op->cmd.rb_id);
	} else {
		ret = sphcs_retrieve_hostres_pagetable(NNP_IPC_DMA_PFN_TO_ADDR(op->cmd.host_ptr),
						       rb_hostres_pagetable_complete_cb,
						       op);
		if (ret != 0) {
			sphcs_send_event_report_ext(sphcs,
						    NNP_IPC_CHANNEL_SET_RB_FAILED,
						    NNP_IPC_NO_MEMORY,
						    NULL,
						    -1,
						    op->cmd.chan_id,
						    op->cmd.rb_id);
		} else {
			/* started to retrieve pagetable from host */
			return;
		}
	}

	sphcs_cmd_chan_put(op->chan);
	kfree(op);
}

void IPC_OPCODE_HANDLER(CHANNEL_RB_OP)(
			struct sphcs        *sphcs,
			union h2c_channel_data_ringbuf_op *cmd)
{
	struct channel_rb_op_work *work;

	if (cmd->rb_id > NNP_IPC_MAX_CHANNEL_RINGBUFS) {
		sphcs_send_event_report_ext(sphcs,
					    NNP_IPC_CHANNEL_SET_RB_FAILED,
					    NNP_IPC_NO_SUCH_CHANNEL,
					    NULL,
					    -1,
					    cmd->chan_id,
					    cmd->rb_id);
		return;
	}

	work = kzalloc(sizeof(*work), GFP_NOWAIT);
	if (unlikely(work == NULL)) {
		sphcs_send_event_report_ext(sphcs,
					    NNP_IPC_CHANNEL_SET_RB_FAILED,
					    NNP_IPC_NO_MEMORY,
					    NULL,
					    -1,
					    cmd->chan_id,
					    cmd->rb_id);
		return;
	}

	work->chan = sphcs_find_channel(sphcs, cmd->chan_id);
	if (unlikely(work->chan == NULL)) {
		sphcs_send_event_report_ext(sphcs,
					    NNP_IPC_CHANNEL_SET_RB_FAILED,
					    NNP_IPC_NO_SUCH_CHANNEL,
					    NULL,
					    -1,
					    cmd->chan_id,
					    cmd->rb_id);
		kfree(work);
		return;
	}


	work->cmd.value = cmd->value;
	INIT_WORK(&work->work, channel_rb_op_work_handler);
	queue_work(work->chan->wq, &work->work);
}

void IPC_OPCODE_HANDLER(CHANNEL_RB_UPDATE)(
			struct sphcs        *sphcs,
			union h2c_ChanRingBufUpdate *cmd)
{
	struct sphcs_cmd_chan *chan;

	chan = sphcs_find_channel(sphcs, cmd->chan_id);
	if (unlikely(chan == NULL))
		sph_log_err(GENERAL_LOG, "Channel does not exist!!\n");
	else {
		host_rb_update_avail_space(&chan->c2h_rb[cmd->rb_id], cmd->size);
		sphcs_cmd_chan_put(chan);
	}
}

struct sphcs_hostres_map *sphcs_cmd_chan_find_hostres(struct sphcs_cmd_chan *chan, uint16_t protocol_id)
{
	struct sphcs_hostres_map *hostres;

	NNP_SPIN_LOCK_BH(&chan->lock_bh);
	hash_for_each_possible(chan->hostres_hash,
			       hostres,
			       hash_node,
			       protocol_id)
		if (hostres->protocol_id == protocol_id) {
			NNP_SPIN_UNLOCK_BH(&chan->lock_bh);
			return hostres;
		}
	NNP_SPIN_UNLOCK_BH(&chan->lock_bh);

	return NULL;
}

static int remove_hostres(struct sphcs_cmd_chan *chan, uint16_t protocol_id)
{
	struct sphcs_hostres_map *hostres;
	bool found = false;

	NNP_SPIN_LOCK_BH(&chan->lock_bh);
	hash_for_each_possible(chan->hostres_hash,
			       hostres,
			       hash_node,
			       protocol_id)
		if (hostres->protocol_id == protocol_id) {
			found = true;
			hash_del(&hostres->hash_node);
			break;
		}
	NNP_SPIN_UNLOCK_BH(&chan->lock_bh);

	if (!found) {
		sph_log_err(GENERAL_LOG, "Failed to unmap hostres %d\n", protocol_id);
		return -ENXIO;
	}

	sg_free_table(&hostres->host_sgt);
	kfree(hostres);

	return 0;
}

struct channel_hostres_op_work {
	struct work_struct  work;
	struct sphcs_cmd_chan *chan;
	union h2c_channel_hostres_op cmd;
};

static void hostres_pagetable_complete_cb(void                  *cb_ctx,
					  int                    status,
					  struct sg_table       *host_sgt,
					  uint64_t               total_size)
{
	struct channel_hostres_op_work *op = (struct channel_hostres_op_work *)cb_ctx;
	struct sphcs_hostres_map *hostres;

	if (status == 0) {
		hostres = kzalloc(sizeof(*hostres), GFP_KERNEL);
		if (!hostres) {
			sphcs_send_event_report_ext(g_the_sphcs,
						    NNP_IPC_CHANNEL_MAP_HOSTRES_FAILED,
						    NNP_IPC_NO_MEMORY,
						    NULL,
						    -1,
						    op->cmd.chan_id,
						    op->cmd.hostres_id);
			sg_free_table(host_sgt);
			goto done;
		}

		memcpy(&hostres->host_sgt, host_sgt, sizeof(struct sg_table));
		hostres->protocol_id = op->cmd.hostres_id;
		hostres->size = total_size;

		NNP_SPIN_LOCK_BH(&op->chan->lock_bh);
		hash_add(op->chan->hostres_hash,
			 &hostres->hash_node,
			 hostres->protocol_id);
		NNP_SPIN_UNLOCK_BH(&op->chan->lock_bh);

		sphcs_send_event_report_ext(g_the_sphcs,
					    NNP_IPC_CHANNEL_MAP_HOSTRES_SUCCESS,
					    0,
					    NULL,
					    -1,
					    op->cmd.chan_id,
					    op->cmd.hostres_id);
	} else {
		sphcs_send_event_report_ext(g_the_sphcs,
					    NNP_IPC_CHANNEL_MAP_HOSTRES_FAILED,
					    status,
					    NULL,
					    -1,
					    op->cmd.chan_id,
					    op->cmd.hostres_id);
	}

done:
	sphcs_cmd_chan_put(op->chan);
	kfree(op);
}

static void channel_hostres_op_work_handler(struct work_struct *work)
{
	struct channel_hostres_op_work *op = container_of(work,
							  struct channel_hostres_op_work,
							  work);
	struct sphcs *sphcs = g_the_sphcs;
	struct sphcs_cmd_chan *chan = op->chan;
	int ret;


	if (op->cmd.unmap) {
		if (remove_hostres(chan, op->cmd.hostres_id) == 0)
			sphcs_send_event_report_ext(sphcs,
						    NNP_IPC_CHANNEL_UNMAP_HOSTRES_SUCCESS,
						    0,
						    NULL,
						    -1,
						    op->cmd.chan_id,
						    op->cmd.hostres_id);
		else
			sphcs_send_event_report_ext(sphcs,
						    NNP_IPC_CHANNEL_UNMAP_HOSTRES_FAILED,
						    NNP_IPC_NO_SUCH_HOSTRES,
						    NULL,
						    -1,
						    op->cmd.chan_id,
						    op->cmd.hostres_id);
	} else {
		ret = sphcs_retrieve_hostres_pagetable(NNP_IPC_DMA_PFN_TO_ADDR(op->cmd.host_ptr),
						       hostres_pagetable_complete_cb,
						       op);
		if (ret != 0) {
			sphcs_send_event_report_ext(sphcs,
						    NNP_IPC_CHANNEL_MAP_HOSTRES_FAILED,
						    NNP_IPC_NO_MEMORY,
						    NULL,
						    -1,
						    op->cmd.chan_id,
						    op->cmd.hostres_id);
		} else {
			/* started to retrieve pagetable from host */
			return;
		}
	}

	sphcs_cmd_chan_put(op->chan);
	kfree(op);
}

void IPC_OPCODE_HANDLER(CHANNEL_HOSTRES_OP)(
			struct sphcs               *sphcs,
			union h2c_channel_hostres_op *cmd)
{
	struct channel_hostres_op_work *work;

	work = kzalloc(sizeof(*work), GFP_NOWAIT);
	if (unlikely(work == NULL)) {
		sphcs_send_event_report_ext(sphcs,
					    cmd->unmap ? NNP_IPC_CHANNEL_UNMAP_HOSTRES_FAILED :
							 NNP_IPC_CHANNEL_MAP_HOSTRES_FAILED,
					    NNP_IPC_NO_MEMORY,
					    NULL,
					    -1,
					    cmd->chan_id,
					    cmd->hostres_id);
		return;
	}

	work->chan = sphcs_find_channel(sphcs, cmd->chan_id);
	if (unlikely(work->chan == NULL)) {
		sphcs_send_event_report_ext(sphcs,
					    cmd->unmap ? NNP_IPC_CHANNEL_UNMAP_HOSTRES_FAILED :
							 NNP_IPC_CHANNEL_MAP_HOSTRES_FAILED,
					    NNP_IPC_NO_SUCH_CHANNEL,
					    NULL,
					    -1,
					    cmd->chan_id,
					    cmd->hostres_id);
		kfree(work);
		return;
	}


	memcpy(work->cmd.value, cmd->value, sizeof(cmd->value));
	INIT_WORK(&work->work, channel_hostres_op_work_handler);
	queue_work(work->chan->wq, &work->work);
}
