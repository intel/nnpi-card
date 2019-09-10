/********************************************
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#include "inf_subresload.h"
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/scatterlist.h>
#include <linux/list_sort.h>
#include "sphcs_cs.h"
#include "sphcs_inf.h"
#include "sph_log.h"
#include "ipc_protocol.h"
#include "inf_context.h"
#include "sphcs_trace.h"


struct subresload_dma_command_data {
	uint32_t           host_pool_index;
	struct inf_subres_load_session *session;
	uint64_t           lli_offset;
	uint16_t           ctxID;
};

struct subres_lli_space_node {
	uint64_t offset;
	uint64_t size;

	struct list_head node;
};

static void lli_remove_space(struct inf_subres_load_session *session,
			     uint64_t offset);

static struct subres_lli_space_node *lli_find_space(struct inf_subres_load_session *session,
						    uint64_t size);

int complete_subresload(struct sphcs *sphcs, void *ctx, const void *user_data, int status, u32 xferTimeUS)
{
	struct subresload_dma_command_data *dma_req_data =  (struct subresload_dma_command_data *)user_data;
	union c2h_SubResourceLoadReply msg;

	u32 ctxId = dma_req_data->ctxID;
	u32 sessionId = dma_req_data->session->sessionID;
	u8 host_pool_idx = dma_req_data->host_pool_index;
	u64 dma_addr = dma_req_data->session->lli_addr + dma_req_data->lli_offset;

	if (unlikely(status == SPHCS_DMA_STATUS_FAILED))
		sph_log_err(EXECUTE_COMMAND_LOG, "subresload dma operation FAILED\n");

	lli_remove_space(dma_req_data->session, dma_req_data->lli_offset);

	msg.value = 0;
	msg.opcode = SPH_IPC_C2H_OP_INF_SUBRES_LOAD_REPLY;
	msg.contextID = ctxId;
	msg.sessionID = sessionId;
	msg.host_pool_index = host_pool_idx;

	DO_TRACE(trace_inf_net_subres(ctxId, sessionId, -1, host_pool_idx,
			-1, dma_addr, SPH_TRACE_OP_STATUS_COMPLETE));

	sphcs_msg_scheduler_queue_add_msg(g_the_sphcs->public_respq, &msg.value, 1);


	return 0;
}

enum event_val inf_subresload_execute(struct inf_context *context, union h2c_SubResourceLoadOp *cmd)
{
	struct subresload_dma_command_data dma_req_data;
	struct sg_table src_sgt;
	struct sg_table *res_dst_sgt;
	int res;
	uint64_t data_size;
	uint32_t lli_size;
	uint64_t transfer_size;
	struct subres_lli_space_node *lli_space;
	struct inf_subres_load_session *session = inf_context_get_subres_load_session(context, cmd->sessionID);

	if (unlikely(session == NULL)) {
		sph_log_err(EXECUTE_COMMAND_LOG, "FATAL: %u failed to find session id %u\n", __LINE__, cmd->sessionID);
		return SPH_IPC_DMA_ERROR;
	}

	dma_req_data.ctxID = context->protocolID;
	dma_req_data.host_pool_index = cmd->host_pool_index;
	dma_req_data.session = session;

	data_size = cmd->n_pages * SPH_PAGE_SIZE + cmd->byte_size;
	res = sg_alloc_table(&src_sgt, 1, GFP_KERNEL);
	if (unlikely(res < 0)) {
		sph_log_err(EXECUTE_COMMAND_LOG, "FATAL: %u err=%d failed to allocate sg_table\n", __LINE__, res);
		return SPH_IPC_NO_MEMORY;
	}
	/* check if offset not bigger than device resource size */
	if (cmd->res_offset >= session->devres->size) {
		sph_log_err(EXECUTE_COMMAND_LOG, "Failed to execute subres, offset %llu exceeds devres size %llu\n", cmd->res_offset, session->devres->size);
		return SPH_IPC_DMA_ERROR;
	}

	src_sgt.sgl->dma_address = SPH_IPC_DMA_PFN_TO_ADDR(cmd->host_pool_dma_address);
	src_sgt.sgl->length = data_size;

	res_dst_sgt = session->devres->dma_map;
	lli_size = g_the_sphcs->hw_ops->dma.calc_lli_size(g_the_sphcs->hw_handle, &src_sgt, res_dst_sgt, cmd->res_offset);
	SPH_ASSERT(lli_size > 0);

	lli_space = lli_find_space(session, lli_size);
	while (lli_space == NULL) {
		wait_event_interruptible(session->lli_waitq,
					 session->lli_space_need_wake == 0);
		lli_space = lli_find_space(session, lli_size);
	}

	dma_req_data.lli_offset = lli_space->offset;
	transfer_size = g_the_sphcs->hw_ops->dma.gen_lli(g_the_sphcs->hw_handle, &src_sgt, res_dst_sgt, session->lli_buf + lli_space->offset, cmd->res_offset);
	SPH_ASSERT(transfer_size > 0);

	sg_free_table(&src_sgt);

	DO_TRACE(trace_inf_net_subres(cmd->contextID, cmd->sessionID, cmd->res_offset, cmd->host_pool_index,
			transfer_size, session->lli_addr + lli_space->offset, SPH_TRACE_OP_STATUS_START));

	sphcs_dma_sched_start_xfer(g_the_sphcs->dmaSched,
				   &g_dma_desc_h2c_normal,
				   session->lli_addr + lli_space->offset,
				   transfer_size,
				   complete_subresload,
				   NULL,
				   &dma_req_data,
				   sizeof(dma_req_data));

	return res;
}

int inf_subresload_create_session(struct inf_context *context, struct inf_devres *devres, union h2c_SubResourceLoadCreateRemoveSession *cmd)
{
	union c2h_SubResourceLoadCreateSessionReply msg;
	struct inf_subres_load_session *session;
	int ret;

	session = inf_context_create_subres_load_session(context, devres, cmd);
	if (unlikely(session == NULL)) {
		sph_log_err(CREATE_COMMAND_LOG, "FATAL: err=%u failed to create subres load session\n", SPH_IPC_ERROR_SUB_RESOURCE_LOAD_FAILED);
		return -ENOMEM;
	}

	//Send reply Msg to confirm session creation on card
	msg.value = 0;
	msg.opcode = SPH_IPC_C2H_OP_INF_SUBRES_LOAD_CREATE_REMOVE_SESSION_REPLY;
	msg.contextID = context->protocolID;
	msg.sessionID = session->sessionID;

	ret = sphcs_msg_scheduler_queue_add_msg(g_the_sphcs->public_respq, &msg.value, 1);

	return  ret;
}

void inf_subresload_delete_lli_space_list(struct inf_subres_load_session *session)
{
	struct subres_lli_space_node *lli_space;

	SPH_SPIN_LOCK(&session->lock);

	while (!list_empty(&session->lli_space_list)) {
		lli_space = list_first_entry(&session->lli_space_list, struct subres_lli_space_node, node);
		list_del(&lli_space->node);
		kfree(lli_space);
	}

	SPH_SPIN_UNLOCK(&session->lock);
}


static void lli_remove_space(struct inf_subres_load_session *session,
			     uint64_t offset)
{
	struct subres_lli_space_node *lli_space;

	SPH_SPIN_LOCK(&session->lock);

	list_for_each_entry(lli_space, &session->lli_space_list, node) {
		if (lli_space->offset == offset) {
			list_del(&lli_space->node);
			session->lli_space_need_wake = 0;
			SPH_SPIN_UNLOCK(&session->lock);
			kfree(lli_space);
			wake_up_all(&session->lli_waitq);
			return;
		}
	}

	SPH_SPIN_UNLOCK(&session->lock);
}


static int cmp_lli_space_node(void *priv, struct list_head *a, struct list_head *b)
{
	struct subres_lli_space_node *a_node = list_entry(a, struct subres_lli_space_node, node);
	struct subres_lli_space_node *b_node = list_entry(b, struct subres_lli_space_node, node);

	if (a_node->offset >= b_node->offset)
		return 1;

	return -1;
}

static struct subres_lli_space_node *lli_find_space(struct inf_subres_load_session *session,
						    uint64_t size)
{
	struct subres_lli_space_node *lli_space, *lli_space_iter;
	uint64_t head_offset = 0;

	if (size > session->lli_size) {
		sph_log_err(EXECUTE_COMMAND_LOG, "ERROR: can't handle size bigger then SPH_PAGE_SIZE\n");
		return NULL;
	}

	lli_space = kzalloc(sizeof(*lli_space), GFP_KERNEL);
	lli_space->size = size;

	SPH_SPIN_LOCK(&session->lock);

	if (list_empty(&session->lli_space_list)) {
		lli_space->offset = 0;
		list_add_tail(&lli_space->node, &session->lli_space_list);
		SPH_SPIN_UNLOCK(&session->lock);
		return lli_space;
	}

	lli_space_iter = list_first_entry(&session->lli_space_list, struct subres_lli_space_node, node);
	while (&lli_space_iter->node != &session->lli_space_list) {
		if (head_offset + size <= lli_space_iter->offset) {
			lli_space->offset = head_offset;
			list_add_tail(&lli_space->node, &session->lli_space_list);
			list_sort(NULL, &session->lli_space_list, cmp_lli_space_node);
			SPH_SPIN_UNLOCK(&session->lock);
			return lli_space;
		}
		head_offset = lli_space_iter->offset + lli_space_iter->size;
		if (head_offset + size > session->lli_size)
			goto free_lli_space;

		lli_space_iter = list_next_entry(lli_space_iter, node);
	}

free_lli_space:
	session->lli_space_need_wake = 1;
	SPH_SPIN_UNLOCK(&session->lock);
	kfree(lli_space);
	return NULL;
}


