/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#include "sphcs_ult.h"
#include "ipc_chan_protocol_ult.h"
#include "sphcs_cs.h"
#include "sph_log.h"
#include "nnp_time.h"
#include "sphcs_dma_sched.h"
#include "nnp_boot_defs.h"
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/interrupt.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>
#include <linux/scatterlist.h>
#include <linux/atomic.h>
#include "sphcs_cmd_chan.h"


struct ult_cmd_entry {
	u64              msg;
	struct list_head node;
};

struct workqueue_struct *g_ult_wq;
static struct list_head g_pending_ult_commands;
static spinlock_t      g_pending_ult_commands_lock;
static struct work_struct g_pending_ult_commands_work;
static uint32_t         g_num_pending_ult_commands;

static int ult2_process_host_hwQ_msg(struct sphcs *sphcs, struct sphcs_cmd_chan *chan, u64 *msg, u32 size)
{
	union ULT2HwQMsg *cmd = (union ULT2HwQMsg *)msg;

	/* write response message in HW Queue (shared memory)
	 * meantime: responses are the request ultMsgId * 2
	 */
	cmd->opcode = C2H_OPCODE_NAME(ULT2_OP);
	cmd->ultMsgId = cmd->ultMsgId << 1;

	sph_log_debug(GENERAL_LOG, "Send reply messgage to host, msg_id %d\n", cmd->ultMsgId);

	sphcs_msg_scheduler_queue_add_msg(chan->respq, &cmd->value, 1);

	return 0;
}

struct ult2_dma_ping_dma_data {
	int state;
	int size;
	int seq;
	int is_last;
	union ULT2DmaPingMsg cmd;
	dma_addr_t dstAddr;
	page_handle dstPageHandle;
	void *dstPtr;
};

static int ult2_dma_ping_complete_callback(struct sphcs *sphcs, void *ctx, const void *user_data, int status, u32 timeUS)
{
	struct ult2_dma_ping_dma_data *dma_data = (struct ult2_dma_ping_dma_data *)user_data;
	struct sphcs_cmd_chan *chan;
	int nchunks, i;
	dma_addr_t chunk_addr[2];
	uint32_t chunk_size[2];
	struct sphcs_host_rb *resp_data_rb;
	struct sphcs_host_rb *cmd_data_rb;
	uint32_t off;

	chan = sphcs_find_channel(sphcs, dma_data->cmd.channelID);
	if (!chan)
		return -EINVAL;

	resp_data_rb = &chan->c2h_rb[dma_data->cmd.rbID];
	cmd_data_rb = &chan->h2c_rb[dma_data->cmd.rbID];

	if (dma_data->state == 0) {

		if (dma_data->is_last)
			sphcs_cmd_chan_update_cmd_head(chan, dma_data->cmd.rbID, dma_data->cmd.size + 1);

		nchunks = host_rb_wait_free_space(resp_data_rb,
						  dma_data->size,
						  2,
						  chunk_addr,
						  chunk_size);

		off = 0;

		for (i = 0; i < nchunks; i++) {
			dma_data->state = 1;
			dma_data->size = chunk_size[i];
			dma_data->seq = i;
			if (dma_data->is_last)
				dma_data->is_last = (i == nchunks - 1) ? 1 : 0;

			sphcs_dma_sched_start_xfer_single(sphcs->dmaSched,
							  &chan->c2h_dma_desc,
							  dma_data->dstAddr + off,
							  chunk_addr[i],
							  chunk_size[i],
							  ult2_dma_ping_complete_callback,
							  NULL,
							  dma_data,
							  sizeof(*dma_data));

			host_rb_update_free_space(resp_data_rb, chunk_size[i]);
			off += chunk_size[i];
		}

	} else if (dma_data->state == 1) {
		if (dma_data->is_last) {
			sphcs_msg_scheduler_queue_add_msg(chan->respq, (u64 *)&dma_data->cmd.value, 1);
			dma_page_pool_set_page_free(sphcs->dma_page_pool, dma_data->dstPageHandle);
		}
	}

	sphcs_cmd_chan_put(chan);

	return 0;
}

static int ult2_process_dma_ping(struct sphcs *sphcs, struct sphcs_cmd_chan *chan, u64 *msg, u32 size)
{
	union ULT2DmaPingMsg *cmd = (union ULT2DmaPingMsg *)msg;
	struct sphcs_host_rb *cmd_data_rb = &chan->h2c_rb[cmd->rbID];
	dma_addr_t chunk_addr[2];
	uint32_t   chunk_size[2];
	int   nchunks, i, rc;
	uint32_t off;
	struct ult2_dma_ping_dma_data dma_data;
	uint32_t packet_size = cmd->size + 1;

	/*
	 * advance ringbuf tail by cmd->size bytes, to sync with host side tail
	 * value
	 */
	host_rb_update_free_space(cmd_data_rb, packet_size);

	nchunks = host_rb_get_avail_space(cmd_data_rb,
					  packet_size,
					  2,
					  chunk_addr,
					  chunk_size);

	if (nchunks < 0) {
		sph_log_err(GENERAL_LOG, "host_rb_get_avail_space failed %d\n", nchunks);
		return -1;
	}

	rc = dma_page_pool_get_free_page(sphcs->dma_page_pool,
					 &dma_data.dstPageHandle,
					 &dma_data.dstPtr,
					 &dma_data.dstAddr);
	if (rc) {
		sph_log_err(GENERAL_LOG, "Could not allocate free dma page\n");
		return -1;
	}

	off = 0;

	for (i = 0; i < nchunks; i++) {
		dma_data.state = 0;
		dma_data.size = chunk_size[i];
		dma_data.seq = i;
		dma_data.is_last = (i == nchunks - 1) ? 1 : 0;
		memcpy(&dma_data.cmd, cmd, sizeof(*cmd));

		rc = sphcs_dma_sched_start_xfer_single(sphcs->dmaSched,
						       &chan->h2c_dma_desc,
						       chunk_addr[i],
						       dma_data.dstAddr + off,
						       chunk_size[i],
						       ult2_dma_ping_complete_callback,
						       NULL,
						       &dma_data,
						       sizeof(dma_data));
		if (rc)
			sph_log_err(GENERAL_LOG, "Failed to start dma xfer\n");

		off += chunk_size[i];
	}

	host_rb_update_avail_space(cmd_data_rb, packet_size);

	return 0;
}

static sphcs_chan_command_handler s_dispatch2[NNP_IPC_ULT2_NUM_OPCODES] = {
	ult2_process_host_hwQ_msg,  /* NNP_IPC_ULT2_OP_CARD_HWQ_MSG */
	ult2_process_dma_ping, /* NNP_IPC_ULT2_OP_DMA_PING */
};

/*
 * Description:  ULT messages dispatcher, Called to process a
 * NNP_IPC_H2C_OP_ULT_OP message receviced from host.
 * identify ULT message sub opcode and call the appropriate handler to handle the message.
 */
static int sphcs_ult_process_command(struct sphcs *sphcs, u64 *msg, u32 size)
{
	int opcode = ((union ult2_message *)msg)->opcode;

	if (opcode == H2C_OPCODE_NAME(ULT2_OP)) {
		int ultOp = ((union ult2_message *)msg)->ultOpcode;
		int chanID = ((union ult2_message *)msg)->channelID;
		struct sphcs_cmd_chan *chan;
		int ret;

		if (ultOp >= NNP_IPC_ULT2_NUM_OPCODES || NULL == s_dispatch2[ultOp]) {
			sph_log_err(GENERAL_LOG, "Unsupported ult2 h2c command opcode=%d\n", ultOp);
			return 0;
		}

		chan = sphcs_find_channel(sphcs, chanID);
		if (!chan) {
			sph_log_err(GENERAL_LOG, "Channel not found opcode=%d chanID=%d\n", ultOp, chanID);
			return 0;
		}

		ret = s_dispatch2[ultOp](sphcs, chan, msg, size);

		sphcs_cmd_chan_put(chan);

		return ret;
	}

	return -EINVAL;
}

static void add_pending_ult_command(struct sphcs      *sphcs,
				    u64                msg)
{
	struct ult_cmd_entry *entry;

	entry = kzalloc(sizeof(*entry), GFP_NOWAIT);
	if (!entry) {
		sph_log_err(GENERAL_LOG, "No memory for pending command entry!!!\n");
		return;
	}

	entry->msg = msg;
	INIT_LIST_HEAD(&entry->node);

	NNP_SPIN_LOCK(&g_pending_ult_commands_lock);

	list_add_tail(&entry->node, &g_pending_ult_commands);
	g_num_pending_ult_commands++;

	if (g_num_pending_ult_commands == 1)
		queue_work(g_ult_wq, &g_pending_ult_commands_work);

	NNP_SPIN_UNLOCK(&g_pending_ult_commands_lock);
}

/*
 * Description: interrupt main thread,called upon receiving ult message(opcode
 * NNP_IPC_H2C_OP_ULT_OP) from host.
 * add message to workqueue, to be processed at some time by the workqueue thread.
 */
void IPC_OPCODE_HANDLER(ULT2_OP)(struct sphcs      *sphcs,
				 union ult2_message *msg)
{
	add_pending_ult_command(sphcs, msg->value);
}

/*
 * Description: workqueue work function - process pending messages received from hwQ
 */
static void sphcs_ult_process_pending(struct work_struct *work)
{
	struct ult_cmd_entry *entry;
	int rc;

	NNP_SPIN_LOCK(&g_pending_ult_commands_lock);
	while (g_num_pending_ult_commands) {
	entry = list_first_entry(&g_pending_ult_commands,
				 struct ult_cmd_entry,
				 node);
	NNP_SPIN_UNLOCK(&g_pending_ult_commands_lock);

	rc = sphcs_ult_process_command(g_the_sphcs, &entry->msg, 1);
	if (rc)
		sph_log_err(GENERAL_LOG, "FATAL: process ult message failed rc=%d\n", rc);

	NNP_SPIN_LOCK(&g_pending_ult_commands_lock);
	list_del(&entry->node);
	kfree(entry);
	g_num_pending_ult_commands--;
	}
	NNP_SPIN_UNLOCK(&g_pending_ult_commands_lock);
}

/*
 * Description: init work queue stuff.
 */
int sphcs_init_ult_module(void)
{
	if (!g_ult_wq)
		g_ult_wq = create_workqueue("ult_wq");

	INIT_LIST_HEAD(&g_pending_ult_commands);
	spin_lock_init(&g_pending_ult_commands_lock);
	INIT_WORK(&g_pending_ult_commands_work, sphcs_ult_process_pending);
	g_num_pending_ult_commands = 0;

	sph_log_info(GENERAL_LOG, "ult module init done\n");

	return 0;
}

/*
 * Description: free work queue stuff.
 */
void sphcs_fini_ult_module(void)
{
	if (g_ult_wq)
		destroy_workqueue(g_ult_wq);
}
