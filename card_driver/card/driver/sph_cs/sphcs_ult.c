/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#include "sphcs_ult.h"
#include "ipc_protocol_ult.h"
#include "sphcs_cs.h"
#include "sph_log.h"
#include "sph_time.h"
#include "sphcs_dma_sched.h"
#include "sph_boot_defs.h"
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
static bool                        g_ult_bop_testing;
static u64                         g_ult_bop_descriptor_addr;
static u32                         g_ult_bop_image_size;

#define SIZE_OF_SG_CHUNCK 64

enum sphcs_sgTable_create_mode_inside {
	SG_TABLE_BIG_CHUNCK = 1,
	SG_TABLE_NON_CONTINUOUS
};

struct sphcs_ult_dma_req_state {
	int state;
	u32 dmaSize;
	dma_addr_t srcAddr;
	dma_addr_t dstAddr;
	page_handle dstPageHandle;
	void *dstPtr;
	dma_addr_t lliAddr;
	u32 lliSize;
	void *lliPtr;
	enum dma_ult_mode dma_ult_mode;
	bool toCard;
	u32 timeUS;
};

struct sphcs_ult_dma_bandwidth_req_state {
	int state;
	u32 dmaSize;
	dma_addr_t srcAddr;
	dma_addr_t dstAddr;
	dma_addr_t lliAddr;
	u32 lliSize;
	uint64_t transfer_size;
	void *lliPtr;
	atomic_t repeat_count;
	struct sphcs_dma_desc dma_desc;
	u32 dma_timeUS;
	u32 cpu_timeUS;
	union ult_dma_bandwidth_request_info *req_info;
	atomic_t *completed_tests;
	wait_queue_head_t *dma_test_completion_wait;
};

struct ult_dma_node {
	struct list_head node;
	dma_addr_t dma_phys;
	void *vptr;
	u32   dma_size;
};

static int process_dma_sg_command(struct sphcs *sphcs,
				  struct sphcs_ult_dma_req_state *dmaState,
				  const struct sphcs_dma_desc    *dmaDesc);

static int sphcs_ult_dma_scatterGather_complete_callback(struct sphcs *sphcs, void *ctx, const void *user_data, int status, u32 timeUS)
{
	struct sphcs_ult_dma_req_state *dmaState = (struct sphcs_ult_dma_req_state *)ctx;

	sph_log_debug(GENERAL_LOG, "Got dma completion dmaState=%p state=%d status=0x%x\n", dmaState, dmaState->state, status);

	if (dmaState->state == 0) {
		struct ult_dma_single_packet_header *packet_header = (struct ult_dma_single_packet_header *)dmaState->dstPtr;
		dma_addr_t host_dst_addr = SPH_IPC_DMA_PFN_TO_ADDR(packet_header->dstHostDmaPfn);

		dmaState->srcAddr = dmaState->dstAddr;
		dmaState->dstAddr = host_dst_addr;

		packet_header->h2cDmaTime = timeUS;

		sph_log_debug(GENERAL_LOG, "Sending data back to host\n");
		dmaState->state = 1;
		dmaState->toCard = false;
		process_dma_sg_command(sphcs,
				       dmaState,
				       &g_dma_desc_c2h_low);
	} else if (dmaState->state == 1) {
		struct ult_dma_single_packet_header *packet_header = (struct ult_dma_single_packet_header *)dmaState->dstPtr;
		union c2h_ULTDMASingleMsgReply msg;

		msg.opcode = SPH_IPC_C2H_OP_ULT_OP;
		msg.ultOpcode = SPH_IPC_ULT_OP_DMA_SINGLE;
		msg.hostPageHandle = packet_header->hostPageHandle;
		msg.c2hDmaTime = timeUS;

		sph_log_debug(GENERAL_LOG, "Send done Reply DMASingle messgage C2H Time %d\n", timeUS);
		sphcs->hw_ops->write_mesg(sphcs->hw_handle, &msg.value, 1);

		dma_page_pool_set_page_free(sphcs->dma_page_pool, dmaState->dstPageHandle);
		if (dmaState->lliSize > 0)
			dma_free_coherent(sphcs->hw_device, dmaState->lliSize, dmaState->lliPtr, dmaState->lliAddr);
		kfree(dmaState);
	}
	return 0;
}

static int sphcs_ult_dma_single_with_polling_complete_callback(struct sphcs *sphcs,
		void *ctx,
		const void *user_data,
		int status,
		u32 timeUS)
{
	int dma_status;
	union c2h_ULTDMASingleMsgReply msg;
	u32 c2h_time_us;
	struct ult_dma_single_packet_header *packet_header;
	dma_addr_t host_dst_addr;

	struct sphcs_ult_dma_req_state *dmaState = (struct sphcs_ult_dma_req_state *)ctx;

	sph_log_debug(GENERAL_LOG, "Got dma completion status=0x%x\n", status);

	packet_header = (struct ult_dma_single_packet_header *)dmaState->dstPtr;
	host_dst_addr = SPH_IPC_DMA_PFN_TO_ADDR(packet_header->dstHostDmaPfn);

	packet_header->h2cDmaTime = timeUS;

	sphcs_dma_sched_stop_and_xfer(sphcs->dmaSched, dmaState->dstAddr, host_dst_addr, dmaState->dmaSize, &dma_status, &c2h_time_us);

	sph_log_info(GENERAL_LOG, "DMA status %d\n", dma_status);

	msg.opcode = SPH_IPC_C2H_OP_ULT_OP;
	msg.ultOpcode = SPH_IPC_ULT_OP_DMA_SINGLE;
	msg.hostPageHandle = packet_header->hostPageHandle;
	msg.c2hDmaTime = c2h_time_us;

	sph_log_info(GENERAL_LOG, "Send done Reply DMASingle messgage C2H Time %d\n", timeUS);

	sphcs_msg_scheduler_queue_add_msg(sphcs->public_respq, &msg.value, 1);

	dma_page_pool_set_page_free(sphcs->dma_page_pool, dmaState->dstPageHandle);
	kfree(dmaState);

	return 0;

}
static int sphcs_ult_dma_single_complete_callback(struct sphcs *sphcs, void *ctx, const void *user_data, int status, u32 timeUS)
{
	struct sphcs_ult_dma_req_state *dmaState = (struct sphcs_ult_dma_req_state *)ctx;

	sph_log_debug(GENERAL_LOG, "Got dma completion dmaState=%p state=%d status=0x%x\n", dmaState, dmaState->state, status);

	if (dmaState->state == 0) {
		struct ult_dma_single_packet_header *packet_header = (struct ult_dma_single_packet_header *)dmaState->dstPtr;
		dma_addr_t host_dst_addr = SPH_IPC_DMA_PFN_TO_ADDR(packet_header->dstHostDmaPfn);

		packet_header->h2cDmaTime = timeUS;

		sph_log_debug(GENERAL_LOG, "Sending data back to host\n");
		dmaState->state = 1;
		sphcs_dma_sched_start_xfer_single(sphcs->dmaSched,
						  &g_dma_desc_c2h_low,
						  dmaState->dstAddr,
						  host_dst_addr,
						  dmaState->dmaSize,
						  sphcs_ult_dma_single_complete_callback,
						  dmaState,
						  NULL,
						  0);
	} else if (dmaState->state == 1) {
		struct ult_dma_single_packet_header *packet_header = (struct ult_dma_single_packet_header *)dmaState->dstPtr;
		union c2h_ULTDMASingleMsgReply msg;

		msg.opcode = SPH_IPC_C2H_OP_ULT_OP;
		msg.ultOpcode = SPH_IPC_ULT_OP_DMA_SINGLE;
		msg.hostPageHandle = packet_header->hostPageHandle;
		msg.c2hDmaTime = timeUS;

		sph_log_debug(GENERAL_LOG, "Send done Reply DMASingle messgage C2H Time %d\n", timeUS);

		sphcs_msg_scheduler_queue_add_msg(sphcs->public_respq, &msg.value, 1);

		dma_page_pool_set_page_free(sphcs->dma_page_pool, dmaState->dstPageHandle);
		kfree(dmaState);
	}

	return 0;
}

/*
 * Description: handle HWQ messages from host.
 * process response id, and store it in Hw Queue, then interrupt host that response is ready.
 */
static int process_host_hwQ_msg(struct sphcs *sphcs, u64 *msg, u32 size)
{
	union ULTHwQMsg *cmd = (union ULTHwQMsg *)msg;

	/* write response message in HW Queue (shared memory)
	 * meantime: responses are the reuqest ultMsgId * 2
	 */
	cmd->opcode = SPH_IPC_C2H_OP_ULT_OP;
	cmd->ultMsgId = cmd->ultMsgId << 1;

	sph_log_debug(GENERAL_LOG, "Send reply messgage to host, msg_id %d\n", cmd->ultMsgId);

	sphcs_msg_scheduler_queue_add_msg(sphcs->public_respq, &cmd->value, 1);

	return 0;
}

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

static void createSGTable(dma_addr_t dmaAddress, u32 dmaSize, struct sg_table *sgt, u16 tableMode)
{
	int nents, i = 0;
	dma_addr_t addressOffset = 0;
	dma_addr_t dmaOffset = 0;
	uint64_t chunckSize = SIZE_OF_SG_CHUNCK;
	struct scatterlist *currentSgl = NULL;
	int sizeOfPacketHeader = sizeof(struct ult_dma_single_packet_header);
	int dataSize = dmaSize - sizeOfPacketHeader;

	if (tableMode & SG_TABLE_BIG_CHUNCK)
		chunckSize *= 2;

	if (tableMode & SG_TABLE_NON_CONTINUOUS) {
		addressOffset = SIZE_OF_SG_CHUNCK;
		nents = dataSize / (chunckSize + SIZE_OF_SG_CHUNCK);
	} else {
		nents = dataSize / chunckSize;
	}

	nents++; // add packet header copy
	sg_alloc_table(sgt, nents, GFP_KERNEL);
	currentSgl = sgt->sgl;
	currentSgl->length = sizeOfPacketHeader;
	currentSgl->dma_address = dmaAddress;
	dmaAddress += sizeOfPacketHeader;
	currentSgl = sg_next(currentSgl);
	for (i = 1; i < nents && currentSgl; i++) {
		currentSgl->length = chunckSize;
		currentSgl->dma_address = dmaAddress + dmaOffset;
		dmaOffset += chunckSize + addressOffset;
		currentSgl = sg_next(currentSgl);
	}
}


static int process_dma_sg_command(struct sphcs *sphcs,
				  struct sphcs_ult_dma_req_state *dmaState,
				  const struct sphcs_dma_desc    *dmaDesc)
{
	int lliSize = 0;
	struct sg_table srcSgt;
	struct sg_table dstSgt;
	enum sphcs_sgTable_create_mode_inside srcMode = 0;
	enum sphcs_sgTable_create_mode_inside dstMode = 0;
	uint64_t srcDmaSize = dmaState->dmaSize;
	uint64_t dstDmaSize = dmaState->dmaSize;
	uint64_t transfer_size;

	switch (dmaState->dma_ult_mode) {
	case DMA_MODE_SG_EQUAL_SIZE:
		break;
	case DMA_MODE_SG_SIZE_MISMATCH:
		srcDmaSize = srcDmaSize * 2;
		break;
	case DMA_MODE_SG_BIG_CHUNCK:
		dstMode = SG_TABLE_BIG_CHUNCK;
		break;
	case DMA_MODE_SG_SIZE_MISMATCH_BIG_CHUNCK:
		dstMode = SG_TABLE_BIG_CHUNCK;
		dstDmaSize = dstDmaSize * 2;
		break;
	case DMA_MODE_SG_EQUAL_SIZE_NON_CONTINUOUS:
		srcMode = SG_TABLE_NON_CONTINUOUS;
		dstMode = SG_TABLE_NON_CONTINUOUS;
		break;
	case DMA_MODE_SG_SIZE_MISMATCH_NON_CONTINUOUS:
		srcMode = SG_TABLE_NON_CONTINUOUS;
		dstMode = SG_TABLE_NON_CONTINUOUS;
		srcDmaSize = srcDmaSize * 2;
		break;
	case DMA_MODE_SG_BIG_CHUNCK_NON_CONTINUOUS:
		srcMode = SG_TABLE_NON_CONTINUOUS;
		dstMode = SG_TABLE_BIG_CHUNCK | SG_TABLE_NON_CONTINUOUS;
		break;
	case DMA_MODE_SG_SIZE_MISMATCH_BIG_CHUNCK_NON_CONTINUOUS:
		srcMode = SG_TABLE_NON_CONTINUOUS;
		dstMode = SG_TABLE_BIG_CHUNCK | SG_TABLE_NON_CONTINUOUS;
		dstDmaSize = dstDmaSize * 2;
		break;
	default:
		break;
	}

	if (dmaState->toCard) {
		createSGTable(dmaState->srcAddr, srcDmaSize, &srcSgt, srcMode);
		createSGTable(dmaState->dstAddr, dstDmaSize, &dstSgt, dstMode);
	} else {
		createSGTable(dmaState->srcAddr, dstDmaSize, &srcSgt, dstMode);
		createSGTable(dmaState->dstAddr, srcDmaSize, &dstSgt, srcMode);
	}

	lliSize = sphcs->hw_ops->dma.calc_lli_size(sphcs->hw_handle, &srcSgt, &dstSgt, 0);
	SPH_ASSERT(lliSize > 0);

	if (lliSize != dmaState->lliSize) {
		if (dmaState->lliSize > 0)
			dma_free_coherent(sphcs->hw_device, dmaState->lliSize, dmaState->lliPtr, dmaState->lliAddr);
		dmaState->lliSize = lliSize;
		dmaState->lliPtr = dma_alloc_coherent(sphcs->hw_device, dmaState->lliSize, &dmaState->lliAddr, GFP_KERNEL);
	}

	transfer_size = sphcs->hw_ops->dma.gen_lli(sphcs->hw_handle, &srcSgt, &dstSgt, dmaState->lliPtr, 0);
	sph_log_info(GENERAL_LOG, "scatter gather total transfer size %llu\n", transfer_size);
	SPH_ASSERT(transfer_size > 0);

	sg_free_table(&srcSgt);
	sg_free_table(&dstSgt);

	sphcs_dma_sched_start_xfer(sphcs->dmaSched,
				   dmaDesc,
				   dmaState->lliAddr,
				   transfer_size,
				   sphcs_ult_dma_scatterGather_complete_callback,
				   dmaState,
				   NULL,
				   0);

	return 0;
}

static int process_dma_single_command(struct sphcs *sphcs, u64 *msg, u32 size)
{
	union h2c_ULTDMASingleMsg *cmd = (union h2c_ULTDMASingleMsg *)msg;
	int rc;
	struct sphcs_ult_dma_req_state *dmaState;
	sphcs_dma_sched_completion_callback cb;

	dmaState = kzalloc(sizeof(*dmaState), GFP_KERNEL);
	if (!dmaState) {
		sph_log_err(GENERAL_LOG, "Could not allocate memory\n");
		return 1;
	}

	rc = dma_page_pool_get_free_page(sphcs->dma_page_pool, &dmaState->dstPageHandle, &dmaState->dstPtr, &dmaState->dstAddr);
	if (rc) {
		sph_log_err(GENERAL_LOG, "Could not allocate free dma page\n");
		kfree(dmaState);
		return 1;
	}

	dmaState->dmaSize = (cmd->size + 1) * ULT_DMA_SIZE_UNIT;
	dmaState->srcAddr = SPH_IPC_DMA_PFN_TO_ADDR(cmd->dma_pfn);
	dmaState->state = 0;
	dmaState->lliSize = 0;
	dmaState->dma_ult_mode = cmd->dma_ult_mode;

	if (is_contiguous(cmd->dma_ult_mode)) {
		cb = (cmd->dma_ult_mode == DMA_MODE_CONTIG) ?
				sphcs_ult_dma_single_complete_callback :
				sphcs_ult_dma_single_with_polling_complete_callback;

		sphcs_dma_sched_start_xfer_single(sphcs->dmaSched,
						  &g_dma_desc_h2c_low,
						  dmaState->srcAddr,
						  dmaState->dstAddr,
						  dmaState->dmaSize,
						  cb,
						  dmaState, NULL, 0);
	} else {
		dmaState->toCard = true;
		process_dma_sg_command(sphcs, dmaState, &g_dma_desc_h2c_low);
	}

	return 0;
}


static int sphcs_ult_dma_bandwidth_complete_callback(struct sphcs *sphcs, void *ctx, const void *user_data, int status, u32 timeUS)
{
	struct sphcs_ult_dma_req_state *dmaState = (struct sphcs_ult_dma_req_state *)ctx;

	if (dmaState->state == 0) { /* callback for dma transaction*/
		struct sphcs_ult_dma_bandwidth_req_state *dmaBwState = (struct sphcs_ult_dma_bandwidth_req_state *)ctx;

		dmaBwState->dma_timeUS += timeUS;

		if (atomic_dec_return(&dmaBwState->repeat_count) > 0) {

			sphcs_dma_sched_start_xfer_single(sphcs->dmaSched,
							  &dmaBwState->dma_desc,
							  dmaBwState->srcAddr,
							  dmaBwState->dstAddr,
							  dmaBwState->dmaSize,
							  sphcs_ult_dma_bandwidth_complete_callback,
							  dmaBwState, NULL, 0);
			return 0;
		}

		if (dmaBwState->req_info) {
			dmaBwState->req_info->out.dma_timeUS = dmaBwState->dma_timeUS;
			dmaBwState->req_info->out.cpu_timeUS = sph_time_us() - dmaBwState->cpu_timeUS;
		}

		atomic_inc(dmaBwState->completed_tests);

		wake_up_interruptible(dmaBwState->dma_test_completion_wait);

		kfree(dmaBwState);

	} else if (dmaState->state == 1) { /* callback for sg dma transaction */

		struct sphcs_ult_dma_bandwidth_req_state *dmaBwState = (struct sphcs_ult_dma_bandwidth_req_state *)ctx;

		dmaBwState->dma_timeUS += timeUS;

		if (atomic_dec_return(&dmaBwState->repeat_count) > 0) {

			sphcs_dma_sched_start_xfer(sphcs->dmaSched,
						   &dmaBwState->dma_desc,
						   dmaBwState->lliAddr,
						   dmaBwState->transfer_size,
						   sphcs_ult_dma_bandwidth_complete_callback,
						   dmaBwState,
						   NULL,
						   0);


			return 0;
		}

		if (dmaBwState->req_info) {
			dmaBwState->req_info->out.dma_timeUS = dmaBwState->dma_timeUS;
			dmaBwState->req_info->out.cpu_timeUS = sph_time_us() - dmaBwState->cpu_timeUS;
		}

		atomic_inc(dmaBwState->completed_tests);

		wake_up_interruptible(dmaBwState->dma_test_completion_wait);

		kfree(dmaBwState);

	} else if (dmaState->state == 2) { /* send results back to host */
		struct ult_dma_single_packet_header *packet_header = (struct ult_dma_single_packet_header *)dmaState->dstPtr;
		union c2h_ULTDMASingleMsgReply msg;

		msg.opcode = SPH_IPC_C2H_OP_ULT_OP;
		msg.ultOpcode = SPH_IPC_ULT_OP_DMA_BANDWIDTH;
		msg.hostPageHandle = packet_header->hostPageHandle;
		msg.c2hDmaTime = (u32)(sph_time_us() - dmaState->timeUS);

		sphcs_msg_scheduler_queue_add_msg(sphcs->public_respq, &msg.value, 1);

		dma_page_pool_set_page_free(sphcs->dma_page_pool, dmaState->dstPageHandle);
		kfree(dmaState);

	}

	return 0;
}


static int sphcs_ult_dma_bandwidth_parse_args_complete_callback(struct sphcs *sphcs, void *ctx, const void *user_data, int status, u32 timeUS)
{
	struct sphcs_ult_dma_req_state *dmaState = (struct sphcs_ult_dma_req_state *)ctx;

	wait_queue_head_t dma_test_completion_wait;
	u32 test_index = 0;
	struct ult_dma_bandwidth_packet_header *packet_header = (struct ult_dma_bandwidth_packet_header *)dmaState->dstPtr;
	union ult_dma_bandwidth_request_info *test_req;
	dma_addr_t *host_dma_phys;
	struct list_head card_dma_list;
	atomic_t completed_tests = ATOMIC_INIT(0);
	u64 startTimeUS = sph_time_us();
	struct ult_dma_node *dma_alloc_req;
	struct ult_dma_node *tmp_dma_req;

	/* create list of dma allocations - used later on for free */

	INIT_LIST_HEAD(&card_dma_list);

	/* init wait queue - need for waiting to all test completion */

	init_waitqueue_head(&dma_test_completion_wait);

	/* offset for all test parameters array */

	test_req = (union ult_dma_bandwidth_request_info *)(dmaState->dstPtr + sizeof(*packet_header));

	/* offset to location of all host dma allocations */

	host_dma_phys = (dma_addr_t *)(test_req + packet_header->dmaBandwidthRequestInfoCount);

	/* start loop for parsing tests parameters */
	for (test_index = 0; test_index < packet_header->dmaBandwidthRequestInfoCount; test_index++, test_req++) {
		struct sphcs_dma_desc dma_desc;
		struct sphcs_ult_dma_bandwidth_req_state *dmaBwState;

		/* convert test parameters to dma sched parameters */

		switch (test_req->in.priority) {
		case ULT_DMA_BANDWIDTH_HIGH:
			dma_desc.dma_priority = SPHCS_DMA_PRIORITY_HIGH;
			break;
		case ULT_DMA_BANDWIDTH_NORMAL:
			dma_desc.dma_priority = SPHCS_DMA_PRIORITY_NORMAL;
			break;
		case ULT_DMA_BANDWIDTH_LOW:
			dma_desc.dma_priority = SPHCS_DMA_PRIORITY_LOW;
			break;
		};

		/* convert test parameters to dma sched parameters */

		switch (test_req->in.direction) {
		case ULT_DMA_BANDWIDTH_CARD_TO_HOST:
			dma_desc.dma_direction = SPHCS_DMA_DIRECTION_CARD_TO_HOST;

			/* in case of dtf we can enable it only in c2h mode */

			if (test_req->in.dtf_mode) {
				dma_desc.dma_priority = SPHCS_DMA_PRIORITY_DTF;
				/* reserve dtf channel for DTF ult test */
				sphcs_dma_sched_reserve_channel_for_dtf(sphcs->dmaSched, true);
			}
			break;
		case ULT_DMA_BANDWIDTH_HOST_TO_CARD:
			if (test_req->in.dtf_mode) {
				/* need to increment completed test - mark this test as done */
				atomic_inc(&completed_tests);

				sph_log_debug(GENERAL_LOG, "test %d: error - dtf mode is not supported in h2c mode", test_index);
				continue;

			}
			dma_desc.dma_direction = SPHCS_DMA_DIRECTION_HOST_TO_CARD;
			break;
		};

		if (test_req->in.noWait)
			dma_desc.flags = SPHCS_DMA_START_XFER_COMPLETION_NO_WAIT;

		if (test_req->in.sg_mode == 0) { /* no sg mode - allocated contiguous memory for dma operation */

			/* requested size * kb */
			u32 requested_dma_copy_size = test_req->in.bufSize;


			/* allocate state information - in case we can't allocate - just skip current test */

			dmaBwState = kzalloc(sizeof(*dmaBwState), GFP_KERNEL);

			if (dmaBwState == NULL) {

				/* need to increment completed test - mark this test as done */
				atomic_inc(&completed_tests);

				sph_log_debug(GENERAL_LOG, "unable to allocated buffer for test request number %d", test_index);

				continue;

			}

			/* allocate dma node for future release of all dma allocations once test ended */

			dma_alloc_req = kzalloc(sizeof(*dma_alloc_req), GFP_NOWAIT);

			if (dma_alloc_req == NULL) {

				/* need to increment completed test - mark this test as done */
				atomic_inc(&completed_tests);

				/* need to pre allocations */
				kfree(dmaBwState);

				sph_log_debug(GENERAL_LOG, "unable to allocate allocation request node");

				continue;
			}

			dma_alloc_req->dma_size = requested_dma_copy_size;
			dma_alloc_req->vptr = dma_alloc_coherent(sphcs->hw_device, dma_alloc_req->dma_size, &dma_alloc_req->dma_phys, GFP_KERNEL);

			if (dma_alloc_req->vptr == NULL) {
				sph_log_debug(GENERAL_LOG, "unable to allocated dma buffer size : %u for test number %d", dma_alloc_req->dma_size, test_index);

				/* need to increment completed test - mark this test as done */
				atomic_inc(&completed_tests);

				/* need to pre allocations */
				kfree(dmaBwState);
				kfree(dma_alloc_req);

				continue;
			}

			/* add request for list - will be free at the */
			/* end of the test */
			INIT_LIST_HEAD(&dma_alloc_req->node);
			list_add_tail(&dma_alloc_req->node, &card_dma_list);

			/* send pointer of dma offset on card buffer, we will write test results on completion */
			dmaBwState->req_info = test_req;

			/* reset dma time */
			dmaBwState->dma_timeUS = 0;
			/* set cpu start time */
			dmaBwState->cpu_timeUS = sph_time_us();
			/* save number of repeats for current test */
			atomic_set(&dmaBwState->repeat_count,
				   test_req->in.repeat_count);
			/* save dma_desc for repeat test */
			dmaBwState->dma_desc = dma_desc;
			/* insert completed test counter */
			dmaBwState->completed_tests = &completed_tests;
			/* wait handle - will wake up once all entire test ended - include repeat */
			dmaBwState->dma_test_completion_wait = &dma_test_completion_wait;
			/* save dma requested size for future repeat */
			dmaBwState->dmaSize = requested_dma_copy_size;

			/* set source and dst based on direction */

			switch (test_req->in.direction) {
			case ULT_DMA_BANDWIDTH_CARD_TO_HOST:
				dmaBwState->srcAddr = dma_alloc_req->dma_phys;
				dmaBwState->dstAddr = *host_dma_phys;
				break;
			case ULT_DMA_BANDWIDTH_HOST_TO_CARD:
				dmaBwState->srcAddr = *host_dma_phys;
				dmaBwState->dstAddr = dma_alloc_req->dma_phys;
				break;
			}

			/* set callback state to 1 - dma completion response for single */
			dmaBwState->state = 0;

			/* since we start the test on the fly - need to decrement repeat by 1 */
			atomic_dec(&dmaBwState->repeat_count);

			/* start dma request for single */
			sphcs_dma_sched_start_xfer_single(sphcs->dmaSched,
							  &dmaBwState->dma_desc,
							  dmaBwState->srcAddr,
							  dmaBwState->dstAddr,
							  dmaBwState->dmaSize,
							  sphcs_ult_dma_bandwidth_complete_callback,
							  dmaBwState, NULL, 0);

			/* increment host dma pointer */
			host_dma_phys++;

		} else {
			/* card sg table */
			struct sg_table card_sgt;
			/* host sg table */
			struct sg_table host_sgt;
			/* source and destination sg table */
			struct sg_table *src_sgt, *dst_sgt;
			u32 i;
			struct scatterlist *currentSgl;
			u32 num_of_pages;
			bool skip_test = false;

			/* create sg table for host dma allocations */

			sg_alloc_table(&host_sgt, test_req->in.dma_addr_count, GFP_KERNEL);

			if (!host_sgt.sgl) {
				/* need to increment completed test - mark this test as done */
				atomic_inc(&completed_tests);

				sph_log_debug(GENERAL_LOG, "unable to allocate host sg_table");
				continue;
			}

			currentSgl = host_sgt.sgl;

			for (i = 0; i < test_req->in.dma_addr_count && currentSgl; i++) {

				sph_log_debug(GENERAL_LOG, "index %d - host_dma: %llu, size: %d\n",
					      i,
					      *host_dma_phys,
					      test_req->in.dma_page_size);

				currentSgl->length = test_req->in.dma_page_size;
				currentSgl->dma_address = *host_dma_phys;
				host_dma_phys++;
				currentSgl = sg_next(currentSgl);
			}

			/* create sg table for card dma allocations */

			num_of_pages = (((test_req->in.bufSize) + (SPH_PAGE_SIZE - 1)) / SPH_PAGE_SIZE);

			/* create sg table for card dma allocations */

			sg_alloc_table(&card_sgt, num_of_pages, GFP_KERNEL);

			if (!card_sgt.sgl) {
				/* need to increment completed test - mark this test as done */
				atomic_inc(&completed_tests);

				sg_free_table(&host_sgt);
				sph_log_debug(GENERAL_LOG, "unable to allocate card sg_table");
				continue;
			}

			currentSgl = card_sgt.sgl;

			/* allocate pages */

			for (i = 0; i < num_of_pages; i++) {
				dma_alloc_req = kzalloc(sizeof(*dma_alloc_req), GFP_NOWAIT);

				if (dma_alloc_req == NULL) {
					skip_test = true;
					sph_log_debug(GENERAL_LOG, "unable to allocate allocation request node");
					break;
				}
				dma_alloc_req->vptr = dma_alloc_coherent(sphcs->hw_device, SPH_PAGE_SIZE, &dma_alloc_req->dma_phys, GFP_KERNEL);

				if (dma_alloc_req->vptr == NULL) {
					/* need to pre allocations */
					kfree(dma_alloc_req);

					skip_test = true;

					sph_log_debug(GENERAL_LOG, "unable to allocate dma page for sg");
					break;
				}

				/* set dma page size for future dma allocation release */

				dma_alloc_req->dma_size = SPH_PAGE_SIZE;

				/* set sgl list dma addr */

				currentSgl->length = SPH_PAGE_SIZE;
				currentSgl->dma_address = dma_alloc_req->dma_phys;
				currentSgl = sg_next(currentSgl);

				dma_alloc_req->dma_size = SPH_PAGE_SIZE;

				/* add request for list - will be freed at the */
				/* end of the test */
				INIT_LIST_HEAD(&dma_alloc_req->node);
				list_add_tail(&dma_alloc_req->node, &card_dma_list);
			}

			if (skip_test) {
				/* need to increment completed test - mark this test as done */
				atomic_inc(&completed_tests);

				/* release sg tables */
				sg_free_table(&host_sgt);
				sg_free_table(&card_sgt);
				sph_log_debug(GENERAL_LOG, "skip test");

				continue;
			}

			/* set sg table for src and dst */

			switch (test_req->in.direction) {
			case ULT_DMA_BANDWIDTH_CARD_TO_HOST:
				src_sgt = &card_sgt;
				dst_sgt = &host_sgt;
				break;
			case ULT_DMA_BANDWIDTH_HOST_TO_CARD:
				src_sgt = &host_sgt;
				dst_sgt = &card_sgt;
				break;
			default:
				sph_log_err(GENERAL_LOG, "Wrong DMA direction\n");
				continue;
			}

			dmaBwState = kzalloc(sizeof(*dmaBwState), GFP_KERNEL);

			if (dmaBwState == NULL) {

				/* need to increment completed test - mark this test as done */
				atomic_inc(&completed_tests);

				/* release sg tables */
				sg_free_table(&host_sgt);
				sg_free_table(&card_sgt);

				sph_log_debug(GENERAL_LOG, "unable to allocated buffer for test request number %d", test_index);
				continue;
			}

			dma_alloc_req = kzalloc(sizeof(*dma_alloc_req), GFP_NOWAIT);

			if (dma_alloc_req == NULL) {
				/* need to increment completed test - mark this test as done */
				atomic_inc(&completed_tests);

				/* release pre allocations */
				kfree(dmaBwState);
				sg_free_table(&host_sgt);
				sg_free_table(&card_sgt);

				sph_log_debug(GENERAL_LOG, "unable to allocate allocation request node for lli");
				continue;
			}

			dmaBwState->lliSize = sphcs->hw_ops->dma.calc_lli_size(sphcs->hw_handle, src_sgt, dst_sgt, 0);

			dmaBwState->lliPtr = dma_alloc_coherent(sphcs->hw_device, dmaBwState->lliSize, &dmaBwState->lliAddr, GFP_KERNEL);

			if (dmaBwState->lliPtr == NULL) {

				/* need to increment completed test - mark this test as done */
				atomic_inc(&completed_tests);

				/* release pre allocations */
				kfree(dma_alloc_req);
				kfree(dmaBwState);
				sg_free_table(&host_sgt);
				sg_free_table(&card_sgt);

				sph_log_debug(GENERAL_LOG, "unable to allocated lli for test request number %d", test_index);
				continue;
			}

			/* set  dma alloction info for future release */
			dma_alloc_req->vptr = dmaBwState->lliPtr;
			dma_alloc_req->dma_phys = dmaBwState->lliAddr;
			dma_alloc_req->dma_size =  dmaBwState->lliSize;

			/* add request for list - will be freed at the */
			/* end of the test */
			INIT_LIST_HEAD(&dma_alloc_req->node);
			list_add_tail(&dma_alloc_req->node, &card_dma_list);

			dmaBwState->transfer_size = sphcs->hw_ops->dma.gen_lli(sphcs->hw_handle, src_sgt, dst_sgt, dmaBwState->lliPtr, 0);

			sg_free_table(src_sgt);
			sg_free_table(dst_sgt);

			dmaBwState->req_info = test_req;
			dmaBwState->dma_timeUS = 0;
			dmaBwState->cpu_timeUS = sph_time_us();
			atomic_set(&dmaBwState->repeat_count,
				   test_req->in.repeat_count);
			dmaBwState->dma_desc = dma_desc;
			dmaBwState->completed_tests = &completed_tests;
			dmaBwState->dma_test_completion_wait = &dma_test_completion_wait;
			dmaBwState->dmaSize = 0;

			/* set callback state to 2 - dma completion response for sg mode */
			dmaBwState->state = 1;

			/* since we start the test on the fly - need to decrement repeat by 1 */
			atomic_dec(&dmaBwState->repeat_count);

			/* start dma request for sg */
			sphcs_dma_sched_start_xfer(sphcs->dmaSched,
						   &dmaBwState->dma_desc,
						   dmaBwState->lliAddr,
						   dmaBwState->transfer_size,
						   sphcs_ult_dma_bandwidth_complete_callback,
						   dmaBwState,
						   NULL,
						   0);
		}

	}

	/* wait for all tests completion */
	while (packet_header->dmaBandwidthRequestInfoCount != atomic_read(&completed_tests)) {
		wait_event_interruptible(dma_test_completion_wait,
					 packet_header->dmaBandwidthRequestInfoCount == atomic_read(&completed_tests));
	}

	/* release dtf channel if it was taken by ult test*/
	sphcs_dma_sched_reserve_channel_for_dtf(sphcs->dmaSched, false);

	/* clear all allocated dma pages*/
	list_for_each_entry_safe(dma_alloc_req, tmp_dma_req, &card_dma_list, node) {
		list_del(&dma_alloc_req->node);
		dma_free_coherent(sphcs->hw_device,
				  dma_alloc_req->dma_size,
				  dma_alloc_req->vptr,
				  dma_alloc_req->dma_phys);

		kfree(dma_alloc_req);
	}


	/* send results on dma buffer back to host */
	dmaState->state = 2;
	dmaState->timeUS = startTimeUS;
	sphcs_dma_sched_start_xfer_single(sphcs->dmaSched,
					  &g_dma_desc_c2h_low,
					  dmaState->dstAddr,
					  dmaState->srcAddr,
					  dmaState->dmaSize,
					  sphcs_ult_dma_bandwidth_complete_callback,
					  dmaState, NULL, 0);
	return 0;
}

static int process_dma_bandwidth(struct sphcs *sphcs, u64 *msg, u32 size)
{
	union h2c_ULTDMABandwidthMsg *cmd = (union h2c_ULTDMABandwidthMsg *)msg;

	int rc;
	struct sphcs_ult_dma_req_state *dmaState;

	dmaState = kzalloc(sizeof(*dmaState), GFP_KERNEL);
	if (!dmaState) {
		sph_log_err(GENERAL_LOG, "Could not allocate memory\n");
		return 1;
	}

	/* allocate dma page dma transaction from host */

	rc = dma_page_pool_get_free_page(sphcs->dma_page_pool, &dmaState->dstPageHandle, &dmaState->dstPtr, &dmaState->dstAddr);
	if (rc) {
		sph_log_err(GENERAL_LOG, "Could not allocate free dma page\n");
		kfree(dmaState);
		return 1;
	}

	dmaState->dmaSize = cmd->size * 64;
	dmaState->srcAddr = SPH_IPC_DMA_PFN_TO_ADDR(cmd->dma_pfn);
	dmaState->state = 0;
	dmaState->lliSize = 0;

	/* collecting test parameters via dma request from host */
	/* DMA bandwidth test will in sphcs_dma_bandwidth_complete_callback */
	sphcs_dma_sched_start_xfer_single(sphcs->dmaSched,
					  &g_dma_desc_h2c_low,
					  dmaState->srcAddr,
					  dmaState->dstAddr,
					  dmaState->dmaSize,
					  sphcs_ult_dma_bandwidth_parse_args_complete_callback,
					  dmaState, NULL, 0);
	return 0;
}

static int process_doorbell(struct sphcs *sphcs, u64 *msg, u32 size)
{
	union ULTDoorbell *db_msg = (union ULTDoorbell *)msg;

	sphcs->hw_ops->set_card_doorbell_value(sphcs->hw_handle, db_msg->db_val);
	return 0;
}

static int process_boot_over_pci(struct sphcs *sphcs, u64 *msg, u32 size)
{
	union ULTDoorbell *db_msg = (union ULTDoorbell *)msg;

	g_ult_bop_testing = true;
	sphcs->hw_ops->set_card_doorbell_value(sphcs->hw_handle, db_msg->db_val);
	return 0;
}

/*
 * this ULT will test if rsyslog filter mechanism is working correctly
 * upon each msg, it'll try to wrtie one log from each category and level.
 * the one that should be written to the loger FIFO are those who match the filter only.
 */
#define LOGC(x) \
do { \
sph_log_err(x, "rsyslog_ult:level- err\n"); \
		 sph_log_info(x, "rsyslog_ult:level- info\n");\
		 sph_log_debug(x, "rsyslog_ult:level- debug\n");\
		 sph_log_warn(x, "rsyslog_ult:level- warning\n");\
} while (0)

static int process_rsyslog(struct sphcs *sphcs, u64 *msg, u32 size)
{
	union ult_message *cmd = (union ult_message *)msg;

	LOGC(GENERAL_LOG);
	LOGC(START_UP_LOG);
	LOGC(GO_DOWN_LOG);
	LOGC(DMA_LOG);
	LOGC(CONTEXT_STATE_LOG);
	LOGC(IPC_LOG);
	LOGC(CREATE_COMMAND_LOG);
	LOGC(SCHEDULE_COMMAND_LOG);
	LOGC(EXECUTE_COMMAND_LOG);
	LOGC(SERVICE_LOG);
	LOGC(ETH_LOG);
	LOGC(INFERENCE_LOG);
	LOGC(ICE_LOG);

	/* send reply to host */
	cmd->opcode = SPH_IPC_C2H_OP_ULT_OP;
	cmd->ultOpcode = SPH_IPC_ULT_OP_RSYSLOG;
	sphcs_msg_scheduler_queue_add_msg(sphcs->public_respq, &cmd->value, 1);

	sph_log_debug(GENERAL_LOG, "Rsyslog ult: Send reply message to host\n");

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

static sphcs_command_handler s_dispatch[SPH_IPC_ULT_NUM_OPCODES] = {
	process_dma_single_command,  /* SPH_IPC_ULT_OP_DMA_SINGLE */
	process_host_hwQ_msg,  /* SPH_IPC_ULT_OP_CARD_HWQ_MSG */
	process_dma_bandwidth, /* SPH_IPC_ULT_OP_DMA_BANDWIDTH */
	process_doorbell,      /* SPH_IPC_ULT_OP_DOORBELL */
	process_boot_over_pci, /* SPH_IPC_ULT_OP_BOOT_OVER_PCI */
	process_rsyslog,	   /* SPH_IPC_ULT_OP_RSYSLOG */
};

static sphcs_chan_command_handler s_dispatch2[SPH_IPC_ULT2_NUM_OPCODES] = {
	ult2_process_host_hwQ_msg,  /* SPH_IPC_ULT2_OP_CARD_HWQ_MSG */
	ult2_process_dma_ping, /* SPH_IPC_ULT2_OP_DMA_PING */
};

/*
 * Description:  ULT messages dispatcher, Called to process a
 * SPH_IPC_H2C_OP_ULT_OP message receviced from host.
 * identify ULT message sub opcode and call the appropriate handler to handle the message.
 */
static int sphcs_ult_process_command(struct sphcs *sphcs, u64 *msg, u32 size)
{
	int opcode = ((union h2c_ULTDMASingleMsg *)msg)->opcode;

	if (opcode == H2C_OPCODE_NAME(ULT_OP)) {
		int ultOp = ((union h2c_ULTDMASingleMsg *)msg)->ultOpcode;

		if (ultOp >= SPH_IPC_ULT_NUM_OPCODES || NULL == s_dispatch[ultOp]) {
			sph_log_err(GENERAL_LOG, "Unsupported ult h2c command opcode=%d\n", ultOp);
			return 0;
		}

		return s_dispatch[ultOp](sphcs, msg, size);
	} else if (opcode == H2C_OPCODE_NAME(ULT2_OP)) {
		int ultOp = ((union ult2_message *)msg)->ultOpcode;
		int chanID = ((union ult2_message *)msg)->channelID;
		struct sphcs_cmd_chan *chan;
		int ret;

		if (ultOp >= SPH_IPC_ULT2_NUM_OPCODES || NULL == s_dispatch2[ultOp]) {
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

void sphcs_ult_process_bios_message(struct sphcs *sphcs, u64 *msg)
{
	union sph_bios_ipc_header *header = (union sph_bios_ipc_header *)msg;


	switch (header->msgType) {
	case SPH_IPC_H2C_TYPE_BOOT_IMAGE_READY:
	{
		union h2c_BootImageReady *bop_msg = (union h2c_BootImageReady *)msg;
		union ULTBootOverPCIReplay reply;

		sph_log_debug(GENERAL_LOG, "boot_over_pci: set image size = %u desc address 0X%llx\n", bop_msg->image_size, bop_msg->descriptor_addr);
		g_ult_bop_descriptor_addr = bop_msg->descriptor_addr;
		g_ult_bop_image_size      = bop_msg->image_size;

		/* replay boot sequence */
		reply.opcode = SPH_IPC_C2H_OP_ULT_OP;
		reply.ultOpcode = SPH_IPC_ULT_OP_BOOT_OVER_PCI;
		reply.descriptor_addr = lower_32_bits(g_ult_bop_descriptor_addr);
		reply.image_size      = ALIGN(g_ult_bop_image_size, ULT_IMAGE_SIZE_FACTOR) / ULT_IMAGE_SIZE_FACTOR;
		sph_log_debug(GENERAL_LOG, "boot over pci: desc addr 0x%x size %d\n", reply.descriptor_addr, reply.image_size);
		sphcs_msg_scheduler_queue_add_msg(sphcs->public_respq, (u64 *)&reply.value, 1);

		g_ult_bop_descriptor_addr = 0;
		g_ult_bop_image_size = 0;
	}
	break;
	default:
	break;
	}
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

	SPH_SPIN_LOCK(&g_pending_ult_commands_lock);

	list_add_tail(&entry->node, &g_pending_ult_commands);
	g_num_pending_ult_commands++;

	if (g_num_pending_ult_commands == 1)
		queue_work(g_ult_wq, &g_pending_ult_commands_work);

	SPH_SPIN_UNLOCK(&g_pending_ult_commands_lock);
}

/*
 * Description: interrupt main thread,called upon receiving ult message(opcode
 * SPH_IPC_H2C_OP_ULT_OP) from host.
 * add message to workqueue, to be processed at some time by the workqueue thread.
 */
void IPC_OPCODE_HANDLER(ULT_OP)(struct sphcs      *sphcs,
				union ult_message *msg)
{
	add_pending_ult_command(sphcs, msg->value);
}

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

	SPH_SPIN_LOCK(&g_pending_ult_commands_lock);
	while (g_num_pending_ult_commands) {
	entry = list_first_entry(&g_pending_ult_commands,
				 struct ult_cmd_entry,
				 node);
	SPH_SPIN_UNLOCK(&g_pending_ult_commands_lock);

	rc = sphcs_ult_process_command(g_the_sphcs, &entry->msg, 1);
	if (rc)
		sph_log_err(GENERAL_LOG, "FATAL: process ult message failed rc=%d\n", rc);

	SPH_SPIN_LOCK(&g_pending_ult_commands_lock);
	list_del(&entry->node);
	kfree(entry);
	g_num_pending_ult_commands--;
	}
	SPH_SPIN_UNLOCK(&g_pending_ult_commands_lock);
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
	g_ult_bop_testing = false;
	g_ult_bop_descriptor_addr = 0;
	g_ult_bop_image_size = 0;

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
