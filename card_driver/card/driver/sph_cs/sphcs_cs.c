/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/
#include "sphcs_cs.h"
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/jiffies.h>
#include <linux/workqueue.h>
#include "ipc_protocol.h"
#include "ipc_chan_protocol.h"
#ifdef ULT
#include "sphcs_ult.h"
#include "ipc_chan_protocol_ult.h"
#endif
#include "sph_log.h"
#include "sphcs_genmsg.h"
#include "sphcs_cs.h"
#include "sphcs_net.h"
#include "sphcs_inf.h"
#include "sphcs_response_page_pool.h"
#include "sphcs_crash_dump.h"
#include "sph_time.h"
#include "sph_boot_defs.h"
#include "sphcs_trace.h"
#include "sph_inbound_mem.h"
#include "sphcs_intel_th.h"
#include "sphcs_maintenance.h"
#include <linux/trace_clock.h>
#include <linux/delay.h>
#include <linux/reboot.h>
#include <linux/version.h>
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 16, 0)) /* SPH_IGNORE_STYLE_CHECK */
#include <linux/dma-direct.h>
#else
#include <linux/dma-mapping.h>
#endif
#ifdef CARD_PLATFORM_BR
#include <linux/ion_exp.h>
#include "sph_mem_alloc_defs.h"
#endif
#include "sphcs_p2p.h"
#include "sphcs_cmd_chan.h"
#include "sphcs_ibecc.h"

/* Disable MCE support on COH and CentOS local builds */
#if defined(RHEL_RELEASE_CODE) || defined(HW_LAYER_LOCAL)
#define NO_MCE
#endif

#ifndef NO_MCE
#include <asm/mce.h>
#endif

struct sphcs *g_the_sphcs;   /* a  global pointer to the sphcs object - currently a singleton */

void *g_hSwCountersInfo_global;
void *g_hSwCountersInfo_context;
void *g_hSwCountersInfo_network;
void *g_hSwCountersInfo_infreq;
void *g_hSwCountersInfo_copy;
struct sph_sw_counters *g_sph_sw_counters;

#ifdef CARD_PLATFORM_BR
LIST_HEAD(p2p_regions);
static void *p2p_heap_handle;
#endif

void sphcs_send_event_report(struct sphcs *sphcs,
			     uint16_t eventCode,
			     uint16_t eventVal,
			     struct msg_scheduler_queue *respq,
			     int contextID,
			     int objID)
{
	sphcs_send_event_report_ext(sphcs,
				    eventCode,
				    eventVal,
				    respq,
				    contextID,
				    objID,
				    -1);
}

void sphcs_send_event_report_ext(struct sphcs *sphcs,
				 uint16_t eventCode,
				 uint16_t eventVal,
				 struct msg_scheduler_queue *respq,
				 int contextID,
				 int objID_1,
				 int objID_2)
{
	union c2h_EventReport event;

	event.value = 0;
	event.opcode = SPH_IPC_C2H_OP_EVENT_REPORT;
	event.eventCode = eventCode;
	event.eventVal = eventVal;
	if (contextID >= 0) {
		event.contextID = contextID;
		event.ctxValid = 1;
	}
	if (objID_1 >= 0) {
		event.objID = objID_1;
		event.objValid = 1;
	}
	if (objID_2 >= 0) {
		event.objID_2 = objID_2;
		event.objValid_2 = 1;
	}

	log_c2h_event("Sending event", &event);

	if (respq)
		sphcs_msg_scheduler_queue_add_msg(respq, &event.value, 1);
	else
		sphcs_msg_scheduler_queue_add_msg(sphcs->public_respq, &event.value, 1);
}

static void IPC_OPCODE_HANDLER(QUERY_VERSION)(
				struct sphcs *sphcs,
				union h2c_QueryVersionMsg *msg)
{
	union c2h_QueryVersionReplyMsg replyMsg;

	replyMsg.value = 0;
	// respond with the driver and protocol versions
	replyMsg.opcode = SPH_IPC_C2H_OP_QUERY_VERSION_REPLY;
	replyMsg.driverVersion = SPH_IPC_PROTOCOL_VERSION;
	replyMsg.protocolVersion = SPH_IPC_PROTOCOL_VERSION;

	sphcs_msg_scheduler_queue_add_msg(sphcs->public_respq, &replyMsg.value, 1);
}

static void IPC_OPCODE_HANDLER(SETUP_CRASH_DUMP)(
			struct sphcs *sphcs,
			union h2c_setup_crash_dump_msg *setup_msg)
{

	sph_log_info(CREATE_COMMAND_LOG, "Setup Crash dump received\n");

	sphcs_crash_dump_setup_host_addr(SPH_IPC_DMA_PFN_TO_ADDR(setup_msg->dma_addr));

}

static void IPC_OPCODE_HANDLER(SETUP_SYS_INFO_PAGE)(
			struct sphcs *sphcs,
			union h2c_setup_sys_info_page *msg)
{

	sph_log_info(CREATE_COMMAND_LOG, "Setup sys info page received\n");

	sphcs->host_sys_info_dma_addr = SPH_IPC_DMA_PFN_TO_ADDR(msg->dma_addr);
	sphcs->host_sys_info_dma_addr_valid = true;

	/* send host sys_info packet, if available */
	sphcs_maint_send_sys_info();

}

static void IPC_OPCODE_HANDLER(CLOCK_SYNC)(
			struct sphcs       *sphcs,
			union ClockSyncMsg *cmd)
{
	union ClockSyncMsg msg;

	// send echo to the host
	memset(msg.value, 0, sizeof(msg.value));
	msg.opcode  = SPH_IPC_C2H_OP_CLOCK_SYNC;
	msg.o_card_ts = sched_clock();
	msg.iteration = cmd->iteration;
	sphcs_msg_scheduler_queue_add_msg(g_the_sphcs->public_respq,
				    (u64 *)msg.value,
				    sizeof(msg) / sizeof(u64));
}

struct sphcs_cmd_chan *sphcs_find_channel(struct sphcs *sphcs, uint16_t protocolID)
{
	struct sphcs_cmd_chan *chan;

	SPH_SPIN_LOCK_BH(&sphcs->lock_bh);
	hash_for_each_possible(sphcs->cmd_chan_hash,
			       chan,
			       hash_node,
			       protocolID)
		if (chan->protocolID == protocolID) {
			sphcs_cmd_chan_get(chan);
			SPH_SPIN_UNLOCK_BH(&sphcs->lock_bh);
			return chan;
		}
	SPH_SPIN_UNLOCK_BH(&sphcs->lock_bh);

	return NULL;
}

int find_and_destroy_channel(struct sphcs *sphcs, uint16_t protocolID)
{
	struct sphcs_cmd_chan *iter, *chan = NULL;
	int i;

	SPH_SPIN_LOCK_BH(&sphcs->lock_bh);
	hash_for_each_possible(sphcs->cmd_chan_hash,
			       iter,
			       hash_node,
			       protocolID)
		if (iter->protocolID == protocolID) {
			chan = iter;
			break;
		}

	if (unlikely(chan == NULL)) {
		SPH_SPIN_UNLOCK_BH(&sphcs->lock_bh);
		return -ENXIO;
	}

	chan->destroyed = true;
	hash_del(&chan->hash_node);
	SPH_SPIN_UNLOCK_BH(&sphcs->lock_bh);

	if (chan->destroy_cb)
		(*chan->destroy_cb)(chan, chan->destroy_cb_ctx);

	/* mark all c2h channels as "disconnected" to release any writers */
	for (i = 0; i < SPH_IPC_MAX_CHANNEL_RINGBUFS; i++)
		if (chan->c2h_rb[i].host_sgt.sgl != NULL) {
			chan->c2h_rb[i].disconnected = true;
			wake_up_all(&chan->c2h_rb[i].waitq);
		}

	sphcs_cmd_chan_put(chan);

	return 0;
}

struct channel_op_work {
	struct work_struct  work;
	union h2c_ChannelOp cmd;
};

static void channel_op_work_handler(struct work_struct *work)
{
	struct channel_op_work *op = container_of(work,
						  struct channel_op_work,
						  work);
	struct sphcs *sphcs = g_the_sphcs;
	struct sphcs_cmd_chan *chan;
	uint8_t event;
	enum event_val val = 0;
	int ret;

	if (op->cmd.destroy) {
		ret = find_and_destroy_channel(sphcs, op->cmd.protocolID);
		if (unlikely(ret < 0)) {
			event = SPH_IPC_DESTROY_CHANNEL_FAILED;
			val = SPH_IPC_NO_SUCH_CHANNEL;
			goto send_error;
		}
	} else {
		chan = sphcs_find_channel(sphcs, op->cmd.protocolID);
		if (unlikely(chan != NULL)) {
			sphcs_cmd_chan_put(chan);
			event = SPH_IPC_CREATE_CHANNEL_FAILED;
			val = SPH_IPC_ALREADY_EXIST;
			goto send_error;
		}

		val = sphcs_cmd_chan_create(op->cmd.protocolID,
					    op->cmd.uid,
					    op->cmd.privileged ? true : false,
					    &chan);
		if (unlikely(val != 0)) {
			event = SPH_IPC_CREATE_CHANNEL_FAILED;
			goto send_error;
		}

		sphcs_send_event_report(sphcs,
					SPH_IPC_CREATE_CHANNEL_SUCCESS,
					0,
					NULL,
					-1,
					op->cmd.protocolID);
	}

	goto done;

send_error:
	sphcs_send_event_report(sphcs, event, val, NULL, -1, op->cmd.protocolID);
done:
	kfree(op);
}

static void IPC_OPCODE_HANDLER(CHANNEL_OP)(
			struct sphcs        *sphcs,
			union h2c_ChannelOp *cmd)
{
	struct channel_op_work *work;
	uint8_t event;

	work = kzalloc(sizeof(*work), GFP_NOWAIT);
	if (unlikely(work == NULL)) {
		if (cmd->destroy)
			event = SPH_IPC_DESTROY_CHANNEL_FAILED;
		else
			event = SPH_IPC_CREATE_CHANNEL_FAILED;
		sphcs_send_event_report(sphcs,
					event,
					SPH_IPC_NO_MEMORY,
					NULL,
					-1,
					cmd->protocolID);
		return;
	}

	work->cmd.value = cmd->value;
	INIT_WORK(&work->work, channel_op_work_handler);
	queue_work(sphcs->wq, &work->work);
}

/*
 * HWQ messages handler,
 * This function is *NOT* re-entrant!!!
 * The assumption is that the h/w layer call this function from interrupt
 * handler while interrupts are disabled.
 * The function may not block !!!
 */
static int sphcs_process_messages(struct sphcs *sphcs, u64 *hw_msg, u32 hw_size)
{
	static u64 s_msgs[32];
	static u64 s_num_msgs = 0;
	u32 j = 0;
	u64 *msg;
	u32 size;
	u64 start_time;
	bool update_sw_counters = SPH_SW_GROUP_IS_ENABLE(g_sph_sw_counters,
							 SPHCS_SW_COUNTERS_GROUP_IPC);

	if (update_sw_counters)
		start_time = sph_time_us();
	else
		start_time = 0;

	/*
	 * if we have pending messages from previous round
	 * copy the new messages to the pending list and process
	 * the pending list.
	 * otherwise process the messages reveived from hw directly
	 */
	if (s_num_msgs > 0) {
		SPH_ASSERT( hw_size + s_num_msgs < 32 );
		if (unlikely(hw_size + s_num_msgs >= 32))
			return 0; // prevent buffer overrun

		memcpy(&s_msgs[s_num_msgs], hw_msg, hw_size*sizeof(u64));
		msg = s_msgs;
		size = s_num_msgs + hw_size;
	}
	else {
		msg = hw_msg;
		size = hw_size;
	}

	/*
	 * loop for each message
	 */
	do {
		int opCode = ((union h2c_QueryVersionMsg *)&msg[j])->opcode;
		u32 msg_size = 0;
		int partial_msg = 0;

		/* dispatch the message request */
		#define H2C_OPCODE(name,val,type)                                    \
			case (val):                                                  \
			msg_size = sizeof(type)/sizeof(u64);                         \
			if (msg_size > (size-j))                                     \
				partial_msg = 1;                                     \
			else {                                                        \
				DO_TRACE(trace__ipc(0, &msg[j], msg_size));           \
				CALL_IPC_OPCODE_HANDLER(name, type, sphcs, &msg[j]); \
			} \
			break;


		switch(opCode) {
		#include "ipc_h2c_opcodes.h"
		#include "ipc_chan_h2c_opcodes.h"
		default:
			/* Should not happen! */
			SPH_ASSERT(0);
			j++;
			continue;
		}
                #undef H2C_OPCODE

		/* exit the loop if not a full sized message arrived */
		if (partial_msg)
			break;

		j += msg_size;

	} while (j < size);

	/* 
	 * if unprocessed messages left, copy it to the pensing messages buffer
	 * for the next time
	 */
	if (j < size) {
		memcpy(&s_msgs[0], &msg[j], (size-j)*sizeof(u64));
		s_num_msgs = size-j;
	} else
		s_num_msgs = 0;

	if (update_sw_counters) {
		SPH_SW_COUNTER_ADD(g_sph_sw_counters, SPHCS_SW_COUNTERS_IPC_COMMANDS_CONSUME_TIME, sph_time_us() - start_time);
		SPH_SW_COUNTER_ADD(g_sph_sw_counters, SPHCS_SW_COUNTERS_IPC_COMMANDS_COUNT, j);
	}

	return hw_size;
}

static int respq_sched_handler(u64 *msg, int size, void *hw_data)
{
	struct sphcs *sphcs = (struct sphcs *)hw_data;
	int ret;

	DO_TRACE(trace__ipc(1, msg, size));

	ret = sphcs->hw_ops->write_mesg(sphcs->hw_handle, msg, size);

	if (SPH_SW_GROUP_IS_ENABLE(g_sph_sw_counters, SPHCS_SW_COUNTERS_GROUP_IPC))
		SPH_SW_COUNTER_ADD(g_sph_sw_counters, SPHCS_SW_COUNTERS_IPC_RESPONSES_COUNT, size);

	return ret;
}

struct msg_scheduler_queue *sphcs_create_response_queue(struct sphcs *sphcs,
							       u32 weight)
{
	return msg_scheduler_queue_create(sphcs->respq_sched,
					  sphcs,
					  respq_sched_handler,
					  weight);
}

int sphcs_destroy_response_queue(struct sphcs               *sphcs,
				 struct msg_scheduler_queue *respq)
{
	return msg_scheduler_queue_destroy(sphcs->respq_sched, respq);
}

#ifndef NO_MCE
static void sphcs_delayed_reset(struct work_struct *work)
{
	sph_log_info(GO_DOWN_LOG, "Delayed reset upon fatal error\n");

	emergency_restart();
}

static int handle_mce_event(struct notifier_block *nb, unsigned long val, void *data)
{
	struct mce *mce = (struct mce *)data;
	union c2h_EventReport event;
	uint16_t eventVal;
	uint16_t eventCode = 0;
	int is_ecc_err;

	/*
	 * Based on chapter "15.9.2 - Compound Error Codes"
	 * in Intel Arch programmer's guide.
	 */
	is_ecc_err = ((mce->status & 0xeffc) == 0x000c) ||
		     ((mce->status & 0xeff0) == 0x0010) ||
		     ((mce->status & 0xef00) == 0x0100);

	eventVal = is_ecc_err;

	/* Uncorrected Error */
	if (mce->status & MCI_STATUS_UC) {
		eventCode = SPH_IPC_ERROR_MCE_UNCORRECTABLE;

		/* check if error in kernel space then report fatal ECC event and reset the device
		 * if error in userspace and processor context is not corrupted,
		 * then kernel will kill the user process
		 * (need to have proper kernel configuration to enable such driver).
		 */
		if (!((mce->cs & 3) == 3) ||
		    (mce->status & MCI_STATUS_PCC)) {
			/* kernel space */
			sph_log_info(MCE_LOG, "FATAL MCE Error is_ecc_error=%d mci_status=0x%llx addr=0x%llx misc=0x%llx\n",
				     is_ecc_err,
				     mce->status,
				     mce->addr,
				     mce->misc);
			eventCode = SPH_IPC_ERROR_MCE_UNCORRECTABLE_FATAL;

			/* report event to host */
			event.value = 0;
			event.opcode = SPH_IPC_C2H_OP_EVENT_REPORT;
			event.eventCode = eventCode;
			event.eventVal = eventVal;
			g_the_sphcs->hw_ops->write_mesg(g_the_sphcs->hw_handle,
							&event.value,
							1);

			/* wait a little then reset the card */
			INIT_DELAYED_WORK(&g_the_sphcs->init_delayed_reset, sphcs_delayed_reset);
			schedule_delayed_work(&g_the_sphcs->init_delayed_reset, msecs_to_jiffies(500));
			return NOTIFY_OK;
		}

		sph_log_info(MCE_LOG, "Uncorrectable MCE Error is_ecc_error=%d mci_status=0x%llx addr=0x%llx misc=0x%llx\n",
			     is_ecc_err,
			     mce->status,
			     mce->addr,
			     mce->misc);

		if (is_ecc_err)
			SPH_SW_COUNTER_ATOMIC_INC(g_sph_sw_counters,
						  SPHCS_SW_COUNTERS_ECC_UNCORRECTABLE_ERROR);
		else
			SPH_SW_COUNTER_ATOMIC_INC(g_sph_sw_counters,
						  SPHCS_SW_COUNTERS_MCE_UNCORRECTABLE_ERROR);

		/* report event to host */
		event.value = 0;
		event.opcode = SPH_IPC_C2H_OP_EVENT_REPORT;
		event.eventCode = eventCode;
		event.eventVal = eventVal;
		g_the_sphcs->hw_ops->write_mesg(g_the_sphcs->hw_handle,
						&event.value,
						1);
	} else {
		/* Corrected Error (signaled via both MCE/CMC)*/
		sph_log_info(MCE_LOG, "Correctable MCE Error is_ecc_error=%d mci_status=0x%llx addr=0x%llx misc=0x%llx\n",
			     is_ecc_err,
			     mce->status,
			     mce->addr,
			     mce->misc);

		SPH_SW_COUNTER_ATOMIC_INC(g_sph_sw_counters,
					  SPHCS_SW_COUNTERS_ECC_CORRECTABLE_ERROR);
		eventCode = SPH_IPC_ERROR_MCE_CORRECTABLE;

		/* report event to host */
		sphcs_send_event_report(g_the_sphcs, eventCode, eventVal, NULL, -1, -1);
	}

	return NOTIFY_OK;
}
#endif

static void sphcs_remove_p2p_heap(void)
{
#ifdef CARD_PLATFORM_BR
	if (p2p_heap_handle)
		ion_chunk_heap_remove(p2p_heap_handle);
#endif
}

static int sphcs_create_p2p_heap(struct sphcs *sphcs)
{
	int ret = 0;

#ifdef CARD_PLATFORM_BR
	struct mem_region *reg;

	reg = vmalloc(sizeof(struct mem_region));

	/* the first SPH_CRASH_DUMP_SIZE bytes of the memory, accessed through BAR2,
	 * are reserved for the crash dump, the rest are managed by peer-to-peer heap
	 */
	if (!reg) {
		sph_log_err(START_UP_LOG, "Allocation failure during p2p heap creation\n");
		return -ENOMEM;
	}
	reg->start = sphcs->inbound_mem_dma_addr + SPH_CRASH_DUMP_SIZE;
	reg->size = sphcs->inbound_mem_size - SPH_CRASH_DUMP_SIZE;
	list_add(&reg->list, &p2p_regions);
	p2p_heap_handle = ion_chunk_heap_setup(&p2p_regions, P2P_HEAP_NAME);
	list_del(&reg->list);
	vfree(reg);

	if (IS_ERR(p2p_heap_handle)) {
		sph_log_err(START_UP_LOG, "Failed to create p2p heap\n");
		ret = PTR_ERR(p2p_heap_handle);
		p2p_heap_handle = NULL;
	} else
		sph_log_debug(START_UP_LOG, "p2p heap successfully created\n");
#endif

	return ret;

}

struct hostres_dma_command_data {
	void               *vptr;
	page_handle         card_dma_page_hndl;
	dma_addr_t          card_dma_addr;
	struct sg_table     host_sgt;
	struct scatterlist *sgl_curr;
	u32                 pages_count;
	uint64_t            total_size;
	hostres_pagetable_cb completion_cb;
	void               *cb_ctx;
};

static int host_page_list_dma_completed(struct sphcs *sphcs, void *ctx, const void *user_data, int status, u32 xferTimeUS)
{
	struct hostres_dma_command_data *dma_req_data = *((struct hostres_dma_command_data **)user_data);
	struct dma_chain_header *chain_header;
	struct dma_chain_entry *chain_entry;
	struct scatterlist *current_sgl;
	struct sg_table *host_sgt = &dma_req_data->host_sgt;
	dma_addr_t dma_src_addr;
	uint64_t total_entries_bytes = 0;
	int i, res = 0;
	enum event_val eventVal = 0;
	uint32_t start_offset = 0;

	if (unlikely(status == SPHCS_DMA_STATUS_FAILED)) {
		/* dma failed */
		sph_log_err(CREATE_COMMAND_LOG, "FATAL: line:%u DMA of host page list number %u failed with status=%d\n",
				__LINE__, dma_req_data->pages_count, status);
		res = -EFAULT;
		eventVal = SPH_IPC_DMA_ERROR;
		goto done;
	}

	/* if status is not an error - it must be done */
	SPH_ASSERT(status == SPHCS_DMA_STATUS_DONE);

	chain_header = (struct dma_chain_header *)dma_req_data->vptr;
	chain_entry = (struct dma_chain_entry *)(dma_req_data->vptr + sizeof(struct dma_chain_header));

	if (dma_req_data->pages_count == 0) { // this is the first page
		res = sg_alloc_table(host_sgt, chain_header->total_nents, GFP_KERNEL);
		if (unlikely(res < 0)) {
			sph_log_err(CREATE_COMMAND_LOG, "FATAL: line:%u err=%d failed to allocate sg_table\n",  __LINE__, res);
			eventVal = SPH_IPC_NO_MEMORY;
			goto done;
		}
		dma_req_data->sgl_curr = &(host_sgt->sgl[0]);
		start_offset = chain_header->start_offset;
	}

	SPH_ASSERT(host_sgt->orig_nents == chain_header->total_nents);

	dma_req_data->pages_count++;

	// set address of next DMA page
	dma_src_addr = chain_header->dma_next;

	// iterate over host's DMA address entries, and fill host sg_table
	// make sure we are not reading last entry, in a non-full page
	// make sure we are not reading more than one page
	current_sgl = dma_req_data->sgl_curr;
	for (i = 0; !sg_is_last(current_sgl) && i < NENTS_PER_PAGE; i++) {
		current_sgl->length = chain_entry[i].n_pages * SPH_PAGE_SIZE;
		current_sgl->dma_address = SPH_IPC_DMA_PFN_TO_ADDR(chain_entry[i].dma_chunk_pfn);

		total_entries_bytes = total_entries_bytes + current_sgl->length;

		SPH_ASSERT(chain_header->size >= total_entries_bytes);

		if (start_offset > 0) {
			current_sgl->offset = start_offset;
			current_sgl->dma_address += start_offset;
			current_sgl->length -= start_offset;
			start_offset = 0;
		}

		current_sgl = sg_next(current_sgl);
	}

	// This is a bit confusing, need to remember that: last entry
	// in the current page doesn't necessarily mean last in sg table.
	// But last in sg table for sure means this is last enrty
	// in the last page.
	if (i >= NENTS_PER_PAGE) { // Finished with this page
		SPH_ASSERT(chain_header->size == total_entries_bytes);
		dma_req_data->sgl_curr = current_sgl;
	} else { // Still in the page and got to the last entry in sg table
		SPH_ASSERT(sg_is_last(current_sgl));
		SPH_ASSERT(chain_header->size > total_entries_bytes);
		SPH_ASSERT(dma_src_addr == 0x0);
		current_sgl->dma_address = SPH_IPC_DMA_PFN_TO_ADDR(chain_entry[i].dma_chunk_pfn);

		// update the length of last entry
		SPH_ASSERT(chain_entry[i].n_pages * SPH_PAGE_SIZE >= chain_header->size - total_entries_bytes);
		current_sgl->length = chain_header->size - total_entries_bytes;

		if (start_offset > 0) {
			current_sgl->offset = start_offset;
			current_sgl->dma_address += start_offset;
			current_sgl->length -= start_offset;
			start_offset = 0;
		}
	}

	/* Finished to iterate the current page and update host sg table */
	dma_req_data->total_size += (chain_header->size - chain_header->start_offset);

	// read next DMA page
	if (dma_src_addr != 0x0) {
		res = sphcs_dma_sched_start_xfer_single(g_the_sphcs->dmaSched,
							&g_dma_desc_h2c_normal,
							dma_src_addr,
							dma_req_data->card_dma_addr,
							SPH_PAGE_SIZE,
							host_page_list_dma_completed,
							ctx,
							&dma_req_data,
							sizeof(dma_req_data));
		if (unlikely(res < 0)) {
			sph_log_err(CREATE_COMMAND_LOG, "FATAL: line: %u err=%d failed to sched dma\n", __LINE__, res);
			eventVal = SPH_IPC_NO_MEMORY;
			goto done;
		}
	} else {
		// done reading all host DMA pages.
		goto done;

	}

	return res;

done:
	if (eventVal != 0) {
		if (dma_req_data->pages_count != 0)
			sg_free_table(host_sgt);
	}

	dma_req_data->completion_cb(dma_req_data->cb_ctx,
				    eventVal,
				    host_sgt,
				    dma_req_data->total_size);

	dma_page_pool_set_page_free(g_the_sphcs->dma_page_pool, dma_req_data->card_dma_page_hndl);
	kfree(dma_req_data);

	return res;
}

int sphcs_retrieve_hostres_pagetable(uint64_t             hostDmaAddr,
				     hostres_pagetable_cb completion_cb,
				     void                *cb_ctx)
{
	struct hostres_dma_command_data *dma_req_data;
	dma_addr_t dma_src_addr = (dma_addr_t)hostDmaAddr;
	int res;

	dma_req_data = kzalloc(sizeof(*dma_req_data), GFP_KERNEL);
	if (unlikely(dma_req_data == NULL)) {
		sph_log_err(CREATE_COMMAND_LOG, "FATAL: %s():%u failed to allocate dma req object\n", __func__, __LINE__);
		return -ENOMEM;
	}


	// get free page from pool to hold the page DMA'ed from host
	res = dma_page_pool_get_free_page(g_the_sphcs->dma_page_pool,
					  &dma_req_data->card_dma_page_hndl,
					  &dma_req_data->vptr,
					  &dma_req_data->card_dma_addr);
	if (unlikely(res < 0)) {
		sph_log_err(CREATE_COMMAND_LOG, "FATAL: %s():%u err=%u failed to get free page for host dma page list\n", __func__, __LINE__, res);
		goto free_dma_req_data;
	}

	dma_req_data->pages_count = 0;
	dma_req_data->completion_cb = completion_cb;
	dma_req_data->cb_ctx = cb_ctx;
	dma_req_data->total_size = 0;

	res = sphcs_dma_sched_start_xfer_single(g_the_sphcs->dmaSched,
						&g_dma_desc_h2c_normal,
						dma_src_addr,
						dma_req_data->card_dma_addr,
						SPH_PAGE_SIZE,
						host_page_list_dma_completed,
						NULL,
						&dma_req_data,
						sizeof(dma_req_data));
	if (unlikely(res < 0)) {
		sph_log_err(CREATE_COMMAND_LOG, "FATAL: %s():%u err=%u failed to sched dma\n", __func__, __LINE__, res);
		goto free_page;
	}


	return 0;

free_page:
	dma_page_pool_set_page_free(g_the_sphcs->dma_page_pool, dma_req_data->card_dma_page_hndl);
free_dma_req_data:
	kfree(dma_req_data);

	return res;
}


static int sphcs_create_sphcs(void                           *hw_handle,
			      struct device                  *hw_device,
			      const struct sphcs_pcie_hw_ops *hw_ops,
			      struct sphcs                  **out_sphcs,
			      struct sphcs_dma_sched        **out_dmaSched)
{
	struct sphcs *sphcs;
	int ret = 0;

	/* Only a single command streamer should be created - fail if it is already exist */
	if (g_the_sphcs != NULL)
		return -EBUSY;

	sphcs = kzalloc(sizeof(struct sphcs), GFP_KERNEL);
	if (!sphcs)
		return -ENOMEM;

	sphcs->hw_handle = hw_handle;
	sphcs->hw_device = hw_device;
	sphcs->hw_ops = hw_ops;

	/* Retrieve addresses set by BIOS and create peer-to-peer heap */
	if (sphcs->hw_ops->get_inbound_mem) {
		sphcs->hw_ops->get_inbound_mem(sphcs->hw_handle, &sphcs->inbound_mem_dma_addr, &sphcs->inbound_mem_size);
		sph_log_info(GENERAL_LOG, "Inbound memory: base addr %pad, size - %zu\n", &sphcs->inbound_mem_dma_addr, sphcs->inbound_mem_size);
		if (sphcs->inbound_mem_dma_addr) {
			ret = sphcs_create_p2p_heap(sphcs);
			if (ret) {
				sph_log_err(START_UP_LOG, "Failed to create p2p heap\n");
				goto free_mem;
			}
		}
	}

	sphcs->debugfs_dir = debugfs_create_dir("sphcs", NULL);
	if (IS_ERR_OR_NULL(sphcs->debugfs_dir)) {
		sph_log_info(START_UP_LOG, "Failed to create debugfs dir - debugfs will not be used\n");
		sphcs->debugfs_dir = NULL;
	}

	ret = dma_page_pool_create(sphcs->hw_device, 128, &sphcs->dma_page_pool);
	if (ret < 0) {
		sph_log_err(START_UP_LOG, "Failed to create dma page pool\n");
		goto free_p2p_heap;
	}

	dma_page_pool_init_debugfs(sphcs->dma_page_pool,
				   sphcs->debugfs_dir,
				   "dma_page_pool");

	ret = dma_page_pool_create(sphcs->hw_device, 32, &sphcs->net_dma_page_pool);
	if (ret < 0) {
		sph_log_err(START_UP_LOG, "Failed to create net dma page pool\n");
		goto free_dma_pool;
	}

	dma_page_pool_init_debugfs(sphcs->net_dma_page_pool,
				   sphcs->debugfs_dir,
				   "net_dma_page_pool");

	sphcs->respq_sched = msg_scheduler_create();
	if (!sphcs->respq_sched) {
		sph_log_err(START_UP_LOG, "Failed to create response q scheduler\n");
		goto free_net_dma_pool;
	}

	msg_scheduler_init_debugfs(sphcs->respq_sched,
				   sphcs->debugfs_dir,
				   "msg_sched");

	sphcs->public_respq = sphcs_create_response_queue(sphcs, 1);
	if (!sphcs->public_respq) {
		sph_log_err(START_UP_LOG, "Failed to create public response q\n");
		goto free_respq_sched;
	}

	sphcs->net_respq = sphcs_create_response_queue(sphcs, 1);
	if (!sphcs->net_respq) {
		sph_log_err(START_UP_LOG, "Failed to create net response q\n");
		goto free_public_respq;
	}

	if (sphcs_create_response_page_pool(sphcs->net_respq, 0) < 0) {
		sph_log_err(START_UP_LOG, "Failed to create net response pool\n");
		goto free_net_respq;
	}

	ret = sphcs_dma_sched_create(sphcs,
			&sphcs->hw_ops->dma,
			sphcs->hw_handle,
			&sphcs->dmaSched);
	if (ret) {
		sph_log_err(START_UP_LOG, "Failed to create dma scheduler\n");
		goto free_net_respq;
	}

	sphcs_dma_sched_init_debugfs(sphcs->dmaSched,
				     sphcs->debugfs_dir,
				     "dma_sched");

	sphcs->wq = alloc_workqueue("sphcs_wq", WQ_UNBOUND, 0);
	if (!sphcs->wq) {
		sph_log_err(START_UP_LOG, "Failed to initialize workqueue\n");
		goto free_sched;
	}

	ret = inference_init(sphcs);
	if (ret) {
		sph_log_err(START_UP_LOG, "Failed to initialize inference module\n");
		goto free_sched;
	}

	sphcs_inf_init_debugfs(sphcs->debugfs_dir);

	ret = sph_create_sw_counters_info_node(NULL,
					       &g_sw_counters_set_global,
					       NULL,
					       &g_hSwCountersInfo_global);
	if (ret) {
		sph_log_err(START_UP_LOG, "Failed to initialize sw counters module\n");
		goto free_inference;
	}
	ret = sph_create_sw_counters_info_node(NULL,
					       &g_sw_counters_set_context,
					       g_hSwCountersInfo_global,
					       &g_hSwCountersInfo_context);
	if (ret) {
		sph_log_err(START_UP_LOG, "Failed to initialize sw counters module\n");
		goto free_counters_info_global;
	}
	ret = sph_create_sw_counters_values_node(g_hSwCountersInfo_global,
						 0x0,
						 NULL,
						 &g_sph_sw_counters);
	if (ret) {
		sph_log_err(START_UP_LOG, "Failed to initialize sw counters module\n");
		goto free_counters_info_context;
	}

	ret = sph_create_sw_counters_info_node(NULL,
					       &g_sw_counters_set_network,
					       g_hSwCountersInfo_context,
					       &g_hSwCountersInfo_network);
	if (ret) {
		sph_log_err(START_UP_LOG, "Failed to initialize sw network counters info\n");
		goto free_counters_values;
	}

	ret = sph_create_sw_counters_info_node(NULL,
					       &g_sw_counters_set_copy,
					       g_hSwCountersInfo_context,
					       &g_hSwCountersInfo_copy);
	if (ret) {
		sph_log_err(START_UP_LOG, "Failed to initialize sw copy counters info\n");
		goto free_counters_network;
	}

	ret = sph_create_sw_counters_info_node(NULL,
					       &g_sw_counters_set_infreq,
					       g_hSwCountersInfo_network,
					       &g_hSwCountersInfo_infreq);
	if (ret) {
		sph_log_err(START_UP_LOG, "Failed to initialize sw infreq counters info\n");
		goto free_counters_copy;
	}

	sphcs_maint_init_debugfs(sphcs->debugfs_dir);

	sphcs->periodic_timer.timer_interval_ms = 50;
	periodic_timer_init(&sphcs->periodic_timer, NULL);
	spin_lock_init(&sphcs->lock_bh);
	hash_init(sphcs->cmd_chan_hash);

	*out_sphcs = sphcs;
	*out_dmaSched = sphcs->dmaSched;
	g_the_sphcs = sphcs;

	ret = sphcs_init_th_driver();
	if (ret) {
		sph_log_err(START_UP_LOG, "Failed to initialize intel trace hub module\n");
		goto free_counters_infreq;
	}

	hwtrace_init_debugfs(&sphcs->hw_tracing,
				sphcs->debugfs_dir,
				"hwtrace");

	ret = sphcs_crash_dump_init();
	if (ret) {
		sph_log_err(START_UP_LOG, "Failed to init crash dump\n");
		goto free_intel_th_driver;
	}

	ret = sphcs_ibecc_init();
	if (ret) {
		sph_log_err(START_UP_LOG, "Failed to init ibecc\n");
		goto cleanup_crash_dump;
	}

	// Set card boot state as "Driver ready"
	sphcs->hw_ops->set_card_doorbell_value(hw_handle,
				    (SPH_CARD_BOOT_STATE_DRV_READY <<
				     SPH_CARD_BOOT_STATE_SHIFT));

#ifndef NO_MCE
	/* register device to reveice mce events (through kernel apei report interface) */
	sphcs->mce_notifier.notifier_call = handle_mce_event;
	sphcs->mce_notifier.priority = MCE_PRIO_MCELOG;
	mce_register_decode_chain(&sphcs->mce_notifier);
#endif

	sph_log_debug(START_UP_LOG, "Created command streamer\n");
	return 0;

cleanup_crash_dump:
	sphcs_crash_dump_cleanup();
free_intel_th_driver:
	sphcs_deinit_th_driver();
free_counters_infreq:
	sph_remove_sw_counters_info_node(g_hSwCountersInfo_infreq);
free_counters_copy:
	sph_remove_sw_counters_info_node(g_hSwCountersInfo_copy);
free_counters_network:
	sph_remove_sw_counters_info_node(g_hSwCountersInfo_network);
free_counters_values:
	sph_remove_sw_counters_values_node(g_sph_sw_counters);
free_counters_info_context:
	sph_remove_sw_counters_info_node(g_hSwCountersInfo_context);
free_counters_info_global:
	sph_remove_sw_counters_info_node(g_hSwCountersInfo_global);
free_inference:
	inference_fini(sphcs);
free_sched:
	sphcs_dma_sched_destroy(sphcs->dmaSched);
free_net_respq:
	sphcs_response_pool_destroy_page_pool(0);
	sphcs_destroy_response_queue(sphcs, sphcs->net_respq);
free_public_respq:
	sphcs_destroy_response_queue(sphcs, sphcs->public_respq);
free_respq_sched:
	msg_scheduler_destroy(sphcs->respq_sched);
free_net_dma_pool:
	dma_page_pool_destroy(sphcs->net_dma_page_pool);
free_dma_pool:
	dma_page_pool_destroy(sphcs->dma_page_pool);
free_p2p_heap:
	sphcs_remove_p2p_heap();
free_mem:
	debugfs_remove_recursive(sphcs->debugfs_dir);
	kfree(sphcs);
	return ret;
}

static void sphcs_clean_host_resp_pages_list(struct sphcs *sphcs)
{
	sphcs_response_pool_clean_page_pool(0);
}

void sphcs_host_doorbell_value_changed(struct sphcs *sphcs,
				       u32           doorbell_value)
{
	uint32_t host_drv_state = (doorbell_value & SPH_HOST_DRV_STATE_MASK) >> SPH_HOST_DRV_STATE_SHIFT;

	sph_log_debug(GENERAL_LOG, "Got host doorbell value 0x%x\n", doorbell_value);

	sphcs_p2p_new_message_arrived();

	sphcs->host_doorbell_val = doorbell_value;

	if (sphcs->host_connected &&
	    host_drv_state == SPH_HOST_DRV_STATE_NOT_READY) {

		/* host driver disconnected */
		sphcs->host_connected = 0;

		sphcs_clean_host_resp_pages_list(sphcs);

		sphcs_crash_dump_setup_host_addr(0);
		sphcs->host_sys_info_dma_addr_valid = false;
	} else if (!sphcs->host_connected &&
		   host_drv_state == SPH_HOST_DRV_STATE_READY) {

		/* host driver connected */
		sphcs->host_connected = 1;

		/* host connected - safe to initialize DMA engine now
		 * as we probably allowed for bus master operations
		 */
		sphcs->hw_ops->dma.init_dma_engine(sphcs->hw_handle);
	}
}

static int sphcs_destroy_sphcs(struct sphcs *sphcs)
{

#ifndef NO_MCE
	/* unregister MCE events */
	mce_unregister_decode_chain(&sphcs->mce_notifier);
#endif
	// Set card boot state as "Not ready"
	sphcs->hw_ops->set_card_doorbell_value(sphcs->hw_handle,
			    (SPH_CARD_BOOT_STATE_NOT_READY <<
			     SPH_CARD_BOOT_STATE_SHIFT));
	sphcs_ibecc_fini();
	sphcs_crash_dump_cleanup();
	destroy_workqueue(sphcs->wq);
	inference_fini(sphcs);
	sphcs_dma_sched_destroy(sphcs->dmaSched);
	msg_scheduler_queue_flush(sphcs->public_respq);
	sphcs_destroy_response_queue(sphcs, sphcs->public_respq);
	sphcs_destroy_response_queue(sphcs, sphcs->net_respq);
	msg_scheduler_destroy(sphcs->respq_sched);
	dma_page_pool_destroy(sphcs->dma_page_pool);
	dma_page_pool_destroy(sphcs->net_dma_page_pool);
	periodic_timer_delete(&sphcs->periodic_timer);
	sph_remove_sw_counters_values_node(g_sph_sw_counters);
	sph_remove_sw_counters_info_node(g_hSwCountersInfo_infreq);
	sph_remove_sw_counters_info_node(g_hSwCountersInfo_copy);
	sph_remove_sw_counters_info_node(g_hSwCountersInfo_network);
	sph_remove_sw_counters_info_node(g_hSwCountersInfo_context);
	sph_remove_sw_counters_info_node(g_hSwCountersInfo_global);
	sphcs_response_pool_destroy_page_pool(0);
	sphcs_deinit_th_driver();
	g_the_sphcs = NULL;
	debugfs_remove_recursive(sphcs->debugfs_dir);

	sphcs_remove_p2p_heap();

	kfree(sphcs);

	return 0;
}

struct sphcs_pcie_callbacks g_sphcs_pcie_callbacks = {

	.create_sphcs = sphcs_create_sphcs,
	.host_doorbell_value_changed = sphcs_host_doorbell_value_changed,
	.destroy_sphcs = sphcs_destroy_sphcs,
	.process_messages = sphcs_process_messages,

	.dma.h2c_xfer_complete_int = sphcs_dma_sched_h2c_xfer_complete_int,
	.dma.c2h_xfer_complete_int = sphcs_dma_sched_c2h_xfer_complete_int,
};

