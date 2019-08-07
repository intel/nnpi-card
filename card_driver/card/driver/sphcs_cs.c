/********************************************
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/
#include "sphcs_cs.h"
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/jiffies.h>
#include <linux/workqueue.h>
#include "ipc_protocol.h"
#ifdef ULT
#include "sphcs_ult.h"
#include "ipc_protocol_ult.h"
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
#include <linux/delay.h>
#include <linux/reboot.h>
#include <linux/version.h>

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

void sphcs_send_event_report(struct sphcs *sphcs,
			     uint16_t eventCode,
			     uint16_t eventVal,
			     int contextID,
			     int objID)
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
	if (objID >= 0) {
		event.objID = objID;
		event.objValid = 1;
	}

	log_c2h_event("Sending event", &event);

	sphcs_msg_scheduler_queue_add_msg(sphcs->public_respq, &event.value, 1);
}

void sphcs_send_event_report_ext(struct sphcs *sphcs,
				 uint16_t eventCode,
				 uint16_t eventVal,
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

	sphcs_msg_scheduler_queue_add_msg(sphcs->public_respq, &event.value, 1);
}

static void IPC_OPCODE_HANDLER(QUERY_VERSION)(
				struct sphcs *sphcs,
				union h2c_QueryVersionMsg *msg)
{
	union c2h_QueryVersionReplyMsg replyMsg;

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
	if (sphcs->hw_ops->map_inbound_mem &&
	    sphcs->inbound_mem &&
	    setup_msg->membar_addr) {
		sphcs->hw_ops->map_inbound_mem(sphcs->hw_handle,
					       setup_msg->membar_addr,
					       sphcs->inbound_mem_dma_addr,
					       SPH_INBOUND_MEM_SIZE);
	}
}

static void IPC_OPCODE_HANDLER(CLOCK_SYNC)(
			struct sphcs       *sphcs,
			union ClockSyncMsg *cmd)
{
	union ClockSyncMsg msg;

	// send echo to the host
	memset(msg.value, 0, sizeof(msg.value));
	msg.opcode  = SPH_IPC_C2H_OP_CLOCK_SYNC;
	msg.o_card_ts = sph_time_us();
	sphcs_msg_scheduler_queue_add_msg(g_the_sphcs->public_respq,
				    (u64 *)msg.value,
				    sizeof(msg) / sizeof(u64));
}

/*
 * process_bios_message - process a message from HWQ coming from bios.
 * bios protocol may have different size messages.
 * This function should not normally be called since the host should not
 * communicate with bios when the card driver is already up. Just make sure to
 * remove the message from queue if it does been sent.
 * avail_size is the number of 64-bit units available from the msg pointer
 * if the message size is larger, the function should return 0 and do not process
 * the message, otherwise the function should process the message and return the
 * actual processed message size (in 64-bit units).
 */
static int process_bios_message(union sph_bios_ipc_header *msg,
				uint32_t                   avail_size)
{
	int msg_size = ((msg->size + 7) / 8) + 1; /* size field does not include header */

	if (msg_size > avail_size)
		return 0;

	sph_log_err(CREATE_COMMAND_LOG, "Got Bios protocol H2C message type 0x%x (header=0x%llx)\n",
		    msg->msgType, msg->value);

	return msg_size;
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
	int j = 0;
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
		int msg_size = 0;
		int partial_msg = 0;

		/* dispatch the message request */
		#define H2C_OPCODE(name,val,type)                                    \
			case (val):                                                  \
			msg_size = sizeof(type)/sizeof(u64);                         \
			if (msg_size > (size-j))                                     \
				partial_msg = 1;                                     \
			else {                                                        \
				DO_TRACE(trace_ipc(0, &msg[j], msg_size));           \
				CALL_IPC_OPCODE_HANDLER(name, type, sphcs, &msg[j]); \
			} \
			break;


		switch(opCode) {
		#include "ipc_h2c_opcodes.h"
		case SPH_IPC_H2C_OP_BIOS_PROTOCOL:
			msg_size = process_bios_message((union sph_bios_ipc_header *)&msg[j], (size-j));
			partial_msg = (msg_size == 0);
			#ifdef ULT
			if (partial_msg == 0) {
				DO_TRACE(trace_ipc(0, &msg[j], msg_size));
				sphcs_ult_process_bios_message(sphcs, &msg[j]);
			}
			#endif
			break;

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

	DO_TRACE(trace_ipc(1, msg, size));

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

			if (is_ecc_err)
				SPH_SW_COUNTER_ATOMIC_INC(g_sph_sw_counters,
							  SPHCS_SW_COUNTERS_ECC_UNCORRECTABLE_ERROR_FATAL);
			else
				SPH_SW_COUNTER_ATOMIC_INC(g_sph_sw_counters,
							  SPHCS_SW_COUNTERS_MCE_UNCORRECTABLE_ERROR_FATAL);

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
		sphcs_send_event_report(g_the_sphcs, eventCode, eventVal, -1, -1);
	}

	return NOTIFY_OK;
}
#endif

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

	sphcs->debugfs_dir = debugfs_create_dir("sphcs", NULL);
	if (IS_ERR_OR_NULL(sphcs->debugfs_dir)) {
		sph_log_info(START_UP_LOG, "Failed to create debugfs dir - debugfs will not be used\n");
		sphcs->debugfs_dir = NULL;
	}

	ret = dma_page_pool_create(sphcs->hw_device, 128, &sphcs->dma_page_pool);
	if (ret < 0) {
		sph_log_err(START_UP_LOG, "Failed to create dma page pool\n");
		goto free_mem;
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

	if (sphcs_create_response_page_pool(sphcs->public_respq, 0) < 0) {
		sph_log_err(START_UP_LOG, "Failed to create main response pool\n");
		goto free_public_respq;
	}

	sphcs->net_respq = sphcs_create_response_queue(sphcs, 1);
	if (!sphcs->net_respq) {
		sph_log_err(START_UP_LOG, "Failed to create net response q\n");
		goto free_public_respq;
	}

	if (sphcs_create_response_page_pool(sphcs->net_respq, 1) < 0) {
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

	sphcs->wq = create_workqueue("sphcs_wq");
	if (!sphcs->wq) {
		sph_log_err(START_UP_LOG, "Failed to initialize workqueue\n");
		goto free_sched;
	}

	ret = inference_init(sphcs);
	if (ret) {
		sph_log_err(START_UP_LOG, "Failed to initialize inference module\n");
		goto free_sched;
	}

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

	*out_sphcs = sphcs;
	*out_dmaSched = sphcs->dmaSched;
	g_the_sphcs = sphcs;

	if (sphcs->hw_ops->map_inbound_mem) {
		sphcs->inbound_mem =
			(struct sph_inbound_mem *)dma_alloc_coherent(sphcs->hw_device,
								     SPH_INBOUND_MEM_SIZE,
								     &sphcs->inbound_mem_dma_addr,
								     GFP_KERNEL);
		if (!sphcs->inbound_mem) {
			sph_log_err(START_UP_LOG,
				    "Failed to allocate inbound memory region of %u bytes vaddr=0x%lx\n",
				    SPH_INBOUND_MEM_SIZE,
				    (uintptr_t)sphcs->inbound_mem);
			ret = -ENOMEM;
			goto free_counters_infreq;
		} else {
			sphcs->inbound_mem->magic = SPH_INBOUND_MEM_MAGIC;
			sphcs->inbound_mem->crash_dump_size = 0;
		}
	}

	ret = sphcs_init_th_driver();
	if (ret) {
		sph_log_err(START_UP_LOG, "Failed to initialize intel trace hub module\n");
		goto free_inbound_mem;
	}

	ret = sphcs_crash_dump_init();
	if (ret) {
		sph_log_err(START_UP_LOG, "Failed to init crash dump\n");
		goto free_intel_th_driver;
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
free_intel_th_driver:
	sphcs_deinit_th_driver();
free_inbound_mem:
	if (sphcs->inbound_mem)
		dma_free_coherent(sphcs->hw_device,
				  SPH_INBOUND_MEM_SIZE,
				  sphcs->inbound_mem,
				  sphcs->inbound_mem_dma_addr);
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
	sphcs_response_pool_destroy_page_pool(1);
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
free_mem:
	debugfs_remove_recursive(sphcs->debugfs_dir);
	kfree(sphcs);
	return ret;
}

static void sphcs_clean_host_resp_pages_list(struct sphcs *sphcs)
{
	int i;

	for (i = 0; i < 2; i++)
		sphcs_response_pool_clean_page_pool(i);
}

void sphcs_host_doorbell_value_changed(struct sphcs *sphcs,
				       u32           doorbell_value)
{
	uint32_t host_drv_state = (doorbell_value & SPH_HOST_DRV_STATE_MASK) >> SPH_HOST_DRV_STATE_SHIFT;

	sph_log_debug(GENERAL_LOG, "Got host doorbell value 0x%x\n", doorbell_value);

	sphcs->host_doorbell_val = doorbell_value;

	if (sphcs->host_connected &&
	    host_drv_state == SPH_HOST_DRV_STATE_NOT_READY) {

		/* host driver disconnected */
		sphcs->host_connected = 0;

		sphcs_clean_host_resp_pages_list(sphcs);

		sphcs_crash_dump_setup_host_addr(0);
	} else if (!sphcs->host_connected &&
		   host_drv_state == SPH_HOST_DRV_STATE_READY) {

		/* host driver connected */
		sphcs->host_connected = 1;

		/* host connected - safe to initialize DMA engine now
		 * as we probably allowed for bus master operations
		 */
		sphcs->hw_ops->dma.init_dma_engine(sphcs->hw_handle);

		/* send host sys_info packet, if available */
		sphcs_maint_send_sys_info();
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
	sphcs_response_pool_destroy_page_pool(1);
	sphcs_deinit_th_driver();
	g_the_sphcs = NULL;
	debugfs_remove_recursive(sphcs->debugfs_dir);

	if (sphcs->inbound_mem)
		dma_free_coherent(sphcs->hw_device,
				  SPH_INBOUND_MEM_SIZE,
				  sphcs->inbound_mem,
				  sphcs->inbound_mem_dma_addr);

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

