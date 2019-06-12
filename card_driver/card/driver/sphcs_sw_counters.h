/********************************************
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#ifndef __SPHCS_SW_COUNTERS_H
#define __SPHCS_SW_COUNTERS_H

#include "sw_counters.h"

enum SPHCS_SW_COUNTERS_GROUPS {
	SPHCS_SW_COUNTERS_GROUP_IPC,
	SPHCS_SW_COUNTERS_GROUP_DMA,
	SPHCS_SW_COUNTERS_GROUP_INFERENCE,
	SPHCS_SW_COUNTERS_GROUP_MCE,
};

static const struct sph_sw_counters_group_info g_sphcs_sw_counters_groups_info[] = {
	/* SPHCS_SW_COUNTERS_GROUP_IPC */
	{"ipc", "group for entire ipc sw counters"},
	/* SPHCS_SW_COUNTERS_GROUP_DMA */
	{"dma", "group for entire dma sw counters"},
	/* SPHCS_SW_COUNTERS_GROUP_INFERENCE */
	{"inference", "group for command streamer inference sw counters"},
	/* SPHCS_SW_COUNTERS_GROUP_MCE */
	{"mce", "group for mce errors sw counters"}
};

enum SPHCS_SW_COUNTERS_GLOBAL {
	SPHCS_SW_COUNTERS_IPC_COMMANDS_COUNT,
	SPHCS_SW_COUNTERS_IPC_COMMANDS_CONSUME_TIME,
	SPHCS_SW_COUNTERS_IPC_RESPONSES_COUNT,
	SPHCS_SW_COUNTERS_IPC_RESPONSES_WAIT_TIME,
	SPHCS_SW_COUNTERS_IPC_COMMANDS_SCHEDULED_COUNT,
	SPHCS_SW_COUNTERS_DMA_0_H2C_COUNT,
	SPHCS_SW_COUNTERS_DMA_0_H2C_BYTES,
	SPHCS_SW_COUNTERS_DMA_0_H2C_BUSY,
	SPHCS_SW_COUNTERS_DMA_0_C2H_COUNT,
	SPHCS_SW_COUNTERS_DMA_0_C2H_BYTES,
	SPHCS_SW_COUNTERS_DMA_0_C2H_BUSY,
	SPHCS_SW_COUNTERS_DMA_1_H2C_COUNT,
	SPHCS_SW_COUNTERS_DMA_1_H2C_BYTES,
	SPHCS_SW_COUNTERS_DMA_1_H2C_BUSY,
	SPHCS_SW_COUNTERS_DMA_1_C2H_COUNT,
	SPHCS_SW_COUNTERS_DMA_1_C2H_BYTES,
	SPHCS_SW_COUNTERS_DMA_1_C2H_BUSY,
	SPHCS_SW_COUNTERS_DMA_2_H2C_COUNT,
	SPHCS_SW_COUNTERS_DMA_2_H2C_BYTES,
	SPHCS_SW_COUNTERS_DMA_2_H2C_BUSY,
	SPHCS_SW_COUNTERS_DMA_2_C2H_COUNT,
	SPHCS_SW_COUNTERS_DMA_2_C2H_BYTES,
	SPHCS_SW_COUNTERS_DMA_2_C2H_BUSY,
	SPHCS_SW_COUNTERS_DMA_3_H2C_COUNT,
	SPHCS_SW_COUNTERS_DMA_3_H2C_BYTES,
	SPHCS_SW_COUNTERS_DMA_3_H2C_BUSY,
	SPHCS_SW_COUNTERS_DMA_3_C2H_COUNT,
	SPHCS_SW_COUNTERS_DMA_3_C2H_BYTES,
	SPHCS_SW_COUNTERS_DMA_3_C2H_BUSY,
	SPHCS_SW_COUNTERS_INFERENCE_NUM_CONTEXTS,
	SPHCS_SW_COUNTERS_INFERENCE_COMPLETED_INF_REQ,
	SPHCS_SW_COUNTERS_ECC_CORRECTABLE_ERROR,
	SPHCS_SW_COUNTERS_ECC_UNCORRECTABLE_ERROR,
	SPHCS_SW_COUNTERS_ECC_UNCORRECTABLE_ERROR_FATAL,
	SPHCS_SW_COUNTERS_MCE_UNCORRECTABLE_ERROR,
	SPHCS_SW_COUNTERS_MCE_UNCORRECTABLE_ERROR_FATAL,
};

#define SPHCS_SW_DMA_GLOBAL_COUNTER_H2C_COUNT(channel) (SPHCS_SW_COUNTERS_DMA_0_H2C_COUNT + channel * 6)
#define SPHCS_SW_DMA_GLOBAL_COUNTER_H2C_BYTES(channel) (SPHCS_SW_DMA_GLOBAL_COUNTER_H2C_COUNT(channel) + 1)
#define SPHCS_SW_DMA_GLOBAL_COUNTER_H2C_BUSY(channel)  (SPHCS_SW_DMA_GLOBAL_COUNTER_H2C_COUNT(channel) + 2)
#define SPHCS_SW_DMA_GLOBAL_COUNTER_C2H_COUNT(channel) (SPHCS_SW_DMA_GLOBAL_COUNTER_H2C_COUNT(channel) + 3)
#define SPHCS_SW_DMA_GLOBAL_COUNTER_C2H_BYTES(channel) (SPHCS_SW_DMA_GLOBAL_COUNTER_H2C_COUNT(channel) + 4)
#define SPHCS_SW_DMA_GLOBAL_COUNTER_C2H_BUSY(channel)  (SPHCS_SW_DMA_GLOBAL_COUNTER_H2C_COUNT(channel) + 5)



static const struct sph_sw_counter_info g_sphcs_sw_counters_info[] = {
	/* SPHCS_SW_COUNTERS_IPC_COMMANDS_COUNT */
	{SPHCS_SW_COUNTERS_GROUP_IPC, "commands.count",
	 "Number of commands received from host"},
	/* SPHCS_SW_COUNTERS_IPC_COMMANDS_CONSUME_TIME */
	{SPHCS_SW_COUNTERS_GROUP_IPC, "commands.consume_time",
	 "Total time spent on first-level processing of received commands, "
	 "That is time took to consume the commands from IPC layer but not including all time spent on fully executing the reqtested action."},
	/* SPHCS_SW_COUNTERS_IPC_RESPONSES_COUNT */
	{SPHCS_SW_COUNTERS_GROUP_IPC, "responses.count",
	 "Number of response commands sent to card"},
	/* SPHCS_SW_COUNTERS_IPC_RESPONSES_WAIT_TIME */
	{SPHCS_SW_COUNTERS_GROUP_IPC, "responses.wait_time",
	 "Total time spent waiting for free slots in queue for sending a card-to-host response"},
	/*SPHCS_SW_COUNTERS_IPC_COMMANDS_SCHEDULED_COUNT*/
	{SPHCS_SW_COUNTERS_GROUP_IPC, "commands.scheduled_count",
	 "Number of commands scheduled to be transferted on the command"},
	/* SPHCS_SW_COUNTERS_DMA_0_H2C_COUNT */
	{SPHCS_SW_COUNTERS_GROUP_DMA, "h2c.chan0.count",
	 "Number of transfers on host-to-card DMA channel #0"},
	/* SPHCS_SW_COUNTERS_DMA_0_H2C_BYTES */
	{SPHCS_SW_COUNTERS_GROUP_DMA, "h2c.chan0.bytes",
	 "Total number of bytes transferred on host-to-card DMA channel #0"},
	/* SPHCS_SW_COUNTERS_DMA_0_H2C_BUSY */
	{SPHCS_SW_COUNTERS_GROUP_DMA, "h2c.chan0.busy_time",
	 "Total time on which host-to-card DMA channel#0 was busy"},
	/* SPHCS_SW_COUNTERS_DMA_0_C2H_COUNT */
	{SPHCS_SW_COUNTERS_GROUP_DMA, "c2h.chan0.count",
	 "Number of transfers on card-to-host DMA channel #0"},
	/* SPHCS_SW_COUNTERS_DMA_0_C2H_BYTES */
	{SPHCS_SW_COUNTERS_GROUP_DMA, "c2h.chan0.bytes",
	 "Total number of bytes transferred on card-to-host DMA channel #0"},
	/* SPHCS_SW_COUNTERS_DMA_0_C2H_BUSY */
	{SPHCS_SW_COUNTERS_GROUP_DMA, "c2h.chan0.busy_time",
	 "Total time on which card-to-host DMA channel#0 was busy"},
	/* SPHCS_SW_COUNTERS_DMA_1_H2C_COUNT */
	{SPHCS_SW_COUNTERS_GROUP_DMA, "h2c.chan1.count",
	 "Number of transfers on host-to-card DMA channel #1"},
	/* SPHCS_SW_COUNTERS_DMA_1_H2C_BYTES */
	{SPHCS_SW_COUNTERS_GROUP_DMA, "h2c.chan1.bytes",
	 "Total number of bytes transferred on host-to-card DMA channel #1"},
	/* SPHCS_SW_COUNTERS_DMA_1_H2C_BUSY */
	{SPHCS_SW_COUNTERS_GROUP_DMA, "h2c.chan1.busy_time",
	 "Total time on which host-to-card DMA channel#1 was busy"},
	/* SPHCS_SW_COUNTERS_DMA_1_C2H_COUNT */
	{SPHCS_SW_COUNTERS_GROUP_DMA, "c2h.chan1.count",
	 "Number of transfers on card-to-host DMA channel #1"},
	/* SPHCS_SW_COUNTERS_DMA_1_C2H_BYTES */
	{SPHCS_SW_COUNTERS_GROUP_DMA, "c2h.chan1.bytes",
	 "Total number of bytes transferred on card-to-host DMA channel #1"},
	/* SPHCS_SW_COUNTERS_DMA_1_C2H_BUSY */
	{SPHCS_SW_COUNTERS_GROUP_DMA, "c2h.chan1.busy_time",
	 "Total time on which card-to-host DMA channel#1 was busy"},
	/* SPHCS_SW_COUNTERS_DMA_2_H2C_COUNT */
	{SPHCS_SW_COUNTERS_GROUP_DMA, "h2c.chan2.count",
	 "Number of transfers on host-to-card DMA channel #2"},
	/* SPHCS_SW_COUNTERS_DMA_2_H2C_BYTES */
	{SPHCS_SW_COUNTERS_GROUP_DMA, "h2c.chan2.bytes",
	 "Total number of bytes transferred on host-to-card DMA channel #2"},
	/* SPHCS_SW_COUNTERS_DMA_2_H2C_BUSY */
	{SPHCS_SW_COUNTERS_GROUP_DMA, "h2c.chan2.busy_time",
	 "Total time on which host-to-card DMA channel#2 was busy"},
	/* SPHCS_SW_COUNTERS_DMA_2_C2H_COUNT */
	{SPHCS_SW_COUNTERS_GROUP_DMA, "c2h.chan2.count",
	 "Number of transfers on card-to-host DMA channel #2"},
	/* SPHCS_SW_COUNTERS_DMA_2_C2H_BYTES */
	{SPHCS_SW_COUNTERS_GROUP_DMA, "c2h.chan2.bytes",
	 "Total number of bytes transferred on card-to-host DMA channel #2"},
	/* SPHCS_SW_COUNTERS_DMA_2_C2H_BUSY */
	{SPHCS_SW_COUNTERS_GROUP_DMA, "c2h.chan2.busy_time",
	 "Total time on which card-to-host DMA channel#2 was busy"},
	/* SPHCS_SW_COUNTERS_DMA_3_H2C_COUNT */
	{SPHCS_SW_COUNTERS_GROUP_DMA, "h2c.chan3.count",
	 "Number of transfers on host-to-card DMA channel #3"},
	/* SPHCS_SW_COUNTERS_DMA_3_H2C_BYTES */
	{SPHCS_SW_COUNTERS_GROUP_DMA, "h2c.chan3.bytes",
	 "Total number of bytes transferred on host-to-card DMA channel #3"},
	/* SPHCS_SW_COUNTERS_DMA_3_H2C_BUSY */
	{SPHCS_SW_COUNTERS_GROUP_DMA, "h2c.chan3.busy_time",
	 "Total time on which host-to-card DMA channel#3 was busy"},
	/* SPHCS_SW_COUNTERS_DMA_3_C2H_COUNT */
	{SPHCS_SW_COUNTERS_GROUP_DMA, "c2h.chan3.count",
	 "Number of transfers on card-to-host DMA channel #3"},
	/* SPHCS_SW_COUNTERS_DMA_3_C2H_BYTES */
	{SPHCS_SW_COUNTERS_GROUP_DMA, "c2h.chan3.bytes",
	 "Total number of bytes transferred on card-to-host DMA channel #3"},
	/* SPHCS_SW_COUNTERS_DMA_3_C2H_BUSY */
	{SPHCS_SW_COUNTERS_GROUP_DMA, "c2h.chan3.busy_time",
	 "Total time on which card-to-host DMA channel#3 was busy"},
	/* SPHCS_SW_COUNTERS_INFERENCE_NUM_CONTEXTS */
	{SPHCS_SW_COUNTERS_GROUP_INFERENCE, "num_contexts",
	 "Number of inference contexts"},
	/* SPHCS_SW_COUNTERS_INFERENCE_COMPLETED_INF_REQ */
	{SPHCS_SW_COUNTERS_GROUP_INFERENCE, "completed_inf_req",
	 "Total number of completed infer requests"},
	 /* SPHCS_SW_COUNTERS_ECC_CORRECTABLE_ERROR */
	 {SPHCS_SW_COUNTERS_GROUP_MCE, "correctable_ecc",
	 "number of correctable ecc errors"},
	 /* SPHCS_SW_COUNTERS_ECC_UNCORRECTABLE_ERROR */
	 {SPHCS_SW_COUNTERS_GROUP_MCE, "uncorrectable_ecc",
	 "number of uncorrectable ecc errors"},
	 /* SPHCS_SW_COUNTERS_ECC_UNCORRECTABLE_ERROR_FATAL */
	 {SPHCS_SW_COUNTERS_GROUP_MCE, "uncorrectable_fatal_ecc",
	 "number of fatal uncorrectable ecc errors"},
	 /* SPHCS_SW_COUNTERS_MCE_UNCORRECTABLE_ERROR */
	 {SPHCS_SW_COUNTERS_GROUP_MCE, "uncorrectable",
	 "number of uncorrectable general MCE event (not ecc related)"},
	 /* SPHCS_SW_COUNTERS_MCE_UNCORRECTABLE_ERROR_FATAL */
	 {SPHCS_SW_COUNTERS_GROUP_MCE, "uncorrectable_fatal",
	 "number of fatal uncorrectable general MCE events (not ecc related)"},
};

static const struct sph_sw_counters_set g_sw_counters_set_global = {
	"sw_counters",
	false,
	g_sphcs_sw_counters_info,
	ARRAY_SIZE(g_sphcs_sw_counters_info),
	g_sphcs_sw_counters_groups_info,
	ARRAY_SIZE(g_sphcs_sw_counters_groups_info)};

enum CTX_SPHCS_SW_COUNTERS_GROUPS {
	CTX_SPHCS_SW_COUNTERS_GROUP_INFERENCE
};

static const struct sph_sw_counters_group_info g_ctx_sphcs_sw_counters_groups_info[] = {
	/*CTX_SPHCS_SW_COUNTERS_GROUP_INFERENCE*/
	{"inference", "group for command streamer inference sw counters per context"}
};

enum  CTX_SPHCS_SW_COUNTERS {
	CTX_SPHCS_SW_COUNTERS_INFERENCE_NUM_NETWORKS,
	CTX_SPHCS_SW_COUNTERS_INFERENCE_COMPLETED_INF_REQ,
	CTX_SPHCS_SW_COUNTERS_INFERENCE_SUBMITTED_INF_REQ,
	CTX_SPHCS_SW_COUNTERS_INFERENCE_RUNTIME_BUSY_TIME,
	CTX_SPHCS_SW_COUNTERS_INFERENCE_DEVICE_RESOURCE_SIZE
};

static const struct sph_sw_counter_info g_ctx_sphcs_sw_counters_info[] = {
	/* CTX_SPHCS_SW_COUNTERS_INFERENCE_NUM_NETWORKS */
	{CTX_SPHCS_SW_COUNTERS_GROUP_INFERENCE, "num_networks",
	 "Number of inference networks per context"},
	/*CTX_SPHCS_SW_COUNTERS_INFERENCE_COMPLETED_INF_REQ*/
	{CTX_SPHCS_SW_COUNTERS_GROUP_INFERENCE, "completed_inf_req",
	 "Number of completed inference requests per context"},
	/*CTX_SPHCS_SW_COUNTERS_INFERENCE_SUBMITTED_INF_REQ*/
	{CTX_SPHCS_SW_COUNTERS_GROUP_INFERENCE, "submitted_inf_req",
	 "Number of submitted inference requests per context"},
	/*CTX_SPHCS_SW_COUNTERS_INFERENCE_RUNTIME_BUSY_TIME */
	{CTX_SPHCS_SW_COUNTERS_GROUP_INFERENCE, "runtime_busy_time",
	 "Total time in which the runtime has some request in its request queue which did not finished per context"},
	/*CTX_SPHCS_SW_COUNTERS_INFERENCE_DEVICE_RESOURCE_SIZE*/
	{CTX_SPHCS_SW_COUNTERS_GROUP_INFERENCE, "deviceResourceSize",
	 "Size (in bytes) occupied by blob, input and output device resources"}
};

static const struct sph_sw_counters_set g_sw_counters_set_context = {
	"context",
	true,
	g_ctx_sphcs_sw_counters_info,
	ARRAY_SIZE(g_ctx_sphcs_sw_counters_info),
	g_ctx_sphcs_sw_counters_groups_info,
	ARRAY_SIZE(g_ctx_sphcs_sw_counters_groups_info)};

extern void *g_hSwCountersInfo_global;
extern void *g_hSwCountersInfo_context;
extern struct sph_sw_counters *g_sph_sw_counters;



#endif // __SPHCS_SW_COUNTERS_H
