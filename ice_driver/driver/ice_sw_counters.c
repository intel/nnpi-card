/*
 * NNP-I Linux Driver
 * Copyright (c) 2017-2019, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 */

#include "ice_sw_counters.h"
#include "sw_counters.h"

void *g_sph_swc_global;

struct swc_value {
	u64 node_id;
	struct cve_dle_t list;
	struct sph_sw_counters *sw_counters;
};

/* To find the parent of any given class */
uint16_t g_class_parent_map[ICEDRV_SWC_CLASS_MAX];
/* Handle of Software Counter (SWC) Info */
void *g_hswc_info[ICEDRV_SWC_CLASS_MAX];
/* Lists of structure to hold Counter values for each class */
struct swc_value *g_swc_value_list[ICEDRV_SWC_CLASS_MAX];

static const struct sph_sw_counters_group_info g_swc_global_group_info[] = {
	/* ICEDRV_SWC_GLOBAL_GROUP_GEN */
	{"-general", "placeholder for actual global groups"}
};

static const struct sph_sw_counter_info g_swc_global_info[] = {
	/* ICEDRV_SWC_GLOBAL_COUNTER_CTX_TOT */
	{ICEDRV_SWC_GLOBAL_GROUP_GEN, "contextTotal",
	 "Total number of Created Context"},
	/* ICEDRV_SWC_GLOBAL_COUNTER_CTX_CUR */
	{ICEDRV_SWC_GLOBAL_GROUP_GEN, "contextCurrent",
	 "Number of Context that are currently active"},
	/* ICEDRV_SWC_GLOBAL_COUNTER_CTX_DES */
	{ICEDRV_SWC_GLOBAL_GROUP_GEN, "contextDestroyed",
	 "Total number of Destroyed Context"},
	/* ICEDRV_SWC_GLOBAL_ACTIVE_ICE_COUNT */
	{ICEDRV_SWC_GLOBAL_GROUP_GEN, "activeICECount",
	 "Total number of Active ICE"}
};

static const struct sph_sw_counters_set g_swc_global_set = {
	"sw_counters",
	false,
	g_swc_global_info,
	ARRAY_SIZE(g_swc_global_info),
	g_swc_global_group_info,
	ARRAY_SIZE(g_swc_global_group_info)
};

static const struct sph_sw_counters_group_info g_swc_context_group_info[] = {
	/* ICEDRV_SWC_CONTEXT_GROUP_GEN */
	{"-general", "placeholder for actual context groups"},
};

static const struct sph_sw_counter_info g_swc_context_info[] = {
	/* ICEDRV_SWC_CONTEXT_COUNTER_INF_TOT */
	{ICEDRV_SWC_CONTEXT_GROUP_GEN, "inferTotal",
	 "Total number of Created Infer Request"},
	/* ICEDRV_SWC_CONTEXT_COUNTER_INF_CUR */
	{ICEDRV_SWC_CONTEXT_GROUP_GEN, "inferCurrent",
	 "Number of Infer Requests that are currently active"},
	/* ICEDRV_SWC_CONTEXT_COUNTER_INF_DES */
	{ICEDRV_SWC_CONTEXT_GROUP_GEN, "inferDestroyed",
	 "Total number of Destroyed Infer Request"}
};

static const struct sph_sw_counters_set g_swc_context_set = {
	"inference.context",
	true,
	g_swc_context_info,
	ARRAY_SIZE(g_swc_context_info),
	g_swc_context_group_info,
	ARRAY_SIZE(g_swc_context_group_info)
};

static const struct sph_sw_counters_group_info g_swc_infer_group_info[] = {
	/* ICEDRV_SWC_INFER_GROUP_GEN */
	{"-general", "placeholder for actual Infer groups"},
};

static const struct sph_sw_counter_info g_swc_infer_info[] = {
	/* ICEDRV_SWC_INFER_COUNTER_EXE_TOTAL */
	{ICEDRV_SWC_INFER_GROUP_GEN, "executeInferTotal",
	 "Total number of Execute Infer Request"},
};

static const struct sph_sw_counters_set g_swc_infer_set = {
	"infercmd",
	true,
	g_swc_infer_info,
	ARRAY_SIZE(g_swc_infer_info),
	g_swc_infer_group_info,
	ARRAY_SIZE(g_swc_infer_group_info)
};

static const struct sph_sw_counters_group_info g_swc_device_group_info[] = {
	/* ICEDRV_SWC_INFER_GROUP_GEN */
	{"-general", "placeholder for actual Device groups"},
};

static const struct sph_sw_counter_info g_swc_device_info[] = {
	/* ICEDRV_SWC_DEVICE_COUNTER_COMMANDS */
	{ICEDRV_SWC_DEVICE_GROUP_GEN, "commandsTotal",
	 "Total number of CBs that are executed on this device"},
	/* ICEDRV_SWC_DEVICE_COUNTER_RUNTIME */
	{ICEDRV_SWC_DEVICE_GROUP_GEN, "runtimeTotal",
	 "Total duration of ICE execution"},
};

static const struct sph_sw_counters_set g_swc_device_set = {
	"ice",
	true,
	g_swc_device_info,
	ARRAY_SIZE(g_swc_device_info),
	g_swc_device_group_info,
	ARRAY_SIZE(g_swc_device_group_info)
};

static const struct sph_sw_counters_group_info
		g_swc_infer_device_group_info[] = {
	/* ICEDRV_SWC_INFER_DEVICE_GROUP_GEN */
	{"-general", "placeholder for actual Infer Device groups"},
};

static const struct sph_sw_counter_info g_swc_infer_device_info[] = {
	/* ICEDRV_SWC_INFER_DEVICE_COUNTER_ECC_SERRCOUNT */
	{ICEDRV_SWC_INFER_DEVICE_GROUP_GEN, "eccSerrCount",
	 "Count of Deep SRAM ECC single errors"},
	/* ICEDRV_SWC_INFER_DEVICE_COUNTER_ECC_DERRCOUNT */
	{ICEDRV_SWC_INFER_DEVICE_GROUP_GEN, "eccDerrCount",
	 "Count of Deep SRAM ECC double errors"},
	/* ICEDRV_SWC_INFER_DEVICE_COUNTER_PARITY_ERRCOUNT */
	{ICEDRV_SWC_INFER_DEVICE_GROUP_GEN, "parityErrCount",
	 "Count of parity errors inside the IP"},
	/* ICEDRV_SWC_INFER_DEVICE_COUNTER_UNMAPPED_ERR_ID */
	{ICEDRV_SWC_INFER_DEVICE_GROUP_GEN, "unmappedErrId",
	 "Unmapped TID that caused the error"},
};

static const struct sph_sw_counters_set g_swc_infer_device_set = {
	"ice",
	true,
	g_swc_infer_device_info,
	ARRAY_SIZE(g_swc_infer_device_info),
	g_swc_infer_device_group_info,
	ARRAY_SIZE(g_swc_infer_device_group_info)
};

int ice_swc_create_node(enum ICEDRV_SWC_CLASS class,
			u64 node_id,
			u64 parent_id,
			void **counters) {

	int ret;
	struct swc_value *value, *parent;

	if ((class <= ICEDRV_SWC_CLASS_GLOBAL) ||
			(class >= ICEDRV_SWC_CLASS_MAX)) {

		cve_os_log(CVE_LOGLEVEL_ERROR,
			"Invalid SWC Class ID: %u\n", class);
		goto exit;
	}

	/* Parent node must exist */
	parent = cve_dle_lookup(g_swc_value_list[g_class_parent_map[class]],
				list,
				node_id,
				parent_id);
	if (!parent) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"Parent node does not exist: %llu\n", parent_id);
		goto exit;
	}

	ret = OS_ALLOC_ZERO(sizeof(struct swc_value), (void **)&value);
	if (ret != 0)
		goto exit;

	ret = sph_create_sw_counters_values_node(g_hswc_info[class],
						(u32)node_id,
						parent->sw_counters,
						&value->sw_counters);
	if (ret) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"Unable to create SWC value node\n");
		goto free_exit;
	}

	*counters = (void *)value->sw_counters;

	value->node_id = node_id;
	cve_dle_add_to_list_before(g_swc_value_list[class], list, value);

	return 0;
free_exit:
	OS_FREE(value, sizeof(struct swc_value));
exit:
	return -1;
}

int ice_swc_destroy_node(enum ICEDRV_SWC_CLASS class,
			u64 node_id) {

	struct swc_value *value;

	value = cve_dle_lookup(g_swc_value_list[class], list, node_id, node_id);
	if (!value) {

		cve_os_log(CVE_LOGLEVEL_ERROR,
			"SWC does not exit in Class %u\n", class);
		goto exit;
	}

	sph_remove_sw_counters_values_node(value->sw_counters);
	cve_dle_remove_from_list(g_swc_value_list[class], list, value);
	OS_FREE(value, sizeof(struct swc_value));

	return 0;
exit:
	return -1;
}

int ice_swc_init(void)
{
	int ret;
	struct swc_value *value;

	g_class_parent_map[ICEDRV_SWC_CLASS_GLOBAL] = ICEDRV_SWC_CLASS_GLOBAL;
	g_class_parent_map[ICEDRV_SWC_CLASS_CONTEXT] = ICEDRV_SWC_CLASS_GLOBAL;
	g_class_parent_map[ICEDRV_SWC_CLASS_INFER] = ICEDRV_SWC_CLASS_CONTEXT;
	g_class_parent_map[ICEDRV_SWC_CLASS_DEVICE] = ICEDRV_SWC_CLASS_GLOBAL;
	g_class_parent_map[ICEDRV_SWC_CLASS_INFER_DEVICE] =
							ICEDRV_SWC_CLASS_INFER;

	ret = sph_create_sw_counters_info_node(
				NULL,
				&g_swc_global_set,
				NULL,
				&g_hswc_info[ICEDRV_SWC_CLASS_GLOBAL]);
	if (ret) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"Unable to create global info for swc\n");
		goto exit;
	}

	ret = sph_create_sw_counters_info_node(
				NULL,
				&g_swc_context_set,
				g_hswc_info[ICEDRV_SWC_CLASS_GLOBAL],
				&g_hswc_info[ICEDRV_SWC_CLASS_CONTEXT]);
	if (ret) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"unable to create context info for swc\n");
		goto cleanup_swc_global_info;
	}

	ret = sph_create_sw_counters_info_node(
				NULL,
				&g_swc_infer_set,
				g_hswc_info[ICEDRV_SWC_CLASS_CONTEXT],
				&g_hswc_info[ICEDRV_SWC_CLASS_INFER]);
	if (ret) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"unable to create infer info for swc\n");
		goto cleanup_swc_context_info;
	}

	ret = sph_create_sw_counters_info_node(
				NULL,
				&g_swc_device_set,
				g_hswc_info[ICEDRV_SWC_CLASS_GLOBAL],
				&g_hswc_info[ICEDRV_SWC_CLASS_DEVICE]);
	if (ret) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"unable to create device info for swc\n");
		goto cleanup_swc_infer_info;
	}

	ret = sph_create_sw_counters_info_node(
				NULL,
				&g_swc_infer_device_set,
				g_hswc_info[ICEDRV_SWC_CLASS_INFER],
				&g_hswc_info[ICEDRV_SWC_CLASS_INFER_DEVICE]);
	if (ret) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"unable to create infer device info for swc\n");
		goto cleanup_swc_device_info;
	}

	ret = OS_ALLOC_ZERO(sizeof(struct swc_value), (void **)&value);
	if (ret != 0)
		goto cleanup_swc_infer_device_info;

	ret = sph_create_sw_counters_values_node(
				g_hswc_info[ICEDRV_SWC_CLASS_GLOBAL],
				0,
				NULL,
				&value->sw_counters);
	if (ret) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"unable to create values file for sw_counters\n");
		goto free_and_cleanup_swc;
	}

	value->node_id = 0;
	cve_dle_add_to_list_before(g_swc_value_list[ICEDRV_SWC_CLASS_GLOBAL],
				list, value);

	g_sph_swc_global = (void *)value->sw_counters;

	return 0;

free_and_cleanup_swc:
	OS_FREE(value, sizeof(struct swc_value));
cleanup_swc_infer_device_info:
	sph_remove_sw_counters_info_node(
				g_hswc_info[ICEDRV_SWC_CLASS_INFER_DEVICE]);
cleanup_swc_device_info:
	sph_remove_sw_counters_info_node(g_hswc_info[ICEDRV_SWC_CLASS_DEVICE]);
cleanup_swc_infer_info:
	sph_remove_sw_counters_info_node(g_hswc_info[ICEDRV_SWC_CLASS_INFER]);
cleanup_swc_context_info:
	sph_remove_sw_counters_info_node(g_hswc_info[ICEDRV_SWC_CLASS_CONTEXT]);
cleanup_swc_global_info:
	sph_remove_sw_counters_info_node(g_hswc_info[ICEDRV_SWC_CLASS_GLOBAL]);
exit:
	return -1;
}

int ice_swc_fini(void)
{
	int i;

	/* Leaves of the tree should be deleted first */
	for (i = (ICEDRV_SWC_CLASS_MAX - 1);
		i >= ICEDRV_SWC_CLASS_GLOBAL; i--) {

		while (g_swc_value_list[i])
			ice_swc_destroy_node(i, g_swc_value_list[i]->node_id);
	}

	sph_remove_sw_counters_info_node(
				g_hswc_info[ICEDRV_SWC_CLASS_INFER_DEVICE]);
	sph_remove_sw_counters_info_node(g_hswc_info[ICEDRV_SWC_CLASS_DEVICE]);
	sph_remove_sw_counters_info_node(g_hswc_info[ICEDRV_SWC_CLASS_INFER]);
	sph_remove_sw_counters_info_node(g_hswc_info[ICEDRV_SWC_CLASS_CONTEXT]);
	sph_remove_sw_counters_info_node(g_hswc_info[ICEDRV_SWC_CLASS_GLOBAL]);

	return 0;
}

inline u32 ice_swc_group_is_enable(void *h_counter, u32 idx)
{
	struct sph_sw_counters *counter = (struct sph_sw_counters *)h_counter;

	return SPH_SW_GROUP_IS_ENABLE(counter, idx);
}

inline void ice_swc_group_set(void *h_counter, u32 idx, u64 val)
{
	struct sph_sw_counters *counter = (struct sph_sw_counters *)h_counter;

	SPH_SW_GROUP_SET(counter, idx, val);
}

inline void ice_swc_counter_set(void *h_counter, u32 idx, u64 val)
{
	struct sph_sw_counters *counter = (struct sph_sw_counters *)h_counter;

	SPH_SW_COUNTER_SET(counter, idx, val);
	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"SwCounter[%u] = %llu\n", idx, counter->values[idx]);
}

inline u64 ice_swc_counter_get(void *h_counter, u32 idx)
{
	struct sph_sw_counters *counter = (struct sph_sw_counters *)h_counter;

	return SPH_SW_COUNTER_GET(counter, idx);
}

inline void ice_swc_counter_inc(void *h_counter, u32 idx)
{
	struct sph_sw_counters *counter = (struct sph_sw_counters *)h_counter;

	SPH_SW_COUNTER_INC(counter, idx);
	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"SwCounter[%u] = %llu\n", idx, counter->values[idx]);
}

inline void ice_swc_counter_dec(void *h_counter, u32 idx)
{
	struct sph_sw_counters *counter = (struct sph_sw_counters *)h_counter;

	SPH_SW_COUNTER_DEC(counter, idx);
	cve_os_log(CVE_LOGLEVEL_DEBUG,
		 "SwCounter[%u] = %llu\n", idx, counter->values[idx]);
}

inline void ice_swc_counter_add(void *h_counter, u32 idx, u64 val)
{
	struct sph_sw_counters *counter = (struct sph_sw_counters *)h_counter;

	SPH_SW_COUNTER_ADD(counter, idx, val);
	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"SwCounter[%u] = %llu\n", idx, counter->values[idx]);
}

inline void ice_swc_counter_dec_val(void *h_counter, u32 idx, u64 val)
{
	struct sph_sw_counters *counter = (struct sph_sw_counters *)h_counter;

	SPH_SW_COUNTER_DEC_VAL(counter, idx, val);
	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"SwCounter[%u] = %llu\n", idx, counter->values[idx]);
}

inline void ice_swc_counter_atomic_inc(void *h_counter, u32 idx)
{
	struct sph_sw_counters *counter = (struct sph_sw_counters *)h_counter;

	SPH_SW_COUNTER_ATOMIC_INC(counter, idx);
	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"SwCounter[%u] = %llu\n", idx, counter->values[idx]);
}

inline void ice_swc_counter_atomic_dec(void *h_counter, u32 idx)
{
	struct sph_sw_counters *counter = (struct sph_sw_counters *)h_counter;

	SPH_SW_COUNTER_ATOMIC_DEC(counter, idx);
	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"SwCounter[%u] = %llu\n", idx, counter->values[idx]);
}

inline void ice_swc_counter_atomic_add(void *h_counter, u32 idx, u64 val)
{
	struct sph_sw_counters *counter = (struct sph_sw_counters *)h_counter;

	SPH_SW_COUNTER_ATOMIC_ADD(counter, idx, val);
	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"SwCounter[%u] = %llu\n", idx, counter->values[idx]);
}

inline void ice_swc_counter_atomic_dec_val(void *h_counter, u32 idx, u64 val)
{
	struct sph_sw_counters *counter = (struct sph_sw_counters *)h_counter;

	SPH_SW_COUNTER_ATOMIC_DEC_VAL(counter, idx, val);
	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"SwCounter[%u] = %llu\n", idx, counter->values[idx]);
}
