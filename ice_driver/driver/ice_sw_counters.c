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
	struct cve_dle_t child_node;
	struct swc_value *child_list;
	struct swc_value *child2_list;
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
	/* ICEDRV_SWC_CONTEXT_COUNTER_NTW_TOT */
	{ICEDRV_SWC_CONTEXT_GROUP_GEN, "networkTotal",
	 "Total number of Created Network Request"},
	/* ICEDRV_SWC_CONTEXT_COUNTER_NTW_CUR */
	{ICEDRV_SWC_CONTEXT_GROUP_GEN, "networkCurrent",
	 "Number of Network Requests that are currently active"},
	/* ICEDRV_SWC_CONTEXT_COUNTER_NTW_DES */
	{ICEDRV_SWC_CONTEXT_GROUP_GEN, "networkDestroyed",
	 "Total number of Destroyed network Request"}
};

static const struct sph_sw_counters_set g_swc_context_set = {
	"inference.context",
	true,
	g_swc_context_info,
	ARRAY_SIZE(g_swc_context_info),
	g_swc_context_group_info,
	ARRAY_SIZE(g_swc_context_group_info)
};

static const struct sph_sw_counters_group_info g_swc_network_group_info[] = {
	/* ICEDRV_SWC_NETWORK_GROUP_GEN */
	{"-general", "placeholder for actual network groups"},
};

static const struct sph_sw_counter_info g_swc_network_info[] = {
	/* ICEDRV_SWC_NETWORK_COUNTER_SUB_NTW_CREATED */
	{ICEDRV_SWC_NETWORK_GROUP_GEN, "subNetworkTotal",
	 "Total number of Created sub network Request"},
	/* ICEDRV_SWC_NETWORK_COUNTER_SUB_NTW_ACTIVE */
	{ICEDRV_SWC_NETWORK_GROUP_GEN, "subNetworkCurrent",
	 "Number of sub network currently allocated"},
	/* ICEDRV_SWC_NETWORK_COUNTER_SUB_NTW_DESTROYED */
	{ICEDRV_SWC_NETWORK_GROUP_GEN, "subNetworkDestroyed",
	 "Total number of Destroyed sub network Request"}
};

static const struct sph_sw_counters_set g_swc_network_set = {
	"network",
	true,
	g_swc_network_info,
	ARRAY_SIZE(g_swc_network_info),
	g_swc_network_group_info,
	ARRAY_SIZE(g_swc_network_group_info)
};

static const struct sph_sw_counters_group_info
	g_swc_sub_network_group_info[] = {
	/* ICEDRV_SWC_SUB_NETWORK_GROUP_GEN */
	{"-general", "placeholder for actual sub network groups"},
};

static const struct sph_sw_counter_info g_swc_sub_network_info[] = {
	/* ICEDRV_SWC_SUB_NETWORK_HANDLE */
	{ICEDRV_SWC_SUB_NETWORK_GROUP_GEN, "handle",
	"Driver defined network handle"},
	/* ICEDRV_SWC_SUB_NETWORK_TOTAL_JOBS */
	{ICEDRV_SWC_SUB_NETWORK_GROUP_GEN, "totalJobs",
	"Toatl number of jobs for this sub network"},
	/* ICEDRV_SWC_SUB_NETWORK_COUNTER_INF_CREATED */
	{ICEDRV_SWC_SUB_NETWORK_GROUP_GEN, "inferTotal",
	 "Total number of Created Infer Request"},
	/* ICEDRV_SWC_SUB_NETWORK_COUNTER_INF_SCHEDULED */
	{ICEDRV_SWC_SUB_NETWORK_GROUP_GEN, "inferCurrent",
	 "Number of Infer Requests that are currently active"},
	/* ICEDRV_SWC_SUB_NETWORK_COUNTER_INF_COMPLETED */
	{ICEDRV_SWC_SUB_NETWORK_GROUP_GEN, "inferCompleted",
	 "Number of Infer Requests that are completed"},
	/* ICEDRV_SWC_SUB_NETWORK_COUNTER_INF_DESTROYED */
	{ICEDRV_SWC_SUB_NETWORK_GROUP_GEN, "inferDestroyed",
	 "Total number of Destroyed Infer Request"}
};

static const struct sph_sw_counters_set g_swc_sub_network_set = {
	"sub_network",
	true,
	g_swc_sub_network_info,
	ARRAY_SIZE(g_swc_sub_network_info),
	g_swc_sub_network_group_info,
	ARRAY_SIZE(g_swc_sub_network_group_info)
};


static const struct sph_sw_counters_group_info g_swc_infer_group_info[] = {
	/* ICEDRV_SWC_INFER_GROUP_GEN */
	{"-general", "placeholder for actual Infer groups"},
};

static const struct sph_sw_counter_info g_swc_infer_info[] = {
	/* ICEDRV_SWC_INFER_HANDLE */
	{ICEDRV_SWC_INFER_GROUP_GEN, "handle",
	"Driver defined inference handle"},
	/* ICEDRV_SWC_INFER_STATE */
	{ICEDRV_SWC_INFER_GROUP_GEN, "state",
	"1=Unknown; 2=wait; 3=scheduling; 4=scheduled; 5=completed; 6=event_sent"
	},
	/* ICEDRV_SWC_INFER_COUNTER_REQUEST_SENT */
	{ICEDRV_SWC_INFER_GROUP_GEN, "reqSent",
	"Number of requests sent for execution"},
	/* ICEDRV_SWC_INFER_COUNTER_REQUEST_COMPLETED */
	{ICEDRV_SWC_INFER_GROUP_GEN, "reqReceived",
	"Number request completed"},
	/* ICEDRV_SWC_INFER_ERROR_STATUS */
	{ICEDRV_SWC_INFER_GROUP_GEN, "errorStatus",
	"HW error status"},
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
	"Total duration of ICE execution - TLC reported cycles"},
	/* ICEDRV_SWC_DEVICE_COUNTER_BUSY_TIME */
	{ICEDRV_SWC_DEVICE_GROUP_GEN, "iceBusyTime",
	 "Total ICE busy duration in microseconds"},
	/* ICEDRV_SWC_DEVICE_COUNTER_IDLE_TIME */
	{ICEDRV_SWC_DEVICE_GROUP_GEN, "iceIdleTime",
	 "Total ICE idle duration in microseconds"},
	/* ICEDRV_SWC_DEVICE_COUNTER_BUSY_START_TIME */
	{ICEDRV_SWC_DEVICE_GROUP_GEN, "iceBusyStartTime",
	 "Last timestamp when doorbell was sent in microseconds"},
	/* ICEDRV_SWC_DEVICE_COUNTER_IDLE_START_TIME */
	{ICEDRV_SWC_DEVICE_GROUP_GEN, "iceIdleStartTime",
	 "Last timestamp when ICE completed execution in microseconds"},
	/* ICEDRV_SWC_DEVICE_COUNTER_POWER_STATE*/
	{ICEDRV_SWC_DEVICE_GROUP_GEN, "icePowerState",
	 "Power state of ICE - 0=OFF 1=ON 2=OFF initiated 3=UNKNOWN"},
	/* ICEDRV_SWC_DEVICE_COUNTER_ECC_SERRCOUNT_WRAP */
	{ICEDRV_SWC_DEVICE_GROUP_GEN, "eccSerrWrap",
	 "Total wrap around for Deep SRAM ECC single errors"},
	/* ICEDRV_SWC_DEVICE_COUNTER_ECC_SERRCOUNT */
	{ICEDRV_SWC_DEVICE_GROUP_GEN, "eccSerrCount",
	 "Total count of Deep SRAM ECC single errors"},
	/* ICEDRV_SWC_DEVICE_COUNTER_ECC_DERRCOUNT_WRAP */
	{ICEDRV_SWC_DEVICE_GROUP_GEN, "eccDerrWrap",
	 "Total wrap around for Deep SRAM ECC double errors"},
	/* ICEDRV_SWC_DEVICE_COUNTER_ECC_DERRCOUNT */
	{ICEDRV_SWC_DEVICE_GROUP_GEN, "eccDerrCount",
	 "Total count of Deep SRAM ECC double errors"},
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
	/* ICEDRV_SWC_INFER_DEVICE_COUNTER_ID */
	{ICEDRV_SWC_INFER_DEVICE_GROUP_GEN, "IceId",
	 "Actual HW ICE ID, ID=0xFFFF(65535) means invalid value"},
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

/** Check if the node is already created
 * return 1 if present
 * return 0 if not present
 * return -1 for an error
 */
int _swc_check_node(enum ICEDRV_SWC_CLASS class,
		uint64_t node_id, void *master, void **swc)
{
	int ret = 0;
	struct swc_value *node;
	struct swc_value *parent = (struct swc_value *)master;

	/* Check if node exsist */
	if (!parent)
		parent = cve_dle_lookup(
				g_swc_value_list[ICEDRV_SWC_CLASS_GLOBAL],
				list, node_id, 0);
	if (!parent) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "Parent is NULL");
		return -EINVAL;
	}

	if (class == ICEDRV_SWC_CLASS_INFER_DEVICE ||
			class == ICEDRV_SWC_CLASS_DEVICE) {
		node = cve_dle_lookup(parent->child2_list, child_node,
			node_id, node_id);
	} else {
		node = cve_dle_lookup(parent->child_list, child_node,
			node_id, node_id);
	}

	if (node == NULL) {
		*swc = parent;
	} else {
		ret = 1;
		*swc = node;
	}

	return ret;
}

int _swc_create_node(enum ICEDRV_SWC_CLASS class,
			u64 node_id, void *master, void **counters) {

	int ret;
	struct swc_value *value, *parent = master;
	void *test;

	*counters = NULL;

	if ((class <= ICEDRV_SWC_CLASS_GLOBAL) ||
			(class >= ICEDRV_SWC_CLASS_MAX)) {

		cve_os_log(CVE_LOGLEVEL_ERROR,
			"Invalid SWC Class ID: %u\n", class);
		goto exit;
	}

	if (!parent) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "Parent node cannot be null\n");
		goto exit;
	}

	ret = _swc_check_node(class, node_id, parent, &test);
	if (ret > 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"SW Counter with ID:%llu in class:%d already present\n",
				node_id, class);
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
	if (class == ICEDRV_SWC_CLASS_INFER_DEVICE ||
			class == ICEDRV_SWC_CLASS_DEVICE) {
		cve_dle_add_to_list_before(parent->child2_list,
				child_node, value);
	} else {
		cve_dle_add_to_list_before(parent->child_list,
				child_node, value);
	}

	return 0;
free_exit:
	OS_FREE(value, sizeof(struct swc_value));
exit:
	return -1;
}

int _swc_destroy_node(enum ICEDRV_SWC_CLASS class, void *master, u64 node_id)
{
	int ret = 0;
	struct swc_value *value, *parent = master;

	if (!parent) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "Parent node cannot be null\n");
		goto exit;
	}

	ret = _swc_check_node(class, node_id, parent, (void **)&value);
	if (ret == 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"SW Counter with ID:%u in class:%d not present\n",
				(u32)node_id, class);
		goto exit;
	}

	ret = sph_remove_sw_counters_values_node(value->sw_counters);
	if (ret) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"Error:%d SW Counter deletion with ID:%u class:%d failed\n",
				ret, (u32)node_id, class);
		goto exit;
	}

	if (class == ICEDRV_SWC_CLASS_INFER_DEVICE ||
			class == ICEDRV_SWC_CLASS_DEVICE) {
		cve_dle_remove_from_list(parent->child2_list,
				child_node, value);
	} else {
		cve_dle_remove_from_list(parent->child_list,
				child_node, value);
	}

	OS_FREE(value, sizeof(struct swc_value));

	return 0;
exit:
	return -1;
}

static void __delete_infer_dev_swc_list(struct swc_value *root,
		struct swc_value *child)
{
	struct swc_value *head = child;
	struct swc_value *curr = NULL;
	struct swc_value *next = NULL;
	u32 is_last = 0;

	if (head == NULL)
		goto exit;

	curr = head;
	do {
		next = cve_dle_next(curr, child_node);

		if (next == curr)
			is_last = 1;

		cve_os_log(CVE_LOGLEVEL_INFO,
				"SWC:%p Remove ID:0x%llx\n",
				curr, curr->node_id);

		sph_remove_sw_counters_values_node(curr->sw_counters);
		cve_dle_remove_from_list(root->child2_list, child_node, curr);
		OS_FREE(curr, sizeof(struct swc_value));

		if (!is_last)
			curr = cve_dle_next(curr, list);
	} while (!is_last);

exit:
	return;
}

static void __delete_infer_swc_list(struct swc_value *root,
		struct swc_value *child)
{
	struct swc_value *head = child;
	struct swc_value *curr = NULL;
	struct swc_value *next = NULL;
	u32 is_last = 0;

	if (head == NULL)
		goto exit;

	curr = head;
	do {
		next = cve_dle_next(curr, child_node);

		if (next == curr)
			is_last = 1;

		cve_os_log(CVE_LOGLEVEL_INFO,
				"SWC:%p Remove ID:0x%llx\n",
				curr, curr->node_id);

		sph_remove_sw_counters_values_node(curr->sw_counters);
		cve_dle_remove_from_list(root->child_list, child_node, curr);
		OS_FREE(curr, sizeof(struct swc_value));

		if (!is_last)
			curr = cve_dle_next(curr, list);
	} while (!is_last);
exit:
	return;
}

static void __delete_sub_ntw_swc_list(struct swc_value *root,
		struct swc_value *child)
{
	struct swc_value *head = child;
	struct swc_value *curr = NULL;
	struct swc_value *next = NULL;
	u32 is_last = 0;

	if (head == NULL)
		goto exit;

	curr = head;
	do {
		next = cve_dle_next(curr, child_node);

		if (next == curr)
			is_last = 1;

		cve_os_log(CVE_LOGLEVEL_INFO,
				"SWC:%p Remove ID:0x%llx\n",
				curr, curr->node_id);

		__delete_infer_swc_list(curr, curr->child_list);
		__delete_infer_dev_swc_list(curr, curr->child2_list);

		sph_remove_sw_counters_values_node(curr->sw_counters);
		cve_dle_remove_from_list(root->child_list, child_node, curr);
		OS_FREE(curr, sizeof(struct swc_value));

		if (!is_last)
			curr = cve_dle_next(curr, list);
	} while (!is_last);
exit:
	return;
}

static void __delete_full_ntw_swc_list(struct swc_value *root,
		struct swc_value *child)
{
	struct swc_value *head = child;
	struct swc_value *curr = NULL;
	struct swc_value *next = NULL;
	u32 is_last = 0;

	if (head == NULL)
		goto exit;

	curr = head;
	do {
		next = cve_dle_next(curr, child_node);

		if (next == curr)
			is_last = 1;

		cve_os_log(CVE_LOGLEVEL_INFO,
				"SWC:%p Remove ID:0x%llx\n",
				curr, curr->node_id);

		__delete_sub_ntw_swc_list(curr, curr->child_list);

		sph_remove_sw_counters_values_node(curr->sw_counters);
		cve_dle_remove_from_list(root->child_list, child_node, curr);
		OS_FREE(curr, sizeof(struct swc_value));

		if (!is_last)
			curr = cve_dle_next(curr, list);
	} while (!is_last);
exit:
	return;
}


static void __delete_ctx_swc_list(struct swc_value *root,
		struct swc_value *child)
{
	struct swc_value *head = child;
	struct swc_value *curr = NULL;
	struct swc_value *next = NULL;
	u32 is_last = 0;

	if (head == NULL)
		goto exit;

	curr = head;
	do {
		next = cve_dle_next(curr, child_node);

		if (next == curr)
			is_last = 1;

		cve_os_log(CVE_LOGLEVEL_INFO,
				"SWC:%p Remove ID:0x%llx\n",
				curr, curr->node_id);

		__delete_full_ntw_swc_list(curr, curr->child_list);

		sph_remove_sw_counters_values_node(curr->sw_counters);
		cve_dle_remove_from_list(root->child_list, child_node, curr);
		OS_FREE(curr, sizeof(struct swc_value));

		if (!is_last)
			curr = cve_dle_next(curr, list);
	} while (!is_last);
exit:
	return;
}

static void __delete_dev_swc_list(struct swc_value *root,
		struct swc_value *child)
{
	struct swc_value *head = child;
	struct swc_value *curr = NULL;
	struct swc_value *next = NULL;
	u32 is_last = 0;

	if (head == NULL)
		goto exit;

	curr = head;
	do {
		next = cve_dle_next(curr, child_node);

		if (next == curr)
			is_last = 1;

		cve_os_log(CVE_LOGLEVEL_INFO,
				"SWC:%p Remove ID:0x%llx\n",
				curr, curr->node_id);

		sph_remove_sw_counters_values_node(curr->sw_counters);
		cve_dle_remove_from_list(root->child2_list, child_node, curr);
		OS_FREE(curr, sizeof(struct swc_value));

		if (!is_last)
			curr = cve_dle_next(curr, list);
	} while (!is_last);
exit:
	return;
}


static void __delete_swc_tree(struct swc_value *root)
{
	if (!root)
		goto exit;

	/* release all child entries*/
	if (root->child_list)
		__delete_ctx_swc_list(root, root->child_list);

	if (root->child2_list)
		__delete_dev_swc_list(root, root->child2_list);

	sph_remove_sw_counters_values_node(root->sw_counters);
	cve_dle_remove_from_list(g_swc_value_list[ICEDRV_SWC_CLASS_GLOBAL],
			list, root);
	OS_FREE(root, sizeof(struct swc_value));

exit:
	return;
}

int _swc_init(void)
{
	int ret;
	struct swc_value *value;

	g_class_parent_map[ICEDRV_SWC_CLASS_GLOBAL] = ICEDRV_SWC_CLASS_GLOBAL;
	g_class_parent_map[ICEDRV_SWC_CLASS_CONTEXT] = ICEDRV_SWC_CLASS_GLOBAL;
	g_class_parent_map[ICEDRV_SWC_CLASS_NETWORK] = ICEDRV_SWC_CLASS_CONTEXT;
	g_class_parent_map[ICEDRV_SWC_CLASS_SUB_NETWORK] =
		ICEDRV_SWC_CLASS_NETWORK;
	g_class_parent_map[ICEDRV_SWC_CLASS_INFER] =
		ICEDRV_SWC_CLASS_SUB_NETWORK;
	g_class_parent_map[ICEDRV_SWC_CLASS_DEVICE] = ICEDRV_SWC_CLASS_GLOBAL;
	g_class_parent_map[ICEDRV_SWC_CLASS_INFER_DEVICE] =
		ICEDRV_SWC_CLASS_SUB_NETWORK;

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
				&g_swc_network_set,
				g_hswc_info[ICEDRV_SWC_CLASS_CONTEXT],
				&g_hswc_info[ICEDRV_SWC_CLASS_NETWORK]);
	if (ret) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"unable to create network info for swc\n");
		goto cleanup_swc_context_info;
	}

	ret = sph_create_sw_counters_info_node(
				NULL,
				&g_swc_sub_network_set,
				g_hswc_info[ICEDRV_SWC_CLASS_NETWORK],
				&g_hswc_info[ICEDRV_SWC_CLASS_SUB_NETWORK]);
	if (ret) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"unable to create infer info for swc\n");
		goto cleanup_swc_ntw_info;
	}

	ret = sph_create_sw_counters_info_node(
				NULL,
				&g_swc_infer_set,
				g_hswc_info[ICEDRV_SWC_CLASS_SUB_NETWORK],
				&g_hswc_info[ICEDRV_SWC_CLASS_INFER]);
	if (ret) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"unable to create infer info for swc\n");
		goto cleanup_swc_sub_ntw_info;
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
				g_hswc_info[ICEDRV_SWC_CLASS_SUB_NETWORK],
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
cleanup_swc_sub_ntw_info:
	sph_remove_sw_counters_info_node(
			g_hswc_info[ICEDRV_SWC_CLASS_SUB_NETWORK]);
cleanup_swc_ntw_info:
	sph_remove_sw_counters_info_node(g_hswc_info[ICEDRV_SWC_CLASS_NETWORK]);
cleanup_swc_context_info:
	sph_remove_sw_counters_info_node(g_hswc_info[ICEDRV_SWC_CLASS_CONTEXT]);
cleanup_swc_global_info:
	sph_remove_sw_counters_info_node(g_hswc_info[ICEDRV_SWC_CLASS_GLOBAL]);
exit:
	return -1;
}

int _swc_fini(void)
{
	__delete_swc_tree(g_swc_value_list[ICEDRV_SWC_CLASS_GLOBAL]);

	sph_remove_sw_counters_info_node(
				g_hswc_info[ICEDRV_SWC_CLASS_INFER_DEVICE]);
	sph_remove_sw_counters_info_node(g_hswc_info[ICEDRV_SWC_CLASS_DEVICE]);
	sph_remove_sw_counters_info_node(g_hswc_info[ICEDRV_SWC_CLASS_INFER]);
	sph_remove_sw_counters_info_node(
			g_hswc_info[ICEDRV_SWC_CLASS_SUB_NETWORK]);
	sph_remove_sw_counters_info_node(g_hswc_info[ICEDRV_SWC_CLASS_NETWORK]);
	sph_remove_sw_counters_info_node(g_hswc_info[ICEDRV_SWC_CLASS_CONTEXT]);
	sph_remove_sw_counters_info_node(g_hswc_info[ICEDRV_SWC_CLASS_GLOBAL]);

	return 0;
}

inline u32 _swc_group_is_enable(void *h_counter, u32 idx)
{
	struct sph_sw_counters *counter = (struct sph_sw_counters *)h_counter;

	if (counter)
		return SPH_SW_GROUP_IS_ENABLE(counter, idx);
	else
		return 0;
}

inline void _swc_group_set(void *h_counter, u32 idx, u64 val)
{
	struct sph_sw_counters *counter = (struct sph_sw_counters *)h_counter;

	if (counter)
		SPH_SW_GROUP_SET(counter, idx, val);
}

inline void _swc_counter_set(void *h_counter, u32 idx, u64 val)
{
	struct sph_sw_counters *counter = (struct sph_sw_counters *)h_counter;

	if (counter) {
		SPH_SW_COUNTER_SET(counter, idx, val);
		cve_os_log(CVE_LOGLEVEL_DEBUG,
				"SwCounter[%u] = %llu\n",
				idx, counter->values[idx]);
	}
}

inline u64 _swc_counter_get(void *h_counter, u32 idx)
{
	struct sph_sw_counters *counter = (struct sph_sw_counters *)h_counter;

	if (counter)
		return SPH_SW_COUNTER_GET(counter, idx);
	else
		return 0;
}

inline void _swc_counter_inc(void *h_counter, u32 idx)
{
	struct sph_sw_counters *counter = (struct sph_sw_counters *)h_counter;

	if (counter) {
		SPH_SW_COUNTER_INC(counter, idx);
		cve_os_log(CVE_LOGLEVEL_DEBUG,
				"SwCounter[%u] = %llu\n",
				idx, counter->values[idx]);
	}
}

inline void _swc_counter_dec(void *h_counter, u32 idx)
{
	struct sph_sw_counters *counter = (struct sph_sw_counters *)h_counter;

	if (counter) {
		SPH_SW_COUNTER_DEC(counter, idx);
		cve_os_log(CVE_LOGLEVEL_DEBUG,
				"SwCounter[%u] = %llu\n",
				idx, counter->values[idx]);
	}
}

inline void _swc_counter_add(void *h_counter, u32 idx, u64 val)
{
	struct sph_sw_counters *counter = (struct sph_sw_counters *)h_counter;

	if (counter) {
		SPH_SW_COUNTER_ADD(counter, idx, val);
		cve_os_log(CVE_LOGLEVEL_DEBUG,
				"SwCounter[%u] = %llu\n",
				idx, counter->values[idx]);
	}
}

inline void _swc_counter_dec_val(void *h_counter, u32 idx, u64 val)
{
	struct sph_sw_counters *counter = (struct sph_sw_counters *)h_counter;

	if (counter) {
		SPH_SW_COUNTER_DEC_VAL(counter, idx, val);
		cve_os_log(CVE_LOGLEVEL_DEBUG,
				"SwCounter[%u] = %llu\n",
				idx, counter->values[idx]);
	}
}

inline void _swc_counter_atomic_inc(void *h_counter, u32 idx)
{
	struct sph_sw_counters *counter = (struct sph_sw_counters *)h_counter;

	if (counter) {
		SPH_SW_COUNTER_ATOMIC_INC(counter, idx);
		cve_os_log(CVE_LOGLEVEL_DEBUG,
				"SwCounter[%u] = %llu\n",
				idx, counter->values[idx]);
	}
}

inline void _swc_counter_atomic_dec(void *h_counter, u32 idx)
{
	struct sph_sw_counters *counter = (struct sph_sw_counters *)h_counter;

	if (counter) {
		SPH_SW_COUNTER_ATOMIC_DEC(counter, idx);
		cve_os_log(CVE_LOGLEVEL_DEBUG,
				"SwCounter[%u] = %llu\n",
				idx, counter->values[idx]);
	}
}

inline void _swc_counter_atomic_add(void *h_counter, u32 idx, u64 val)
{
	struct sph_sw_counters *counter = (struct sph_sw_counters *)h_counter;

	if (counter) {
		SPH_SW_COUNTER_ATOMIC_ADD(counter, idx, val);
		cve_os_log(CVE_LOGLEVEL_DEBUG,
				"SwCounter[%u] = %llu\n",
				idx, counter->values[idx]);
	}
}

inline void _swc_counter_atomic_dec_val(void *h_counter, u32 idx, u64 val)
{
	struct sph_sw_counters *counter = (struct sph_sw_counters *)h_counter;

	if (counter) {
		SPH_SW_COUNTER_ATOMIC_DEC_VAL(counter, idx, val);
		cve_os_log(CVE_LOGLEVEL_DEBUG,
				"SwCounter[%u] = %llu\n",
				idx, counter->values[idx]);
	}
}
