/********************************************
 * Copyright (C) 2019-2021 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/
#ifndef __NNP_SW_COUNTERS_H
#define __NNP_SW_COUNTERS_H

//
// INTEL CORPORATION CONFIDENTIAL Copyright(c) 2018-2021 Intel Corporation. All Rights Reserved.
//


#include <linux/types.h>
#include <linux/spinlock.h>

struct kobject;

/* struct to define a counter information */
struct nnp_sw_counter_info {
	u32	group_id;
	char	*name;
	char	*description;
};

/* struct to define a counter group information */
struct nnp_sw_counters_group_info {
	char	*name;
	char	*description;
};


/*struct to define a set of counters*/
struct nnp_sw_counters_set {
	const char				*name;
	const bool				perID;
	const struct nnp_sw_counter_info	*counters_info;
	const u32				counters_count;
	const struct nnp_sw_counters_group_info *groups_info;
	const u32				groups_count;
};

/* struct to describe counter values and enabled groups */
struct nnp_sw_counters {
	u64        *values;
	u32        *groups;
	const u32  *global_groups;
	spinlock_t *spinlocks;
};

/* create sw counters_set_node */
int nnp_create_sw_counters_info_node(struct kobject *kobj,
				     const struct nnp_sw_counters_set	*counters_set,
				     void *hParentInfo,
				     void **hNewInfo);

/* release global sw counters object */
int nnp_remove_sw_counters_info_node(void *hInfoNode);

/* create values object, also need to attach to corrent info node that matches values creation */
int nnp_create_sw_counters_values_node(void *hInfoNode,
				       u32 node_id,
				       struct nnp_sw_counters *parentSwCounters,
				       struct nnp_sw_counters **counters);

/* create values object, also need to attach to corrent info node that matches values creation */
int nnp_remove_sw_counters_values_node(struct nnp_sw_counters *counters);

/* MACROS FOR SW COUNTER - g_nnp_sw_counters */

#define NNP_SW_GROUP_IS_ENABLE(_obj, _index)    \
	(((_obj)->groups[(_index)] != 0) ||       \
	 ((_obj)->global_groups[(_index)] != 0))

#define SPH_SW_GROUP_SET(_obj, _index, _val)                               \
	((_val) ? ++((_obj)->groups[(_index)]) :                           \
	 (((_obj)->groups[(_index)]) ? --((_obj)->groups[(_index)]) : 0))

#define SPH_SW_COUNTER_SET(_obj, _index, _val) \
	((_obj)->values[(_index)] = (_val))

#define SPH_SW_COUNTER_GET(_obj, _index) \
	((_obj)->values[(_index)])

#define NNP_SW_COUNTER_INC(_obj, _index) \
	(_obj->values[_index]++)

#define SPH_SW_COUNTER_DEC(_obj, _index) \
	((_obj)->values[(_index)]--)

#define NNP_SW_COUNTER_ADD(_obj, _index, _val) \
	((_obj)->values[(_index)] += (_val))

#define SPH_SW_COUNTER_DEC_VAL(_obj, _index, _val) \
	((_obj)->values[(_index)] -= (_val))

#define SPH_SW_COUNTER_ATOMIC_INC(_obj, _index)            \
	do {                                               \
		spin_lock(&((_obj)->spinlocks[(_index)]));   \
		((_obj)->values[(_index)]++);                  \
		spin_unlock(&((_obj)->spinlocks[(_index)])); \
	} while (0)

#define SPH_SW_COUNTER_ATOMIC_DEC(_obj, _index)            \
	do {                                               \
		spin_lock(&((_obj)->spinlocks[(_index)]));   \
		((_obj)->values[(_index)]--);                  \
		spin_unlock(&((_obj)->spinlocks[(_index)])); \
	} while (0)

#define NNP_SW_COUNTER_ATOMIC_ADD(_obj, _index, _val)        \
	do {                                                 \
		spin_lock(&((_obj)->spinlocks[(_index)]));     \
		((_obj)->values[(_index)] += (_val));            \
		spin_unlock(&((_obj)->spinlocks[(_index)]));   \
	} while (0)

#define NNP_SW_COUNTER_ATOMIC_DEC_VAL(_obj, _index, _val)         \
	do {                                                      \
		spin_lock(&((_obj)->spinlocks[(_index)]));          \
		((_obj)->values[(_index)] -= (_val));                 \
		spin_unlock(&((_obj)->spinlocks[(_index)]));        \
	} while (0)


#endif //__NNP_SW_COUNTERS_H
