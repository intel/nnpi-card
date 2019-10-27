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

#ifndef _ICE_SW_COUNTERS_H_
#define _ICE_SW_COUNTERS_H_

#include "os_interface.h"

#ifdef RING3_VALIDATION
#define DISBALE_SWC 1
#else
#define DISBALE_SWC 0
#endif

extern void *g_sph_swc_global;

/* A Counter belongs to one of the following class */
enum ICEDRV_SWC_CLASS {
	/* Global counters */
	ICEDRV_SWC_CLASS_GLOBAL,
	/* Context specific counters */
	ICEDRV_SWC_CLASS_CONTEXT,
	/* Full Network specific counters */
	ICEDRV_SWC_CLASS_NETWORK,
	/* Sub Network specific counters */
	ICEDRV_SWC_CLASS_SUB_NETWORK,
	/* Infer specific counters */
	ICEDRV_SWC_CLASS_INFER,
	/* ICE specific counters */
	ICEDRV_SWC_CLASS_DEVICE,
	/* Network specific ICE counters */
	ICEDRV_SWC_CLASS_INFER_DEVICE,
	/* Groups count */
	ICEDRV_SWC_CLASS_MAX
};

/* Groups in ICEDRV_SWC_CLASS_GLOBAL */
enum ICEDRV_SWC_GLOBAL_GROUP {
	ICEDRV_SWC_GLOBAL_GROUP_GEN,
};

/* Counters in ICEDRV_SWC_CLASS_GLOBAL */
enum ICEDRV_SWC_GLOBAL_COUNTER {
	ICEDRV_SWC_GLOBAL_COUNTER_CTX_TOTAL,
	ICEDRV_SWC_GLOBAL_COUNTER_CTX_CURR,
	ICEDRV_SWC_GLOBAL_COUNTER_CTX_DEST,
	ICEDRV_SWC_GLOBAL_ACTIVE_ICE_COUNT
};

/* Groups in ICEDRV_SWC_CLASS_CONTEXT */
enum ICEDRV_SWC_CONTEXT_GROUP {
	ICEDRV_SWC_CONTEXT_GROUP_GEN,
};

/* Counters in ICEDRV_SWC_CLASS_CONTEXT */
enum ICEDRV_SWC_CONTEXT_COUNTER {
	ICEDRV_SWC_CONTEXT_COUNTER_NTW_TOTAL,
	ICEDRV_SWC_CONTEXT_COUNTER_NTW_CURR,
	ICEDRV_SWC_CONTEXT_COUNTER_NTW_DEST
};

/* Groups in ICEDRV_SWC_CLASS_NETWORK */
enum ICEDRV_SWC_NETWORK_GROUP {
	ICEDRV_SWC_NETWORK_GROUP_GEN,
};

/** Counters in ICEDRV_SWC_CLASS_NETWORK */
enum ICEDRV_SWC_NETWORK_COUNTER {
	ICEDRV_SWC_NETWORK_COUNTER_SUB_NTW_CREATED,
	ICEDRV_SWC_NETWORK_COUNTER_SUB_NTW_ACTIVE,
	ICEDRV_SWC_NETWORK_COUNTER_SUB_NTW_DESTROYED
};

/** Groups in ICEDRV_SWC_CLASS_SUB_NETWORK */
enum ICEDRV_SWC_SUB_NETWORK_GROUP {
	ICEDRV_SWC_SUB_NETWORK_GROUP_GEN,
};

/** Counters in ICEDRV_SWC_CLASS_SUB_NETWORK */
enum ICEDRV_SWC_SUB_NETWORK_COUNTER {
	ICEDRV_SWC_SUB_NETWORK_HANDLE,
	ICEDRV_SWC_SUB_NETWORK_TOTAL_JOBS,
	ICEDRV_SWC_SUB_NETWORK_COUNTER_INF_CREATED,
	ICEDRV_SWC_SUB_NETWORK_COUNTER_INF_SCHEDULED,
	ICEDRV_SWC_SUB_NETWORK_COUNTER_INF_COMPLETED,
	ICEDRV_SWC_SUB_NETWORK_COUNTER_INF_DESTROYED
};

/* Groups in ICEDRV_SWC_CLASS_INFER */
enum ICEDRV_SWC_INFER_GROUP {
	ICEDRV_SWC_INFER_GROUP_GEN,
};

enum ICEDRV_SWC_INFER_STATES {
	ICEDRV_SWC_INFER_STATE_UNKNOWN,
	ICEDRV_SWC_INFER_STATE_WAITING,
	ICEDRV_SWC_INFER_STATE_SCHEDULING,
	ICEDRV_SWC_INFER_STATE_SCHEDULED,
	ICEDRV_SWC_INFER_STATE_COMPLETED,
	ICEDRV_SWC_INFER_STATE_EVENT_SENT,
};


/* Counters in ICEDRV_SWC_CLASS_INFER */
enum ICEDRV_SWC_INFER_COUNTER {
	ICEDRV_SWC_INFER_HANDLE,
	ICEDRV_SWC_INFER_STATE,
	ICEDRV_SWC_INFER_COUNTER_REQUEST_SENT,
	ICEDRV_SWC_INFER_COUNTER_REQUEST_COMPLETED,
	ICEDRV_SWC_INFER_ERROR_STATUS,
};

/* Groups in ICEDRV_SWC_CLASS_DEVICE */
enum ICEDRV_SWC_DEVICE_GROUP {
	ICEDRV_SWC_DEVICE_GROUP_GEN,
};

/* Counters in ICEDRV_SWC_CLASS_DEVICE */
enum ICEDRV_SWC_DEVICE_COUNTER {
	ICEDRV_SWC_DEVICE_COUNTER_COMMANDS,
	ICEDRV_SWC_DEVICE_COUNTER_RUNTIME,
	ICEDRV_SWC_DEVICE_COUNTER_BUSY_TIME,
	ICEDRV_SWC_DEVICE_COUNTER_IDLE_TIME,
	ICEDRV_SWC_DEVICE_COUNTER_BUSY_START_TIME,
	ICEDRV_SWC_DEVICE_COUNTER_IDLE_START_TIME,
	ICEDRV_SWC_DEVICE_COUNTER_POWER_STATE,
};

/* Groups in ICEDRV_SWC_CLASS_INFER_DEVICE */
enum ICEDRV_SWC_INFER_DEVICE_GROUP {
	ICEDRV_SWC_INFER_DEVICE_GROUP_GEN,
};

/* Counters in ICEDRV_SWC_CLASS_INFER_DEVICE */
enum ICEDRV_SWC_INFER_DEVICE_COUNTER {
	ICEDRV_SWC_INFER_DEVICE_COUNTER_ID,
	ICEDRV_SWC_INFER_DEVICE_COUNTER_ECC_SERRCOUNT,
	ICEDRV_SWC_INFER_DEVICE_COUNTER_ECC_DERRCOUNT,
	ICEDRV_SWC_INFER_DEVICE_COUNTER_PARITY_ERRCOUNT,
	ICEDRV_SWC_INFER_DEVICE_COUNTER_UNMAPPED_ERR_ID,
};

#define _swc_no_op do {} while (0)
#define _swc_no_op_return_val ((0 == 0) ? 0 : 1)


#if DISBALE_SWC

#define ice_swc_init() _swc_no_op_return_val
#define ice_swc_fini() _swc_no_op

#define ice_swc_check_node(class, node_id, parent, out) _swc_no_op_return_val
#define ice_swc_create_node(class, node_id, parent, counters) \
	_swc_no_op_return_val
#define ice_swc_destroy_node(class, master, node_id) _swc_no_op_return_val
#define ice_swc_group_is_enable(h_counter, idx) _swc_no_op
#define ice_swc_group_set(h_counter, idx, val) _swc_no_op
#define ice_swc_counter_set(h_counter, idx, val) _swc_no_op
#define ice_swc_counter_get(h_counter, idx) _swc_no_op
#define ice_swc_counter_inc(h_counter, idx) _swc_no_op
#define ice_swc_counter_dec(h_counter, idx) _swc_no_op
#define ice_swc_counter_add(h_counter, idx, val) _swc_no_op
#define ice_swc_counter_dec_val(h_counter, idx, val) _swc_no_op
#define ice_swc_counter_atomic_inc(h_counter, idx) _swc_no_op
#define ice_swc_counter_atomic_dec(h_counter, idx) _swc_no_op
#define ice_swc_counter_atomic_add(h_counter, idx, val) _swc_no_op
#define ice_swc_counter_atomic_dec_val(h_counter, idx, val) _swc_no_op

#else
int _swc_init(void);
int _swc_fini(void);

int _swc_check_node(enum ICEDRV_SWC_CLASS class,
		uint64_t node_id, void *parent, void **swc);
int _swc_create_node(enum ICEDRV_SWC_CLASS class,
		uint64_t node_id, void *parent, void **counters);

int _swc_destroy_node(enum ICEDRV_SWC_CLASS class,
		void *master, uint64_t node_id);

u32 _swc_group_is_enable(void *h_counter, u32 idx);
void _swc_group_set(void *h_counter, u32 idx, u64 val);
void _swc_counter_set(void *h_counter, u32 idx, u64 val);
u64 _swc_counter_get(void *h_counter, u32 idx);
void _swc_counter_inc(void *h_counter, u32 idx);
void _swc_counter_dec(void *h_counter, u32 idx);
void _swc_counter_add(void *h_counter, u32 idx, u64 val);
void _swc_counter_dec_val(void *h_counter, u32 idx, u64 val);
void _swc_counter_atomic_inc(void *h_counter, u32 idx);
void _swc_counter_atomic_dec(void *h_counter, u32 idx);
void _swc_counter_atomic_add(void *h_counter, u32 idx, u64 val);
void _swc_counter_atomic_dec_val(void *h_counter, u32 idx, u64 val);


#define ice_swc_init() _swc_init()
#define ice_swc_fini() _swc_fini()
#define ice_swc_check_node(class, node_id, parent, out) \
	_swc_check_node(class, node_id, parent, out)
#define ice_swc_create_node(class, node_id, parent, counters) \
	_swc_create_node(class, node_id, parent, counters)
#define ice_swc_destroy_node(class, master, node_id) \
	_swc_destroy_node(class, master, node_id)
#define ice_swc_group_is_enable(h_counter, idx) \
	_swc_group_is_enable(h_counter, idx)
#define ice_swc_group_set(h_counter, idx, val) \
	_swc_group_set(h_counter, idx, val)
#define ice_swc_counter_set(h_counter, idx, val) \
	_swc_counter_set(h_counter, idx, val)
#define ice_swc_counter_get(h_counter, idx) _swc_counter_get(h_counter, idx)
#define ice_swc_counter_inc(h_counter, idx) _swc_counter_inc(h_counter, idx)
#define ice_swc_counter_dec(h_counter, idx) _swc_counter_dec(h_counter, idx)
#define ice_swc_counter_add(h_counter, idx, val) \
	_swc_counter_add(h_counter, idx, val)
#define ice_swc_counter_dec_val(h_counter, idx, val) \
	_swc_counter_dec_val(h_counter, idx, val)
#define ice_swc_counter_atomic_inc(h_counter, idx) \
	_swc_counter_atomic_inc(h_counter, idx)
#define ice_swc_counter_atomic_dec(h_counter, idx) \
	_swc_counter_atomic_dec(h_counter, idx)
#define ice_swc_counter_atomic_add(h_counter, idx, val) \
	_swc_counter_atomic_add(h_counter, idx, val)
#define ice_swc_counter_atomic_dec_val(h_counter, idx, val) \
	_swc_counter_atomic_dec_val(h_counter, idx, val)

#endif /* DISBALE_SWC */

#endif /* _ICE_SW_COUNTERS_H_ */
