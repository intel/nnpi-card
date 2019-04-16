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

extern void *g_sph_swc_global;

/* A Counter belongs to one of the following class */
enum ICEDRV_SWC_CLASS {
	/* Global counters */
	ICEDRV_SWC_CLASS_GLOBAL,
	/* Context specific counters */
	ICEDRV_SWC_CLASS_CONTEXT,
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
	ICEDRV_SWC_GLOBAL_COUNTER_CTX_DEST
};

/* Groups in ICEDRV_SWC_CLASS_CONTEXT */
enum ICEDRV_SWC_CONTEXT_GROUP {
	ICEDRV_SWC_CONTEXT_GROUP_GEN,
};

/* Counters in ICEDRV_SWC_CLASS_CONTEXT */
enum ICEDRV_SWC_CONTEXT_COUNTER {
	ICEDRV_SWC_CONTEXT_COUNTER_INF_TOTAL,
	ICEDRV_SWC_CONTEXT_COUNTER_INF_CURR,
	ICEDRV_SWC_CONTEXT_COUNTER_INF_DEST
};

/* Groups in ICEDRV_SWC_CLASS_INFER */
enum ICEDRV_SWC_INFER_GROUP {
	ICEDRV_SWC_INFER_GROUP_GEN,
};

/* Counters in ICEDRV_SWC_CLASS_INFER */
enum ICEDRV_SWC_INFER_COUNTER {
	ICEDRV_SWC_INFER_COUNTER_EXE_TOTAL,
};

/* Groups in ICEDRV_SWC_CLASS_DEVICE */
enum ICEDRV_SWC_DEVICE_GROUP {
	ICEDRV_SWC_DEVICE_GROUP_GEN,
};

/* Counters in ICEDRV_SWC_CLASS_DEVICE */
enum ICEDRV_SWC_DEVICE_COUNTER {
	ICEDRV_SWC_DEVICE_COUNTER_COMMANDS,
	ICEDRV_SWC_DEVICE_COUNTER_RUNTIME,
};

/* Groups in ICEDRV_SWC_CLASS_INFER_DEVICE */
enum ICEDRV_SWC_INFER_DEVICE_GROUP {
	ICEDRV_SWC_INFER_DEVICE_GROUP_GEN,
};

/* Counters in ICEDRV_SWC_CLASS_INFER_DEVICE */
enum ICEDRV_SWC_INFER_DEVICE_COUNTER {
	ICEDRV_SWC_INFER_DEVICE_COUNTER_ECC_SERRCOUNT,
	ICEDRV_SWC_INFER_DEVICE_COUNTER_ECC_DERRCOUNT,
	ICEDRV_SWC_INFER_DEVICE_COUNTER_PARITY_ERRCOUNT,
	ICEDRV_SWC_INFER_DEVICE_COUNTER_UNMAPPED_ERR_ID,
};

int ice_swc_init(void);
int ice_swc_fini(void);

int ice_swc_create_node(enum ICEDRV_SWC_CLASS class,
			uint64_t node_id,
			uint64_t parent_id,
			void **counters);

int ice_swc_destroy_node(enum ICEDRV_SWC_CLASS class,
			uint64_t node_id);

u32 ice_swc_group_is_enable(void *h_counter, u32 idx);
void ice_swc_group_set(void *h_counter, u32 idx, u64 val);
void ice_swc_counter_set(void *h_counter, u32 idx, u64 val);
u64 ice_swc_counter_get(void *h_counter, u32 idx);
void ice_swc_counter_inc(void *h_counter, u32 idx);
void ice_swc_counter_dec(void *h_counter, u32 idx);
void ice_swc_counter_add(void *h_counter, u32 idx, u64 val);
void ice_swc_counter_dec_val(void *h_counter, u32 idx, u64 val);
void ice_swc_counter_atomic_inc(void *h_counter, u32 idx);
void ice_swc_counter_atomic_dec(void *h_counter, u32 idx);
void ice_swc_counter_atomic_add(void *h_counter, u32 idx, u64 val);
void ice_swc_counter_atomic_dec_val(void *h_counter, u32 idx, u64 val);

#endif /* _ICE_SW_COUNTERS_H_ */
