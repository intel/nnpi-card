/*
 * NNP-I Linux Driver
 * Copyright (c) 2019, Intel Corporation.
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

#ifndef _ICEDRV_INTERNAL_SW_COUNTER_FUNCS_H_
#define _ICEDRV_INTERNAL_SW_COUNTER_FUNCS_H_

#ifndef RING3_VALIDATION
#include "ice_sw_counters.h"
#endif

#include "cve_device.h"

#ifndef RING3_VALIDATION
#define _ENABLE_ICE_SWC 1
#else
#define _ENABLE_ICE_SWC 0
#endif

int _create_dev_node(struct cve_device *dev);
int _destroy_dev_node(struct cve_device *dev);

int _create_context_node(struct ds_context *ctx);
int _destroy_context_node(struct ds_context *ctx);

int _create_ntw_node(struct ice_network *ntw);
int _destroy_ntw_node(struct ice_network *ntw);

int _create_infer_node(struct ice_infer *infer);
int _destroy_infer_node(struct ice_infer *infer);

void ice_swc_create_infer_device_node(struct ice_network *ntw);
void ice_swc_destroy_infer_device_node(struct ice_network *ntw);


#define _internal_swc_no_op do {} while (0)
#define _internal_swc_no_op_return_val ((0 == 0) ? 0 : 1)

#if _ENABLE_ICE_SWC

#define ice_swc_create_dev_node(dev) _create_dev_node(dev)
#define ice_swc_destroy_dev_node(dev) _destroy_dev_node(dev)
#define ice_swc_create_context_node(ctx) _create_context_node(ctx)
#define ice_swc_destroy_context_node(ctx) _destroy_context_node(ctx)
#define ice_swc_create_ntw_node(ntw) _create_ntw_node(ntw)
#define ice_swc_destroy_ntw_node(ntw) _destroy_ntw_node(ntw)
#define ice_swc_create_infer_node(infer) _create_infer_node(infer)
#define ice_swc_destroy_infer_node(infer) _destroy_infer_node(infer)

#else /*_ENABLE_ICE_SWC */

#define ice_swc_create_dev_node(dev) _internal_swc_no_op
#define ice_swc_destroy_dev_node(ctx) _internal_swc_no_op
#define ice_swc_create_context_node(ctx) _internal_swc_no_op
#define ice_swc_destroy_context_node(ctx) _internal_swc_no_op
#define ice_swc_create_ntw_node(ntw) _internal_swc_no_op
#define ice_swc_destroy_ntw_node(ntw) _internal_swc_no_op
#define ice_swc_create_infer_node(infer) _internal_swc_no_op
#define ice_swc_destroy_infer_node(infer) _internal_swc_no_op

#endif /*_ENABLE_ICE_SWC */

#endif /* _ICEDRV_INTERNAL_SW_COUNTER_FUNCS_H_ */
