/********************************************
 * Copyright (C) 2019-2021 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/



#ifndef _ICEDRV_INTERNAL_SW_COUNTER_FUNCS_H_
#define _ICEDRV_INTERNAL_SW_COUNTER_FUNCS_H_

#include "ice_sw_counters.h"

#include "cve_device.h"

int _create_dev_node(struct cve_device *dev);
int _destroy_dev_node(struct cve_device *dev);

int _create_context_node(struct ds_context *ctx);
int _destroy_context_node(struct ds_context *ctx);

int _create_pntw_node(struct ice_pnetwork *pntw);
int _destroy_pntw_node(struct ice_pnetwork *pntw);

int _create_ntw_node(struct ice_network *ntw);
int _destroy_ntw_node(struct ice_network *ntw);

int _create_infer_node(struct ice_infer *infer);
int _destroy_infer_node(struct ice_infer *infer);

void _create_infer_device_node(struct ice_network *ntw);
void _destroy_infer_device_node(struct ice_network *ntw);


#define _internal_swc_no_op do {} while (0)
#define _internal_swc_no_op_return_val ((0 == 0) ? 0 : 1)

#if DISBALE_SWC

#define ice_swc_create_dev_node(dev) _internal_swc_no_op
#define ice_swc_destroy_dev_node(ctx) _internal_swc_no_op
#define ice_swc_create_context_node(ctx) _internal_swc_no_op
#define ice_swc_destroy_context_node(ctx) _internal_swc_no_op
#define ice_swc_create_pntw_node(pntw) _internal_swc_no_op
#define ice_swc_destroy_pntw_node(pntw) _internal_swc_no_op
#define ice_swc_create_ntw_node(ntw) _internal_swc_no_op
#define ice_swc_destroy_ntw_node(ntw) _internal_swc_no_op
#define ice_swc_create_infer_node(infer) _internal_swc_no_op
#define ice_swc_destroy_infer_node(infer) _internal_swc_no_op

#define ice_swc_create_infer_device_node(ntw) _internal_swc_no_op
#define ice_swc_destroy_infer_device_node(ntw) _internal_swc_no_op

#else /*DISBALE_SWC */

#define ice_swc_create_dev_node(dev) _create_dev_node(dev)
#define ice_swc_destroy_dev_node(dev) _destroy_dev_node(dev)
#define ice_swc_create_context_node(ctx) _create_context_node(ctx)
#define ice_swc_destroy_context_node(ctx) _destroy_context_node(ctx)
#define ice_swc_create_ntw_node(ntw) _create_ntw_node(ntw)
#define ice_swc_destroy_ntw_node(ntw) _destroy_ntw_node(ntw)
#define ice_swc_create_pntw_node(pntw) _create_pntw_node(pntw)
#define ice_swc_destroy_pntw_node(pntw) _destroy_pntw_node(pntw)
#define ice_swc_create_infer_node(infer) _create_infer_node(infer)
#define ice_swc_destroy_infer_node(infer) _destroy_infer_node(infer)

#define ice_swc_create_infer_device_node(ntw) _create_infer_device_node(ntw)
#define ice_swc_destroy_infer_device_node(ntw) _destroy_infer_device_node(ntw)

#endif /*DISBALE_SWC */

#endif /* _ICEDRV_INTERNAL_SW_COUNTER_FUNCS_H_ */
