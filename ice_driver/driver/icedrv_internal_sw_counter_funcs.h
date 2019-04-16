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

void ice_swc_create_infer_device_node(struct ice_network *ntw);

#endif /* _ICEDRV_INTERNAL_SW_COUNTER_FUNCS_H_ */
