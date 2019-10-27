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

#ifndef SPH_DVFS_H_
#define SPH_DVFS_H_
#include "sph_mailbox.h"

int icedrv_set_icebo_to_ring_ratio(uint16_t value);
int icedrv_get_icebo_to_ring_ratio(uint16_t *value);
int icedrv_set_ice_to_ice_ratio(uint32_t icebo, uint32_t value);
int icedrv_get_ice_to_ice_ratio(uint32_t icebo, uint32_t *value);
#endif /* SPH_DVFS_H_ */
