/********************************************
 * Copyright (C) 2019-2021 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/



#ifndef SPH_DVFS_H_
#define SPH_DVFS_H_
#include "sph_mailbox.h"

int icedrv_set_icebo_to_ring_ratio(uint16_t value);
int icedrv_get_icebo_to_ring_ratio(uint16_t *value);
int icedrv_set_ice_to_ice_ratio(union FREQUENCY_RATIO value);
int icedrv_get_ice_to_ice_ratio(union FREQUENCY_RATIO *value);
int icedrv_get_icebo_frequency(uint32_t icebo_num, uint32_t *freq);
int icedrv_set_clock_squash(uint32_t icebo_mask, uint8_t t_state_req,
								bool enable);
#endif /* SPH_DVFS_H_ */
