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

#ifndef DRIVER_SCHEDULER_H_
#define DRIVER_SCHEDULER_H_

#include "cve_device.h"

void ice_schedule_network(struct ice_network *ntw);
int ice_schedule_remove_network(struct ice_network *ntw);
void ice_scheduler_engine(struct ice_network *ntw);
void ice_deschedule_network(struct ice_network *ntw);
void ice_sch_reset_exe_order(void);
struct ice_infer *ice_sch_get_next_ntw_infer(
			struct ice_network *ntw);
struct ice_infer *ice_sch_get_next_sch_infer(void);
#endif /* DRIVER_SCHEDULER_H_ */
