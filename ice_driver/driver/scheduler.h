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

void ice_sch_engine(struct ice_network *ntw);
void ice_sch_add_inf_to_queue(struct ice_infer *inf);
void ice_sch_del_inf_from_queue(struct ice_infer *inf);
void ice_sch_add_rr_to_queue(struct execution_node *node);
int ice_sch_del_rr_from_queue(struct execution_node *node);
#endif /* DRIVER_SCHEDULER_H_ */
