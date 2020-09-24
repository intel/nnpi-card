/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/



#ifndef DRIVER_SCHEDULER_H_
#define DRIVER_SCHEDULER_H_

#include "cve_device.h"

int ice_sch_init(void);
void ice_sch_engine(struct ice_pnetwork *pntw, bool from_bh);
bool ice_lsch_add_inf_to_queue(struct ice_infer *inf,
	enum ice_execute_infer_priority pr, bool enable_bp);
bool ice_lsch_del_inf_from_queue(struct ice_infer *inf, bool lock);
bool ice_lsch_add_rr_to_queue(struct execution_node *node);
bool ice_lsch_del_rr_from_queue(struct execution_node *node, bool lock);
void ice_lsch_destroy_pnetwork(struct ice_pnetwork *pntw);
#endif /* DRIVER_SCHEDULER_H_ */
