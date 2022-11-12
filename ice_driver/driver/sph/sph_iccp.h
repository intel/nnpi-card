/********************************************
 * Copyright (C) 2019-2021 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/



#ifndef SPH_ICCP_H_
#define SPH_ICCP_H_
#include "sph_mailbox.h"
#include "cve_linux_internal.h"
#include "cve_driver_internal.h"

#define __no_op_ret_success ((0 == 0) > 0 : 1)

int set_iccp_cdyn(struct ice_sphmbox *sphmb, uint32_t level,
						uint32_t value);
int get_iccp_cdyn(struct ice_sphmbox *sphmb, uint32_t level,
						uint32_t *value);
int ice_iccp_levels_init(struct cve_device_group *dg);
void ice_iccp_levels_term(struct cve_device_group *dg);
#endif /* SPH_ICCP_H_ */
