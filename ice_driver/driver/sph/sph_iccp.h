/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/



#ifndef SPH_ICCP_H_
#define SPH_ICCP_H_
#include "sph_mailbox.h"
#include "cve_linux_internal.h"
#include "cve_driver_internal.h"

#define __no_op_ret_success ((0 == 0) > 0 : 1)

#ifdef RING3_VALIDATION
#define init_iccp_sysfs() __no_op_return_success
#define term_iccp_sysfs() __no_op_stub
#else
#define init_iccp_sysfs() iccp_sysfs_init()
#define term_iccp_sysfs() iccp_sysfs_term()
#endif

int iccp_sysfs_init(void);
void iccp_sysfs_term(void);
int set_iccp_cdyn(struct ice_sphmbox *sphmb, uint32_t level,
						uint32_t value);
int get_iccp_cdyn(struct ice_sphmbox *sphmb, uint32_t level,
						uint32_t *value);
int ice_iccp_levels_init(struct cve_device_group *dg);
void ice_iccp_levels_term(struct cve_device_group *dg);
#endif /* SPH_ICCP_H_ */
