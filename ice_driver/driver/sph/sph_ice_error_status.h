/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/




#ifndef SPH_ICE_ERROR_STATUS_H_
#define SPH_ICE_ERROR_STATUS_H_
#include "cve_linux_internal.h"
#include "cve_driver_internal.h"

#define __no_op_ret_success ((0 == 0) > 0 : 1)

void ice_flow_debug_term(void);
int ice_flow_debug_init(void);
u32 ice_os_get_user_intst(int dev_id);
u64 ice_os_get_user_idc_intst(void);

#endif /* SPH_ICE_ERROR_STATUS_H_ */
