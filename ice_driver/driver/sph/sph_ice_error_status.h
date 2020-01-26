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
