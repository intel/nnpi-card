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


#ifndef DRIVER_INTERFACE_H_
#define DRIVER_INTERFACE_H_

#include "cve_driver.h"
#include "cve_driver_internal_funcs.h"

int cve_ioctl_misc(int fd, int request, struct cve_ioctl_param * param);
int cve_open_misc(void);
int cve_close_misc(int fd);

#endif /* DRIVER_INTERFACE_H_ */
