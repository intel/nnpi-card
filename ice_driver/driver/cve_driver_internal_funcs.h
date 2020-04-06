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

#ifndef _CVE_DRIVER_INTERNAL_FUNCS_H_
#define _CVE_DRIVER_INTERNAL_FUNCS_H_

/*
 * initiaizes the device. done once on system power up
 * inputs :
 * outputs:
 * returns: 0 on success, a negative error value on error
 */
int cve_driver_init(void);

/*
 * tears down the device. done once on system power down
 * inputs :
 * outputs:
 * returns:
 */
void cve_driver_cleanup(void);

#endif /* _CVE_DRIVER_INTERNAL_H_ */
