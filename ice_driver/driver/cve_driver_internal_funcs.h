/********************************************
 * Copyright (C) 2019-2021 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/



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
