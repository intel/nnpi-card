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

#ifndef _CVE_DRIVER_INTERNAL_H_
#define _CVE_DRIVER_INTERNAL_H_

#include "os_interface.h"
#include "cve_driver_internal_macros.h"
#include "cve_device.h"
#include "cve_device_group.h"
#include "version.h"

/* driver's global lock */
extern cve_os_lock_t g_cve_driver_biglock;

/* driver's global versions */
extern Version tlc_version;
extern Version ivp_version;
extern Version asip_version;

/*
 * Cache maintenance direction enum
 */
enum cve_cache_sync_direction {
	SYNC_TO_HOST = 0x01,
	SYNC_TO_DEVICE = 0x02
};

#endif /* _CVE_DRIVER_INTERNAL_H_ */
