/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/



#ifndef _CVE_DRIVER_INTERNAL_H_
#define _CVE_DRIVER_INTERNAL_H_

#include "os_interface.h"
#include "cve_driver_internal_macros.h"
#include "cve_device.h"
#include "cve_device_group.h"
#include "version.h"

#define ICEDRV_ENABLE_HSLE_FLOW 0

#define __no_op_stub do {} while (0)

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
