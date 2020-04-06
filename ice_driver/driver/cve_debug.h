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

#ifndef CVE_DEBUG_H_
#define CVE_DEBUG_H_

#ifndef RING3_VALIDATION
#include <linux/types.h>
#else
#include <stdint.h>
#include <stdint_ext.h>
#endif

/* This variable contains the debug-fs value of debug_wd_en
 * It will be updated only before dispatching a new workload
 */
extern u32 enable_wdt_debugfs;
extern int mem_detect_en;

enum cve_debug_config {
	/*tensilica configuration enable*/
	DEBUG_TENS_EN,		/* 0:disable , 1:enable */
	DEBUG_WD_EN,		/* 0:disable , 1:enable */
	DEBUG_DTF_SRC_EN,
	DEBUG_DTF_DST_EN,
	DEBUG_RECOVERY_EN,	/* 0:disable , 1:enable */
	DEBUG_CONF_NUM
};

/*
 * Initialize debug configuration
 * inputs : none
 * outputs:	none
 * returns: none
 */
void cve_debug_init(void);

/*
 * destroy debug configuration
 * inputs : none
 * outputs:	none
 * returns: none
 */
void cve_debug_destroy(void);

/*
 * set global debug configuration
 * inputs :
 * val - value of debug configuration
 * d_config - debug configuration type/index
 * outputs:	none
 * returns: none
 */
void cve_debug_set(enum cve_debug_config d_config, u32 val);

/*
 * get global debug configuration of
 * inputs :
 *	d_config - debug configuration type/index
 * outputs:	none
 * returns: configuration setting
 */
u32 cve_debug_get(enum cve_debug_config d_config);

#endif /* CVE_DEBUG_H_ */
