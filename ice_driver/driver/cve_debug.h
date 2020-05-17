/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/



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

enum cve_debug_config {
	/*tensilica configuration enable*/
	DEBUG_WD_EN,		/* 0:disable , 1:enable */
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
