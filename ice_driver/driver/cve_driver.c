/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/



#include "os_interface.h"
#include "dispatcher.h"
#include "device_interface.h"
#include "memory_manager.h"
#include "cve_driver_internal.h"
#include "cve_driver_internal_funcs.h"
#include "cve_firmware.h"
#include "cve_device.h"
#include "cve_linux_internal.h"
#include "cve_device_group.h"
#include "project_settings.h"
#include "scheduler.h"
#ifdef RING3_VALIDATION
#include "coral_memory.h"
#endif

/* GLOBAL VARIABLES */

/* driver's general lock */
cve_os_lock_t g_cve_driver_biglock;

/* PUBLIC FUNCTIONS */

int cve_driver_init(void)
{
	int retval;

	/*debug fs and module params set*/
	cve_debug_init();

#ifdef RING3_VALIDATION
	/*FixMe:Currently w/o error check as coral api returns void */
	size_t pa_size = 0x100000000;

	coral_pa_mem_init_with_size(&pa_size);
	if (pa_size != 0x100000000) {
		cve_os_log(CVE_LOGLEVEL_INFO,
				"coral mem init with size = %lu\n", pa_size);
	}

	retval = ice_os_mutex_init();
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"ice_os_mutex_init failed %d\n", retval);
		goto debug_cleanup;
	}
#endif

	retval = cve_fw_init();
#ifdef RING3_VALIDATION
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"cve_fw_init failed %d\n", retval);
		goto debug_cleanup;
	}
#endif

	retval = ice_kmd_create_dg();
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"failed to created device groups %d\n", retval);
		goto debug_cleanup;
	}

	cve_dg_start_poweroff_thread();

	retval = cve_os_interface_init();
#ifdef RING3_VALIDATION
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"os_driver_init failed %d\n", retval);
		goto dg_cleanup;
	}
#endif

	ice_sch_init();

	retval = cve_os_lock_init(&g_cve_driver_biglock);
#ifdef RING3_VALIDATION
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"os_lock_init failed %d\n", retval);
		goto os_interface_cleanup;
	}
#endif


	return 0;

#ifdef RING3_VALIDATION
os_interface_cleanup:
	cve_os_interface_cleanup();
dg_cleanup:
	ice_kmd_destroy_dg();
#endif
debug_cleanup:
	cve_debug_destroy();

	return retval;
}

void cve_driver_cleanup(void)
{
	/* block input from users */
	int ret = cve_os_lock(&g_cve_driver_biglock, CVE_INTERRUPTIBLE);

	if (ret) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"Something bad happened when cleaning, ret=%d.", ret);
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"Got interrupted while trying to get a lock. Ignoring it.");
	}

	ice_di_deactivate_driver();

	cve_di_cleanup();

	cve_debug_destroy();
	cve_os_unlock(&g_cve_driver_biglock);

	/* need to be outside the lock to avoid deadlocks */
	cve_os_interface_cleanup();

	ice_kmd_destroy_dg();

#ifdef RING3_VALIDATION
	ice_os_mutex_cleanup();
	coral_pa_mem_delete();
#endif
}
