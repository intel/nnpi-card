/********************************************
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/stringify.h>

#include "sphcs_pcie.h"
#include "sph_log.h"
#include "sphcs_cs.h"
#include "sphcs_genmsg.h"
#ifdef ULT
#include "sphcs_ult.h"
#endif
#include "sphcs_net.h"
#include "sph_version.h"
#include "sphcs_maintenance.h"
#include "sphcs_trace.h"
#include "sphcs_p2p_test.h"


int sphcs_init_module(void)
{
	int ret = 0;

	sph_log_debug(START_UP_LOG, "module (version %s) started\n", SPH_VERSION);

	DO_TRACE(sphcs_trace_init());

	ret = sphcs_hw_init(&g_sphcs_pcie_callbacks);
	if (ret)
		sph_log_err(START_UP_LOG, "Failed to init hw layer\n");

	/* Initliaize general messaging interface character device */
	ret = sphcs_init_genmsg_interface();
	if (ret) {
		sph_log_err(START_UP_LOG, "Failed to init general messaging interface\n");
		ret = -ENODEV;
		goto pcie_cleanup;
	}

	/* Initialize maintenance interface character device */
	ret = sphcs_init_maint_interface();
	if (ret) {
		sph_log_err(START_UP_LOG, "Failed to init maintenance interface\n");
		ret = -ENODEV;
		goto sphcs_genmsg_cleanup;
	}
#ifdef ULT
	/* Initlize ULT module */
	ret = sphcs_init_ult_module();
	if (ret) {
		sph_log_err(START_UP_LOG, "Failed to init ult module\n");
		ret = -ENODEV;
		goto sphcs_maint_cleanup;
	}

	sphcs_p2p_test_init();
#endif


	return 0;

#ifdef ULT
	sphcs_p2p_test_cleanup();
	sphcs_fini_ult_module();

sphcs_maint_cleanup:
#endif
	sphcs_release_maint_interface();
sphcs_genmsg_cleanup:
	sphcs_release_genmsg_interface();
pcie_cleanup:
	sphcs_hw_cleanup();

	return ret;
}

void sphcs_cleanup(void)
{
	sph_log_debug(GO_DOWN_LOG, "Cleaning Up the Module\n");
#ifdef ULT
	sphcs_p2p_test_cleanup();

	sphcs_fini_ult_module();
#endif
	sphcs_net_dev_exit();

	sphcs_release_maint_interface();

	sphcs_release_genmsg_interface();

	sphcs_hw_cleanup();
}

module_init(sphcs_init_module);
module_exit(sphcs_cleanup);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("SpringHill Card Driver");
MODULE_AUTHOR("Intel Corporation");
MODULE_VERSION(SPH_VERSION);
#ifdef DEBUG
MODULE_INFO(git_hash, SPH_GIT_HASH);
#endif
