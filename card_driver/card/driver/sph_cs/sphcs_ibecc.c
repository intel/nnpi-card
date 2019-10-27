/********************************************
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#include "sphcs_ibecc.h"
#include "sph_log.h"
#include <linux/kernel.h>

#ifdef CARD_PLATFORM_BR

#include <../drivers/edac/igen6_edac.h>

/* IBECC error cb runs in process ctxt */
static int ibecc_error_cb(struct notifier_block *nb, unsigned long action, void *data)
{
	struct ibecc_err_info *err_info = (struct ibecc_err_info *)data;

	sph_log_info(GENERAL_LOG, "IBECC error at addr 0x%llX\n", err_info->sys_addr);

	return NOTIFY_OK;
}

static struct notifier_block ibecc_errors_notifier = {
	.notifier_call = ibecc_error_cb,
};

int sphcs_ibecc_init(void)
{
	return ibecc_err_register_notifer(&ibecc_errors_notifier);
}

int sphcs_ibecc_fini(void)
{
	return ibecc_err_unregister_notifer(&ibecc_errors_notifier);
}
#else
int sphcs_ibecc_init(void)
{
	return 0;
}

int sphcs_ibecc_fini(void)
{
	return 0;
}
#endif
