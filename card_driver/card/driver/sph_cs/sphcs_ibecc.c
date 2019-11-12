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
#include <linux/scatterlist.h>
#include <linux/ion_exp.h>
#include "sphcs_cs.h"
#include "sph_mem_alloc_defs.h"

/* IBECC error cb runs in process ctxt */
static int ibecc_error_cb(struct notifier_block *nb, unsigned long action, void *data)
{
	struct ibecc_err_info *err_info = (struct ibecc_err_info *)data;
	union sph_mem_protected_buff_attr buff_attr;
	bool corrected;
	bool is_fatal = false;
	int context_id = -1;
	uint16_t eventCode;
	uint16_t eventVal;
	int ret;

	corrected = (err_info->type == HW_EVENT_ERR_CORRECTED);
	is_fatal = (err_info->type == HW_EVENT_ERR_UNCORRECTED);

	sph_log_info(GENERAL_LOG, "IBECC error at addr 0x%llX corrected=%d\n",
		     err_info->sys_addr, corrected);

	ret = ion_get_buf_user_data(err_info->sys_addr, &buff_attr.value);
	if (ret == 0) {
		/* This is an ion buffer - consider non-fatal if context id valid */
		if (buff_attr.context_id_valid == 1 &&
		    buff_attr.uc_ecc_severity != 2) {
			context_id = buff_attr.context_id;
			is_fatal = (buff_attr.uc_ecc_severity == 1) ? true : false;
		}
	}

	if (corrected)
		eventCode = SPH_IPC_ERROR_MCE_CORRECTABLE;
	else if (is_fatal && context_id != -1)
		eventCode = SPH_IPC_CTX_MCE_UNCORRECTABLE;
	else if (is_fatal)
		eventCode = SPH_IPC_ERROR_MCE_UNCORRECTABLE_FATAL;
	else
		eventCode = SPH_IPC_ERROR_MCE_UNCORRECTABLE;

	eventVal = 1; // flags ecc error

	sphcs_send_event_report(g_the_sphcs,
				eventCode,
				eventVal,
				-1,
				context_id); /* context_id is passed as objID in purpose! */

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
