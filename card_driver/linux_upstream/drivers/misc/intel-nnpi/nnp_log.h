/* SPDX-License-Identifier: GPL-2.0-or-later */

/********************************************
 * Copyright (C) 2019-2021 Intel Corporation
 ********************************************/

#ifndef _NNP_LOG_H
#define _NNP_LOG_H

#include <linux/printk.h>

/*  log categories */
#define GENERAL_LOG "NNPLOG_GENERAL"
#define START_UP_LOG "NNPLOG_START_UP"
#define GO_DOWN_LOG "NNPLOG_GO_DOWN"
#define IPC_LOG "NNPLOG_IPC"
#define CREATE_COMMAND_LOG "NNPLOG_CREATE_COMMAND"

#define nnp_log_debug(category, fmt, arg...) \
	pr_debug(KBUILD_MODNAME ", " category " , DEBUG, %s: " fmt, \
		 __func__, ##arg)

#define nnp_log_info(category, fmt, arg...)  \
	pr_info(KBUILD_MODNAME ", " category " , INFO, %s: " fmt, \
		__func__, ##arg)

#define nnp_log_warn(category, fmt, arg...)  \
	pr_warn(KBUILD_MODNAME ", " category " , WARNING, %s: " fmt, \
		__func__, ##arg)

#define nnp_log_err(category, fmt, arg...)   \
	pr_err(KBUILD_MODNAME ", " category " , ERROR, %s: " fmt, \
	       __func__, ##arg)

#endif
