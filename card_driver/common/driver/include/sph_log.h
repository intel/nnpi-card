/********************************************
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#ifndef _SPH_LOG_H
#define _SPH_LOG_H

#include <linux/printk.h>
#include "log_category_defs.h"

#define sph_log_debug(category, fmt, arg...)   pr_debug(KBUILD_MODNAME ", " category ", %s: " fmt, __func__, ##arg)
#define sph_log_info(category, fmt, arg...)    pr_info(KBUILD_MODNAME ", " category ", %s: " fmt, __func__, ##arg)
#define sph_log_warn(category, fmt, arg...)    pr_warn(KBUILD_MODNAME ", " category ", %s: " fmt, __func__, ##arg)
#define sph_log_err(category, fmt, arg...)     pr_err(KBUILD_MODNAME ", " category ", %s: " fmt, __func__, ##arg)

#endif
