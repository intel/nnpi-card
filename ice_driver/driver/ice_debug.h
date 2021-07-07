/********************************************
 * Copyright (C) 2019-2021 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/



#ifndef _ICE_DEBUG_H_
#define _ICE_DEBUG_H_

#ifndef RING3_VALIDATION
#include <linux/types.h>
#else
#include <stdint.h>
#endif

#define COLOR_RED(a) "\033[0;31m" a "\033[0m;"
#define COLOR_GREEN(a) "\033[0;32m" a "\033[0m;"
#define COLOR_YELLOW(a) "\033[0;33m" a "\033[0m;"
#define COLOR_BLUE(a) "\033[0;34m" a "\033[0m;"

const char *get_cve_jobs_group_status_str(uint32_t status);

const char *get_osmm_memory_type_str(uint32_t type);

const char *get_cve_memory_protection_str(uint32_t prot);

const char *get_cve_surface_direction_str(uint32_t dir);

const char *get_fw_binary_type_str(uint32_t type);

const char *get_regs_str(uint32_t offset);

const char *get_idc_regs_str(uint32_t offset);

const char *get_other_regs_str(uint32_t offset);

#endif /* _ICE_DEBUG_H_ */
