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

const char *get_SCB_STATE_str(uint32_t state);

const char *get_cve_jobs_group_status_str(uint32_t status);

const char *get_osmm_memory_type_str(uint32_t type);

const char *get_cve_memory_protection_str(uint32_t prot);

const char *get_cve_surface_direction_str(uint32_t dir);

const char *get_fw_binary_type_str(uint32_t type);

const char *get_regs_str(uint32_t offset);

const char *get_idc_regs_str(uint32_t offset);
#endif /* _ICE_DEBUG_H_ */
