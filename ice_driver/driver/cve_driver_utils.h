/********************************************
 * Copyright (C) 2019-2021 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/



#ifndef CVE_DRIVER_UTILS_H_
#define CVE_DRIVER_UTILS_H_

void cve_utils_print_buffer(void *kbuf,
		u32 buf_len,
		const char *buf_name, const char *addr);

void cve_utils_print_version_struct(const char *fw_name,
		const Version *version_struct);

#endif /* CVE_DRIVER_UTILS_H_ */

