/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/



#include "os_interface.h"
#include "cve_driver_utils.h"
#include "cve_driver_internal.h"

#define PRINT_BUF_LINE_SIZE 128

/*
 * CAUTION: This function consume time & space: it contains data array
 * (size PRINT_BUF_LINE_SIZE). Please use this function only for
 * debugging purpose
 */
void cve_utils_print_buffer(void *kbuf,
		u32 buf_len,
		const char *buf_name, const char *addr)
{
	u32 i;
	u8 *kbuf_8 = (u8 *)kbuf;
	u32 cur_pos = 0;
	char data_buf[PRINT_BUF_LINE_SIZE] = {0};

	/*
	 * print with ERROR log level, to avoid add of this
	 * messages to dynamic debug messages list. Print
	 * of all of the messages below is controlled by dummy
	 * print message in cve_utils_print_user_buffer() &
	 * cve_utils_print_kernel_buffer() functions
	 */
	_cve_os_log(CVE_LOGLEVEL_INFO,
		"\n***********************************\n");
	_cve_os_log(CVE_LOGLEVEL_INFO,
		" buf_name = '%s', buf_len = %d",
		buf_name, buf_len);
	for (i = 0; i < buf_len; i++) {
		if ((i % 32) == 0) {
			_cve_os_log(CVE_LOGLEVEL_INFO,
				"%s\n",
				data_buf);
			cur_pos = snprintf(data_buf,
				PRINT_BUF_LINE_SIZE,
				"0x%p:",
				addr + i);
		}

		/*
		 *  Caution: snprintf is needed because, each
		 *  call to pr_debug will print new line in the log.
		 *  So, we will build a line with snprintf and then
		 *  call pr_debug func.
		 */
		cur_pos += snprintf(&data_buf[cur_pos],
			PRINT_BUF_LINE_SIZE - cur_pos,
			"%02X",
			kbuf_8[i]);
	}
	_cve_os_log(CVE_LOGLEVEL_INFO,
		"%s", data_buf);
	_cve_os_log(CVE_LOGLEVEL_INFO,
		"\n***********************************\n");
}
void cve_utils_print_version_struct(const char *fw_name,
		const Version *version_struct) {
	cve_os_log(CVE_LOGLEVEL_DEBUG,
			"print %s version\n",
			fw_name);

	cve_os_log(CVE_LOGLEVEL_DEBUG,
			"component: product=%d, major=%d, minor=%x, patch=%x, metadata=%x, checksum=%x\n",
			version_struct->component.product,
			version_struct->component.major,
			version_struct->component.minor,
			version_struct->component.patch,
			version_struct->component.metadata,
			version_struct->component.checksum);

	cve_os_log(CVE_LOGLEVEL_DEBUG,
			"product: product=%d, major=%d, minor=%x, patch=%x, metadata=%x, checksum=%x\n",
			version_struct->product.product,
			version_struct->product.major,
			version_struct->product.minor,
			version_struct->product.patch,
			version_struct->product.metadata,
			version_struct->product.checksum);
}

