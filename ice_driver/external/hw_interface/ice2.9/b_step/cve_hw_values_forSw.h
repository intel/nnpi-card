/*******************************************************************************
INTEL CORPORATION CONFIDENTIAL Copyright(c) 2015-2021 Intel Corporation. All Rights Reserved.

The source code contained or described herein and all documents related to the
source code ("Material") are owned by Intel Corporation or its suppliers or
licensors. Title to the Material remains with Intel Corporation or its suppliers
and licensors. The Material contains trade secrets and proprietary and
confidential information of Intel or its suppliers and licensors. The Material
is protected by worldwide copyright and trade secret laws and treaty provisions.
No part of the Material may be used, copied, reproduced, modified, published,
uploaded, posted, transmitted, distributed, or disclosed in any way without
Intel's prior express written permission.

No license under any patent, copyright, trade secret or other intellectual
property right is granted to or conferred upon you by disclosure or delivery of
the Materials, either expressly, by implication, inducement, estoppel or
otherwise. Any license under such intellectual property rights must be express
and approved by Intel in writing.
*******************************************************************************/

#ifndef _CVE_HW_VALUES_H_
#define _CVE_HW_VALUES_H_

/*
 * status of the command buffer, set by both the driver and the TLC
 * used in the 'status' field in the command-buffer descriptor
 */
enum cve_command_buffer_status {
	CVE_STATUS_EMPTY = 0,
	CVE_STATUS_PENDING,
	CVE_STATUS_DISPATCHED,
	CVE_STATUS_RUNNING,
	CVE_STATUS_COMPLETED,
	CVE_STATUS_ABORTED,
	CVE_STATUS_LOADED,

	/* must be last */
	CVE_STATUS_NR
};

/*
 * MMU error codes. used for MMU error reporting
 */
enum cve_mmu_error_code {
	CVE_MMU_ERRORCODE_ADDRESS_NOT_MAPPED = -1,
	CVE_MMU_ERRORCODE_ACCESS_VIOLATION = -2
};

/*
 * types of memory access. used for MMU error reporting
 */
enum cve_mmu_access_type {
	CVE_MMU_ACCESS_TYPE_READ = 0,
	CVE_MMU_ACCESS_TYPE_WRITE,
	CVE_MMU_ACCESS_TYPE_EXEC
};

#endif /* _CVE_HW_VALUES_H_ */

