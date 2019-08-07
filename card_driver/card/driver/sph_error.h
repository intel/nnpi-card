



/*******************************************************************************
 * INTEL CORPORATION CONFIDENTIAL Copyright(c) 2017-2019 Intel Corporation. All Rights Reserved.
 *
 * The source code contained or described herein and all documents related to the
 * source code ("Material") are owned by Intel Corporation or its suppliers or
 * licensors. Title to the Material remains with Intel Corporation or its suppliers
 * and licensors. The Material contains trade secrets and proprietary and
 * confidential information of Intel or its suppliers and licensors. The Material
 * is protected by worldwide copyright and trade secret laws and treaty provisions.
 * No part of the Material may be used, copied, reproduced, modified, published,
 * uploaded, posted, transmitted, distributed, or disclosed in any way without
 * Intel's prior express written permission.
 *
 * No license under any patent, copyright, trade secret or other intellectual
 * property right is granted to or conferred upon you by disclosure or delivery of
 * the Materials, either expressly, by implication, inducement, estoppel or
 * otherwise. Any license under such intellectual property rights must be express
 * and approved by Intel in writing.
 ********************************************************************************/
#ifndef _SPH_ERROR_H
#define _SPH_ERROR_H

#define	SPH_ERRNO_BASE	200	/* SPH errno followed SPH_ERRNO_BASE, and is complementary linux errno */

#define	SPHER_DEVICE_NOT_READY			(SPH_ERRNO_BASE + 1)	/* Device not ready */
#define	SPHER_NO_SUCH_RESOURCE			(SPH_ERRNO_BASE + 2)	/* No such resource */
#define	SPHER_NO_SUCH_CONTEXT			(SPH_ERRNO_BASE + 3)	/* No such context */
#define	SPHER_INCOMPATIBLE_RESOURCES		(SPH_ERRNO_BASE + 4)	/* Incompatible resources */
#define	SPHER_NO_SUCH_NETWORK			(SPH_ERRNO_BASE + 5)	/* No such network */
#define	SPHER_TOO_MANY_CONTEXTS			(SPH_ERRNO_BASE + 6)	/* Too many contexts */
#define	SPHER_CONTEXT_BROKEN			(SPH_ERRNO_BASE + 7)	/* Context broken */
#define	SPHER_DEVICE_ERROR			(SPH_ERRNO_BASE + 8)	/* Device error */
#define	SPHER_TIMED_OUT				(SPH_ERRNO_BASE + 9)	/* Timed out */
#define	SPHER_BROKEN_MARKER			(SPH_ERRNO_BASE + 10)	/* Broken marker */
#define	SPHER_NO_SUCH_COPY_HANDLE		(SPH_ERRNO_BASE + 11)	/* No such copy handle */
#define	SPHER_NO_SUCH_INFREQ_HANDLE		(SPH_ERRNO_BASE + 12)	/* No such infreq handle */
#define	SPHER_INTERNAL_DRIVER_ERROR		(SPH_ERRNO_BASE + 13)	/* Internal driver error */
#define	SPHER_NOT_SUPPORTED			(SPH_ERRNO_BASE + 14)	/* Not supported */
#define	SPHER_INVALID_EXECUTABLE_NETWORK_BINARY	(SPH_ERRNO_BASE + 15)	/* Invalid exe network binary*/
#define	SPHER_INFER_MISSING_RESOURCE		(SPH_ERRNO_BASE + 16)	/* Infer missing error */
#define	SPHER_INFER_EXEC_ERROR			(SPH_ERRNO_BASE + 17)	/* Infer exec error */
#define	SPHER_INFER_SCHEDULE_ERROR		(SPH_ERRNO_BASE + 18)	/* Infer schedule error */
#define	SPHER_DMA_ERROR				(SPH_ERRNO_BASE + 19)	/* DMA Error */
#define	SPHER_ERROR_RUNTIME_LAUNCH		(SPH_ERRNO_BASE + 20)	/* Error Runtime launch */
#define	SPHER_ERROR_RUNTIME_DIED		(SPH_ERRNO_BASE + 21)	/* Runtime died */
#define	SPHER_ERROR_OS_CRASHED			(SPH_ERRNO_BASE + 22)	/* OS crashed */
#define	SPHER_ERROR_EXECUTE_COPY_FAILED		(SPH_ERRNO_BASE + 23)	/* Execute copy failed */
#define	SPHER_CRITICAL_ERROR_UNKNOWN		(SPH_ERRNO_BASE + 24)	/* Critical error unknown */
#define	SPHER_HOSTRES_BROKEN			(SPH_ERRNO_BASE + 25)	/* Hostres broken */
#define SPHER_GRACEFUL_DESTROY                  (SPH_ERRNO_BASE + 26)   /* Graceful destroy requested by administrator */
#define SPHER_CARD_RESET                        (SPH_ERRNO_BASE + 27)   /* Card has been reset */
#define SPHER_INCOMPLETE_NETWORK                (SPH_ERRNO_BASE + 28)   /* Network handle is incomplete */
#define	SPHER_INSUFFICIENT_RESOURCES		(SPH_ERRNO_BASE + 29)	/* insufficient resources for DevNet */

#endif
