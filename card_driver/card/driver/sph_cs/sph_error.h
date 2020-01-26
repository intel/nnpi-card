



/*******************************************************************************
 * INTEL CORPORATION CONFIDENTIAL Copyright(c) 2017-2020 Intel Corporation. All Rights Reserved.
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
#ifndef _SPH_CS_ERROR_H
#define _SPH_CS_ERROR_H

#define	SPH_ERRNO_BASE	200	/* SPH errno followed SPH_ERRNO_BASE, and is complementary linux errno */

#define	SPHER_CONTEXT_BROKEN			(SPH_ERRNO_BASE + 1)	/* Context broken */
#define	SPHER_NOT_SUPPORTED			(SPH_ERRNO_BASE + 2)	/* Not supported */
#define	SPHER_INFER_EXEC_ERROR			(SPH_ERRNO_BASE + 3)	/* Infer exec error */
#define	SPHER_INFER_SCHEDULE_ERROR		(SPH_ERRNO_BASE + 4)	/* Infer schedule error */
#define	SPHER_DMA_ERROR				(SPH_ERRNO_BASE + 5)	/* DMA Error */
#define SPHER_INFER_ICEDRV_ERROR                (SPH_ERRNO_BASE + 6)    /* Infer failed on icedrv error */
#define SPHER_INFER_ICEDRV_ERROR_RESET          (SPH_ERRNO_BASE + 7)    /* Infer failed on icedrv error network reset needed */
#define SPHER_INFER_ICEDRV_ERROR_CARD_RESET     (SPH_ERRNO_BASE + 8)    /* Infer failed on icedrv error card reset needed */

#endif
