/********************************************
 * Copyright (C) 2019-2021 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/
#ifndef _SPH_CS_ERROR_H
#define _SPH_CS_ERROR_H

#define	NNP_ERRNO_BASE	200	/* SPH errno followed NNP_ERRNO_BASE, and is complementary linux errno */

#define	NNPER_CONTEXT_BROKEN			(NNP_ERRNO_BASE + 1)	/* Context broken */
#define	NNPER_NOT_SUPPORTED			(NNP_ERRNO_BASE + 2)	/* Not supported */
#define	NNPER_INFER_EXEC_ERROR			(NNP_ERRNO_BASE + 3)	/* Infer exec error */
#define	NNPER_INFER_SCHEDULE_ERROR		(NNP_ERRNO_BASE + 4)	/* Infer schedule error */
#define	NNPER_DMA_ERROR				(NNP_ERRNO_BASE + 5)	/* DMA Error */
#define NNPER_INFER_ICEDRV_ERROR                (NNP_ERRNO_BASE + 6)    /* Infer failed on icedrv error */
#define NNPER_INFER_ICEDRV_ERROR_RESET          (NNP_ERRNO_BASE + 7)    /* Infer failed on icedrv error network reset needed */
#define NNPER_INFER_ICEDRV_ERROR_CARD_RESET     (NNP_ERRNO_BASE + 8)    /* Infer failed on icedrv error card reset needed */
#define NNPER_INPUT_IS_DIRTY			(NNP_ERRNO_BASE + 9)    /* One of the inputs is dirty */

#endif
