/* SPDX-License-Identifier: GPL-2.0-or-later */

/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 ********************************************/

#ifndef _NNP_KERNEL_DEBUG_H
#define _NNP_KERNEL_DEBUG_H

#define NNP_STATIC_ASSERT(x, s) _Static_assert((x), s)

#ifdef _DEBUG
#define NNP_ASSERT(x)						\
	do {							\
		if (likely(x))					\
			break;					\
		pr_err("NNP ASSERTION FAILED %s: %s: %u: %s\n", \
			__FILE__, __func__, __LINE__, #x);      \
		WARN();                                         \
	} while (0)

#else
#define NNP_ASSERT(x)

#endif //_DEBUG

#endif
