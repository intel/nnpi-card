/* SPDX-License-Identifier: GPL-2.0-or-later */

/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 ********************************************/

#ifndef _NNPDRV_TRACE_DEFS_H
#define _NNPDRV_TRACE_DEFS_H

enum {
	NNP_TRACE_UNLOCK_ENTER = 0,
	NNP_TRACE_UNLOCK_EXIT  = 1,
	NNP_TRACE_LOCK_ENTER   = 2,
	NNP_TRACE_LOCK_EXIT    = 3
};

#define __NNP_TRACE_LOCK_STR(x) \
	((x) == NNP_TRACE_UNLOCK_ENTER ? "unlock_enter" : \
	 ((x) == NNP_TRACE_UNLOCK_EXIT  ? "unlock_exit" : \
	  ((x) == NNP_TRACE_LOCK_ENTER   ? "lock_enter" : "lock_exit")))

#endif /* _NNPDRV_TRACE_DEFS_H */
