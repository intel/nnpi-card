/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#ifndef _SPHCS_CTX_UIDS_H
#define _SPHCS_CTX_UIDS_H

#include "sw_counters.h"

extern struct sph_sw_counters *g_ctx_uids_counters;

int sphcs_ctx_uids_init(void);
void sphcs_ctx_uids_fini(void);

#define CTX_UIDS_SET_UID(ctxid, uid) \
	if (ctxid < 256) \
		SPH_SW_COUNTER_SET(g_ctx_uids_counters, ctxid, uid)

#endif
