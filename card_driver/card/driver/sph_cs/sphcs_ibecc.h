/********************************************
 * Copyright (C) 2019-2021 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#ifndef _SPHCS_IBECC_H
#define _SPHCS_IBECC_H

#include <linux/types.h>

int sphcs_ibecc_init(void);
int sphcs_ibecc_fini(void);

bool sphcs_ibecc_get_uc_severity_ctxt_requested(void);
bool sphcs_ibecc_correctable_error_requested(void);
int sphcs_ibecc_inject_ctxt_err(phys_addr_t addr, void *vaddr);
int sphcs_ibecc_clean_ctxt_err(void *vaddr);

extern bool ibecc_error_injection_requested;

#endif
