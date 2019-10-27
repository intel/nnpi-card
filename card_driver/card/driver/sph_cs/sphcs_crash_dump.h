/********************************************
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#ifndef _SPHCS_CRASH_DUMP_H
#define _SPHCS_CRASH_DUMP_H

int sphcs_crash_dump_init(void);
void sphcs_crash_dump_cleanup(void);
void sphcs_crash_dump_setup_host_addr(u64 host_dma_addr);

#endif
