/********************************************
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#ifndef _SPH_INBOUND_MEM_H
#define _SPH_INBOUND_MEM_H

#include "ipc_protocol.h"

#define SPH_INBOUND_MEM_MAGIC  0x4d687073  /* value of 'sphM' */
#define SPH_CRASH_DUMP_SIZE    (1lu << (SPH_PAGE_SHIFT + SPH_CRASH_DUMP_SIZE_PAGE_ORDER))
#define SPH_CRASH_DUMP_SIZE_PAGES    (SPH_CRASH_DUMP_SIZE >> SPH_PAGE_SHIFT)
#pragma pack(push, 1)

union sph_inbound_mem {
	struct {
		u32     magic;
		u32     crash_dump_size;
		u8	crash_dump[];
	};
	u8 row[SPH_CRASH_DUMP_SIZE];
};

#pragma pack(pop)

#endif
