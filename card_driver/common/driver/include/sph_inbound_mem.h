/********************************************
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#include "ipc_protocol.h"

//#define SPH_INBOUND_MEM_SIZE   (64 * 1024 * 1024)
#define SPH_INBOUND_MEM_SIZE   (64 * 1024)
#define SPH_INBOUND_MEM_MAGIC  0x4d687073  /* value of 'sphM' */
#define SPH_CRASH_DUMP_SIZE    (1 << (SPH_PAGE_SHIFT + SPH_CRASH_DUMP_SIZE_PAGE_ORDER))

#pragma pack(push, 1)

struct sph_inbound_mem {
	u32     magic;
	u32     crash_dump_size;
	u8      crash_dump[SPH_CRASH_DUMP_SIZE];
};

SPH_STATIC_ASSERT(sizeof(struct sph_inbound_mem) <= SPH_INBOUND_MEM_SIZE,
		  "SPH_INBOUND_MEM_SIZE is too small!!");

#pragma pack(pop)
