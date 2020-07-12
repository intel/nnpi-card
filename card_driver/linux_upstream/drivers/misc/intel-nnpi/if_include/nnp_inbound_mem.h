/* SPDX-License-Identifier: GPL-2.0-or-later */

/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 ********************************************/

#ifndef _NNP_INBOUND_MEM_H
#define _NNP_INBOUND_MEM_H

#include <linux/types.h>

#ifndef NNP_PAGE_SHIFT
#define NNP_PAGE_SHIFT 12
#endif

/* The crash dump buffer size is PAGE-SIZE*2^NNP_CRASH_DUMP_SIZE_PAGE_ORDER or
 * 2^(PAGE_SHIFT+NNP_CRASH_DUMP_SIZE_PAGE_ORDER)
 */
#define NNP_CRASH_DUMP_SIZE_PAGE_ORDER 2


#define NNP_INBOUND_MEM_MAGIC  0x4d687073  /* value of 'sphM' */
#define NNP_CRASH_DUMP_SIZE   \
	(1lu << (NNP_PAGE_SHIFT + NNP_CRASH_DUMP_SIZE_PAGE_ORDER))
#define NNP_CRASH_DUMP_SIZE_PAGES    (NNP_CRASH_DUMP_SIZE >> NNP_PAGE_SHIFT)
#pragma pack(push, 1)

union nnp_inbound_mem {
	struct {
		__le32  magic;
		__le32  crash_dump_size;
		__u8	crash_dump[];
	};
	__u8 row[NNP_CRASH_DUMP_SIZE];
};

#pragma pack(pop)

#endif
