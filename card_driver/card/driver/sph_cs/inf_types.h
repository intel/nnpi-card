/********************************************
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/
#ifndef _SPHCS_INF_TYPES_H
#define _SPHCS_INF_TYPES_H

#include <linux/list.h>
#include "sph_types.h"

struct inf_req_sequence {
	u32              seq_id;
	struct list_head node;
};

enum create_status {
	CREATE_STARTED	= 0,
	DMA_COMPLETED	= 1,
	CREATED		= 2
};

#endif
