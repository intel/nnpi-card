/********************************************
 * Copyright (C) 2019-2021 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/
#ifndef _NNP_TYPES_H
#define _NNP_TYPES_H

#include <linux/types.h>

struct nnp_memdesc {
	phys_addr_t   pa;
	void __iomem *va;
	size_t        len;
};

#define NNP_ALIGN(x, align)   (((x)+((align)-1)) & ~((align)-1))

#endif
