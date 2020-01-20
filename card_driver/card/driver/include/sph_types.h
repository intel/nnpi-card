/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/
#ifndef _SPH_TYPES_H
#define _SPH_TYPES_H

#include <linux/types.h>

struct sph_memdesc {
	phys_addr_t   pa;
	void __iomem *va;
	size_t        len;
};

#define SPH_ALIGN(x, align)   (((x)+((align)-1)) & ~((align)-1))

#endif
