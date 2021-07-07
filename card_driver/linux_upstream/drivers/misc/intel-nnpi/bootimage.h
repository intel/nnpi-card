/* SPDX-License-Identifier: GPL-2.0-or-later */

/********************************************
 * Copyright (C) 2019-2021 Intel Corporation
 ********************************************/

#ifndef _NNPDRV_BOOTIMAGE_H
#define _NNPDRV_BOOTIMAGE_H

#include "hostres.h"

struct nnp_device;

void nnpdrv_bootimage_fini(void);

int nnpdrv_bootimage_load_boot_image(struct nnp_device *nnpdev,
				     const char        *boot_image_name);
int nnpdrv_bootimage_unload_boot_image(struct nnp_device *nnpdev,
				       const char        *boot_image_name);

bool nnpdrv_bootimage_image_list_empty(void);

#endif /* _NNPDRV_BOOTIMAGE_H */
