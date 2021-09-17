/********************************************
 * Copyright (C) 2019-2021 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

/**
 * @file sphcs_intel_th.h
 *
 * @brief Header file defining sphcs intel trace hub
 *
 * This header file defines api for intel trace hub interface.
 *
 */

#ifndef _SPHCS_INTEL_TH_H_
#define _SPHCS_INTEL_TH_H_

struct device;
struct sg_table;

int sphcs_init_th_driver(void);
void sphcs_deinit_th_driver(void);
void sphcs_intel_th_window_unlock(struct device *dev, struct sg_table *sgt);

void sphcs_assign_intel_th_mode(int *mode);

#endif //_SPHCS_INTEL_TH_H_

