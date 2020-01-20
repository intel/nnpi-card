/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#ifndef SPHCS_INF_SUBRESLOAD_H
#define SPHCS_INF_SUBRESLOAD_H

#include <linux/kref.h>
#include <linux/hashtable.h>
#include <linux/spinlock.h>
#include <linux/dma-buf.h>
#include <linux/list.h>
#include "inf_devres.h"
#include "inf_context.h"


enum event_val inf_subresload_execute(struct inf_context *context, union h2c_SubResourceLoadOp *cmd);

int inf_subresload_create_session(struct inf_context *context, struct inf_devres *devres, union h2c_SubResourceLoadCreateRemoveSession *cmd);

void inf_subresload_delete_lli_space_list(struct inf_subres_load_session *session);

#endif
