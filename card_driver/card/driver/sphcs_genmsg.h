/********************************************
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#ifndef _SPHCS_GENMSG_H
#define _SPHCS_GENMSG_H

#include "sph_types.h"
#include "ipc_protocol.h"

int sphcs_init_genmsg_interface(void);
void sphcs_release_genmsg_interface(void);

void IPC_OPCODE_HANDLER(GENERIC_MSG_PACKET)(struct sphcs               *sphcs,
					    union h2c_GenericMessaging *msg);

#endif
