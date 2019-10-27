/********************************************
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#ifndef _SPHCS_NET_H
#define _SPHCS_NET_H

#include "sph_types.h"
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include "ipc_protocol.h"

struct sphcs;

int sphcs_net_dev_init(void);
void sphcs_net_dev_exit(void);

void IPC_OPCODE_HANDLER(ETH_MSG_DSCR)(struct sphcs              *sphcs,
				      union h2c_EthernetMsgDscr *msg);

void IPC_OPCODE_HANDLER(ETH_CONFIG)(struct sphcs              *sphcs,
				      union h2c_EthernetConfig *msg);

#endif

