/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#ifndef _SPHCS_CHAN_NET_H
#define _SPHCS_CHAN_NET_H

#include "ipc_chan_protocol.h"

struct sphcs;

void IPC_OPCODE_HANDLER(CHAN_ETH_MSG_DSCR)(struct sphcs              *sphcs,
					   union h2c_ChanEthernetMsgDscr *cmd);

void IPC_OPCODE_HANDLER(CHAN_ETH_CONFIG)(struct sphcs                 *sphcs,
					 union h2c_ChanEthernetConfig *cmd);

#endif

