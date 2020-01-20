/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#ifndef _SPHCS_ULT_H
#define _SPHCS_ULT_H

#ifdef ULT

#include "sph_types.h"
#include "ipc_protocol_ult.h"
#include "ipc_chan_protocol_ult.h"

struct sphcs;
int sphcs_init_ult_module(void);
void sphcs_fini_ult_module(void);

void sphcs_ult_process_bios_message(struct sphcs *sphcs, u64 *msg);

void IPC_OPCODE_HANDLER(ULT_OP)(struct sphcs      *sphcs,
				union ult_message *msg);

void IPC_OPCODE_HANDLER(ULT2_OP)(struct sphcs      *sphcs,
				 union ult2_message *msg);

#endif

#endif
