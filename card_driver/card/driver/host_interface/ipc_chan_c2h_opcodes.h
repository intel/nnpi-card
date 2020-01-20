/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

/**
 * Card-to-Host IPC opcode definitions.
 *
 * Each C2H_OPCODE line below defines one c2h opcode in the IPC protocol
 * it has three agruments:
 *     name - this is the name of the response the opcode represent. In the
 *            opcode enumeration type it is expanded to be SPH_IPC_C2H_OP_<name>.
 *            in the code this expanded form can be used, the macro
 *            C2H_OPCODE_NAME(name) defined in ipc_protocol.h provide that
 *            epansion and can be used as well.
 *     value - This is the opcode value in the protocol, it must be unique among
 *             all other c2h opcodes and must be less then 32 as we have only 5
 *             bits in the protocol for the opcode.
 *     type  - This is the union/structure type which defines the format of the
 *             command of this opcode. The function handler of that opcode
 *             receives a pointer to that type.
 *
 * Handler function:
 * The function which handles received responses from card, sphdrv_device_process_messages,
 * dispatch a handler function for the received response according to the opcode
 * feild in the response. There should be only a single handler function for each
 * opcode which should be defined with the following prototype:
 *      void IPC_OPCODE_HANDLER(<name>)(struct sphcs *sphcs,
 *                                      <type>       *msg);
 * Where <name> and <type> are the defined name and type of the opcode as
 * defined by the C2H_OPCODE line below.
 */

C2H_OPCODE(CHANNEL_RB_UPDATE, 32, union c2h_ChanRingBufUpdate)
C2H_OPCODE(CHAN_GENERIC_MSG_PACKET, 33, union c2h_ChanGenericMessaging)
C2H_OPCODE(CHAN_SERVICE_LIST, 34, union c2h_ChanServiceListMsg)
C2H_OPCODE(CHAN_SYNC_DONE, 35, union c2h_ChanSyncDone)
C2H_OPCODE(CHAN_INFREQ_FAILED, 36, union c2h_ChanInfReqFailed)
C2H_OPCODE(CHAN_HWTRACE_STATE, 37, union c2h_ChanHwTraceState)

#ifdef ULT
C2H_OPCODE(ULT2_OP,              63, union ult_message)
#endif
