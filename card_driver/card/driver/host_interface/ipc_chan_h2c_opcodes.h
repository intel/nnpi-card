/********************************************
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

/**
 * Host-to-Card IPC opcode definitions.
 *
 * Each H2C_OPCODE line below defines one h2c opcode in the IPC protocol
 * it has three agruments:
 *     name - this is the name of the command the opcode represent. In the
 *            opcode enumeration type it is expanded to be SPH_IPC_H2C_OP_<name>.
 *            in the code this expanded form can be used, the macro
 *            H2C_OPCODE_NAME(name) defined in ipc_protocol.h provide that
 *            epansion and can be used as well.
 *     value - This is the opcode value in the protocol, it must be unique among
 *             all other h2c opcodes and must be less then 32 as we have only 5
 *             bits in the protocol for the opcode.
 *     type  - This is the union/structure type which defines the format of the
 *             command of this opcode. The function handler of that opcode
 *             receives a pointer to that type.
 *
 * Handler function:
 * The function which handles received commands from host, sphcs_process_messages,
 * dispatch a handler function for the received command according to the opcode
 * feild in the command. There should be only a single handler function for each
 * opcode which should be defined with the following prototype:
 *      void IPC_OPCODE_HANDLER(<name>)(struct sphcs *sphcs,
 *                                      <type>       *msg);
 * Where <name> and <type> are the defined name and type of the opcode as
 * defined by the H2C_OPCODE line below.
 */

H2C_OPCODE(CHANNEL_RB_UPDATE, 32, union h2c_ChanRingBufUpdate)
H2C_OPCODE(CHAN_GENERIC_MSG_PACKET, 33, union h2c_ChanGenericMessaging)
H2C_OPCODE(CHAN_INF_CONTEXT, 34, union h2c_ChanInferenceContextOp)
H2C_OPCODE(CHAN_INF_RESOURCE, 35, union h2c_ChanInferenceResourceOp)
H2C_OPCODE(CHAN_COPY_OP, 36, union h2c_ChanInferenceCopyOp)
H2C_OPCODE(CHAN_SCHEDULE_COPY, 37, union h2c_ChanInferenceSchedCopy)
H2C_OPCODE(CHAN_SCHEDULE_COPY_LARGE, 38, union h2c_ChanInferenceSchedCopyLarge)
H2C_OPCODE(CHAN_SCHEDULE_COPY_SUBRES, 39, union h2c_ChanInferenceSchedCopySubres)
H2C_OPCODE(CHAN_INF_NETWORK, 40, union h2c_ChanInferenceNetworkOp)
H2C_OPCODE(CHAN_INF_REQ_OP, 41, union h2c_ChanInferenceReqOp)
H2C_OPCODE(CHAN_SCHEDULE_INF_REQ, 42, union h2c_ChanInferenceReqSchedule)
H2C_OPCODE(CHAN_SYNC, 43, union h2c_ChanSync)
H2C_OPCODE(CHAN_INF_NETWORK_RESOURCE_RESERVATION, 44, union h2c_ChanInferenceNetworkResourceReservation)

#ifdef ULT
H2C_OPCODE(ULT2_OP,              63, union ult2_message)
#endif
