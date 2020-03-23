/********************************************
* Copyright (C) 2019-2020 Intel Corporation
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

H2C_OPCODE(QUERY_VERSION,		0, union h2c_QueryVersionMsg)
H2C_OPCODE(HOST_RESPONSE_PAGES,		1, union h2c_HostResponsePagesMsg)
H2C_OPCODE(ETH_MSG_DSCR,		3, union h2c_EthernetMsgDscr)
H2C_OPCODE(SETUP_CRASH_DUMP,		6, union h2c_setup_crash_dump_msg)
H2C_OPCODE(SETUP_SYS_INFO_PAGE,         7, union h2c_setup_sys_info_page)
H2C_OPCODE(CLOCK_SYNC,			15, union ClockSyncMsg)
H2C_OPCODE(ETH_CONFIG,			16, union h2c_EthernetConfig)
H2C_OPCODE(CHANNEL_OP,			22, union h2c_ChannelOp)
H2C_OPCODE(CHANNEL_RB_OP,		23, union h2c_ChannelDataRingbufOp)
H2C_OPCODE(CHANNEL_HOSTRES_OP,		24, union h2c_ChannelHostresOp)

