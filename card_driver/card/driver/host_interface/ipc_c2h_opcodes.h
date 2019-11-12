/********************************************
 * Copyright (C) 2019 Intel Corporation
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

C2H_OPCODE(QUERY_VERSION_REPLY,		0, union c2h_QueryVersionReplyMsg)
C2H_OPCODE(SERVICE_LIST,		1, union c2h_ServiceListMsg)
C2H_OPCODE(GENERIC_MSG_PACKET,		2, union c2h_GenericMessaging)
C2H_OPCODE(ETH_MSG_DSCR,		3, union c2h_EthernetMsgDscr)
C2H_OPCODE(EVENT_REPORT,		4, union c2h_EventReport)
C2H_OPCODE(SYNC_DONE,			5, union c2h_SyncDone)
C2H_OPCODE(INF_SUBRES_LOAD_REPLY,	6, union c2h_SubResourceLoadReply)
C2H_OPCODE(INF_SUBRES_LOAD_CREATE_REMOVE_SESSION_REPLY, 7, union c2h_SubResourceLoadCreateSessionReply)
C2H_OPCODE(DMA_PAGE_HANDLE_FREE,	8, union c2h_DmaPageHandleFree)
C2H_OPCODE(CLOCK_SYNC,			9, union ClockSyncMsg)
C2H_OPCODE(ETH_CONFIG,			10, union c2h_EthernetConfig)
C2H_OPCODE(SYS_INFO,			11, union c2h_SysInfo)
C2H_OPCODE(HWTRACE_STATE,		12, union c2h_HwTraceState)
C2H_OPCODE(INFREQ_FAILED,		13, union c2h_InfreqFailed)

#ifdef ULT
C2H_OPCODE(ULT_OP,              30, union ult_message)
#endif
