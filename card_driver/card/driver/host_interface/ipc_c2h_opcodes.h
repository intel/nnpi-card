/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

/**
 * THIS FILE HAS REMOVED !!!!
 *
 * When adding new H2C opcode - the following files needs be edited:
 *     1) src/card/driver/host_interface/ipc_protocol.h  => add to enum nnp_c2h_opcodes
 *     2) src/host/driver/nnpdrv_device.c => handle in nnpdrv_device_process_messages function
 *     3) src/card/driver/include/sphcs_trace.h => handle in C2H_HWQ_MSG_STR function
 *     4) src/host/driver/nnpdrv_trace.h => handle in C2H_HWQ_MSG_STR function
 */
