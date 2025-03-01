/********************************************
 * Copyright (C) 2019-2021 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/
#ifndef _SPHCS_INF_H
#define _SPHCS_INF_H

#include <linux/debugfs.h>
#include "sphcs_cs.h"
#include "ipc_chan_protocol.h"

struct inf_daemon;

/**
 * @struct inf_data
 * structure to hold card global inference related data.
 */
struct inf_data {
	spinlock_t lock_bh;
	struct mutex io_lock;
	DECLARE_HASHTABLE(context_hash, 4);
	struct workqueue_struct *inf_wq;
	struct inf_daemon *daemon;
#ifdef ULT
	struct inf_daemon *ult_daemon_save;
#endif
};

int inference_init(struct sphcs *sphcs);
int inference_fini(struct sphcs *sphcs);
void sphcs_inf_init_debugfs(struct dentry *parent);

void IPC_OPCODE_HANDLER(CHAN_INF_CONTEXT)(struct sphcs *sphcs,
					  union h2c_ChanInferenceContextOp *cmd);

void IPC_OPCODE_HANDLER(CHAN_SYNC)(struct sphcs   *sphcs,
				   union h2c_ChanSync *cmd);

void IPC_OPCODE_HANDLER(CHAN_INF_RESOURCE)(struct sphcs                  *sphcs,
					   union h2c_ChanInferenceResourceOp     *cmd);

void IPC_OPCODE_HANDLER(CHAN_INF_CMDLIST)(struct sphcs                      *sphcs,
					  union h2c_ChanInferenceCmdListOp  *cmd);

void IPC_OPCODE_HANDLER(CHAN_SCHEDULE_CMDLIST)(struct sphcs                    *sphcs,
					       union h2c_ChanInferenceCmdListOp *cmd);

void IPC_OPCODE_HANDLER(CHAN_INF_NETWORK)(struct sphcs *sphcs, union h2c_ChanInferenceNetworkOp *cmd);

void IPC_OPCODE_HANDLER(CHAN_COPY_OP)(struct sphcs                  *sphcs,
				      union h2c_ChanInferenceCopyOp *cmd);

void IPC_OPCODE_HANDLER(CHAN_SCHEDULE_COPY)(struct sphcs                 *sphcs,
					    union h2c_ChanInferenceSchedCopy *cmd);

void IPC_OPCODE_HANDLER(CHAN_SCHEDULE_COPY_LARGE)(struct sphcs                 *sphcs,
						  union h2c_ChanInferenceSchedCopyLarge *cmd);

void IPC_OPCODE_HANDLER(CHAN_SCHEDULE_COPY_SUBRES)(struct sphcs                 *sphcs,
						   union h2c_ChanInferenceSchedCopySubres *cmd);

void IPC_OPCODE_HANDLER(CHAN_INF_REQ_OP)(struct sphcs             *sphcs,
					 union h2c_ChanInferenceReqOp *cmd);

void IPC_OPCODE_HANDLER(CHAN_SCHEDULE_INF_REQ)(struct sphcs                   *sphcs,
					       union h2c_ChanInferenceReqSchedule *cmd);

void IPC_OPCODE_HANDLER(CHAN_NETWORK_PROPERTY)(struct sphcs *sphcs,
							       union h2c_ChanInferenceNetworkSetProperty *cmd);

void IPC_OPCODE_HANDLER(CHAN_EXEC_ERROR_LIST)(struct sphcs              *sphcs,
					      union h2c_ExecErrorList   *cmd);

void IPC_OPCODE_HANDLER(CHAN_TRACE_USER_DATA)(struct sphcs                *sphcs,
					      union h2c_ChanTraceUserData *cmd);

void IPC_OPCODE_HANDLER(CHAN_IDS_MAP)(struct sphcs         *sphcs,
				      union h2c_ChanIdsMap *cmd);

void IPC_OPCODE_HANDLER(CHAN_MARK_INF_RESOURCE)(struct sphcs *sphcs, union h2c_ChanMarkInferenceResource *cmd);

#endif
