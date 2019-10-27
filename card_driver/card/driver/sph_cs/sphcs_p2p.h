/********************************************
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#ifndef _SPHCS_P2P_H
#define _SPHCS_P2P_H

#include <linux/kernel.h>
#include <linux/spinlock.h>
#include "ipc_protocol.h"

struct sphcs;
struct sphcs_p2p_peer_dev;

struct sphcs_p2p_buf {
	/* For src buffer, ready means that data in the destination buffer
	 * is consumed and d2d copy may be executed
	 * For dst buffer, ready means that d2d copy is completed and
	 * data may be consumed
	 */
	bool ready;
	bool is_src_buf;
	u8 buf_id;
	u8 peer_buf_id;
	struct sphcs_p2p_peer_dev *peer_dev;
};

/* */
struct sphcs_p2p_cbs {
	/* Called on consumer side when new element is pushed into
	 * fw cr fifo with dbid equal to buf->buf_id
	 */
	void (*new_data_arrived)(struct sphcs_p2p_buf *buf);

	/* Called on producer side when new element is pushed into
	 * rel cr fifo with sbid equal to buf->buf_id
	 */
	void (*data_consumed)(struct sphcs_p2p_buf *buf);
};

/* Only for SPH EP */
#ifdef HW_LAYER_SPH

int sphcs_p2p_init(struct sphcs *sphcs, struct sphcs_p2p_cbs *p2p_cbs);
void sphcs_p2p_fini(struct sphcs *sphcs);

void IPC_OPCODE_HANDLER(P2P_DEV)(struct sphcs *sphcs, union h2c_P2PDev *cmd);
void IPC_OPCODE_HANDLER(PEER_BUF)(struct sphcs *sphcs, union h2c_PeerBuf *cmd);
void IPC_OPCODE_HANDLER(GET_CR_FIFO)(struct sphcs *sphcs, union h2c_GetCrFIFO *cmd);

void sphcs_p2p_init_p2p_buf(bool is_src_buf, struct sphcs_p2p_buf *buf);
int sphcs_p2p_add_buffer(struct sphcs_p2p_buf *buf);
void sphcs_p2p_remove_buffer(struct sphcs_p2p_buf *buf);

int sphcs_p2p_send_fw_cr(struct sphcs_p2p_buf *buf);
int sphcs_p2p_send_rel_cr(struct sphcs_p2p_buf *buf);
int sphcs_p2p_ring_doorbell(struct sphcs_p2p_buf *buf);

/* Called on doorbell value changed and looks for the forwarded credit or released credit*/
int sphcs_p2p_new_message_arrived(void);
#else
static inline int sphcs_p2p_init(struct sphcs *sphcs, struct sphcs_p2p_cbs *p2p_cbs)
{
	return 0;
}
static inline void sphcs_p2p_fini(struct sphcs *sphcs)
{

}

static inline void IPC_OPCODE_HANDLER(P2P_DEV)(struct sphcs *sphcs, union h2c_P2PDev *cmd)
{

}
static inline void IPC_OPCODE_HANDLER(PEER_BUF)(struct sphcs *sphcs, union h2c_PeerBuf *cmd)
{

}
static inline void IPC_OPCODE_HANDLER(GET_CR_FIFO)(struct sphcs *sphcs, union h2c_GetCrFIFO *cmd)
{

}

static inline void sphcs_p2p_init_p2p_buf(bool is_src_buf, struct sphcs_p2p_buf *buf)
{

}
static inline int sphcs_p2p_add_buffer(struct sphcs_p2p_buf *buf)
{
	return 0;
}
static inline void sphcs_p2p_remove_buffer(struct sphcs_p2p_buf *buf)
{

}

static inline int sphcs_p2p_send_fw_cr(struct sphcs_p2p_buf *buf)
{
	return 0;
}
static inline int sphcs_p2p_send_rel_cr(struct sphcs_p2p_buf *buf)
{
	return 0;
}
static inline int sphcs_p2p_ring_doorbell(struct sphcs_p2p_buf *buf)
{
	return 0;
}

/* Called on doorbell value changed and looks for the forwarded credit or released credit*/
static inline int sphcs_p2p_new_message_arrived(void)
{
	return 0;
}

#endif
#endif
