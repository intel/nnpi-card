/********************************************
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#ifndef _SPHCS_P2P_H
#define _SPHCS_P2P_H

#include <linux/kernel.h>
#include "ipc_protocol.h"

struct sphcs;

struct sphcs_p2p_peer_fifo {
	u32 depth;
	u32 wr_ptr;
	dma_addr_t base_addr;

	/* local buffer to be used for DMA */
	dma_addr_t buf_dma_addr;
	void *buf_vaddr;
	size_t buf_size;
};

struct sphcs_p2p_peer_dev {
	dma_addr_t doorbell;
	struct sphcs_p2p_peer_fifo peer_cr_fifo;

	/* local buffer of size 1 byte to be used for DMA */
	dma_addr_t buf_dma_addr;
	void *buf_vaddr;

};

struct sphcs_p2p_buf {
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

int sphcs_p2p_init(struct sphcs *sphcs, struct sphcs_p2p_cbs *p2p_cbs);
void sphcs_p2p_fini(struct sphcs *sphcs);

void IPC_OPCODE_HANDLER(P2P_DEV)(struct sphcs *sphcs, union h2c_P2PDev *cmd);
void IPC_OPCODE_HANDLER(PEER_BUF)(struct sphcs *sphcs, union h2c_PeerBuf *cmd);

void sphcs_p2p_init_p2p_buf(struct sphcs_p2p_buf *buf);
int sphcs_p2p_add_buffer(bool is_src_buf, struct sphcs_p2p_buf *buf);
void sphcs_p2p_remove_buffer(struct sphcs_p2p_buf *buf);

int sphcs_p2p_send_fw_cr(struct sphcs_p2p_peer_dev *dev, struct sphcs_p2p_buf *buf);
int sphcs_p2p_send_rel_cr(struct sphcs_p2p_peer_dev *dev, struct sphcs_p2p_buf *buf);
int sphcs_p2p_ring_doorbell(struct sphcs_p2p_peer_dev *dev);

/* Called on doorbell value changed and looks for the forwarded credit or released credit*/
int sphcs_p2p_new_message_arrived(u8 value);

/* Allocate new fifo for specified producer */
int sphcs_p2p_alloc_fw_cr_fifo(u32 producer_id, dma_addr_t *fw_cr_fifo);

/* Allocate new fifo for specified consumer */
int sphcs_p2p_alloc_rel_cr_fifo(u32 consumer_id, dma_addr_t *fw_cr_fifo);

#endif
