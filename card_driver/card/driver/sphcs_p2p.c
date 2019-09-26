/********************************************
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#include <linux/types.h>
#include <linux/dma-mapping.h>
#include "sphcs_p2p.h"
#include "sph_log.h"
#include "sphcs_cs.h"

#define MAX_NUM_OF_P2P_DEVS 32
#define MAX_NUM_OF_P2P_BUFS 32

static struct sphcs_p2p_peer_dev p2p_producers[MAX_NUM_OF_P2P_DEVS] = {
		[0 ... MAX_NUM_OF_P2P_DEVS - 1] = { .doorbell = 0, { .depth = 0, .wr_ptr = 0, .base_addr = 0 }, .buf_dma_addr = 0, .buf_vaddr = NULL}
};
static struct sphcs_p2p_peer_dev p2p_consumers[MAX_NUM_OF_P2P_DEVS] = {
		[0 ... MAX_NUM_OF_P2P_DEVS - 1] = { .doorbell = 0, { .depth = 0, .wr_ptr = 0, .base_addr = 0 }, .buf_dma_addr = 0, .buf_vaddr = NULL }
};

static struct sphcs_p2p_buf *src_bufs[MAX_NUM_OF_P2P_BUFS] = {NULL};
static struct sphcs_p2p_buf *dst_bufs[MAX_NUM_OF_P2P_BUFS] = {NULL};

DEFINE_IDA(p2p_dbid_ida);
DEFINE_IDA(p2p_sbid_ida);

static struct sphcs_p2p_cbs *s_p2p_cbs;

static inline const char *get_buf_type_string(bool is_src_buf)
{
	if (is_src_buf)
		return "src";
	else
		return "dst";
}
void sphcs_p2p_init_p2p_buf(struct sphcs_p2p_buf *buf)
{
	buf->buf_id = (-1);
	buf->peer_buf_id = (-1);
	buf->peer_dev = NULL;
	buf->ready = false;
}

int sphcs_p2p_add_buffer(bool is_src_buf, struct sphcs_p2p_buf *buf)
{
	int id;
	struct sphcs_p2p_buf **bufs;
	struct ida *ida;

	buf->is_src_buf = is_src_buf;
	if (buf->is_src_buf) {
		bufs = src_bufs;
		ida = &p2p_sbid_ida;
	} else {
		bufs = dst_bufs;
		ida = &p2p_dbid_ida;
	}

	id = ida_simple_get(ida, 0, MAX_NUM_OF_P2P_BUFS, GFP_KERNEL);

	if (id < 0)
		return id;

	buf->buf_id = id;
	bufs[id] = buf;

	sph_log_debug(GENERAL_LOG, "New %s p2p buffer added (id %u)\n", get_buf_type_string(is_src_buf), buf->buf_id);

	return 0;
}

void sphcs_p2p_remove_buffer(struct sphcs_p2p_buf *buf)
{
	if (buf->is_src_buf) {
		src_bufs[buf->buf_id] = NULL;
		ida_simple_remove(&p2p_sbid_ida, buf->buf_id);
	} else {
		dst_bufs[buf->buf_id] = NULL;
		ida_simple_remove(&p2p_dbid_ida, buf->buf_id);
	}
	sph_log_debug(GENERAL_LOG, " %s p2p buffer remove (id %u)\n", get_buf_type_string(buf->is_src_buf), buf->buf_id);

	sphcs_p2p_init_p2p_buf(buf);
}

int sphcs_p2p_ring_doorbell(struct sphcs_p2p_peer_dev *dev)
{
	sph_log_debug(GENERAL_LOG, "Notify peer\n");

	*(u8 *)dev->buf_vaddr = 0x80;
	return sphcs_dma_sched_start_xfer_single(g_the_sphcs->dmaSched,
					       &g_dma_desc_c2h_high,
					       dev->buf_dma_addr,
					       dev->doorbell,
					       1,
					       NULL,
					       NULL,
					       NULL,
					       0);

}

void IPC_OPCODE_HANDLER(P2P_DEV)(struct sphcs *sphcs, union h2c_P2PDev *cmd)
{
	if (cmd->destroy) {
		if (cmd->is_producer) {
			sph_log_debug(GENERAL_LOG, "producer removed\n");
			p2p_producers[cmd->dev_id].doorbell = 0;
		} else {
			sph_log_debug(GENERAL_LOG, "producer removed\n");
			p2p_consumers[cmd->dev_id].doorbell = 0;
		}
	} else {
		if (cmd->is_producer) {
			p2p_producers[cmd->dev_id].doorbell = cmd->db_addr;
			sph_log_debug(GENERAL_LOG, "New producer registered (id - %u, db - %pad)\n", cmd->dev_id, &p2p_producers[cmd->dev_id].doorbell);
		} else {
			p2p_consumers[cmd->dev_id].doorbell = cmd->db_addr;
			sph_log_debug(GENERAL_LOG, "New consumer registered (id - %u, db - %pad)\n", cmd->dev_id, &p2p_consumers[cmd->dev_id].doorbell);
		}
	}
}

void IPC_OPCODE_HANDLER(PEER_BUF)(struct sphcs *sphcs, union h2c_PeerBuf *cmd)
{
	struct sphcs_p2p_buf *buf;

	sph_log_debug(GENERAL_LOG, "is_src_buf %u buf_id %u peer_buf_id %u peer_dev_id %u\n", cmd->is_src_buf, cmd->buf_id, cmd->peer_buf_id, cmd->dev_id);

	buf = (cmd->is_src_buf) ? src_bufs[cmd->buf_id] : dst_bufs[cmd->buf_id];
	buf->peer_buf_id = cmd->peer_buf_id;
	buf->peer_dev = (cmd->is_src_buf) ? &p2p_consumers[cmd->dev_id] : &p2p_producers[cmd->dev_id];
}

int sphcs_p2p_new_message_arrived(u8 value)
{
	u32 i;

	sph_log_debug(GENERAL_LOG, "Signaled by peer (value - %X)\n", value);

	for (i = 0; i < MAX_NUM_OF_P2P_BUFS; i++) {
		if (dst_bufs[i] != NULL) {
			dst_bufs[i]->ready = true;
			s_p2p_cbs->new_data_arrived(dst_bufs[i]);
		}
	}
	return 0;
}

int sphcs_p2p_init(struct sphcs *sphcs, struct sphcs_p2p_cbs *p2p_cbs)
{
	u32 i;
	int rc;

	for (i = 0; i < MAX_NUM_OF_P2P_DEVS; i++) {
		p2p_producers[i].buf_vaddr = dma_alloc_coherent(sphcs->hw_device, 1, &p2p_producers[i].buf_dma_addr, GFP_KERNEL);
		if (p2p_producers[i].buf_vaddr == NULL) {
			sph_log_err(GENERAL_LOG, "couldn't allocate memory\n");
			rc = -ENOMEM;
			goto err;
		}

		p2p_consumers[i].buf_vaddr = dma_alloc_coherent(sphcs->hw_device, 1, &p2p_consumers[i].buf_dma_addr, GFP_KERNEL);
		if (p2p_consumers[i].buf_vaddr == NULL) {
			sph_log_err(GENERAL_LOG, "couldn't allocate memory\n");
			rc = -ENOMEM;
			goto err;
		}

	}

	s_p2p_cbs = p2p_cbs;

	return 0;

err:
	sphcs_p2p_fini(sphcs);
	return rc;
}

void sphcs_p2p_fini(struct sphcs *sphcs)
{
	u32 i;

	for (i = 0; i < MAX_NUM_OF_P2P_DEVS; i++) {
		if (p2p_producers[i].buf_vaddr)
			dma_free_coherent(sphcs->hw_device, 1, p2p_producers[i].buf_vaddr, p2p_producers[i].buf_dma_addr);
		if (p2p_consumers[i].buf_vaddr)
			dma_free_coherent(sphcs->hw_device, 1, p2p_consumers[i].buf_vaddr, p2p_consumers[i].buf_dma_addr);

	}
}
