/********************************************
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#include <linux/types.h>
#include <linux/dma-mapping.h>
#include <linux/ion_exp.h>
#include <linux/dma-mapping.h>
#include "sphcs_p2p.h"
#include "sph_log.h"
#include "sphcs_cs.h"
#include "sph_mem_alloc_defs.h"

#define MAX_NUM_OF_P2P_DEVS 32
#define MAX_NUM_OF_P2P_BUFS 32
#define CR_FIFO_DEPTH 512

struct sphcs_p2p_peer_db {
	dma_addr_t dma_addr;

	/* local buffer of size 1 byte to be used for DMA */
	dma_addr_t buf_dma_addr;
	void *buf_vaddr;
};

struct sphcs_p2p_peer_fifo {
	/* fifo dma addr */
	dma_addr_t dma_addr;
	u32 elem_size;
	u32 depth;

	/* for wr_ptr */
	spinlock_t lock;

	/* index of next element to be written */
	u32 wr_ptr;

	/* local buffer to be used for DMA */
	dma_addr_t buf_dma_addr;
	void *buf_vaddr;
};

struct sphcs_p2p_peer_dev {
	u32 serial_channel;
	struct sphcs_p2p_peer_db peer_db;
	struct sphcs_p2p_peer_fifo peer_cr_fifo;
};

/* 64 bit forward credit message */
struct sphcs_p2p_fw_cr_fifo_elem {
	u64 sbid :5;
	u64 dbid :5;
	u64 is_new :1;
	u64 reserved :53;
};

/* 32 bit release creadit message */
struct sphcs_p2p_rel_cr_fifo_elem {
	u32 sbid :5;
	u64 is_new :1;
	u32 reserved :26;
};

struct sphcs_p2p_cr_fifo {
	u32 depth;
	u32 rd_ptr;
	u32 elem_size;

	void *buf_handle;
	struct sg_table *sgt;
	void *vaddr;
};

/* Peer devices */
static struct sphcs_p2p_peer_dev p2p_producers[MAX_NUM_OF_P2P_DEVS];
static struct sphcs_p2p_peer_dev p2p_consumers[MAX_NUM_OF_P2P_DEVS];

/* Buffers managed by this device */
static struct sphcs_p2p_buf *src_bufs[MAX_NUM_OF_P2P_BUFS] = {NULL};
static struct sphcs_p2p_buf *dst_bufs[MAX_NUM_OF_P2P_BUFS] = {NULL};

/* Credit FIFOs managed by this device */
static struct sphcs_p2p_cr_fifo fw_fifos[MAX_NUM_OF_P2P_DEVS];
static struct sphcs_p2p_cr_fifo rel_fifos[MAX_NUM_OF_P2P_DEVS];

DEFINE_IDA(p2p_dbid_ida);
DEFINE_IDA(p2p_sbid_ida);

struct sphcs_dma_desc pr_c2h_dma_desc;
struct sphcs_dma_desc cons_c2h_dma_desc;

static struct sphcs_p2p_cbs *s_p2p_cbs;

static inline u32 inc_fifo_ptr(u32 fifo_depth, u32 fifo_ptr)
{
	return (fifo_ptr + 1) % fifo_depth;
}
static inline const char *get_buf_type_string(bool is_src_buf)
{
	if (is_src_buf)
		return "src";
	else
		return "dst";
}

void sphcs_p2p_init_p2p_buf(bool is_src_buf, struct sphcs_p2p_buf *buf)
{
	buf->is_src_buf = is_src_buf;
	buf->buf_id = (-1);
	buf->peer_buf_id = (-1);
	buf->peer_dev = NULL;
}

int sphcs_p2p_add_buffer(struct sphcs_p2p_buf *buf)
{
	int id;
	struct sphcs_p2p_buf **bufs;
	struct ida *ida;

	if (buf->is_src_buf) {
		bufs = src_bufs;
		ida = &p2p_sbid_ida;
		buf->ready = true;
	} else {
		bufs = dst_bufs;
		ida = &p2p_dbid_ida;
		buf->ready = false;
	}

	id = ida_simple_get(ida, 0, MAX_NUM_OF_P2P_BUFS, GFP_KERNEL);

	if (id < 0)
		return id;

	buf->buf_id = id;
	bufs[id] = buf;

	sph_log_debug(GENERAL_LOG, "New %s p2p buffer added (id %u)\n", get_buf_type_string(buf->is_src_buf), buf->buf_id);

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

}

/* TODO: Make one DMA transaction to send the credit and to ring the db. */
int sphcs_p2p_ring_doorbell(struct sphcs_p2p_buf *buf)
{
	sph_log_debug(GENERAL_LOG, "Ring the doorbell of device\n");

	*(u8 *)buf->peer_dev->peer_db.buf_vaddr = 0x80;
	return sphcs_dma_sched_start_xfer_single(g_the_sphcs->dmaSched,
					       (buf->is_src_buf) ? &pr_c2h_dma_desc : &cons_c2h_dma_desc,
					       buf->peer_dev->peer_db.buf_dma_addr,
					       buf->peer_dev->peer_db.dma_addr,
					       1,
					       NULL,
					       NULL,
					       NULL,
					       0);

}

int sphcs_p2p_send_fw_cr(struct sphcs_p2p_buf *buf)
{
	struct sphcs_p2p_fw_cr_fifo_elem *fifo_elem;
	u32 off;
	int ret = 0;

	sph_log_debug(GENERAL_LOG, "Forward credit (src buf id %u, dst buf id %u)\n", buf->buf_id, buf->peer_buf_id);

	/* We assume that FIFO depth is always greater or equal the total number of credits
	 * that may be sent from the same producer
	 */
	SPH_SPIN_LOCK(&buf->peer_dev->peer_cr_fifo.lock);
	off = buf->peer_dev->peer_cr_fifo.wr_ptr * buf->peer_dev->peer_cr_fifo.elem_size;
	fifo_elem = (struct sphcs_p2p_fw_cr_fifo_elem *)(buf->peer_dev->peer_cr_fifo.buf_vaddr + off);
	fifo_elem->sbid = buf->buf_id;
	fifo_elem->dbid = buf->peer_buf_id;
	fifo_elem->is_new = 1;

	ret = sphcs_dma_sched_start_xfer_single(g_the_sphcs->dmaSched,
					  &pr_c2h_dma_desc,
					  buf->peer_dev->peer_cr_fifo.buf_dma_addr + off,
					  buf->peer_dev->peer_cr_fifo.dma_addr + off,
					  buf->peer_dev->peer_cr_fifo.elem_size,
					  NULL,
					  NULL,
					  NULL,
					  0);
	buf->peer_dev->peer_cr_fifo.wr_ptr = inc_fifo_ptr(buf->peer_dev->peer_cr_fifo.depth, buf->peer_dev->peer_cr_fifo.wr_ptr);

	SPH_SPIN_UNLOCK(&buf->peer_dev->peer_cr_fifo.lock);

	return ret;

}

int sphcs_p2p_send_rel_cr(struct sphcs_p2p_buf *buf)
{
	struct sphcs_p2p_rel_cr_fifo_elem *fifo_elem;
	u32 off;
	int ret = 0;

	sph_log_debug(GENERAL_LOG, "Release credit (src buf id %u, dst buf id %u)\n", buf->buf_id, buf->peer_buf_id);

	/* We assume that FIFO depth is always greater or equal the total number of credits
	 * that may be sent from the same consumer
	 */
	SPH_SPIN_LOCK(&buf->peer_dev->peer_cr_fifo.lock);
	off = buf->peer_dev->peer_cr_fifo.wr_ptr * buf->peer_dev->peer_cr_fifo.elem_size;
	fifo_elem = (struct sphcs_p2p_rel_cr_fifo_elem *)(buf->peer_dev->peer_cr_fifo.buf_vaddr + off);
	fifo_elem->sbid = buf->peer_buf_id;
	fifo_elem->is_new = 1;

	ret = sphcs_dma_sched_start_xfer_single(g_the_sphcs->dmaSched,
					  &cons_c2h_dma_desc,
					  buf->peer_dev->peer_cr_fifo.buf_dma_addr + off,
					  buf->peer_dev->peer_cr_fifo.dma_addr + off,
					  buf->peer_dev->peer_cr_fifo.elem_size,
					  NULL,
					  NULL,
					  NULL,
					  0);
	buf->peer_dev->peer_cr_fifo.wr_ptr = inc_fifo_ptr(buf->peer_dev->peer_cr_fifo.depth, buf->peer_dev->peer_cr_fifo.wr_ptr);
	SPH_SPIN_UNLOCK(&buf->peer_dev->peer_cr_fifo.lock);

	return ret;

}

void IPC_OPCODE_HANDLER(P2P_DEV)(struct sphcs *sphcs, union h2c_P2PDev *cmd)
{
	if (cmd->destroy) {
		if (cmd->is_producer) {
			sph_log_debug(GENERAL_LOG, "producer removed\n");
			p2p_producers[cmd->dev_id].peer_db.dma_addr = 0;
		} else {
			sph_log_debug(GENERAL_LOG, "producer removed\n");
			p2p_consumers[cmd->dev_id].peer_db.dma_addr = 0;
		}
	} else {
		if (cmd->is_producer) {
			p2p_producers[cmd->dev_id].peer_db.dma_addr = cmd->db_addr;
			p2p_producers[cmd->dev_id].peer_cr_fifo.dma_addr = SPH_IPC_DMA_PFN_TO_ADDR(cmd->cr_fifo_addr);
			sph_log_debug(GENERAL_LOG, "New producer registered (id - %u, db - %pad, cr fifo - %pad)\n",
									     cmd->dev_id,
									     &p2p_producers[cmd->dev_id].peer_db.dma_addr,
									     &p2p_producers[cmd->dev_id].peer_cr_fifo.dma_addr);
		} else {
			p2p_consumers[cmd->dev_id].peer_db.dma_addr = cmd->db_addr;
			p2p_consumers[cmd->dev_id].peer_cr_fifo.dma_addr = SPH_IPC_DMA_PFN_TO_ADDR(cmd->cr_fifo_addr);
			sph_log_debug(GENERAL_LOG, "New consumer registered (id - %u, db - %pad, cr fifo - %pad)\n",
									     cmd->dev_id,
									     &p2p_consumers[cmd->dev_id].peer_db.dma_addr,
									     &p2p_consumers[cmd->dev_id].peer_cr_fifo.dma_addr);
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

void IPC_OPCODE_HANDLER(GET_CR_FIFO)(struct sphcs *sphcs, union h2c_GetCrFIFO *cmd)
{
	struct sphcs_p2p_cr_fifo *fifo;

	sph_log_debug(GENERAL_LOG, "tr id %u, peer_id %u fw_fifo %u\n", cmd->tr_id, cmd->peer_id, cmd->fw_fifo);

	fifo = cmd->fw_fifo ? &fw_fifos[cmd->peer_id] : &rel_fifos[cmd->peer_id];

	sphcs_send_event_report(sphcs,
				SPH_IPC_GET_FIFO,
				cmd->tr_id,
				-1,
				(sg_dma_address(fifo->sgt->sgl) - sphcs->inbound_mem_dma_addr) >> PAGE_SHIFT);
}

int sphcs_p2p_new_message_arrived(void)
{
	u32 i;
	struct sphcs_p2p_fw_cr_fifo_elem *fw_fifo_elem;
	struct sphcs_p2p_rel_cr_fifo_elem *rel_fifo_elem;

	sph_log_debug(GENERAL_LOG, "Signaled by peer\n");

	/* Check all FIFOs managed by this device */
	for (i = 0; i < MAX_NUM_OF_P2P_DEVS; i++) {
		/* Check whether the new element has been written to the fw credit fifo */
		fw_fifo_elem = fw_fifos[i].vaddr + fw_fifos[i].rd_ptr * fw_fifos[i].elem_size;
		SPH_ASSERT(fw_fifo_elem);
		if (fw_fifo_elem->is_new) {
			sph_log_debug(GENERAL_LOG, "Credit forwarded for dst buffer %u\n", fw_fifo_elem->dbid);
			dst_bufs[fw_fifo_elem->dbid]->ready = true;
			s_p2p_cbs->new_data_arrived(dst_bufs[fw_fifo_elem->dbid]);
			/* Mark the element as handled and promote the read ptr */
			fw_fifo_elem->is_new = 0;
			fw_fifos[i].rd_ptr = inc_fifo_ptr(fw_fifos[i].depth, fw_fifos[i].rd_ptr);
		}

		/* Check whether the new element has been written to the rel credit fifo */
		rel_fifo_elem = rel_fifos[i].vaddr + rel_fifos[i].rd_ptr * rel_fifos[i].elem_size;
		SPH_ASSERT(rel_fifo_elem);
		if (rel_fifo_elem->is_new) {
			sph_log_debug(GENERAL_LOG, "Credit released for src buffer %u\n", rel_fifo_elem->sbid);
			src_bufs[rel_fifo_elem->sbid]->ready = true;
			s_p2p_cbs->data_consumed(src_bufs[rel_fifo_elem->sbid]);
			/* Mark the element as handled and promote the read ptr */
			rel_fifo_elem->is_new = 0;
			rel_fifos[i].rd_ptr = inc_fifo_ptr(rel_fifos[i].depth, rel_fifos[i].rd_ptr);
		}
	}

	return 0;
}

int sphcs_p2p_init(struct sphcs *sphcs, struct sphcs_p2p_cbs *p2p_cbs)
{
	u32 i;
	int rc;

	pr_c2h_dma_desc.dma_direction = SPHCS_DMA_DIRECTION_CARD_TO_HOST;
	pr_c2h_dma_desc.dma_priority = SPHCS_DMA_PRIORITY_HIGH;
	pr_c2h_dma_desc.flags = 0;
	pr_c2h_dma_desc.serial_channel = sphcs_dma_sched_create_serial_channel(sphcs->dmaSched);

	cons_c2h_dma_desc.dma_direction = SPHCS_DMA_DIRECTION_CARD_TO_HOST;
	cons_c2h_dma_desc.dma_priority = SPHCS_DMA_PRIORITY_HIGH;
	cons_c2h_dma_desc.flags = 0;
	cons_c2h_dma_desc.serial_channel = sphcs_dma_sched_create_serial_channel(sphcs->dmaSched);

	for (i = 0; i < MAX_NUM_OF_P2P_DEVS; i++) {

		p2p_producers[i].peer_db.buf_vaddr = dma_alloc_coherent(sphcs->hw_device, 1, &p2p_producers[i].peer_db.buf_dma_addr, GFP_KERNEL);
		if (p2p_producers[i].peer_db.buf_vaddr == NULL) {
			sph_log_err(GENERAL_LOG, "couldn't allocate memory\n");
			rc = -ENOMEM;
			goto err;
		}

		p2p_producers[i].peer_cr_fifo.depth = CR_FIFO_DEPTH;
		p2p_producers[i].peer_cr_fifo.wr_ptr = 0;
		spin_lock_init(&p2p_producers[i].peer_cr_fifo.lock);
		p2p_producers[i].peer_cr_fifo.elem_size = sizeof(struct sphcs_p2p_fw_cr_fifo_elem);
		p2p_producers[i].peer_cr_fifo.buf_vaddr = dma_alloc_coherent(sphcs->hw_device,
									     CR_FIFO_DEPTH * sizeof(struct sphcs_p2p_fw_cr_fifo_elem),
									     &p2p_producers[i].peer_cr_fifo.buf_dma_addr,
									     GFP_KERNEL);
		if (p2p_producers[i].peer_cr_fifo.buf_vaddr == NULL) {
			sph_log_err(GENERAL_LOG, "couldn't allocate memory\n");
			rc = -ENOMEM;
			goto err;
		}

		p2p_consumers[i].peer_db.buf_vaddr = dma_alloc_coherent(sphcs->hw_device, 1, &p2p_consumers[i].peer_db.buf_dma_addr, GFP_KERNEL);
		if (p2p_consumers[i].peer_db.buf_vaddr == NULL) {
			sph_log_err(GENERAL_LOG, "couldn't allocate memory\n");
			rc = -ENOMEM;
			goto err;
		}

		p2p_consumers[i].peer_cr_fifo.depth = CR_FIFO_DEPTH;
		p2p_consumers[i].peer_cr_fifo.wr_ptr = 0;
		spin_lock_init(&p2p_consumers[i].peer_cr_fifo.lock);
		p2p_consumers[i].peer_cr_fifo.elem_size = sizeof(struct sphcs_p2p_rel_cr_fifo_elem);
		p2p_consumers[i].peer_cr_fifo.buf_vaddr = dma_alloc_coherent(sphcs->hw_device,
									     CR_FIFO_DEPTH * sizeof(struct sphcs_p2p_rel_cr_fifo_elem),
									     &p2p_consumers[i].peer_cr_fifo.buf_dma_addr,
									     GFP_KERNEL);
		if (p2p_consumers[i].peer_cr_fifo.buf_vaddr == NULL) {
			sph_log_err(GENERAL_LOG, "couldn't allocate memory\n");
			rc = -ENOMEM;
			goto err;
		}

	}

	s_p2p_cbs = p2p_cbs;

	/* Allocate fw cr fifos */
	for (i = 0; i < MAX_NUM_OF_P2P_DEVS; i++) {
		fw_fifos[i].depth = CR_FIFO_DEPTH;
		fw_fifos[i].rd_ptr = 0;
		fw_fifos[i].elem_size = sizeof(struct sphcs_p2p_fw_cr_fifo_elem);
		fw_fifos[i].buf_handle = ion_kbuf_alloc(CR_FIFO_DEPTH * fw_fifos[i].elem_size,
							PAGE_SIZE,
							P2P_HEAP_NAME,
							2, /*ION_FLAG_CONTIG*/
							&fw_fifos[i].sgt,
							&fw_fifos[i].vaddr);
		if (IS_ERR_OR_NULL(fw_fifos[i].buf_handle)) {
			sph_log_err(GENERAL_LOG, "couldn't allocate fw fifo\n");
			goto err;
		}

		/* Need to zero is_new */
		memset(fw_fifos[i].vaddr, 0, CR_FIFO_DEPTH * fw_fifos[i].elem_size);

		fw_fifos[i].sgt->orig_nents = dma_map_sg(sphcs->hw_device,
							 fw_fifos[i].sgt->sgl,
							 fw_fifos[i].sgt->orig_nents,
							 DMA_FROM_DEVICE);
		if (unlikely(fw_fifos[i].sgt->orig_nents < 0)) {
			sph_log_err(GENERAL_LOG, "Failed to map fw fifo\n");
			goto err;
		}

	}

	/* Allocate rel cr fifos */
	for (i = 0; i < MAX_NUM_OF_P2P_DEVS; i++) {
		rel_fifos[i].depth = CR_FIFO_DEPTH;
		rel_fifos[i].rd_ptr = 0;
		rel_fifos[i].elem_size = sizeof(struct sphcs_p2p_rel_cr_fifo_elem);
		rel_fifos[i].buf_handle = ion_kbuf_alloc(CR_FIFO_DEPTH * rel_fifos[i].elem_size,
							 PAGE_SIZE,
							 P2P_HEAP_NAME,
							 2, /*ION_FLAG_CONTIG*/
							 &rel_fifos[i].sgt,
							 &rel_fifos[i].vaddr);
		if (IS_ERR_OR_NULL(rel_fifos[i].buf_handle)) {
			sph_log_err(GENERAL_LOG, "couldn't allocate rel fifo\n");
			goto err;
		}

		/* Need to zero is_new */
		memset(rel_fifos[i].vaddr, 0, CR_FIFO_DEPTH * rel_fifos[i].elem_size);

		rel_fifos[i].sgt->orig_nents = dma_map_sg(sphcs->hw_device,
							  rel_fifos[i].sgt->sgl,
							  rel_fifos[i].sgt->orig_nents,
							  DMA_FROM_DEVICE);
		if (unlikely(rel_fifos[i].sgt->orig_nents < 0)) {
			sph_log_err(GENERAL_LOG, "Failed to map rel fifo\n");
			goto err;
		}

	}

	return 0;

err:
	sphcs_p2p_fini(sphcs);
	return rc;
}

void sphcs_p2p_fini(struct sphcs *sphcs)
{
	u32 i;

	for (i = 0; i < MAX_NUM_OF_P2P_DEVS; i++) {
		if (p2p_producers[i].peer_db.buf_vaddr) {
			dma_free_coherent(sphcs->hw_device, 1, p2p_producers[i].peer_db.buf_vaddr, p2p_producers[i].peer_db.buf_dma_addr);
			p2p_producers[i].peer_db.buf_vaddr = NULL;
		}
		if (p2p_consumers[i].peer_db.buf_vaddr) {
			dma_free_coherent(sphcs->hw_device, 1, p2p_consumers[i].peer_db.buf_vaddr, p2p_consumers[i].peer_db.buf_dma_addr);
			p2p_consumers[i].peer_db.buf_vaddr = NULL;
		}
		if (!IS_ERR_OR_NULL(fw_fifos[i].buf_handle)) {
			ion_kbuf_free(fw_fifos[i].buf_handle);
			fw_fifos[i].buf_handle = NULL;
		}
		if (!IS_ERR_OR_NULL(rel_fifos[i].buf_handle)) {
			ion_kbuf_free(rel_fifos[i].buf_handle);
			rel_fifos[i].buf_handle = NULL;
		}
	}
}
