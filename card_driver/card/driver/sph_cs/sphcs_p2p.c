/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#include <linux/types.h>
#include <linux/dma-mapping.h>
#include <linux/ion_exp.h>
#include <linux/dma-mapping.h>
#include <linux/slab.h>
#include <linux/bits.h>
#include "sphcs_p2p.h"
#include "sph_log.h"
#include "sphcs_cs.h"
#include "sph_mem_alloc_defs.h"

#define MAX_NUM_OF_P2P_DEVS 32
#define MAX_NUM_OF_P2P_BUFS_SHIFT 8
#define MAX_NUM_OF_P2P_BUFS BIT(MAX_NUM_OF_P2P_BUFS_SHIFT)
#define CR_FIFO_DEPTH MAX_NUM_OF_P2P_BUFS

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

	/* Preallocated LLIs*/
	struct lli_desc *llis;
};

struct sphcs_p2p_peer_dev {
	struct sphcs_p2p_peer_db peer_db;
	struct sphcs_p2p_peer_fifo peer_cr_fifo;
};

/* 64 bit forward credit message */
struct sphcs_p2p_fw_cr_fifo_elem {
	u64 sbid :MAX_NUM_OF_P2P_BUFS_SHIFT;
	u64 dbid :MAX_NUM_OF_P2P_BUFS_SHIFT;
	u64 is_new :1;
	u64 reserved :47;
};

/* 32 bit release creadit message */
struct sphcs_p2p_rel_cr_fifo_elem {
	u32 sbid :MAX_NUM_OF_P2P_BUFS_SHIFT;
	u32 is_new :1;
	u32 reserved :23;
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

static struct sphcs_p2p_cbs *s_p2p_cbs;

/* Describes the PAGE_SIZE bytes to be used for LLIs*/
struct sphcs_p2p_allocated_page {
	struct list_head list;
	dma_addr_t dma_addr;
	void *vaddr;
};

LIST_HEAD(producer_allocated_pages);
LIST_HEAD(consumer_allocated_pages);

static struct sphcs_p2p_allocated_page *sphcs_p2p_allocate_new_page(struct sphcs *sphcs, struct list_head *head)
{

	struct sphcs_p2p_allocated_page *new = NULL;

	new = kmalloc(sizeof(*new), GFP_KERNEL);
	if (!new)
		goto out;

	new->vaddr = dma_alloc_coherent(sphcs->hw_device, PAGE_SIZE, &new->dma_addr, GFP_KERNEL);
	if (!new->vaddr) {
		kfree(new);
		new = NULL;
	} else
		list_add(&new->list, head);
out:
	return new;
}

static void sphcs_p2p_release_allocated_pages(struct sphcs *sphcs, struct list_head *head)
{
	struct sphcs_p2p_allocated_page *curr, *tmp;

	list_for_each_entry_safe(curr, tmp, head, list) {
		list_del(&curr->list);
		dma_free_coherent(sphcs->hw_device, PAGE_SIZE, curr->vaddr, curr->dma_addr);
		kfree(curr);
	}

}

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

u8 sphcs_p2p_get_peer_dev_id(struct sphcs_p2p_buf *buf)
{
	struct sphcs_p2p_peer_dev *peer_devs;

	peer_devs = (buf->is_src_buf) ? p2p_consumers : p2p_producers;

	/* The device N is at index N */
	return (buf->peer_dev - peer_devs);
}

int sphcs_p2p_init_p2p_buf(bool is_src_buf, struct sphcs_p2p_buf *buf)
{
	int id;
	struct sphcs_p2p_buf **bufs;
	struct ida *ida;

	buf->is_src_buf = is_src_buf;
	buf->peer_buf_id = (-1);
	buf->peer_dev = NULL;

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
	if (id < 0) {
		sph_log_err(GENERAL_LOG, "Failed to assign id to p2p buffer\n");
		return id;
	}

	buf->buf_id = id;
	bufs[id] = buf;

	sph_log_debug(GENERAL_LOG, "New %s p2p buffer created (id %u)\n", get_buf_type_string(buf->is_src_buf), buf->buf_id);

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

int sphcs_p2p_send_fw_cr_and_ring_db(struct sphcs_p2p_buf *buf,
				     sphcs_dma_sched_completion_callback callback,
				     void *callback_ctx)
{
	struct sphcs_p2p_fw_cr_fifo_elem *fifo_elem;
	u32 off;
	int ret = 0;

	sph_log_debug(GENERAL_LOG, "Forward credit (src buf id %u, dst buf id %u)\n", buf->buf_id, buf->peer_buf_id);

	NNP_SPIN_LOCK(&buf->peer_dev->peer_cr_fifo.lock);
	off = buf->peer_dev->peer_cr_fifo.wr_ptr * buf->peer_dev->peer_cr_fifo.elem_size;
	fifo_elem = (struct sphcs_p2p_fw_cr_fifo_elem *)(buf->peer_dev->peer_cr_fifo.buf_vaddr + off);
	fifo_elem->sbid = buf->buf_id;
	fifo_elem->dbid = buf->peer_buf_id;
	fifo_elem->is_new = 1;

	ret = sphcs_dma_sched_start_xfer_multi(g_the_sphcs->dmaSched,
					       NULL,
					       &g_dma_desc_c2h_high_nowait,
					       &buf->peer_dev->peer_cr_fifo.llis[buf->peer_dev->peer_cr_fifo.wr_ptr],
					       buf->peer_dev->peer_cr_fifo.elem_size + 1,
					       callback,
					       callback_ctx);
	if (unlikely(ret))
		sph_log_err(GENERAL_LOG, "Failed to forward credit (src buf id %u, dst buf id %u)\n", buf->buf_id, buf->peer_buf_id);
	else
		buf->peer_dev->peer_cr_fifo.wr_ptr = inc_fifo_ptr(buf->peer_dev->peer_cr_fifo.depth, buf->peer_dev->peer_cr_fifo.wr_ptr);

	NNP_SPIN_UNLOCK(&buf->peer_dev->peer_cr_fifo.lock);

	return ret;

}

int sphcs_p2p_send_rel_cr_and_ring_db(struct sphcs_p2p_buf *buf,
				      sphcs_dma_sched_completion_callback callback,
				      void *callback_ctx)
{
	struct sphcs_p2p_rel_cr_fifo_elem *fifo_elem;
	u32 off;
	int ret = 0;

	sph_log_debug(GENERAL_LOG, "Release credit (src buf id %u, dst buf id %u)\n", buf->buf_id, buf->peer_buf_id);

	NNP_SPIN_LOCK(&buf->peer_dev->peer_cr_fifo.lock);
	off = buf->peer_dev->peer_cr_fifo.wr_ptr * buf->peer_dev->peer_cr_fifo.elem_size;
	fifo_elem = (struct sphcs_p2p_rel_cr_fifo_elem *)(buf->peer_dev->peer_cr_fifo.buf_vaddr + off);
	fifo_elem->sbid = buf->peer_buf_id;
	fifo_elem->is_new = 1;

	ret = sphcs_dma_sched_start_xfer_multi(g_the_sphcs->dmaSched,
					       NULL,
					       &g_dma_desc_c2h_high_nowait,
					       &buf->peer_dev->peer_cr_fifo.llis[buf->peer_dev->peer_cr_fifo.wr_ptr],
					       buf->peer_dev->peer_cr_fifo.elem_size + 1,
					       callback,
					       callback_ctx);

	buf->peer_dev->peer_cr_fifo.wr_ptr = inc_fifo_ptr(buf->peer_dev->peer_cr_fifo.depth, buf->peer_dev->peer_cr_fifo.wr_ptr);

	NNP_SPIN_UNLOCK(&buf->peer_dev->peer_cr_fifo.lock);

	return ret;

}

void IPC_OPCODE_HANDLER(CHAN_P2P_GET_CR_FIFO)(struct sphcs *sphcs, union h2c_ChanGetCrFIFO *cmd)
{
	struct sphcs_p2p_cr_fifo *fifo;

	sph_log_debug(GENERAL_LOG, "tr id %u, peer_id %u fw_fifo %u\n", cmd->p2p_tr_id, cmd->peer_id, cmd->fw_fifo);

	fifo = cmd->fw_fifo ? &fw_fifos[cmd->peer_id] : &rel_fifos[cmd->peer_id];

	sphcs_send_event_report_ext(sphcs,
				NNP_IPC_GET_CR_FIFO_REPLY,
				0,
				NULL,
				cmd->chan_id,
				cmd->p2p_tr_id,
				(sg_dma_address(fifo->sgt->sgl) - sphcs->inbound_mem_dma_addr) >> PAGE_SHIFT);
}

void IPC_OPCODE_HANDLER(CHAN_P2P_CONNECT_PEERS)(struct sphcs *sphcs, union h2c_ChanConnectPeers *cmd)
{
	struct sphcs_p2p_buf *buf;

	sph_log_debug(GENERAL_LOG, "is_src_buf %u buf_id %u peer_buf_id %u peer_dev_id %u\n", cmd->is_src_buf, cmd->buf_id, cmd->peer_buf_id, cmd->peer_dev_id);

	buf = (cmd->is_src_buf) ? src_bufs[cmd->buf_id] : dst_bufs[cmd->buf_id];
	buf->peer_buf_id = cmd->peer_buf_id;
	buf->peer_dev = (cmd->is_src_buf) ? &p2p_consumers[cmd->peer_dev_id] : &p2p_producers[cmd->peer_dev_id];

	sphcs_send_event_report(sphcs, NNP_IPC_P2P_PEERS_CONNECTED, 0, NULL, cmd->chan_id, cmd->p2p_tr_id);
}

static void _sphcs_p2p_remove_lli_templates(struct sphcs *sphcs,
					    struct list_head *allocated_pages)
{
	sphcs_p2p_release_allocated_pages(sphcs, allocated_pages);
}

static int _sphcs_p2p_create_lli_templates(struct sphcs *sphcs,
					   struct sphcs_p2p_peer_dev *peer_devs,
					   struct list_head *allocated_pages,
					   struct sg_table *to_sgt,
					   struct sg_table *from_sgt)
{
	u32 lli_idx, dev_idx;
	struct  lli_desc *lli;
	u64 transfer_size;
	int ret;
	struct sphcs_p2p_allocated_page *current_page;
	u32 page_off = 0;

	/* Allocate first page */
	current_page = sphcs_p2p_allocate_new_page(sphcs, allocated_pages);
	if (!current_page)
		return -ENOMEM;

	/* Prepare LLIs */
	for (dev_idx = 0; dev_idx < MAX_NUM_OF_P2P_DEVS; dev_idx++) {
		for (lli_idx = 0; lli_idx < CR_FIFO_DEPTH; lli_idx++) {
			lli = &peer_devs[dev_idx].peer_cr_fifo.llis[lli_idx];

			/* The LLI can't be transferred over different DMA channels */
			ret = sphcs->hw_ops->dma.init_lli(sphcs->hw_handle,
							  lli,
							  from_sgt, to_sgt, 0,
							  true);
			if (ret != 0) {
				sph_log_err(GENERAL_LOG, "Failed to init lli\n");
				goto failed_to_init_lli;
			}

			NNP_ASSERT(lli->size <= PAGE_SIZE);

			/* Allocate new page if not enough free space in the current one */
			if (page_off > (PAGE_SIZE - lli->size)) {
				current_page = sphcs_p2p_allocate_new_page(sphcs, allocated_pages);
				if (!current_page) {
					sph_log_err(GENERAL_LOG, "Failed to allocate new page\n");
					ret = -ENOMEM;
					goto failed_to_allocate_new_page;
				}
				page_off = 0;
			}

			/* Set LLI memory */
			lli->dma_addr = current_page->dma_addr + page_off;
			lli->vptr = (u8 *)current_page->vaddr + page_off;
			page_off += lli->size;

			/* Generate LLI */
			transfer_size = sphcs->hw_ops->dma.gen_lli(sphcs->hw_handle, from_sgt, to_sgt, lli, 0);
			if (transfer_size != (peer_devs[dev_idx].peer_cr_fifo.elem_size + 1)) {
				sph_log_err(GENERAL_LOG, "Failed to generate lli\n");
				ret = -ENOMEM;
				goto failed_to_generate_lli;
			}
		}
	}
	return 0;

failed_to_generate_lli:
failed_to_allocate_new_page:
failed_to_init_lli:
	_sphcs_p2p_remove_lli_templates(sphcs, allocated_pages);
	return ret;
}

static int sphcs_p2p_create_lli_templates(struct sphcs *sphcs)
{
	int rc;
	struct sg_table to_sgt, from_sgt;

	rc = sg_alloc_table(&to_sgt, 2, GFP_KERNEL);
	if (rc)
		goto out;

	rc = sg_alloc_table(&from_sgt, 2, GFP_KERNEL);
	if (rc)
		goto failed_to_alloc_src_sgt;

	to_sgt.sgl[0].length = p2p_producers[0].peer_cr_fifo.elem_size;
	to_sgt.sgl[0].dma_address = 0;
	to_sgt.sgl[1].length = 1;
	to_sgt.sgl[1].dma_address = 0;
	from_sgt.sgl[0].length = p2p_producers[0].peer_cr_fifo.elem_size;
	from_sgt.sgl[0].dma_address =  0;
	from_sgt.sgl[1].length = 1;
	from_sgt.sgl[1].dma_address = 0;

	/* Create LLI templates for producers */
	rc = _sphcs_p2p_create_lli_templates(sphcs, p2p_producers, &producer_allocated_pages, &to_sgt, &from_sgt);
	if (rc)
		goto failed_to_create_prod_template;

	to_sgt.sgl[0].length = p2p_consumers[0].peer_cr_fifo.elem_size;
	from_sgt.sgl[0].length = p2p_consumers[0].peer_cr_fifo.elem_size;

	/* Create LLI templates for consumers */
	rc = _sphcs_p2p_create_lli_templates(sphcs, p2p_consumers, &consumer_allocated_pages, &to_sgt, &from_sgt);
	if (rc)
		goto failed_to_create_con_template;

	sg_free_table(&from_sgt);
	sg_free_table(&to_sgt);

	return 0;

failed_to_create_con_template:
	_sphcs_p2p_remove_lli_templates(sphcs, &producer_allocated_pages);
failed_to_create_prod_template:
	sg_free_table(&from_sgt);
failed_to_alloc_src_sgt:
	sg_free_table(&to_sgt);
out:
	return rc;
}

void IPC_OPCODE_HANDLER(CHAN_P2P_UPDATE_PEER_DEV)(struct sphcs *sphcs, union h2c_ChanUpdatePeerDev *cmd)
{
	struct sphcs_p2p_peer_dev *peer_dev;
	char *dev_role;
	u32 i, off;
	dma_addr_t src;
	dma_addr_t dst;
	struct lli_desc *lli;

	if (cmd->is_producer) {
		peer_dev = &p2p_producers[cmd->dev_id];
		dev_role = "producer";
	} else {
		peer_dev = &p2p_consumers[cmd->dev_id];
		dev_role = "consumer";
	}

	peer_dev->peer_db.dma_addr = cmd->db_addr;
	peer_dev->peer_cr_fifo.dma_addr = NNP_IPC_DMA_PFN_TO_ADDR(cmd->cr_fifo_addr);

	sph_log_debug(GENERAL_LOG, "New %s registered (id - %u, db - %pad, cr fifo - %pad)\n",
			dev_role,
			cmd->dev_id,
			&peer_dev->peer_db.dma_addr,
			&peer_dev->peer_cr_fifo.dma_addr);

	/* Edit lli templates */
	for (i = 0; i < peer_dev->peer_cr_fifo.depth; i++) {
		off = i * peer_dev->peer_cr_fifo.elem_size;
		lli = &peer_dev->peer_cr_fifo.llis[i];

		/* Edit first lli element - credit*/
		src = peer_dev->peer_cr_fifo.buf_dma_addr + off;
		dst = peer_dev->peer_cr_fifo.dma_addr + off;
		g_the_sphcs->hw_ops->dma.edit_lli_elem(lli, 0, src, dst);

		/* Edit second lli element - db*/
		src = peer_dev->peer_db.buf_dma_addr;
		dst = peer_dev->peer_db.dma_addr;
		g_the_sphcs->hw_ops->dma.edit_lli_elem(lli, 1, src, dst);
	}

	sphcs_send_event_report(sphcs, NNP_IPC_P2P_PEER_DEV_UPDATED, 0, NULL, cmd->chan_id, cmd->p2p_tr_id);
}


int sphcs_p2p_new_message_arrived(void)
{
	u32 i;
	struct sphcs_p2p_fw_cr_fifo_elem *fw_fifo_elem;
	struct sphcs_p2p_rel_cr_fifo_elem *rel_fifo_elem;
	bool new_element_found;

	/* Check all FIFOs managed by this device */
	for (i = 0; i < MAX_NUM_OF_P2P_DEVS; i++) {
		do {
			/* Check whether the new element has been written to the fw credit fifo */
			fw_fifo_elem = fw_fifos[i].vaddr + fw_fifos[i].rd_ptr * fw_fifos[i].elem_size;
			NNP_ASSERT(fw_fifo_elem);
			new_element_found = fw_fifo_elem->is_new;
			if (new_element_found) {
				sph_log_debug(GENERAL_LOG, "Credit forwarded for dst buffer %u\n", fw_fifo_elem->dbid);
				s_p2p_cbs->new_data_arrived(dst_bufs[fw_fifo_elem->dbid]);
				/* Mark the element as handled and promote the read ptr */
				fw_fifo_elem->is_new = 0;
				fw_fifos[i].rd_ptr = inc_fifo_ptr(fw_fifos[i].depth, fw_fifos[i].rd_ptr);
			}
		} while (new_element_found);

		do {
			/* Check whether the new element has been written to the rel credit fifo */
			rel_fifo_elem = rel_fifos[i].vaddr + rel_fifos[i].rd_ptr * rel_fifos[i].elem_size;
			NNP_ASSERT(rel_fifo_elem);
			new_element_found = rel_fifo_elem->is_new;
			if (new_element_found) {
				sph_log_debug(GENERAL_LOG, "Credit released for src buffer %u\n", rel_fifo_elem->sbid);
				s_p2p_cbs->data_consumed(src_bufs[rel_fifo_elem->sbid]);
				/* Mark the element as handled and promote the read ptr */
				rel_fifo_elem->is_new = 0;
				rel_fifos[i].rd_ptr = inc_fifo_ptr(rel_fifos[i].depth, rel_fifos[i].rd_ptr);
			}
		} while (new_element_found);
	}

	return 0;
}

int sphcs_p2p_init(struct sphcs *sphcs, struct sphcs_p2p_cbs *p2p_cbs)
{
	u32 i;
	int rc = 0;

	for (i = 0; i < MAX_NUM_OF_P2P_DEVS; i++) {

		p2p_producers[i].peer_db.buf_vaddr = dma_alloc_coherent(sphcs->hw_device, 1, &p2p_producers[i].peer_db.buf_dma_addr, GFP_KERNEL);
		if (p2p_producers[i].peer_db.buf_vaddr == NULL) {
			sph_log_err(GENERAL_LOG, "couldn't allocate memory\n");
			rc = -ENOMEM;
			goto err;
		}
		*(u8 *)p2p_producers[i].peer_db.buf_vaddr = 0x80;

		p2p_producers[i].peer_cr_fifo.depth = CR_FIFO_DEPTH;
		p2p_producers[i].peer_cr_fifo.wr_ptr = 0;
		spin_lock_init(&p2p_producers[i].peer_cr_fifo.lock);
		/* We send release credit messages to producers */
		p2p_producers[i].peer_cr_fifo.elem_size = sizeof(struct sphcs_p2p_rel_cr_fifo_elem);
		p2p_producers[i].peer_cr_fifo.buf_vaddr = dma_alloc_coherent(sphcs->hw_device,
									     CR_FIFO_DEPTH * sizeof(struct sphcs_p2p_fw_cr_fifo_elem),
									     &p2p_producers[i].peer_cr_fifo.buf_dma_addr,
									     GFP_KERNEL);
		if (p2p_producers[i].peer_cr_fifo.buf_vaddr == NULL) {
			sph_log_err(GENERAL_LOG, "couldn't allocate memory\n");
			rc = -ENOMEM;
			goto err;
		}

		p2p_producers[i].peer_cr_fifo.llis = kcalloc(CR_FIFO_DEPTH, sizeof(struct lli_desc), GFP_KERNEL);
		if (p2p_producers[i].peer_cr_fifo.llis == NULL) {
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
		*(u8 *)p2p_consumers[i].peer_db.buf_vaddr = 0x80;

		p2p_consumers[i].peer_cr_fifo.depth = CR_FIFO_DEPTH;
		p2p_consumers[i].peer_cr_fifo.wr_ptr = 0;
		spin_lock_init(&p2p_consumers[i].peer_cr_fifo.lock);
		/* We send forward credit messages to consumers */
		p2p_consumers[i].peer_cr_fifo.elem_size = sizeof(struct sphcs_p2p_fw_cr_fifo_elem);
		p2p_consumers[i].peer_cr_fifo.buf_vaddr = dma_alloc_coherent(sphcs->hw_device,
									     CR_FIFO_DEPTH * sizeof(struct sphcs_p2p_rel_cr_fifo_elem),
									     &p2p_consumers[i].peer_cr_fifo.buf_dma_addr,
									     GFP_KERNEL);
		if (p2p_consumers[i].peer_cr_fifo.buf_vaddr == NULL) {
			sph_log_err(GENERAL_LOG, "couldn't allocate memory\n");
			rc = -ENOMEM;
			goto err;
		}

		p2p_consumers[i].peer_cr_fifo.llis = kcalloc(CR_FIFO_DEPTH, sizeof(struct lli_desc), GFP_KERNEL);
		if (p2p_consumers[i].peer_cr_fifo.llis == NULL) {
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

		fw_fifos[i].sgt->nents = dma_map_sg(sphcs->hw_device,
						    fw_fifos[i].sgt->sgl,
						    fw_fifos[i].sgt->orig_nents,
						    DMA_FROM_DEVICE);
		if (unlikely(!fw_fifos[i].sgt->nents)) {
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

		rel_fifos[i].sgt->nents = dma_map_sg(sphcs->hw_device,
						     rel_fifos[i].sgt->sgl,
						     rel_fifos[i].sgt->orig_nents,
						     DMA_FROM_DEVICE);
		if (unlikely(!rel_fifos[i].sgt->nents)) {
			sph_log_err(GENERAL_LOG, "Failed to map rel fifo\n");
			goto err;
		}

	}

	/* Create LLI templates */
	rc = sphcs_p2p_create_lli_templates(sphcs);
	if (rc) {
		sph_log_err(GENERAL_LOG, "Failed to create lli templates\n");
		goto err;
	}

	return 0;

err:
	sphcs_p2p_fini(sphcs);
	return rc;
}

void sphcs_p2p_fini(struct sphcs *sphcs)
{
	u32 i;

	_sphcs_p2p_remove_lli_templates(sphcs, &producer_allocated_pages);
	_sphcs_p2p_remove_lli_templates(sphcs, &consumer_allocated_pages);

	for (i = 0; i < MAX_NUM_OF_P2P_DEVS; i++) {
		if (p2p_producers[i].peer_db.buf_vaddr) {
			dma_free_coherent(sphcs->hw_device,
					  1,
					  p2p_producers[i].peer_db.buf_vaddr,
					  p2p_producers[i].peer_db.buf_dma_addr);
			p2p_producers[i].peer_db.buf_vaddr = NULL;
		}

		if (p2p_producers[i].peer_cr_fifo.buf_vaddr) {
			dma_free_coherent(sphcs->hw_device,
					  p2p_producers[i].peer_cr_fifo.depth * p2p_producers[i].peer_cr_fifo.elem_size,
					  p2p_producers[i].peer_cr_fifo.buf_vaddr,
					  p2p_producers[i].peer_cr_fifo.buf_dma_addr);
			p2p_producers[i].peer_cr_fifo.buf_vaddr = NULL;
		}

		if (p2p_producers[i].peer_cr_fifo.llis)
			kzfree(p2p_producers[i].peer_cr_fifo.llis);

		if (p2p_consumers[i].peer_db.buf_vaddr) {
			dma_free_coherent(sphcs->hw_device,
					  1,
					  p2p_consumers[i].peer_db.buf_vaddr,
					  p2p_consumers[i].peer_db.buf_dma_addr);
			p2p_consumers[i].peer_db.buf_vaddr = NULL;
		}
		if (p2p_consumers[i].peer_cr_fifo.buf_vaddr) {
			dma_free_coherent(sphcs->hw_device,
					  p2p_consumers[i].peer_cr_fifo.depth * p2p_consumers[i].peer_cr_fifo.elem_size,
					  p2p_consumers[i].peer_cr_fifo.buf_vaddr,
					  p2p_consumers[i].peer_cr_fifo.buf_dma_addr);
			p2p_consumers[i].peer_cr_fifo.buf_vaddr = NULL;
		}

		if (p2p_consumers[i].peer_cr_fifo.llis)
			kzfree(p2p_consumers[i].peer_cr_fifo.llis);

		if (!IS_ERR_OR_NULL(fw_fifos[i].buf_handle)) {
			if (fw_fifos[i].sgt->nents)
				dma_unmap_sg(sphcs->hw_device,
					     fw_fifos[i].sgt->sgl,
					     fw_fifos[i].sgt->orig_nents,
					     DMA_FROM_DEVICE);
			ion_kbuf_free(fw_fifos[i].buf_handle);
			fw_fifos[i].buf_handle = NULL;
		}
		if (!IS_ERR_OR_NULL(rel_fifos[i].buf_handle)) {
			if (rel_fifos[i].sgt->nents)
				dma_unmap_sg(sphcs->hw_device,
					     rel_fifos[i].sgt->sgl,
					     rel_fifos[i].sgt->orig_nents,
					     DMA_FROM_DEVICE);
			ion_kbuf_free(rel_fifos[i].buf_handle);
			rel_fifos[i].buf_handle = NULL;
		}
	}

}
