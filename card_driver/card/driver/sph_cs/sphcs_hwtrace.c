/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/interrupt.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>
#include <linux/scatterlist.h>
#include <linux/sort.h>
#include <linux/spinlock.h>
#include <linux/dma-buf.h>
#include <linux/workqueue.h>
#include <asm-generic/getorder.h>


#include "sphcs_intel_th.h"
#include "sphcs_hwtrace.h"
#include "dma_page_pool.h"
#include "sphcs_cs.h"
#include "ipc_protocol.h"
#include "sph_hwtrace_protocol.h"
#include "sph_debug.h"
#include "sph_log.h"
#include "sphcs_dma_sched.h"
#include "sphcs_cmd_chan.h"
#include "sphcs_pcie.h"

#define BIT_SET(a)	(((uint32_t)(1))<<(a))


#define HWTRACE_STATE_HOST_RESOURCE_CLEANUP	BIT_SET(0)
#define HWTRACE_STATE_HOST_RESOURCE_BUSY	BIT_SET(1)
#define HWTRACE_STATE_NPK_RESOURCE_CLEANUP	BIT_SET(2)
#define HWTRACE_STATE_NPK_RESOURCE_BUSY		BIT_SET(3)

#define HWTRACE_STATE_NPK_RESOURCE_READY	BIT_SET(4)
#define HWTRACE_STATE_DMA_INFO_READY		BIT_SET(5)
#define HWTRACE_STATE_DMA_INFO_DIRTY		BIT_SET(6)
#define HWTRACE_STATE_RESOURCE_CLEANUP		BIT_SET(7)
#define HWTRACE_STATE_NO_CLEANUP_RESOURCE	BIT_SET(8)


#define SGT_NR_BLOCK 3
#define MSC_SW_TAG_LASTBLK	BIT(0)
#define MSC_SW_TAG_LASTWIN	BIT(1)




#define HWTRACE_STATE_RESOURCES_BUSY(flag)	((flag) & (HWTRACE_STATE_NPK_RESOURCE_BUSY | HWTRACE_STATE_HOST_RESOURCE_BUSY | HWTRACE_STATE_DMA_INFO_DIRTY))


//dtf channel config for dma engine
const struct sphcs_dma_desc g_dma_desc_c2h_dtf_nowait = {
	.dma_direction  = SPHCS_DMA_DIRECTION_CARD_TO_HOST,
	.dma_priority   = SPHCS_DMA_PRIORITY_DTF,
	.serial_channel = 0,
	.flags          = SPHCS_DMA_START_XFER_COMPLETION_NO_WAIT
};



//npk resource information
struct npk_res_info {
	struct sg_table *sgt;
	struct page	*pages;
	uint32_t	nr_pages;
};

//host resource information
struct host_res_info {
	//TODO: remove this when old UMD removed
	bool            chan_owned;
	uint32_t	resource_index;
	size_t		resource_size;
	struct		sg_table sgt;
};

//dma resource information
struct dma_res_info {
	struct			sg_table *sgt;
	struct page		*pages;
	uint32_t		nr_pages;
	struct lli_desc         lli;
	struct sphcs_dma_multi_xfer_handle multi_xfer_handle;
};


//dma resources information
struct sphcs_dma_res_info {
	struct list_head		node;
	struct host_res_info		*host_res;
	struct npk_res_info		*npk_res;
	struct dma_res_info		*dma_res;
	size_t				bytes_to_copy;
	uint32_t			state;
};

//structure contain information for new resource
struct sphcs_hwtrace_res_add_req {
	struct host_res_info *res_info;
	dma_addr_t card_dma_addr;
	page_handle card_dma_page_hndl;
	void *vptr;
};

enum SPH_HWTRACE_WORK_CMD_TYPE {
	SPH_HWTRACE_WORK_ADD_RESOURCE = 0,
	SPH_HWTRACE_WORK_STATE = 1
};

struct sphcs_add_resource_cmd {
	dma_addr_t descriptor_addr;
	u16 mapID;
	u32 resource_size;
};

struct sphcs_state_cmd {
	u16 subOpcode		: 5;
	u32 resource_index;
};

struct sphcs_hwtrace_cmd_work {
	struct work_struct		work;
	enum SPH_HWTRACE_WORK_CMD_TYPE	type;
	struct sphcs_add_resource_cmd	add_resource_cmd;
	struct sphcs_state_cmd		state_cmd;
	struct sphcs_cmd_chan		*chan;
};

/*
 * Multiblock/multiwindow block descriptor
 */
struct msc_block_desc {
	u32	sw_tag;
	u32	block_sz;
	u32	next_blk;
	u32	next_win;
	u32	res0[4];
	u32	hw_tag;
	u32	valid_dw;
	u32	ts_low;
	u32	ts_high;
	u32	res1[4];
} __packed;


void sphcs_hwtrace_wakeup_clients(void)
{
	struct sphcs_hwtrace_data *hw_tracing = &g_the_sphcs->hw_tracing;

	if (hw_tracing)
		wake_up(&hw_tracing->waitq);
}

int assign_npk_pages_from_pool(struct page **o_pages, size_t size)
{
	struct sphcs_hwtrace_data *hw_tracing = &g_the_sphcs->hw_tracing;
	int i;
	uint32_t page_count = DIV_ROUND_UP(size, PAGE_SIZE);

	if (page_count > hw_tracing->nr_pool_pages) {
		sph_log_err(HWTRACE_LOG, "Error: requested page allocation(%u) is higher then pool(%u)\n", page_count, hw_tracing->nr_pool_pages);
		return -ENOMEM;
	}

	for (i = 0; i < SPHCS_HWTRACING_MAX_POOL_LENGTH; i++) {
		if (!hw_tracing->mem_pool[i].used) {
			hw_tracing->mem_pool[i].used = true;
			*o_pages = hw_tracing->mem_pool[i].pages;
			return 0;
		}
	}

	return -EINVAL;

}

void free_npk_pages_pool_item(struct page *page)
{
	struct sphcs_hwtrace_data *hw_tracing = &g_the_sphcs->hw_tracing;
	int i;

	for (i = 0; i < SPHCS_HWTRACING_MAX_POOL_LENGTH; i++) {
		if (page == hw_tracing->mem_pool[i].pages) {
			hw_tracing->mem_pool[i].used = false;
			return;
		}
	}

}

int sphcs_hwtrace_create_sg_table_from_pages(struct page *pages,
					      uint32_t	nr_pages,
					      struct sg_table *sgt)
{
	struct scatterlist *current_sgl;
	int ret;

	ret = sg_alloc_table(sgt, SGT_NR_BLOCK, GFP_NOWAIT);
	if (ret) {
		return ret;
	}

	// iterate over host's DMA address entries, and fill host sg_table
	// make sure we are not reading last entry, in a non-full page
	// make sure we are not reading more than one page
	current_sgl = sgt->sgl;

	sg_set_page(&(current_sgl[0]), &(pages[0]), (4) * PAGE_SIZE, 0);
	sg_set_page(&(current_sgl[1]), &(pages[54]), (nr_pages-54) * PAGE_SIZE, 0);
	sg_set_page(&(current_sgl[2]), &(pages[4]), (50) * PAGE_SIZE, 0);

	return 0;
}


void sphcs_hwtrace_cleanup_npk_resource(struct npk_res_info *npk)
{
	struct sphcs_hwtrace_data *hw_tracing = &g_the_sphcs->hw_tracing;
	struct device *ith_dma_device = hw_tracing->intel_th_device->parent->parent;

	dma_unmap_sg(ith_dma_device,
		     npk->sgt->sgl,
		     npk->sgt->orig_nents,
		     DMA_FROM_DEVICE);

	sg_free_table(npk->sgt);

	free_npk_pages_pool_item(npk->pages);

	kfree(npk->sgt);

	kfree(npk);
}

void sphcs_hwtrace_cleanup_host_resource(struct host_res_info *host)
{
	//TODO: remove this when old UMD removed
	if (!host->chan_owned)
		sg_free_table(&host->sgt);
	kfree(host);
}


void sphcs_hwtrace_cleanup_dma_info(struct dma_res_info *dma)
{
	dma_free_coherent(g_the_sphcs->hw_device,
			  dma->lli.size,
			  dma->lli.vptr,
			  dma->lli.dma_addr);

	dma_unmap_sg(g_the_sphcs->hw_device,
		     dma->sgt->sgl,
		     dma->sgt->orig_nents,
		     DMA_FROM_DEVICE);

	sg_free_table(dma->sgt);

	kfree(dma->sgt);

	kfree(dma);
}

struct dma_res_info *sphcs_hwtrace_alloc_dma_info(struct sphcs_dma_res_info *r)
{
	struct dma_res_info *dma;
	int ret = 0;
	size_t size;
	uint32_t max_segment;
	uint64_t transfer_size;

	dma = kzalloc(sizeof(*dma), GFP_NOWAIT);
	if (unlikely(dma == NULL)) {
		sph_log_err(HWTRACE_LOG, "Dma info allocation failed\n");
		return NULL;
	}

	dma->pages = r->npk_res->pages;
	dma->nr_pages = r->npk_res->nr_pages;

	dma->sgt = kzalloc(sizeof(*dma->sgt), GFP_NOWAIT);
	if (unlikely(dma->sgt == NULL)) {
		sph_log_err(HWTRACE_LOG, "unable to allocated sg table struct");
		goto cleanup_dma_res_info;
	}

	size = dma->nr_pages * sizeof(PAGE_SIZE);
	max_segment = size - PAGE_SIZE;

	//allocate sg table from NPK RES pages.
	ret = sphcs_hwtrace_create_sg_table_from_pages(dma->pages,
						       dma->nr_pages,
						       dma->sgt);
	if (ret) {
		sph_log_err(HWTRACE_LOG, "fail allocate sg_table from pages - %d", ret);
		goto cleanup_sg_table;
	}

	//map allocated sg table to sphcs device - so it can use
	//pep for DMA
	ret = dma_map_sg(g_the_sphcs->hw_device,
			 dma->sgt->sgl,
			 dma->sgt->orig_nents,
			 DMA_FROM_DEVICE);
	if (unlikely(ret < 0)) {
		sph_log_err(HWTRACE_LOG, "fail map sgl - %d\n", ret);
		goto cleanup_sgt;
	}

	dma->sgt->nents = ret;

	//get required lli size for dma op
	ret = g_the_sphcs->hw_ops->dma.init_lli(g_the_sphcs->hw_handle,
						&dma->lli,
						dma->sgt,
						&(r->host_res->sgt), 0);
	if (ret != 0 || dma->lli.size == 0) {
		sph_log_err(HWTRACE_LOG, "failed to init lli buffer\n");
		goto cleanup_dma_map;
	}

	// allocate memory in size lli_size
	dma->lli.vptr =
		dma_alloc_coherent(g_the_sphcs->hw_device,
				   dma->lli.size,
				   &dma->lli.dma_addr,
				   GFP_NOWAIT);
	if (!dma->lli.vptr) {
		sph_log_err(HWTRACE_LOG, "failed to allocate lli buffer\n");
		goto cleanup_dma_map;
	}

	//generate lli
	transfer_size = g_the_sphcs->hw_ops->dma.gen_lli(g_the_sphcs->hw_handle,
					 dma->sgt,
					 &(r->host_res->sgt),
					 &dma->lli,
					 0);
	SPH_ASSERT(transfer_size > 0);
	if (unlikely(transfer_size == 0)) {
		sph_log_err(HWTRACE_LOG, "gen_lli returned 0\n");
		goto cleanup_dma_map;
	}

	sphcs_dma_multi_xfer_handle_init(&dma->multi_xfer_handle);

	r->dma_res = dma;

	r->state &= ~HWTRACE_STATE_DMA_INFO_DIRTY;

	r->state |= HWTRACE_STATE_DMA_INFO_READY;

	return dma;

cleanup_dma_map:
	dma_unmap_sg(g_the_sphcs->hw_device,
		     dma->sgt->sgl,
		     dma->sgt->orig_nents,
		     DMA_FROM_DEVICE);
cleanup_sgt:
	sg_free_table(dma->sgt);
cleanup_sg_table:
	kfree(dma->sgt);
cleanup_dma_res_info:
	kfree(dma);

	return NULL;
}


void sphcs_hwtrace_update_state(void)
{
	struct sphcs_hwtrace_data *hw_tracing = &g_the_sphcs->hw_tracing;
	struct sphcs_dma_res_info *r, *tmp_r;
	unsigned long flags;
	struct dma_res_info *dma = NULL;
	struct npk_res_info *npk = NULL;
	struct host_res_info *host = NULL;
	bool bCleanup = true;
	struct sphcs_dma_res_info *clean_r = NULL;

	while (bCleanup) {
		SPH_SPIN_LOCK_IRQSAVE(&hw_tracing->lock_irq, flags);

		bCleanup = false;

		dma = NULL;
		npk = NULL;
		host = NULL;
		clean_r = NULL;

		list_for_each_entry_safe(r, tmp_r,
					 &hw_tracing->dma_stream_list,
					 node) {
			//check if it is possible to detach npk resource
			if (r->state & HWTRACE_STATE_NPK_RESOURCE_CLEANUP &&
			    !(r->state & HWTRACE_STATE_NPK_RESOURCE_BUSY) &&
			    !(r->state & HWTRACE_STATE_NO_CLEANUP_RESOURCE)) {
				npk = r->npk_res;
				r->npk_res = NULL;
				bCleanup = true;
				r->state &= ~HWTRACE_STATE_NPK_RESOURCE_CLEANUP;
			}

			//check if it is possible to detach npk resource
			if (r->state & HWTRACE_STATE_HOST_RESOURCE_CLEANUP &&
			    !(r->state & HWTRACE_STATE_NPK_RESOURCE_BUSY) &&
			    !(r->state & HWTRACE_STATE_NO_CLEANUP_RESOURCE)) {
				host = r->host_res;
				r->host_res = NULL;
				bCleanup = true;
				r->state &= ~HWTRACE_STATE_HOST_RESOURCE_CLEANUP;
			}

			//check if it is possible to detach dma binding resource
			if (r->state & HWTRACE_STATE_DMA_INFO_DIRTY &&
			    !(r->state & HWTRACE_STATE_NPK_RESOURCE_BUSY) &&
			    r->dma_res) {
				dma = r->dma_res;
				r->dma_res = NULL;
				bCleanup = true;
				r->state &= ~HWTRACE_STATE_DMA_INFO_DIRTY;
			}

			//check if it is possible to detach resources container
			if (r->host_res == NULL &&
			    r->npk_res == NULL &&
			    r->dma_res == NULL) {
				list_del(&r->node);
				clean_r = r;
				bCleanup = true;
			} else if (!r->dma_res && r->npk_res && r->host_res &&
				   !(r->state & HWTRACE_STATE_NO_CLEANUP_RESOURCE)) {
				//in case no dma binding resource available -
				//need to disable removal of npk and host resource
				//until new dma binding resource is added
				r->state |= HWTRACE_STATE_NO_CLEANUP_RESOURCE;
				bCleanup = true;
			}

			if (bCleanup)
				break;
		}

		SPH_SPIN_UNLOCK_IRQRESTORE(&hw_tracing->lock_irq, flags);

		//in case of update, in loop - need to modifiy detached resources.
		if (bCleanup) {
			//clean dma binding resource
			if (dma)
				sphcs_hwtrace_cleanup_dma_info(dma);

			//clean npk resource
			if (npk)
				sphcs_hwtrace_cleanup_npk_resource(npk);

			//clean host resource
			if (host)
				sphcs_hwtrace_cleanup_host_resource(host);

			//in case need to bind npk resource
			if (r  &&
			    r->state & HWTRACE_STATE_NO_CLEANUP_RESOURCE) {

				dma = sphcs_hwtrace_alloc_dma_info(r);
				if (dma) {
					SPH_SPIN_LOCK_IRQSAVE(&hw_tracing->lock_irq, flags);

					r->dma_res = dma;
					r->state &= ~HWTRACE_STATE_NO_CLEANUP_RESOURCE;

					SPH_SPIN_UNLOCK_IRQRESTORE(&hw_tracing->lock_irq, flags);
				}
			}

			//try to clean resources container
			kfree(clean_r);
		}

	}
}

static void sphcs_hwtrace_window_header_cleanup(struct npk_res_info *r)
{
	struct scatterlist *sg;
	unsigned int blk;

	for_each_sg(r->sgt->sgl, sg, SGT_NR_BLOCK, blk) {
		struct msc_block_desc *bdesc = sg_virt(sg);
		u32 next_win = bdesc->next_win;
		u32 next_blk = bdesc->next_blk;
		u32 sw_tag = bdesc->sw_tag;

		if (sw_tag & MSC_SW_TAG_LASTBLK)
			sw_tag = MSC_SW_TAG_LASTBLK;
		else
			sw_tag = 0x0;

		memset(bdesc, 0, sizeof(*bdesc));

		bdesc->next_win = next_win;
		bdesc->next_blk = next_blk;
		bdesc->sw_tag	= sw_tag;
		bdesc->block_sz = sg->length / 64;
	}
}

//callback from dma engine when NPK resource to host copy via pep ended
static int sphcs_hwtrace_dma_stream_complete_cb(struct sphcs *sphcs, void *ctx, const void *user_data, int status, u32 timeUS)
{
	struct sphcs_hwtrace_data *hw_tracing = &sphcs->hw_tracing;
	struct sphcs_cmd_chan *chan = hw_tracing->chan;
	struct sphcs_dma_res_info *r = (struct sphcs_dma_res_info *)ctx;
	unsigned long flags;
	union c2h_ChanHwTraceState chan_response_msg;
	int hwtrace_err = SPH_HWTRACE_ERR_NO_ERR;
	bool bIsLast = true;
	int index = -1;
	uint32_t bytes = 0;

	SPH_ASSERT(r != NULL);


	//release npk resource
	if (hw_tracing->intel_th_device && r->npk_res) {
		sphcs_hwtrace_window_header_cleanup(r->npk_res);

		sphcs_intel_th_window_unlock(hw_tracing->intel_th_device,
					     r->npk_res->sgt);
	}

	//update resource state.
	SPH_SPIN_LOCK_IRQSAVE(&hw_tracing->lock_irq, flags);

	r->state &= ~HWTRACE_STATE_NPK_RESOURCE_BUSY;

	hw_tracing->requests_in_flight--;
	hw_tracing->npk_resources_ready--;

	if (r->host_res) {
		index = r->host_res->resource_index;
		if (hw_tracing->requests_in_flight != 0 ||
		    hw_tracing->npk_resources_ready != 0 ||
		    !(g_the_sphcs->hw_tracing.hwtrace_status == SPHCS_HWTRACE_DEACTIVATED))
			bIsLast = false;
	}

	if (bIsLast)
		sphcs_dma_sched_reserve_channel_for_dtf(g_the_sphcs->dmaSched, false);

	bytes = r->bytes_to_copy;

	SPH_SPIN_UNLOCK_IRQRESTORE(&hw_tracing->lock_irq, flags);

	//if status != 0 report error to host
	if (status != SPHCS_DMA_STATUS_DONE) {
		if (r->host_res) {
			sph_log_err(HWTRACE_LOG, "hwtrace dma failed for resource number %d\n",
				    r->host_res->resource_index);
		} else {
			sph_log_err(HWTRACE_LOG, "hwtrace dma failed for resource unknown\n");
		}

		return -EINVAL;
	}

	//send notification to host that resource is ready for read.
	memset(chan_response_msg.value, 0x0, sizeof(chan_response_msg.value));

	chan_response_msg.chanID	= chan->protocolID;
	chan_response_msg.opcode	= SPH_IPC_C2H_OP_CHAN_HWTRACE_STATE;

	//in case of last resource, set appropriate sub_opcode
	if (bIsLast)
		chan_response_msg.subOpcode = HWTRACE_LAST_RESOURCE_READY;
	else
		chan_response_msg.subOpcode = HWTRACE_RESOURCE_READY;

	chan_response_msg.val1	= bytes;
	chan_response_msg.val2	= index;
	chan_response_msg.err	= hwtrace_err;

	sphcs_msg_scheduler_queue_add_msg(chan->respq, chan_response_msg.value, 2);

	return 0;
}

//function handle streaming NPK resource to host
void do_stream_hwtrace(struct sphcs_dma_res_info *r)
{
	int ret;
	struct sphcs_hwtrace_data *hw_tracing = &g_the_sphcs->hw_tracing;

	SPH_ASSERT(r != NULL);
	if (unlikely(r == NULL))
		return;

	if (!r->host_res || !r->npk_res || !r->dma_res)
		return;

	if (HWTRACE_STATE_RESOURCES_BUSY(r->state))
		return;

	//if there is no NPK RESOURCE ready - no need to send dma to host
	if (!(r->state & HWTRACE_STATE_NPK_RESOURCE_READY))
		return;

	//remove NPK RESOURCE READY, and change to NPK RESOURCE BUSY
	r->state &= ~HWTRACE_STATE_NPK_RESOURCE_READY;

	//set NPK RESOURCE BUSY and HOST RESOURCE BUSY during dma
	//once dma is completed npk resource busy is unset
	//host resource busy is unset after unlock from host
	r->state |= (HWTRACE_STATE_NPK_RESOURCE_BUSY |
		     HWTRACE_STATE_HOST_RESOURCE_BUSY);

	hw_tracing->requests_in_flight++;

	//now we start dma transaction from card to host.
	ret = sphcs_dma_sched_start_xfer_multi(g_the_sphcs->dmaSched,
					       &r->dma_res->multi_xfer_handle,
					       &g_dma_desc_c2h_dtf_nowait,
					       &r->dma_res->lli,
					       r->host_res->resource_size,
					       sphcs_hwtrace_dma_stream_complete_cb,
					       r);
	if (ret)
		sph_log_err(HWTRACE_LOG, "dma from card to host failed\n err = %d", ret);

}


void *intel_th_assign_mode(struct device *intel_th_dev, int *mode)
{
	struct sphcs_hwtrace_data *hw_tracing = &g_the_sphcs->hw_tracing;

	sphcs_assign_intel_th_mode(mode);

	//increment reference count for device.
	hw_tracing->intel_th_device = get_device(intel_th_dev);

	return hw_tracing;
}

void intel_th_unassign(void *priv)
{
	struct sphcs_hwtrace_data *hw_tracing = (struct sphcs_hwtrace_data *)priv;

	//decrement reference count for intel_th device
	put_device(hw_tracing->intel_th_device);
	hw_tracing->intel_th_device = NULL;
}

int intel_th_alloc_window(void *priv, struct sg_table **sgt, size_t size)
{
	struct sphcs_hwtrace_data *hw_tracing = (struct sphcs_hwtrace_data *)priv;
	struct sphcs_dma_res_info *r;
	struct npk_res_info *npk;
	int ret = 0;
	unsigned long flags;
	bool bFound = false;
	uint32_t max_segment;
	struct device *ith_dma_device = hw_tracing->intel_th_device->parent->parent;

	if (size == 0)
		return -EINVAL;

	npk = kzalloc(sizeof(*npk), GFP_NOWAIT);
	if (unlikely(npk == NULL)) {
		ret = -ENOMEM;
		goto err;
	}

	npk->sgt = kzalloc(sizeof(*npk->sgt), GFP_NOWAIT);
	if (unlikely(npk->sgt == NULL)) {
		ret = -ENOMEM;
		goto cleanup_npk_res_info;
	}

	ret = assign_npk_pages_from_pool(&npk->pages, size);
	if (ret)
		goto cleanup_npk_sgt;

	max_segment = size - PAGE_SIZE;
	npk->nr_pages = DIV_ROUND_UP(size, PAGE_SIZE);

	ret = sphcs_hwtrace_create_sg_table_from_pages(npk->pages,
						       npk->nr_pages,
						       npk->sgt);
	if (ret) {
		sph_log_err(HWTRACE_LOG, "fail allocate table from pages - %d", ret);
		goto cleanup_pages;
	}

	ret = dma_map_sg(ith_dma_device,
			 npk->sgt->sgl,
			 npk->sgt->orig_nents,
			 DMA_FROM_DEVICE);
	if (unlikely(ret < 0)) {
		sph_log_err(HWTRACE_LOG, "fail map sgl - %d", ret);
		goto cleanup_sgt;
	}

	npk->sgt->nents = ret;

	*sgt = npk->sgt;

	SPH_SPIN_LOCK_IRQSAVE(&hw_tracing->lock_irq, flags);

	list_for_each_entry(r,
			    &hw_tracing->dma_stream_list,
			    node) {
		if (r->npk_res == NULL &&
		    !(r->state & HWTRACE_STATE_HOST_RESOURCE_CLEANUP)) {
			bFound = true;
			r->npk_res = npk;
			r->state |= HWTRACE_STATE_DMA_INFO_DIRTY;
			break;
		}
	}

	SPH_SPIN_UNLOCK_IRQRESTORE(&hw_tracing->lock_irq, flags);

	if (!bFound) {
		r = kzalloc(sizeof(*r), GFP_NOWAIT);
		if (unlikely(r == NULL)) {
			ret = -ENOMEM;
			goto cleanup_dma_map_sg;
		}

		r->npk_res = npk;

		r->state |= HWTRACE_STATE_DMA_INFO_DIRTY;

		SPH_SPIN_LOCK_IRQSAVE(&hw_tracing->lock_irq, flags);

		list_add_tail(&r->node, &hw_tracing->dma_stream_list);

		SPH_SPIN_UNLOCK_IRQRESTORE(&hw_tracing->lock_irq, flags);
	}

	sphcs_hwtrace_update_state();

	return ret;

cleanup_dma_map_sg:
	dma_unmap_sg(ith_dma_device,
		     npk->sgt->sgl,
		     npk->sgt->orig_nents,
		     DMA_FROM_DEVICE);
cleanup_sgt:
	sg_free_table(npk->sgt);
cleanup_pages:
	free_npk_pages_pool_item(npk->pages);
	kfree(npk->pages);
cleanup_npk_sgt:
	kfree(npk->sgt);
cleanup_npk_res_info:
	kfree(npk);
err:

	return ret;
}

void intel_th_free_window(void *priv, struct sg_table *sgt)
{
	struct sphcs_hwtrace_data *hw_tracing = (struct sphcs_hwtrace_data *)priv;
	struct sphcs_dma_res_info *r;
	unsigned long flags;
	bool bFound = false;

	SPH_SPIN_LOCK_IRQSAVE(&hw_tracing->lock_irq, flags);

	list_for_each_entry(r,
			    &hw_tracing->dma_stream_list,
			    node) {
		if (r->npk_res &&
		    r->npk_res->sgt == sgt) {
			bFound = true;
			r->state |= (HWTRACE_STATE_DMA_INFO_DIRTY |
				     HWTRACE_STATE_NPK_RESOURCE_CLEANUP);
			r->state &= ~HWTRACE_STATE_NPK_RESOURCE_READY;
			break;
		}
	}

	SPH_SPIN_UNLOCK_IRQRESTORE(&hw_tracing->lock_irq, flags);

	sphcs_hwtrace_update_state();
}

void intel_th_activate(void *priv)
{
	struct sphcs_hwtrace_data *hw_tracing = (struct sphcs_hwtrace_data *)priv;
	struct sphcs_dma_res_info *r;


	if (g_the_sphcs->hw_tracing.hwtrace_status == SPHCS_HWTRACE_REGISTERED) {
		sph_log_err(HWTRACE_LOG, "callback request, but trace was not initialized\n");
		return;
	}

	sphcs_dma_sched_reserve_channel_for_dtf(g_the_sphcs->dmaSched, true);

	list_for_each_entry(r,
			    &hw_tracing->dma_stream_list,
			    node) {
		if (r->npk_res)
			sphcs_hwtrace_window_header_cleanup(r->npk_res);
	}


	g_the_sphcs->hw_tracing.hwtrace_status = SPHCS_HWTRACE_ACTIVATED;
}

//callback from intel trace hub driver
// notification when trace stopped
void intel_th_deactivate(void *priv)
{
	if (g_the_sphcs->hw_tracing.hwtrace_status == SPHCS_HWTRACE_REGISTERED) {
		sph_log_err(HWTRACE_LOG, "callback request, but trace was not initialized\n");
		return;
	}


	g_the_sphcs->hw_tracing.hwtrace_status = SPHCS_HWTRACE_DEACTIVATED;
}

//callback from intel trace hub driver when window - sgl is ready with content
//and can sent data to host.
int intel_th_window_ready(void *priv, struct sg_table *sgt, size_t bytes)
{
	struct sphcs_hwtrace_data *hw_tracing = (struct sphcs_hwtrace_data *)priv;
	unsigned long flags;
	struct sphcs_dma_res_info *r;
	bool bFound = false;


	//print debug log everytime a new window is ready.
	if (g_the_sphcs->hw_tracing.hwtrace_status == SPHCS_HWTRACE_REGISTERED) {
		sph_log_info(HWTRACE_LOG, "trace activated request, but trace was not initialized\n");
		return 0;
	}

	SPH_SPIN_LOCK_IRQSAVE(&hw_tracing->lock_irq, flags);


	list_for_each_entry(r,
			    &hw_tracing->dma_stream_list,
			    node) {
		if (r->npk_res &&
		    r->npk_res->sgt == sgt) {
			bFound = true;
			r->state |= HWTRACE_STATE_NPK_RESOURCE_READY;
			r->bytes_to_copy = bytes;
			break;
		}
	}

	if (bFound) {
		hw_tracing->npk_resources_ready++;
		do_stream_hwtrace(r);
	}

	SPH_SPIN_UNLOCK_IRQRESTORE(&hw_tracing->lock_irq, flags);



	return 0;
}

void sphcs_hwtrace_cleanup_resources_request(struct sphcs *sphcs)
{
	struct sphcs_hwtrace_data *hw_tracing = &sphcs->hw_tracing;
	struct sphcs_cmd_chan *chan = hw_tracing->chan;
	union c2h_ChanHwTraceState chan_response_msg;
	struct sphcs_dma_res_info *r;
	unsigned long flags;

	SPH_SPIN_LOCK_IRQSAVE(&hw_tracing->lock_irq, flags);

	list_for_each_entry(r, &hw_tracing->dma_stream_list, node) {
		r->state |= (HWTRACE_STATE_DMA_INFO_DIRTY |
			     HWTRACE_STATE_HOST_RESOURCE_CLEANUP);
	}

	SPH_SPIN_UNLOCK_IRQRESTORE(&hw_tracing->lock_irq, flags);

	sphcs_hwtrace_update_state();

	memset(chan_response_msg.value, 0x0, sizeof(chan_response_msg));

	chan_response_msg.chanID	= chan->protocolID;
	chan_response_msg.opcode	= SPH_IPC_C2H_OP_CHAN_HWTRACE_STATE;
	chan_response_msg.subOpcode	= HWTRACE_RESOURCE_CLEANUP;
	chan_response_msg.err		= SPH_HWTRACE_ERR_NO_ERR;

	sphcs_msg_scheduler_queue_add_msg(chan->respq, chan_response_msg.value, 2);

	hw_tracing->chan = NULL;
}

int sphcs_hwtrace_init(struct sphcs *sphcs, struct sphcs_cmd_chan *chan)
{
	struct sphcs_hwtrace_data *hw_tracing = &sphcs->hw_tracing;
	int hwtrace_err = SPH_HWTRACE_ERR_NO_ERR;
	union c2h_ChanHwTraceState chan_response_msg;
	unsigned long flags;
	struct sphcs_dma_res_info *r;

	if (hw_tracing->hwtrace_status == SPHCS_HWTRACE_NOT_SUPPORTED) {
		hwtrace_err = SPH_HWTRACE_ERR_INTEL_TH_REG;
		sph_log_err(HWTRACE_LOG, "unable to initialize hwtrace service err\n");
		goto reply_message;

	}

	hw_tracing->chan = chan;

	SPH_SPIN_LOCK_IRQSAVE(&hw_tracing->lock_irq, flags);

	list_for_each_entry(r, &hw_tracing->dma_stream_list, node) {
		r->state |= (HWTRACE_STATE_DMA_INFO_DIRTY |
			     HWTRACE_STATE_HOST_RESOURCE_CLEANUP);
		r->state &= ~HWTRACE_STATE_HOST_RESOURCE_BUSY;
	}

	hw_tracing->host_resource_count = 0;

	SPH_SPIN_UNLOCK_IRQRESTORE(&hw_tracing->lock_irq, flags);

	sphcs_hwtrace_update_state();

	hw_tracing->requests_in_flight = 0;
	hw_tracing->npk_resources_ready = 0;
	hw_tracing->hwtrace_status = SPHCS_HWTRACE_INITIALIZED;

reply_message:
	memset(chan_response_msg.value, 0x0, sizeof(chan_response_msg.value));

	chan_response_msg.chanID	= chan->protocolID;
	chan_response_msg.opcode	= SPH_IPC_C2H_OP_CHAN_HWTRACE_STATE;
	chan_response_msg.subOpcode	= HWTRACE_INIT;
	chan_response_msg.err	= hwtrace_err;

	sphcs_msg_scheduler_queue_add_msg(chan->respq, chan_response_msg.value, 2);

	return 0;
}


int sphcs_hwtrace_deinit(struct sphcs *sphcs)
{
	struct sphcs_hwtrace_data *hw_tracing = &sphcs->hw_tracing;
	struct sphcs_cmd_chan *chan = hw_tracing->chan;
	int hwtrace_err = SPH_HWTRACE_ERR_NO_ERR;
	union c2h_ChanHwTraceState chan_response_msg;
	struct sphcs_dma_res_info *r;
	unsigned long flags;

	if (hw_tracing->hwtrace_status == SPHCS_HWTRACE_NOT_SUPPORTED) {
		hwtrace_err = SPH_HWTRACE_ERR_INTEL_TH_REG;
		sph_log_err(HWTRACE_LOG, "unable to deinit hwtrace service err\n");
		goto reply_message;
	}


	SPH_SPIN_LOCK_IRQSAVE(&hw_tracing->lock_irq, flags);

	list_for_each_entry(r, &hw_tracing->dma_stream_list, node) {
		r->state |= (HWTRACE_STATE_DMA_INFO_DIRTY |
			     HWTRACE_STATE_HOST_RESOURCE_CLEANUP);
		r->state &= ~HWTRACE_STATE_HOST_RESOURCE_BUSY;
	}


	SPH_SPIN_UNLOCK_IRQRESTORE(&hw_tracing->lock_irq, flags);

	sphcs_hwtrace_update_state();

	hw_tracing->hwtrace_status = SPHCS_HWTRACE_REGISTERED;

reply_message:

	memset(chan_response_msg.value, 0x0, sizeof(chan_response_msg.value));

	chan_response_msg.chanID	= chan->protocolID;
	chan_response_msg.opcode	= SPH_IPC_C2H_OP_CHAN_HWTRACE_STATE;
	chan_response_msg.subOpcode	= HWTRACE_DEINIT;
	chan_response_msg.err	= hwtrace_err;

	sphcs_msg_scheduler_queue_add_msg(chan->respq, chan_response_msg.value, 2);

	return 0;
}

void sphcs_hwtrace_unlock_host_res(struct sphcs *sphcs,
				   uint32_t resource_index)
{
	struct sphcs_hwtrace_data *hw_tracing = &sphcs->hw_tracing;
	struct sphcs_cmd_chan *chan = hw_tracing->chan;
	union c2h_ChanHwTraceState chan_response_msg;
	unsigned long flags;
	int hwtrace_err = SPH_HWTRACE_ERR_NO_ERR;
	bool bFound = false;
	struct sphcs_dma_res_info *r;


	if (resource_index >= hw_tracing->host_resource_count) {
		sph_log_err(HWTRACE_LOG, "bad resource index to unlock\n");
		hwtrace_err = SPH_HWTRACE_ERR_INVALID_VALUE;
		goto reply_message;
	}

	sphcs_hwtrace_update_state();

	SPH_SPIN_LOCK_IRQSAVE(&hw_tracing->lock_irq, flags);

	list_for_each_entry(r,
			    &hw_tracing->dma_stream_list,
			    node) {
		if (r->host_res &&
		    r->host_res->resource_index == resource_index) {
			bFound = true;
			r->state &= ~HWTRACE_STATE_HOST_RESOURCE_BUSY;
			break;
		}
	}

	if (bFound)
		do_stream_hwtrace(r);


	SPH_SPIN_UNLOCK_IRQRESTORE(&hw_tracing->lock_irq, flags);


reply_message:
	memset(chan_response_msg.value, 0x0, sizeof(chan_response_msg.value));

	chan_response_msg.chanID	= chan->protocolID;
	chan_response_msg.opcode	= SPH_IPC_C2H_OP_CHAN_HWTRACE_STATE;
	chan_response_msg.subOpcode	= HWTRACE_UNLOCK_RESOURCE;
	chan_response_msg.val1		= resource_index;
	chan_response_msg.err		= hwtrace_err;

	sphcs_msg_scheduler_queue_add_msg(chan->respq, chan_response_msg.value, 2);
}

void sphcs_hwtrace_query_state(struct sphcs *sphcs, struct sphcs_cmd_chan *chan)
{
	struct sphcs_hwtrace_data *hw_tracing = &sphcs->hw_tracing;
	union c2h_ChanHwTraceState chan_response_msg;

	memset(chan_response_msg.value, 0x0, sizeof(chan_response_msg.value));

	chan_response_msg.chanID	= chan->protocolID;
	chan_response_msg.opcode	= SPH_IPC_C2H_OP_CHAN_HWTRACE_STATE;
	chan_response_msg.subOpcode	= HWTRACE_QUERY_STATE;
	chan_response_msg.val1	= hw_tracing->hwtrace_status;
	chan_response_msg.val2	= hw_tracing->host_resource_count;
	chan_response_msg.val3	= hw_tracing->resource_max_size;

	sphcs_msg_scheduler_queue_add_msg(chan->respq, chan_response_msg.value, 2);
}

void sphcs_hwtrace_query_mem_pool_info(struct sphcs *sphcs, struct sphcs_cmd_chan *chan)
{
	struct sphcs_hwtrace_data *hw_tracing = &sphcs->hw_tracing;
	union c2h_ChanHwTraceState chan_response_msg;

	memset(chan_response_msg.value, 0x0, sizeof(chan_response_msg.value));

	chan_response_msg.chanID	= chan->protocolID;
	chan_response_msg.opcode	= SPH_IPC_C2H_OP_CHAN_HWTRACE_STATE;
	chan_response_msg.subOpcode	= HWTRACE_GET_MEM_POOL_INFO;
	chan_response_msg.val1		= hw_tracing->nr_pool_pages;
	chan_response_msg.val2		= SPHCS_HWTRACING_MAX_POOL_LENGTH;

	sphcs_msg_scheduler_queue_add_msg(chan->respq, chan_response_msg.value, 2);
}

void sphcs_hwtrace_add_resource_2(struct sphcs *sphcs,
				struct sphcs_add_resource_cmd *res_data)
{
	struct sphcs_hwtrace_data *hw_tracing = &sphcs->hw_tracing;
	struct sphcs_cmd_chan *chan = hw_tracing->chan;
	struct sphcs_hostres_map *hostres_map;
	int hwtrace_err = SPH_HWTRACE_ERR_NO_ERR;
	union c2h_ChanHwTraceState response_msg;
	struct sphcs_dma_res_info *r;
	struct host_res_info *res_info;
	unsigned long flags;
	bool bFound = false;

	hostres_map = sphcs_cmd_chan_find_hostres(chan, res_data->mapID);
	if (!hostres_map) {
		sph_log_err(HWTRACE_LOG, "Fail to find host res map channel (%u) res map id (%u)\n", chan->protocolID, res_data->mapID);
		hwtrace_err = SPH_HWTRACE_ERR_ADD_RESOURCE_FAIL;
		goto reply_message;
	}

	switch (hw_tracing->hwtrace_status) {
	case SPHCS_HWTRACE_INITIALIZED:
	case SPHCS_HWTRACE_ASIGNED:
	case SPHCS_HWTRACE_DEACTIVATED:
		break;
	default:
		hwtrace_err = SPH_HWTRACE_ERR_INVALID_OPCODE;
		sph_log_err(HWTRACE_LOG, "add resource request in a bad state\n");
		goto reply_message;
	}

	//allocate new resource info.
	res_info = kzalloc(sizeof(*res_info), GFP_KERNEL);
	if (unlikely(res_info == NULL)) {
		sph_log_err(HWTRACE_LOG, "allocation failed\n");
		hwtrace_err = SPH_HWTRACE_ERR_NO_MEMORY;
		goto reply_message;
	}

	res_info->sgt = hostres_map->host_sgt;
	res_info->resource_size = hostres_map->size;
	//TODO: remove this when old UMD removed
	res_info->chan_owned = true;

	SPH_SPIN_LOCK_IRQSAVE(&hw_tracing->lock_irq, flags);

	list_for_each_entry(r,
			    &hw_tracing->dma_stream_list,
			    node) {
		if (r->host_res == NULL &&
		    ~(r->state & HWTRACE_STATE_NPK_RESOURCE_CLEANUP)) {
			bFound = true;
			r->host_res = res_info;
			r->state |= HWTRACE_STATE_DMA_INFO_DIRTY;
			break;
		}
	}

	SPH_SPIN_UNLOCK_IRQRESTORE(&hw_tracing->lock_irq, flags);


	if (!bFound) {
		r = kzalloc(sizeof(*r), GFP_NOWAIT);
		if (unlikely(r == NULL)) {
			hwtrace_err = SPH_HWTRACE_ERR_NO_MEMORY;
			kfree(res_info);
			goto reply_message;
		}

		r->state |= HWTRACE_STATE_DMA_INFO_DIRTY;
		r->host_res = res_info;

		SPH_SPIN_LOCK_IRQSAVE(&hw_tracing->lock_irq, flags);

		res_info->resource_index = hw_tracing->host_resource_count++;
		list_add_tail(&r->node, &hw_tracing->dma_stream_list);

		SPH_SPIN_UNLOCK_IRQRESTORE(&hw_tracing->lock_irq, flags);
	}

	sphcs_hwtrace_update_state();

reply_message:

	memset(response_msg.value, 0x0, sizeof(response_msg.value));

	response_msg.chanID     = chan->protocolID;
	response_msg.opcode	= SPH_IPC_C2H_OP_CHAN_HWTRACE_STATE;
	response_msg.subOpcode	= HWTRACE_ADD_RESOURCE;
	response_msg.err	= hwtrace_err;

	sphcs_msg_scheduler_queue_add_msg(chan->respq, response_msg.value, 2);

	return;
}

static void cleanup_hwtrace(struct sphcs_cmd_chan *chan, void *cb_ctx)
{
	struct sphcs *sphcs = (struct sphcs *)cb_ctx;

	sphcs_hwtrace_deinit(sphcs);
	sphcs_hwtrace_cleanup_resources_request(sphcs);
}

void sphcs_hwtrace_state(struct sphcs *sphcs,
				struct sphcs_state_cmd	*state_cmd,
				struct sphcs_cmd_chan	*chan)
{
	union c2h_ChanHwTraceState chan_response_msg;
	struct sphcs_hwtrace_data *hw_tracing = &sphcs->hw_tracing;
	int hwtrace_err = SPH_HWTRACE_ERR_NO_ERR;

	if (hw_tracing->hwtrace_status == SPHCS_HWTRACE_NOT_SUPPORTED) {
		hwtrace_err = SPH_HWTRACE_ERR_INTEL_TH_REG;
		goto reply_message;
	}

	switch (state_cmd->subOpcode) {
	case HWTRACE_INIT:
		sphcs_hwtrace_init(sphcs, chan);
		if (chan && hw_tracing->hwtrace_status == SPHCS_HWTRACE_INITIALIZED) {
			chan->destroy_cb = cleanup_hwtrace;
			chan->destroy_cb_ctx = sphcs;
		}
		break;
	case HWTRACE_DEINIT:
		if (chan) {
			if (!hw_tracing->chan || (chan->protocolID !=  hw_tracing->chan->protocolID)) {
				sph_log_err(HWTRACE_LOG, "Err: Deinit Invalid channel\n");
				hwtrace_err = SPH_HWTRACE_ERR_INVALID_VALUE;
				goto reply_message;
			}
		}
		sphcs_hwtrace_deinit(sphcs);
		break;
	case HWTRACE_RESOURCE_CLEANUP:
		if (chan) {
			if (!hw_tracing->chan || (chan->protocolID !=  hw_tracing->chan->protocolID)) {
				sph_log_err(HWTRACE_LOG, "Err: Deinit Invalid channel\n");
				hwtrace_err = SPH_HWTRACE_ERR_INVALID_VALUE;
				goto reply_message;
			}
		}
		sphcs_hwtrace_cleanup_resources_request(sphcs);
		if (chan) {
			chan->destroy_cb = NULL;
			chan->destroy_cb_ctx = NULL;
		}
		break;
	case HWTRACE_QUERY_STATE:
		sphcs_hwtrace_query_state(sphcs, chan);
		break;
	case HWTRACE_GET_MEM_POOL_INFO:
		sphcs_hwtrace_query_mem_pool_info(sphcs, chan);
		break;
	case HWTRACE_UNLOCK_RESOURCE:
		if (chan) {
			if (!hw_tracing->chan || (chan->protocolID !=  hw_tracing->chan->protocolID)) {
				sph_log_err(HWTRACE_LOG, "Err: Deinit Invalid channel\n");
				hwtrace_err = SPH_HWTRACE_ERR_INVALID_VALUE;
				goto reply_message;
			}
		}
		sphcs_hwtrace_unlock_host_res(sphcs, state_cmd->resource_index);
		break;
	default:
		hwtrace_err = SPH_HWTRACE_ERR_INVALID_OPCODE;
		goto reply_message;
	};

	return;
reply_message:
	memset(chan_response_msg.value, 0x0, sizeof(chan_response_msg.value));

	chan_response_msg.chanID	= chan->protocolID;
	chan_response_msg.opcode	= SPH_IPC_C2H_OP_CHAN_HWTRACE_STATE;
	chan_response_msg.subOpcode	= state_cmd->subOpcode;
	chan_response_msg.err	= hwtrace_err;

	sphcs_msg_scheduler_queue_add_msg(chan->respq, chan_response_msg.value, 2);
}

static void hwtrace_op_work_handler(struct work_struct *work)
{
	struct sphcs *sphcs = g_the_sphcs;
	struct sphcs_hwtrace_cmd_work *op = container_of(work,
							 struct sphcs_hwtrace_cmd_work,
							 work);

	switch (op->type) {
	case SPH_HWTRACE_WORK_ADD_RESOURCE:
		sphcs_hwtrace_add_resource_2(sphcs, &op->add_resource_cmd);
		break;
	case SPH_HWTRACE_WORK_STATE:
		sphcs_hwtrace_state(sphcs, &op->state_cmd, op->chan);
		break;
	};

	sphcs_cmd_chan_put(op->chan);
	kfree(op);
}

void IPC_OPCODE_HANDLER(CHAN_HWTRACE_ADD_RESOURCE)(struct sphcs *sphcs,
					      union h2c_ChanHwTraceAddResource *msg)
{
	struct sphcs_hwtrace_cmd_work *work;
	union c2h_ChanHwTraceState response_msg;
	struct sphcs_hwtrace_data *hw_tracing = &sphcs->hw_tracing;
	struct sphcs_cmd_chan *chan;
	int hwtrace_err = SPH_HWTRACE_ERR_NO_ERR;

	chan = sphcs_find_channel(sphcs, msg->chanID);
	if (!chan) {
		sph_log_err(HWTRACE_LOG, "Channel not found opcode=%d chanID=%d\n", msg->opcode, msg->chanID);
		return;
	}

	if ((!hw_tracing->chan) || (chan->protocolID != hw_tracing->chan->protocolID)) {
		sph_log_err(HWTRACE_LOG, "Err: add resource Invalid channel\n");
		hwtrace_err = SPH_HWTRACE_ERR_INVALID_VALUE;
		goto reply_err;
	}

	work = kzalloc(sizeof(*work), GFP_NOWAIT);
	if (unlikely(work == NULL)) {
		sph_log_err(HWTRACE_LOG, "unable to allocate hwtrace_cmd_work object\n");
		hwtrace_err = SPH_HWTRACE_ERR_NO_MEMORY;
		goto reply_err;
	}

	work->type = SPH_HWTRACE_WORK_ADD_RESOURCE;
	work->chan = chan;
	work->add_resource_cmd.resource_size = msg->resource_size;
	work->add_resource_cmd.mapID = msg->mapID;

	INIT_WORK(&work->work, hwtrace_op_work_handler);
	queue_work(chan->wq, &work->work);

	return;
reply_err:
	memset(response_msg.value, 0x0, sizeof(response_msg.value));

	response_msg.chanID	= msg->chanID;
	response_msg.opcode	= SPH_IPC_C2H_OP_CHAN_HWTRACE_STATE;
	response_msg.subOpcode	= HWTRACE_ADD_RESOURCE;
	response_msg.err	= hwtrace_err;

	sphcs_msg_scheduler_queue_add_msg(chan->respq, response_msg.value, 2);
	sphcs_cmd_chan_put(chan);
}

void IPC_OPCODE_HANDLER(CHAN_HWTRACE_STATE)(struct sphcs *sphcs,
				       union h2c_ChanHwTraceState *msg)
{
	struct sphcs_hwtrace_cmd_work *work;
	union c2h_ChanHwTraceState response_msg;
	struct sphcs_cmd_chan *chan;

	chan = sphcs_find_channel(sphcs, msg->chanID);
	if (!chan) {
		sph_log_err(HWTRACE_LOG, "Channel not found opcode=%d chanID=%d\n", msg->opcode, msg->chanID);
		return;
	}

	work = kzalloc(sizeof(*work), GFP_NOWAIT);
	if (unlikely(work == NULL)) {
		sph_log_err(HWTRACE_LOG, "unable to allocate hwtrace_cmd_work object\n");
		goto reply_err;
	}

	work->chan = chan;
	work->type = SPH_HWTRACE_WORK_STATE;
	work->state_cmd.subOpcode = msg->subOpcode;
	work->state_cmd.resource_index = msg->val;

	INIT_WORK(&work->work, hwtrace_op_work_handler);
	queue_work(chan->wq, &work->work);

	return;
reply_err:
	memset(response_msg.value, 0x0, sizeof(response_msg.value));

	response_msg.chanID	= msg->chanID;
	response_msg.opcode	= SPH_IPC_C2H_OP_CHAN_HWTRACE_STATE;
	response_msg.subOpcode	= msg->subOpcode;
	response_msg.err	= SPH_HWTRACE_ERR_NO_MEMORY;

	sphcs_msg_scheduler_queue_add_msg(chan->respq, response_msg.value, 2);
	sphcs_cmd_chan_put(chan);
}

static int debug_status_show(struct seq_file *m, void *v)
{
	struct sphcs_hwtrace_data *hw_tracing = m->private;
	unsigned long flags;
	struct sphcs_dma_res_info *r;
	uint32_t host_res_cleanup = 0, host_res_busy = 0,
		npk_res_cleanup = 0, npk_res_busy = 0,
		npk_res_ready = 0, dma_info_ready = 0,
		dma_info_dirty = 0, res_cleanup = 0,
		res_no_cleanup = 0, host_res_count = 0, dma_stream_list_count = 0;

	if (unlikely(hw_tracing == NULL))
		return -EINVAL;

	SPH_SPIN_LOCK_IRQSAVE(&hw_tracing->lock_irq, flags);

	seq_printf(m, "status %d\n", hw_tracing->hwtrace_status);

	list_for_each_entry(r,
			    &hw_tracing->dma_stream_list,
			    node) {
		if (r->state & HWTRACE_STATE_HOST_RESOURCE_CLEANUP)
			host_res_cleanup++;
		if (r->state & HWTRACE_STATE_HOST_RESOURCE_BUSY)
			host_res_busy++;
		if (r->state & HWTRACE_STATE_NPK_RESOURCE_CLEANUP)
			npk_res_cleanup++;
		if (r->state & HWTRACE_STATE_NPK_RESOURCE_BUSY)
			npk_res_busy++;
		if (r->state & HWTRACE_STATE_NPK_RESOURCE_READY)
			npk_res_ready++;
		if (r->state & HWTRACE_STATE_DMA_INFO_READY)
			dma_info_ready++;
		if (r->state & HWTRACE_STATE_DMA_INFO_DIRTY)
			dma_info_dirty++;
		if (r->state & HWTRACE_STATE_RESOURCE_CLEANUP)
			res_cleanup++;
		if (r->state & HWTRACE_STATE_NO_CLEANUP_RESOURCE)
			res_no_cleanup++;
		if (r->host_res)
			host_res_count++;
		dma_stream_list_count++;
	}

	seq_printf(m, "HWTRACE_STATE_HOST_RESOURCE_CLEANUP  %u\n", host_res_cleanup);
	seq_printf(m, "HWTRACE_STATE_HOST_RESOURCE_BUSY  %u\n", host_res_busy);
	seq_printf(m, "HWTRACE_STATE_NPK_RESOURCE_CLEANUP  %u\n", npk_res_cleanup);
	seq_printf(m, "HWTRACE_STATE_NPK_RESOURCE_BUSY  %u\n", npk_res_busy);
	seq_printf(m, "HWTRACE_STATE_NPK_RESOURCE_READY  %u\n", npk_res_ready);
	seq_printf(m, "HWTRACE_STATE_DMA_INFO_READY  %u\n", dma_info_ready);
	seq_printf(m, "HWTRACE_STATE_DMA_INFO_DIRTY  %u\n", dma_info_dirty);
	seq_printf(m, "HWTRACE_STATE_RESOURCE_CLEANUP  %u\n", res_cleanup);
	seq_printf(m, "HWTRACE_STATE_NO_CLEANUP_RESOURCE  %u\n", res_no_cleanup);
	seq_printf(m, "number of host resources mapped to npk resource  %u\n", host_res_count);
	seq_printf(m, "npk resources count  %u\n", dma_stream_list_count);
	seq_printf(m, "npk nr_pool_pages %u\n", hw_tracing->nr_pool_pages);

	SPH_SPIN_UNLOCK_IRQRESTORE(&hw_tracing->lock_irq, flags);
	return 0;
}

static int debug_status_open(struct inode *inode, struct file *filp)
{
	return single_open(filp, debug_status_show, inode->i_private);
}

static const struct file_operations debug_status_fops = {
	.open		= debug_status_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

void hwtrace_init_debugfs(struct sphcs_hwtrace_data *hw_tracing,
				struct dentry *parent,
				const char    *dirname)
{
	struct dentry *dir, *stats;

	if (!parent)
		return;

	dir = debugfs_create_dir(dirname, parent);
	if (IS_ERR_OR_NULL(dir))
		return;


	stats = debugfs_create_file("status",
				    0444,
				    dir,
				    (void *)hw_tracing,
				    &debug_status_fops);
	if (IS_ERR_OR_NULL(stats)) {
		debugfs_remove(dir);
		return;
	}
}
