/********************************************
 * Copyright (C) 2019 Intel Corporation
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
	struct page	**pages;
	uint32_t	nr_pages;
};

//host resource information
struct host_res_info {
	uint32_t	resource_index;
	size_t		resource_size;
	struct		sg_table sgt;
};

//dma resource information
struct dma_res_info {
	struct			sg_table *sgt;
	struct page		**pages;
	uint32_t		nr_pages;
	void			*lli_buf;
	dma_addr_t		lli_addr;
	u32			lli_size;
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

void sphcs_hwtrace_wakeup_clients(void)
{
	struct sphcs_hwtrace_data *hw_tracing = &g_the_sphcs->hw_tracing;

	if (hw_tracing)
		wake_up(&hw_tracing->waitq);
}

void sphcs_hwtrace_cleanup_npk_resource(struct npk_res_info *npk)
{
	struct sphcs_hwtrace_data *hw_tracing = &g_the_sphcs->hw_tracing;
	int i;

	dma_unmap_sg(hw_tracing->intel_th_device,
		     npk->sgt->sgl,
		     npk->sgt->orig_nents,
		     DMA_FROM_DEVICE);

	sg_free_table(npk->sgt);

	for (i = 0; i < npk->nr_pages; i++) {
		if (npk->pages[i] != NULL)
			__free_page(npk->pages[i]);
		else
			break;
	}

	kfree(npk->pages);

	kfree(npk->sgt);

	kfree(npk);
}

void sphcs_hwtrace_cleanup_host_resource(struct host_res_info *host)
{
	sg_free_table(&host->sgt);
	kfree(host);
}


void sphcs_hwtrace_cleanup_dma_info(struct dma_res_info *dma)
{
	dma_free_coherent(g_the_sphcs->hw_device,
			  dma->lli_size,
			  dma->lli_buf,
			  dma->lli_addr);

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

	//allocate sg table from NPK RES pages.
	ret = sg_alloc_table_from_pages(dma->sgt,
					dma->pages,
					dma->nr_pages,
					0,
					dma->nr_pages * sizeof(SPH_PAGE_SIZE),
					GFP_NOWAIT);
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
		sph_log_err(HWTRACE_LOG, "fail map sgl - %d", ret);
		goto cleanup_sgt;
	}

	dma->sgt->nents = ret;

	//get required lli size for dma op
	dma->lli_size =
		g_the_sphcs->hw_ops->dma.calc_lli_size(g_the_sphcs->hw_handle,
						       dma->sgt,
						       &(r->host_res->sgt), 0);

	// allocate memory in size lli_size
	dma->lli_buf =
		dma_alloc_coherent(g_the_sphcs->hw_device,
				   dma->lli_size,
				   &dma->lli_addr,
				   GFP_NOWAIT);
	if (!dma->lli_buf) {
		sph_log_err(HWTRACE_LOG, "failed to allocate lli buffer\n");
		goto cleanup_dma_map;
	}

	//generate lli
	g_the_sphcs->hw_ops->dma.gen_lli(g_the_sphcs->hw_handle,
					 dma->sgt,
					 &(r->host_res->sgt),
					 dma->lli_buf,
					 0);
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

			//try to clean resources container
			kfree(clean_r);

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
		}

	}
}


//callback from dma engine when NPK resource to host copy via pep ended
static int sphcs_hwtrace_dma_stream_complete_cb(struct sphcs *sphcs, void *ctx, const void *user_data, int status, u32 timeUS)
{
	struct sphcs_hwtrace_data *hw_tracing = &sphcs->hw_tracing;
	struct sphcs_dma_res_info *r = (struct sphcs_dma_res_info *)ctx;
	unsigned long flags;
	union c2h_HwTraceState response_msg;
	int hwtrace_err = SPH_HWTRACE_NO_ERR;
	bool bIsLast = true;
	int index = -1;
	uint32_t bytes = 0;


	//lock for updating window work has done.
	SPH_SPIN_LOCK_IRQSAVE(&hw_tracing->lock_irq, flags);

	if (r->host_res) {
		index = r->host_res->resource_index;
		bIsLast = (g_the_sphcs->hw_tracing.hwtrace_status == SPHCS_HWTRACE_DEACTIVATED);
	}

	bytes = r->bytes_to_copy;

	SPH_SPIN_UNLOCK_IRQRESTORE(&hw_tracing->lock_irq, flags);

	//release npk resource
	if (hw_tracing->intel_th_device &&
	    r && r->npk_res)
		sphcs_intel_th_window_unlock(hw_tracing->intel_th_device,
					     r->npk_res->sgt);

	//if status != 0 report error to host
	if (status)
		hwtrace_err = SPH_HWTRACE_ERR_DMA_FAILED;

	//send notification to host that resource is ready for read.
	memset(&response_msg.value, 0x0, sizeof(response_msg));

	response_msg.opcode	= SPH_IPC_C2H_OP_HWTRACE_STATE;

	response_msg.subOpcode = (bIsLast) ?
		HWTRACE_LAST_RESOURCE_READY :
		HWTRACE_RESOURCE_READY;

	response_msg.val1	= bytes;
	response_msg.val2	= index;
	response_msg.err	= hwtrace_err;

	sphcs_msg_scheduler_queue_add_msg(sphcs->public_respq, &response_msg.value, 1);

	//lock for updating window work has done.
	SPH_SPIN_LOCK_IRQSAVE(&hw_tracing->lock_irq, flags);

	r->state &= ~HWTRACE_STATE_NPK_RESOURCE_BUSY;

	SPH_SPIN_UNLOCK_IRQRESTORE(&hw_tracing->lock_irq, flags);

	return 0;
}

//function handle streaming NPK resource to host
void do_stream_hwtrace(struct sphcs_dma_res_info *r)
{
	int ret;
	size_t dma_size;

	if (!r ||
	    !r->host_res ||
	    !r->npk_res ||
	    !r->dma_res)
		return;

	if (r->state &
	    (HWTRACE_STATE_NPK_RESOURCE_BUSY | HWTRACE_STATE_HOST_RESOURCE_BUSY |
	     HWTRACE_STATE_DMA_INFO_DIRTY))
		return;

	r->state |= (HWTRACE_STATE_NPK_RESOURCE_BUSY |
		     HWTRACE_STATE_HOST_RESOURCE_BUSY);

	r->state &= ~HWTRACE_STATE_NPK_RESOURCE_READY;

	dma_size = r->host_res->resource_size;

	//now we start dma transaction from card to host.
	ret = sphcs_dma_sched_start_xfer(g_the_sphcs->dmaSched,
					 &g_dma_desc_c2h_dtf_nowait,
					 r->dma_res->lli_addr,
					 dma_size,
					 sphcs_hwtrace_dma_stream_complete_cb,
					 r,
					 NULL,
					 0);
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
	int i;
	bool bFound = false;

	if (size == 0)
		return -EINVAL;

	npk = kzalloc(sizeof(*npk), GFP_NOWAIT);
	if (unlikely(npk == NULL)) {
		ret = -ENOMEM;
		goto err;
	}

	npk->nr_pages = DIV_ROUND_UP(size, PAGE_SIZE);

	npk->sgt = kzalloc(sizeof(*npk->sgt), GFP_KERNEL);
	if (unlikely(npk->sgt == NULL)) {
		ret = -ENOMEM;
		goto cleanup_npk_res_info;
	}

	npk->pages = kmalloc_array(npk->nr_pages,
			      sizeof(struct page *),
			      GFP_KERNEL);
	if (unlikely(npk->pages == NULL)) {
		ret = -ENOMEM;
		goto cleanup_npk_sgt;
	}

	for (i = 0; i < npk->nr_pages; ++i) {
		//TODO: Possible optimization: try to call alloc_pages, reducing order, until success
		npk->pages[i] = alloc_page(GFP_DMA32);
		if (unlikely(npk->pages[i] == NULL)) {
			sph_log_err(HWTRACE_LOG, "fail allocate page number - %d", i);
			ret = -ENOMEM;
			goto cleanup_pages;
		}
	}


	ret = sg_alloc_table_from_pages(npk->sgt,
					npk->pages,
					npk->nr_pages,
					0,
					size,
					GFP_KERNEL);
	if (ret) {
		sph_log_err(HWTRACE_LOG, "fail allocate table from pages - %d", ret);
		goto cleanup_pages;
	}

	ret = dma_map_sg(hw_tracing->intel_th_device,
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
	dma_unmap_sg(hw_tracing->intel_th_device,
		     npk->sgt->sgl,
		     npk->sgt->orig_nents,
		     DMA_FROM_DEVICE);
cleanup_sgt:
	sg_free_table(npk->sgt);
cleanup_pages:
	for (i = 0; i < npk->nr_pages; i++) {
		if (npk->pages[i] != NULL)
			__free_page(npk->pages[i]);
		else
			break;
	}
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
	if (g_the_sphcs->hw_tracing.hwtrace_status == SPHCS_HWTRACE_REGISTERED) {
		sph_log_err(HWTRACE_LOG, "callback request, but trace was not initialized\n");
		return;
	}

	g_the_sphcs->hw_tracing.hwtrace_status = SPHCS_HWTRACE_ACTIVATED;
}

//callback from intel trace hub driver
// notification when tracSPHCS_HWTRACE_DEACTIVATEDe stopped
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
	sph_log_debug(HWTRACE_LOG, "got window ready with size %lu\n", bytes);

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

	if (bFound)
		do_stream_hwtrace(r);

	SPH_SPIN_UNLOCK_IRQRESTORE(&hw_tracing->lock_irq, flags);



	return 0;
}

void sphcs_hwtrace_cleanup_resources_request(struct sphcs *sphcs)
{
	struct sphcs_hwtrace_data *hw_tracing = &sphcs->hw_tracing;
	union c2h_HwTraceState response_msg;
	struct sphcs_dma_res_info *r;
	unsigned long flags;

	SPH_SPIN_LOCK_IRQSAVE(&hw_tracing->lock_irq, flags);

	list_for_each_entry(r, &hw_tracing->dma_stream_list, node) {
		if (r)
			r->state |= (HWTRACE_STATE_DMA_INFO_DIRTY |
				     HWTRACE_STATE_HOST_RESOURCE_CLEANUP);
	}

	SPH_SPIN_UNLOCK_IRQRESTORE(&hw_tracing->lock_irq, flags);

	sphcs_hwtrace_update_state();

	memset(&response_msg.value, 0x0, sizeof(response_msg));

	response_msg.opcode	= SPH_IPC_C2H_OP_HWTRACE_STATE;
	response_msg.subOpcode	= HWTRACE_RESOURCE_CLEANUP;
	response_msg.err	= SPH_HWTRACE_NO_ERR;

	sphcs_msg_scheduler_queue_add_msg(sphcs->public_respq, &response_msg.value, 1);
}

int sphcs_hwtrace_init(struct sphcs *sphcs)
{
	struct sphcs_hwtrace_data *hw_tracing = &sphcs->hw_tracing;
	int ret = 0;
	int hwtrace_err = SPH_HWTRACE_NO_ERR;
	union c2h_HwTraceState response_msg;
	unsigned long flags;
	struct sphcs_dma_res_info *r;

	if (hw_tracing->hwtrace_status == SPHCS_HWTRACE_NOT_SUPPORTED) {
		hwtrace_err = SPH_HWTRACE_ERR_INTEL_TH_REG;
		sph_log_err(HWTRACE_LOG, "unable to initialize hwtrace service err\n");
		goto reply_message;

	}

	ret = sphcs_dma_sched_reserve_channel_for_dtf(sphcs->dmaSched, true);
	if (ret) {
		sph_log_err(HWTRACE_LOG, "unable to reserve dma channel for streaming trace resources\n");
		hwtrace_err = SPH_HWTRACE_ERR_DTF_CHANNEL;
		goto reply_message;
	}


	SPH_SPIN_LOCK_IRQSAVE(&hw_tracing->lock_irq, flags);

	list_for_each_entry(r, &hw_tracing->dma_stream_list, node) {
		r->state |= (HWTRACE_STATE_DMA_INFO_DIRTY |
			     HWTRACE_STATE_HOST_RESOURCE_CLEANUP);
		r->state &= ~HWTRACE_STATE_HOST_RESOURCE_BUSY;
	}

	hw_tracing->host_resource_count = 0;

	SPH_SPIN_UNLOCK_IRQRESTORE(&hw_tracing->lock_irq, flags);

	sphcs_hwtrace_update_state();


	hw_tracing->hwtrace_status = SPHCS_HWTRACE_INITIALIZED;

reply_message:
	memset(&response_msg.value, 0x0, sizeof(response_msg));

	response_msg.opcode	= SPH_IPC_C2H_OP_HWTRACE_STATE;
	response_msg.subOpcode	= HWTRACE_INIT;
	response_msg.err	= hwtrace_err;

	sphcs_msg_scheduler_queue_add_msg(sphcs->public_respq, &response_msg.value, 1);

	return 0;
}


int sphcs_hwtrace_deinit(struct sphcs *sphcs)
{
	struct sphcs_hwtrace_data *hw_tracing = &sphcs->hw_tracing;
	int  ret = 0;
	int hwtrace_err = SPH_HWTRACE_NO_ERR;
	union c2h_HwTraceState response_msg;
	struct sphcs_dma_res_info *r;
	unsigned long flags;

	if (hw_tracing->hwtrace_status == SPHCS_HWTRACE_NOT_SUPPORTED) {
		hwtrace_err = SPH_HWTRACE_ERR_INTEL_TH_REG;
		sph_log_err(HWTRACE_LOG, "unable to deinit hwtrace service err\n");
		goto reply_message;
	}


	ret = sphcs_dma_sched_reserve_channel_for_dtf(sphcs->dmaSched, false);
	if (ret) {
		sph_log_err(HWTRACE_LOG, "unable release reserved dma channel used for hw trace streamimg resources\n");
		hwtrace_err = SPH_HWTRACE_ERR_INTEL_TH_REG;
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

	memset(&response_msg.value, 0x0, sizeof(response_msg));

	response_msg.opcode	= SPH_IPC_C2H_OP_HWTRACE_STATE;
	response_msg.subOpcode	= HWTRACE_DEINIT;
	response_msg.err	= hwtrace_err;

	sphcs_msg_scheduler_queue_add_msg(sphcs->public_respq, &response_msg.value, 1);

	return 0;
}

//get host resource dma data.
static int sphcs_hwtrace_get_hostres_complete_cb(struct sphcs *sphcs,
						 void *ctx,
						 const void *user_data,
						 int status,
						 u32 timeUS)
{
	struct sphcs_hwtrace_data *hw_tracing = &sphcs->hw_tracing;
	struct dma_chain_header *chain_header;
	struct dma_chain_entry *chain_entry;
	struct scatterlist *current_sgl;
	struct sphcs_hwtrace_res_add_req *dma_req_data = (struct sphcs_hwtrace_res_add_req *)user_data;
	struct host_res_info *host = dma_req_data->res_info;
	struct sphcs_dma_res_info *r;
	struct sg_table *sgt = &(host->sgt);
	struct scatterlist *sgl_curr;
	int hwtrace_err = SPH_HWTRACE_NO_ERR;
	int i, ret = 0;
	uint64_t total_entries_bytes = 0;
	unsigned long flags;
	bool bFound = false;

	chain_header = (struct dma_chain_header *)dma_req_data->vptr;
	chain_entry = (struct dma_chain_entry *)(dma_req_data->vptr + sizeof(struct dma_chain_header));

	ret = sg_alloc_table(sgt, chain_header->total_nents, GFP_KERNEL);
	if (ret) {
		hwtrace_err = SPH_HWTRACE_ERR_ADD_RESOURCE_FAIL;
		goto err;
	}

	sgl_curr = &(sgt->sgl[0]);

	// iterate over host's DMA address entries, and fill host sg_table
	// make sure we are not reading last entry, in a non-full page
	// make sure we are not reading more than one page
	current_sgl = sgl_curr;

	for (i = 0; !sg_is_last(current_sgl) && i < NENTS_PER_PAGE; i++) {
		current_sgl->length = chain_entry[i].n_pages * SPH_PAGE_SIZE;
		current_sgl->dma_address = SPH_IPC_DMA_PFN_TO_ADDR(chain_entry[i].dma_chunk_pfn);

		total_entries_bytes = total_entries_bytes + current_sgl->length;

		SPH_ASSERT(chain_header->size >= total_entries_bytes);

		current_sgl = sg_next(current_sgl);
	}

	// might need to fix the size of last entry
	// this is a bit confusing, need to remember that last entry in current page
	// doesn't necessarily mean last in sg table. But last in sg table for sure
	// means this is last enrty in the last page.
	if (sg_is_last(current_sgl)) {
		SPH_ASSERT(chain_header->size > total_entries_bytes);
		current_sgl->dma_address = SPH_IPC_DMA_PFN_TO_ADDR(chain_entry[i].dma_chunk_pfn);

		// update the length of last entry
		SPH_ASSERT(chain_entry[i].n_pages * SPH_PAGE_SIZE >= chain_header->size - total_entries_bytes);
		current_sgl->length = chain_header->size - total_entries_bytes;
	} else {
		SPH_ASSERT(chain_header->size == total_entries_bytes);
		sgl_curr = current_sgl;
	}

	SPH_SPIN_LOCK_IRQSAVE(&hw_tracing->lock_irq, flags);

	list_for_each_entry(r,
			    &hw_tracing->dma_stream_list,
			    node) {
		if (r->host_res == NULL &&
		    ~(r->state & HWTRACE_STATE_NPK_RESOURCE_CLEANUP)) {
			bFound = true;
			r->host_res = host;
			r->state |= HWTRACE_STATE_DMA_INFO_DIRTY;
			break;
		}
	}

	SPH_SPIN_UNLOCK_IRQRESTORE(&hw_tracing->lock_irq, flags);


	if (!bFound) {
		r = kzalloc(sizeof(*r), GFP_NOWAIT);
		if (unlikely(r == NULL)) {
			hwtrace_err = SPH_HWTRACE_ERR_NO_MEMORY;
			goto err;
		}

		r->state |= HWTRACE_STATE_DMA_INFO_DIRTY;
		r->host_res = host;

		SPH_SPIN_LOCK_IRQSAVE(&hw_tracing->lock_irq, flags);

		host->resource_index = hw_tracing->host_resource_count++;
		list_add_tail(&r->node, &hw_tracing->dma_stream_list);

		SPH_SPIN_UNLOCK_IRQRESTORE(&hw_tracing->lock_irq, flags);
	}


	sphcs_hwtrace_wakeup_clients();

	return ret;

err:
	hw_tracing->hwtrace_status = SPHCS_HWTRACE_ERR;

	kfree(host);

	sphcs_hwtrace_wakeup_clients();

	return ret;
}

void sphcs_hwtrace_unlock_host_res(struct sphcs *sphcs,
				   uint32_t resource_index)
{
	struct sphcs_hwtrace_data *hw_tracing = &sphcs->hw_tracing;
	union c2h_HwTraceState response_msg;
	unsigned long flags;
	int hwtrace_err = SPH_HWTRACE_NO_ERR;
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

	if (!bFound)
		do_stream_hwtrace(r);


	SPH_SPIN_UNLOCK_IRQRESTORE(&hw_tracing->lock_irq, flags);


reply_message:
	memset(&response_msg.value, 0x0, sizeof(response_msg));

	response_msg.opcode	= SPH_IPC_C2H_OP_HWTRACE_STATE;
	response_msg.subOpcode	= HWTRACE_UNLOCK_RESOURCE;
	response_msg.val1	= resource_index;
	response_msg.err	= hwtrace_err;

	sphcs_msg_scheduler_queue_add_msg(sphcs->public_respq, &response_msg.value, 1);
}

void sphcs_hwtrace_query_state(struct sphcs *sphcs)
{
	struct sphcs_hwtrace_data *hw_tracing = &sphcs->hw_tracing;
	union c2h_HwTraceState response_msg;

	memset(&response_msg.value, 0x0, sizeof(response_msg));

	response_msg.opcode	= SPH_IPC_C2H_OP_HWTRACE_STATE;
	response_msg.subOpcode	= HWTRACE_QUERY_STATE;
	response_msg.val1	= hw_tracing->hwtrace_status;
	response_msg.val2	= hw_tracing->host_resource_count;

	sphcs_msg_scheduler_queue_add_msg(sphcs->public_respq, &response_msg.value, 1);
}

// opcode for adding new host resource for streaming data
void IPC_OPCODE_HANDLER(HWTRACE_ADD_RESOURCE)(struct sphcs *sphcs,
					      union h2c_HwTraceAddResource *msg)
{
	struct sphcs_hwtrace_data *hw_tracing = &sphcs->hw_tracing;
	struct sphcs_hwtrace_res_add_req *dma_req_data;
	struct host_res_info *res_info;
	union c2h_HwTraceState response_msg;
	dma_addr_t dma_src_addr;
	int hwtrace_err = SPH_HWTRACE_NO_ERR;
	uint32_t resources_count = hw_tracing->host_resource_count;
	int ret;

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

	//allocate dma request data object
	dma_req_data = kzalloc(sizeof(*dma_req_data), GFP_KERNEL);
	if (unlikely(dma_req_data == NULL)) {
		sph_log_err(HWTRACE_LOG, "allocation failed\n");
		hwtrace_err = SPH_HWTRACE_ERR_NO_MEMORY;
		goto reply_message;
	}

	//allocate new resource info.
	res_info = kzalloc(sizeof(*res_info), GFP_KERNEL);
	if (unlikely(res_info == NULL)) {
		sph_log_err(HWTRACE_LOG, "allocation failed\n");
		hwtrace_err = SPH_HWTRACE_ERR_NO_MEMORY;
		goto cleanup_dma_req_data;
	}

	dma_req_data->res_info = res_info;
	dma_req_data->res_info->resource_size = msg->resource_size;
	dma_src_addr = msg->descriptor_addr;

	ret = dma_page_pool_get_free_page(sphcs->dma_page_pool,
					  &dma_req_data->card_dma_page_hndl,
					  &dma_req_data->vptr,
					  &dma_req_data->card_dma_addr);
	if (ret) {
		sph_log_err(HWTRACE_LOG, "ERROR %d: unable to allocate memory from pool\n", ret);
		hwtrace_err = SPH_HWTRACE_ERR_NO_MEMORY;
		goto cleanup_dma_req_data;
	}

	ret = sphcs_dma_sched_start_xfer_single(sphcs->dmaSched,
						&g_dma_desc_h2c_normal,
						dma_src_addr,
						dma_req_data->card_dma_addr,
						SPH_PAGE_SIZE,
						sphcs_hwtrace_get_hostres_complete_cb,
						NULL,
						dma_req_data,
						sizeof(*dma_req_data));
	if (ret) {
		sph_log_err(HWTRACE_LOG, "ERROR %d: unable to get reousce information from host\n", ret);
		hwtrace_err = SPH_HWTRACE_ERR_ADD_RESOURCE_FAIL;
		goto cleanup_dma_allocation;
	}

	wait_event_interruptible(hw_tracing->waitq,
				 (resources_count < hw_tracing->host_resource_count));

	sphcs_hwtrace_update_state();

	kfree(dma_req_data);

	goto reply_message;

cleanup_dma_allocation:
	dma_page_pool_set_page_free(sphcs->dma_page_pool,
				    dma_req_data->card_dma_page_hndl);
cleanup_dma_req_data:
	kfree(dma_req_data);

reply_message:
	memset(&response_msg.value, 0x0, sizeof(response_msg));

	response_msg.opcode	= SPH_IPC_C2H_OP_HWTRACE_STATE;
	response_msg.subOpcode	= HWTRACE_ADD_RESOURCE;
	response_msg.err	= hwtrace_err;

	sphcs_msg_scheduler_queue_add_msg(sphcs->public_respq, &response_msg.value, 1);
}


void IPC_OPCODE_HANDLER(HWTRACE_STATE)(struct sphcs *sphcs,
				       union h2c_HwTraceState *msg)
{
	union c2h_HwTraceState response_msg;
	struct sphcs_hwtrace_data *hw_tracing = &sphcs->hw_tracing;
	int hwtrace_err = SPH_HWTRACE_NO_ERR;

	if (hw_tracing->hwtrace_status == SPHCS_HWTRACE_NOT_SUPPORTED) {
		hwtrace_err = SPH_HWTRACE_ERR_INTEL_TH_REG;
		goto reply_message;
	}

	switch (msg->subOpcode) {
	case HWTRACE_INIT:
		sphcs_hwtrace_init(sphcs);
		break;
	case HWTRACE_DEINIT:
		sphcs_hwtrace_deinit(sphcs);
		break;
	case HWTRACE_RESOURCE_CLEANUP:
		sphcs_hwtrace_cleanup_resources_request(sphcs);
		break;
	case HWTRACE_QUERY_STATE:
		sphcs_hwtrace_query_state(sphcs);
		break;
	case HWTRACE_UNLOCK_RESOURCE:
		sphcs_hwtrace_unlock_host_res(sphcs, msg->val);
		break;
	default:
		hwtrace_err = SPH_HWTRACE_ERR_INVALID_OPCODE;
		goto reply_message;
	};

	return;
reply_message:
	memset(&response_msg.value, 0x0, sizeof(response_msg));

	response_msg.opcode	= SPH_IPC_C2H_OP_HWTRACE_STATE;
	response_msg.subOpcode	= msg->subOpcode;
	response_msg.err	= hwtrace_err;

	sphcs_msg_scheduler_queue_add_msg(sphcs->public_respq, &response_msg.value, 1);
}
