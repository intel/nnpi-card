/********************************************
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#include "inf_copy.h"
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/scatterlist.h>
#include "sphcs_cs.h"
#include "sphcs_inf.h"
#include "sph_log.h"
#include "ipc_protocol.h"
#include "inf_context.h"
#include "sph_error.h"
#include "sphcs_trace.h"

struct copy_dma_command_data {
	void               *vptr;
	page_handle         card_dma_page_hndl;
	dma_addr_t          card_dma_addr;
	struct sg_table     host_sgt;
	struct scatterlist *sgl_curr;
	struct inf_copy    *copy;
	u32                 pages_count;
};

int host_page_list_dma_completed(struct sphcs *sphcs, void *ctx, const void *user_data, int status, u32 xferTimeUS)
{
	struct copy_dma_command_data *dma_req_data = *((struct copy_dma_command_data **)user_data);
	struct dma_chain_header *chain_header;
	struct dma_chain_entry *chain_entry;
	struct scatterlist *current_sgl;
	struct inf_copy *copy = dma_req_data->copy;
	struct sg_table *host_sgt = &dma_req_data->host_sgt;
	struct sg_table *src_sgt;
	struct sg_table *dst_sgt;
	dma_addr_t dma_src_addr;
	uint64_t total_entries_bytes = 0;
	int i, res = 0;
	enum event_val eventVal = 0;

	if (unlikely(status == SPHCS_DMA_STATUS_FAILED)) {
		/* dma failed */
		sph_log_err(CREATE_COMMAND_LOG, "FATAL: line:%u DMA of host page list number %u failed with status=%d\n",
				__LINE__, dma_req_data->pages_count, status);
		res = -EFAULT;
		eventVal = SPH_IPC_DMA_ERROR;
		goto failed;
	}

	if (unlikely(copy->destroyed))
		goto failed;

	/* if status is not an error - it must be done */
	SPH_ASSERT(status == SPHCS_DMA_STATUS_DONE);
	SPH_ASSERT(copy != NULL);

	chain_header = (struct dma_chain_header *)dma_req_data->vptr;
	chain_entry = (struct dma_chain_entry *)(dma_req_data->vptr + sizeof(struct dma_chain_header));

	if (dma_req_data->pages_count == 0) { // this is the first page
		res = sg_alloc_table(host_sgt, chain_header->total_nents, GFP_KERNEL);
		if (unlikely(res < 0)) {
			sph_log_err(CREATE_COMMAND_LOG, "FATAL: line:%u err=%u failed to allocate sg_table\n",  __LINE__, res);
			eventVal = SPH_IPC_NO_MEMORY;
			goto failed;
		}
		dma_req_data->sgl_curr = &(host_sgt->sgl[0]);
	}

	SPH_ASSERT(host_sgt->orig_nents == chain_header->total_nents);

	dma_req_data->pages_count++;

	// set address of next DMA page
	dma_src_addr = chain_header->dma_next;

	// iterate over host's DMA address entries, and fill host sg_table
	// make sure we are not reading last entry, in a non-full page
	// make sure we are not reading more than one page
	current_sgl = dma_req_data->sgl_curr;
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
		SPH_ASSERT(dma_src_addr == 0x0);
		current_sgl->dma_address = SPH_IPC_DMA_PFN_TO_ADDR(chain_entry[i].dma_chunk_pfn);

		// update the length of last entry
		SPH_ASSERT(chain_entry[i].n_pages * SPH_PAGE_SIZE >= chain_header->size - total_entries_bytes);
		current_sgl->length = chain_header->size - total_entries_bytes;
	} else {
		SPH_ASSERT(chain_header->size == total_entries_bytes);
		dma_req_data->sgl_curr = current_sgl;
	}

	/* Finished to iterate the current page and update host sg table */

#ifdef _DEBUG
	// increment hostres size by amount of this pages's total bytes
	copy->hostres_size = copy->hostres_size + chain_header->size;
#endif

	// read next DMA page
	if (dma_src_addr != 0x0) {
		res = sphcs_dma_sched_start_xfer_single(g_the_sphcs->dmaSched,
							&g_dma_desc_h2c_normal,
							dma_src_addr,
							dma_req_data->card_dma_addr,
							SPH_PAGE_SIZE,
							host_page_list_dma_completed,
							ctx,
							&dma_req_data,
							sizeof(dma_req_data));
		if (unlikely(res < 0)) {
			sph_log_err(CREATE_COMMAND_LOG, "FATAL: line: %u err=%u failed to sched dma\n", __LINE__, res);
			eventVal = SPH_IPC_NO_MEMORY;
			goto failed;
		}
	} else {
		// done reading all host DMA pages. Now create lli buffer

#ifdef _DEBUG
	// By definition, copy handle should be created for host resouce and device resource with the same size
	// It should be validated first in the UMD during creation of copy handle, we add this check in the card only in debug.
	SPH_ASSERT(copy->hostres_size == copy->devres->size);
#endif

		if (copy->card2Host) {
			src_sgt = (copy->devres)->dma_map; // sg_table from device resource
			dst_sgt = host_sgt;
		} else {
			src_sgt = host_sgt;
			dst_sgt = (copy->devres)->dma_map; // sg_table from device resource
		}

		copy->lli_size = g_the_sphcs->hw_ops->dma.calc_lli_size(g_the_sphcs->hw_handle, src_sgt, dst_sgt, 0);

		// allocate memory in size lli_size
		copy->lli_buf = dma_alloc_coherent(g_the_sphcs->hw_device, copy->lli_size, &copy->lli_addr, GFP_KERNEL);
		if (unlikely(copy->lli_buf == NULL)) {
			sph_log_err(CREATE_COMMAND_LOG, "FATAL: line:%u failed to allocate lli buffer\n", __LINE__);
			res = -ENOMEM;
			eventVal = SPH_IPC_NO_MEMORY;
			goto failed;
		}

		// send lli buffer to dma
		copy->transfer_size = g_the_sphcs->hw_ops->dma.gen_lli(g_the_sphcs->hw_handle, src_sgt, dst_sgt, copy->lli_buf, 0);

		sphcs_send_event_report(g_the_sphcs,
					SPH_IPC_CREATE_COPY_SUCCESS,
					0,
					copy->context->protocolID,
					copy->protocolID);

		sg_free_table(host_sgt);
		res = dma_page_pool_set_page_free(g_the_sphcs->dma_page_pool, dma_req_data->card_dma_page_hndl);

		DO_TRACE(trace_infer_create((copy->card2Host ? SPH_TRACE_INF_CREATE_C2H_COPY_HANDLE : SPH_TRACE_INF_CREATE_H2C_COPY_HANDLE),
				copy->context->protocolID, copy->protocolID, SPH_TRACE_OP_STATUS_COMPLETE, -1, -1));

		// put refcount, taken for create process
		inf_copy_put(dma_req_data->copy);

		kfree(dma_req_data);
	}

	return res;

failed:
	if (dma_req_data->pages_count != 0)
		sg_free_table(host_sgt);
	dma_page_pool_set_page_free(g_the_sphcs->dma_page_pool, dma_req_data->card_dma_page_hndl);
	kfree(dma_req_data);

	sphcs_send_event_report(g_the_sphcs,
				SPH_IPC_CREATE_COPY_FAILED,
				eventVal,
				copy->context->protocolID,
				copy->protocolID);

	destroy_copy_on_create_failed(copy);
	// put refcount, taken for create process
	inf_copy_put(copy);

	return res;
}

static int copy_complete_cb(struct sphcs *sphcs, void *ctx, const void *user_data, int status, u32 xferTimeUS)
{
	int err;

	if (status == SPHCS_DMA_STATUS_FAILED) {
		err = -SPHER_DMA_ERROR;
	} else {
		/* if status is not an error - it must be done */
		SPH_ASSERT(status == SPHCS_DMA_STATUS_DONE);
		err = 0;
	}

	inf_copy_req_complete(*((struct inf_exec_req **)user_data), err);

	return err;
}

int inf_copy_create(uint16_t protocolCopyID, struct inf_context *context, struct inf_devres *devres, uint64_t hostDmaAddr, bool card2Host,
		    struct inf_copy **out_copy)
{
	struct copy_dma_command_data *dma_req_data;
	dma_addr_t dma_src_addr;
	int res;

	inf_devres_get(devres);

	dma_req_data = kzalloc(sizeof(*dma_req_data), GFP_KERNEL);
	if (unlikely(dma_req_data == NULL)) {
		sph_log_err(CREATE_COMMAND_LOG, "FATAL: %s():%u failed to allocate dma req object\n", __func__, __LINE__);
		inf_devres_put(devres);
		return -ENOMEM;
	}

	dma_req_data->copy = kzalloc(sizeof(*dma_req_data->copy), GFP_KERNEL);
	if (unlikely(dma_req_data->copy == NULL)) {
		sph_log_err(CREATE_COMMAND_LOG, "FATAL: %s():%u failed to allocate copy object\n", __func__, __LINE__);
		res = -ENOMEM;
		inf_devres_put(devres);
		goto free_dma_req;
	}

	kref_init(&dma_req_data->copy->ref);
	dma_req_data->copy->magic = inf_copy_create;
	dma_req_data->copy->protocolID = protocolCopyID;
	dma_req_data->copy->context = context;
	dma_req_data->copy->devres = devres;
	dma_req_data->copy->card2Host = card2Host;
	dma_req_data->copy->lli_buf = NULL;
	dma_req_data->copy->destroyed = false;
#ifdef _DEBUG
	dma_req_data->copy->hostres_size = 0;
#endif

	/* make sure the context will exist for the copy handle life */
	inf_context_get(context);
	SPH_SPIN_LOCK(&dma_req_data->copy->context->lock);
	hash_add(dma_req_data->copy->context->copy_hash,
		 &dma_req_data->copy->hash_node,
		 dma_req_data->copy->protocolID);
	SPH_SPIN_UNLOCK(&dma_req_data->copy->context->lock);

	// get free page from pool to hold the page DMA'ed from host
	res = dma_page_pool_get_free_page(g_the_sphcs->dma_page_pool,
					  &dma_req_data->card_dma_page_hndl,
					  &dma_req_data->vptr,
					  &dma_req_data->card_dma_addr);
	if (unlikely(res < 0)) {
		sph_log_err(CREATE_COMMAND_LOG, "FATAL: %s():%u err=%u failed to get free page for host dma page list\n", __func__, __LINE__, res);
		goto free_copy;
	}
	// get DMA from host address
	dma_src_addr = hostDmaAddr;

	dma_req_data->pages_count = 0;

	// get ref to ensure copy will not be destoyed in the middle of create
	inf_copy_get(dma_req_data->copy);
	res = sphcs_dma_sched_start_xfer_single(g_the_sphcs->dmaSched,
						&g_dma_desc_h2c_normal,
						dma_src_addr,
						dma_req_data->card_dma_addr,
						SPH_PAGE_SIZE,
						host_page_list_dma_completed,
						NULL,
						&dma_req_data,
						sizeof(dma_req_data));
	if (unlikely(res < 0)) {
		sph_log_err(CREATE_COMMAND_LOG, "FATAL: %s():%u err=%u failed to sched dma\n", __func__, __LINE__, res);
		goto free_page;
	}

	*out_copy = dma_req_data->copy;

	return 0;

free_page:
	inf_copy_put(dma_req_data->copy);
	dma_page_pool_set_page_free(g_the_sphcs->dma_page_pool, dma_req_data->card_dma_page_hndl);
free_copy:
	destroy_copy_on_create_failed(dma_req_data->copy);
free_dma_req:
	kfree(dma_req_data);

	return res;
}

static void release_copy(struct work_struct *work)
{
	struct inf_copy *copy;
	copy = container_of(work, struct inf_copy, work);

	if (likely(copy->lli_buf != NULL))
		dma_free_coherent(g_the_sphcs->hw_device,
				copy->lli_size,
				copy->lli_buf,
				copy->lli_addr);

	if (likely(copy->destroyed))
		sphcs_send_event_report(g_the_sphcs,
				SPH_IPC_COPY_DESTROYED,
				0,
				copy->context->protocolID,
				copy->protocolID);

	inf_context_put(copy->context);
	inf_devres_put(copy->devres);

	kfree(copy);
}

static void sched_release_copy(struct kref *kref)
{
	struct inf_copy *copy;

	copy = container_of(kref, struct inf_copy, ref);

	INIT_WORK(&copy->work, release_copy);
	queue_work(g_the_sphcs->wq, &copy->work);
}

inline void inf_copy_get(struct inf_copy *copy)
{
	int ret;

	ret = kref_get_unless_zero(&copy->ref);
	SPH_ASSERT(ret != 0);
}

inline int inf_copy_put(struct inf_copy *copy)
{
	return kref_put(&copy->ref, sched_release_copy);
}

int inf_copy_sched(struct inf_copy *copy, size_t size)
{
	int err;
	struct inf_exec_req *req;

	req = kmem_cache_alloc(copy->context->exec_req_slab_cache, GFP_NOWAIT);
	if (unlikely(req == NULL)) {
		sph_log_err(SCHEDULE_COMMAND_LOG, "failed to allocate memory for copy schedule\n");
		return -ENOMEM;
	}

	inf_copy_get(copy);

	spin_lock_init(&req->lock_irq);
	req->in_progress = false;
	req->is_copy = true;
	req->copy = copy;
	req->size = size;
	inf_context_seq_id_init(req->copy->context, &req->seq);

	err = inf_devres_add_req_to_queue(copy->devres, req, copy->card2Host);
	if (unlikely(err < 0)) {
		inf_context_seq_id_fini(req->copy->context, &req->seq);
		kmem_cache_free(copy->context->exec_req_slab_cache, req);
		inf_copy_put(copy);
		return err;
	}
	// Request scheduled

	// First try to execute
	inf_req_try_execute(req);

	return 0;
}

bool inf_copy_req_ready(struct inf_exec_req *copy_req)
{
	SPH_ASSERT(copy_req->is_copy);

	return !copy_req->copy->active && inf_devres_req_ready(copy_req->copy->devres,
								copy_req,
								copy_req->copy->card2Host);
}

int inf_copy_req_execute(struct inf_exec_req *copy_req)
{
	struct sphcs_dma_desc const *desc;

	SPH_ASSERT(copy_req->is_copy);
	SPH_ASSERT(copy_req->in_progress);

	DO_TRACE(trace_copy(SPH_TRACE_OP_STATUS_START,
		   copy_req->copy->context->protocolID,
		   copy_req->copy->protocolID,
		   copy_req->copy->card2Host,
		   copy_req->size ? copy_req->size : copy_req->copy->devres->size));

	if (copy_req->copy->card2Host)
		desc = &g_dma_desc_c2h_high_nowait;
	else
		desc = &g_dma_desc_h2c_high_nowait;

	copy_req->copy->active = true;

	if (inf_context_get_state(copy_req->copy->context) != CONTEXT_OK)
		return -SPHER_CONTEXT_BROKEN;

	g_the_sphcs->hw_ops->dma.edit_lli(g_the_sphcs->hw_handle, copy_req->copy->lli_buf, copy_req->size);

	return sphcs_dma_sched_start_xfer(g_the_sphcs->dmaSched, desc,
					  copy_req->copy->lli_addr,
					  copy_req->size ? copy_req->size : copy_req->copy->devres->size,
					  copy_complete_cb, NULL,
					  &copy_req, sizeof(copy_req));
}

void inf_copy_req_complete(struct inf_exec_req *req, int err)
{
	uint16_t status;
	enum event_val eventVal;

	SPH_ASSERT(req != NULL);
	SPH_ASSERT(req->is_copy);
	SPH_ASSERT(req->in_progress);

	DO_TRACE(trace_copy(SPH_TRACE_OP_STATUS_COMPLETE,
		   req->copy->context->protocolID,
		   req->copy->protocolID,
		   req->copy->card2Host,
		   req->size ? req->size : req->copy->devres->size));

	if (unlikely(err < 0)) {
		sph_log_err(EXECUTE_COMMAND_LOG, "Execute copy failed with err=%d\n", err);
		status = SPH_IPC_EXECUTE_COPY_FAILED;
		switch (err) {
		case -ENOMEM:
			eventVal = SPH_IPC_NO_MEMORY;
			break;
		case -SPHER_CONTEXT_BROKEN:
			eventVal = SPH_IPC_CONTEXT_BROKEN;
			break;
		default:
			eventVal = SPH_IPC_DMA_ERROR;
		}
	} else {
		status = SPH_IPC_EXECUTE_COPY_SUCCESS;
		eventVal = 0;
	}
	sphcs_send_event_report(g_the_sphcs,
				status,
				eventVal,
				req->copy->context->protocolID,
				req->copy->protocolID);

	if (unlikely(err < 0))
		inf_context_set_state(req->copy->context,
				      CONTEXT_BROKEN_RECOVERABLE);

	req->copy->active = false;

	inf_devres_del_req_from_queue(req->copy->devres, req);

	inf_context_seq_id_fini(req->copy->context, &req->seq);
	inf_copy_put(req->copy);
	kmem_cache_free(req->copy->context->exec_req_slab_cache, req);
}
