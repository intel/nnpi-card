/********************************************
 * Copyright (C) 2019-2021 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#include "inf_devnet.h"
#include <linux/kernel.h>
#include <linux/slab.h>
#include "sphcs_cs.h"
#include "sph_log.h"
#include "inf_devres.h"
#include "inf_context.h"
#include "inf_req.h"
#include "sphcs_trace.h"
#include "inf_ptr2id.h"

int inf_devnet_add_devres(struct inf_devnet *devnet,
			  struct inf_devres *devres)
{
	struct devres_node *n;

	n = kzalloc(sizeof(*n), GFP_KERNEL);
	if (unlikely(n == NULL))
		return -ENOMEM;

	n->devres = devres;

	inf_devres_get(devres);

	NNP_SPIN_LOCK(&devnet->lock);
	list_add_tail(&n->node, &devnet->devres_list);
	devnet->num_devres++;
	if (devnet->first_devres == NULL)
		devnet->first_devres = devres;
	NNP_SPIN_UNLOCK(&devnet->lock);

	return 0;
}

struct inf_devres *inf_devnet_find_ecc_devres(struct inf_devnet *devnet, uint32_t usage_flags)
{
	bool found = false;
	struct devres_node *n;

	sph_log_debug(GENERAL_LOG, "requested usage flags 0x%X\n", usage_flags);

	NNP_SPIN_LOCK(&devnet->lock);
	list_for_each_entry(n, &devnet->devres_list, node) {
		if ((n->devres->usage_flags & usage_flags) == usage_flags) {
			found = true;
			break;
		}
	}
	NNP_SPIN_UNLOCK(&devnet->lock);

	return found ? n->devres : NULL;
}
void inf_devnet_attach_all_devres(struct inf_devnet *devnet)
{
	struct devres_node *n;

	NNP_SPIN_LOCK(&devnet->lock);
	list_for_each_entry(n, &devnet->devres_list, node) {
		n->attached = true;
	}
	NNP_SPIN_UNLOCK(&devnet->lock);
}

void inf_devnet_delete_devres(struct inf_devnet *devnet,
			      bool               del_all)
{
	struct devres_node *n;
	bool found;

	NNP_SPIN_LOCK(&devnet->lock);
	do {
		found = false;
		list_for_each_entry(n, &devnet->devres_list, node) {
			if (del_all || !n->attached) {
				list_del(&n->node);
				if (n->devres == devnet->first_devres)
					devnet->first_devres = NULL;
				NNP_SPIN_UNLOCK(&devnet->lock);
				found = true;
				inf_devres_put(n->devres);
				kfree(n);
				NNP_SPIN_LOCK(&devnet->lock);
				break;
			}
		}
	} while (found);

	if (devnet->first_devres == NULL &&
	    !list_empty(&devnet->devres_list)) {
		n = list_first_entry(&devnet->devres_list, struct devres_node, node);
		devnet->first_devres = n->devres;
	}

	NNP_SPIN_UNLOCK(&devnet->lock);
}

int inf_devnet_create(uint16_t protocol_id,
		      struct inf_context *context,
		      struct inf_devnet **out_devnet)
{
	struct inf_devnet *devnet;
	int ret = 0;

	devnet = kzalloc(sizeof(*devnet), GFP_KERNEL);
	if (unlikely(devnet == NULL))
		return -ENOMEM;

	kref_init(&devnet->ref);
	devnet->magic = inf_devnet_create;
	devnet->protocol_id = protocol_id;
	devnet->context = context;
	devnet->created = false;
	devnet->destroyed = 0;
	devnet->ptr2id = add_ptr2id(devnet);
	if (unlikely(devnet->ptr2id == 0))
		goto free_devnet;

	hash_init(devnet->infreq_hash);
	spin_lock_init(&devnet->lock);

	INIT_LIST_HEAD(&devnet->devres_list);

	ret = nnp_create_sw_counters_values_node(g_hSwCountersInfo_network,
						 (u32)protocol_id,
						 context->sw_counters,
						 &devnet->sw_counters);
	if (unlikely(ret < 0))
		goto free_devnet;

	inf_context_get(context);

	SPH_SW_COUNTER_ATOMIC_INC(context->sw_counters, CTX_SPHCS_SW_COUNTERS_INFERENCE_NUM_NETWORKS);

	inf_devnet_get(devnet);
	NNP_SPIN_LOCK(&context->lock);
	hash_add(context->devnet_hash,
		 &devnet->hash_node,
		 protocol_id);
	NNP_SPIN_UNLOCK(&context->lock);

	*out_devnet = devnet;

	return 0;

free_devnet:
	kfree(devnet);
	return ret;
}

int is_inf_devnet_ptr(void *ptr)
{
	struct inf_devnet *devnet = (struct inf_devnet *)ptr;

	return (devnet && devnet->magic == inf_devnet_create);
}

/* This function is called only when creation is failed,
 * to destroy already created part
 */
void inf_devnet_on_create_or_add_res_failed(struct inf_devnet *devnet)
{
	bool dma_completed, should_destroy = false, add_res_revert = false;

	NNP_SPIN_LOCK(&devnet->lock);

	dma_completed = (devnet->edit_status == DMA_COMPLETED);
	// roll back status, to put kref once
	if (dma_completed)
		devnet->edit_status = CREATE_STARTED;

	if (!devnet->created) { // create failed, destroy
		should_destroy = (devnet->destroyed == 0);
		if (should_destroy)
			devnet->destroyed = -1;
	} else { // add res failed, revert
		add_res_revert = true;
	}

	NNP_SPIN_UNLOCK(&devnet->lock);


	if (add_res_revert)
		inf_devnet_delete_devres(devnet, false);

	if (should_destroy)
		inf_devnet_put(devnet);

	// if got failure from RT
	if (dma_completed)
		inf_devnet_put(devnet);
}

static void release_devnet(struct kref *kref)
{
	struct inf_devnet *devnet = container_of(kref,
			struct inf_devnet,
			ref);
	struct inf_destroy_network cmd_args;
	int ret;

	NNP_SPIN_LOCK(&devnet->context->lock);
	hash_del(&devnet->hash_node);
	NNP_SPIN_UNLOCK(&devnet->context->lock);

	if (likely(devnet->created)) {
		/* send command to runtime to destoy the network */
		cmd_args.devnet_rt_handle = devnet->rt_handle;
		ret = inf_cmd_queue_add(&devnet->context->cmdq,
					SPHCS_RUNTIME_CMD_DESTROY_NETWORK,
					&cmd_args, sizeof(cmd_args),
					NULL, NULL);
		if (unlikely(ret < 0))
			sph_log_err(CREATE_COMMAND_LOG, "Failed to send destroy network command to runtime\n");
	}

	inf_devnet_delete_devres(devnet, true);

	nnp_remove_sw_counters_values_node(devnet->sw_counters);

	SPH_SW_COUNTER_ATOMIC_DEC(devnet->context->sw_counters, CTX_SPHCS_SW_COUNTERS_INFERENCE_NUM_NETWORKS);

	if (likely(devnet->destroyed == 1))
		sphcs_send_event_report(g_the_sphcs,
					NNP_IPC_DEVNET_DESTROYED,
					0,
					devnet->context->chan->respq,
					devnet->context->protocol_id,
					devnet->protocol_id);

	inf_context_put(devnet->context);
	del_ptr2id(devnet);

	kfree(devnet);
}

int inf_devnet_get(struct inf_devnet *devnet)
{
	return kref_get_unless_zero(&devnet->ref);
}

int inf_devnet_put(struct inf_devnet *devnet)
{
	return kref_put(&devnet->ref, release_devnet);
}

struct infreq_dma_data {
	void           *vptr;
	page_handle     card_dma_page_hndl;
	dma_addr_t      host_dma_addr;
	dma_addr_t      card_dma_addr;
	struct inf_req *infreq;
#ifdef _DEBUG
	uint16_t        size;
#endif
};

static int inf_req_create_dma_complete_callback(struct sphcs *sphcs,
						void *ctx,
						const void *user_data,
						int status,
						u32 xferTimeUS)
{
	struct infreq_dma_data *dma_data = (struct infreq_dma_data *)user_data;
	struct inf_req *infreq = dma_data->infreq;
	struct inf_create_infreq *cmd_args;
	uint32_t cmd_size;
	uint64_t *int64ptr;
	uint32_t *intptr;
	uint16_t *shortptr;
	uint32_t n_inputs, n_outputs, i;
	uint32_t config_data_size;
	struct inf_devres **inputs;
	struct inf_devres **outputs;
	void *config_data;
	int ret;
	unsigned long flags;
	enum event_val val;

	sphcs_cmd_chan_update_cmd_head(infreq->devnet->context->chan,
				       0,  /* TODO: change to real rb_id */
				       NNP_PAGE_SIZE);

	if (unlikely(status == SPHCS_DMA_STATUS_FAILED)) {
		val = NNP_IPC_DMA_ERROR;
		ret = -EFAULT;
		goto send_error;
	}
	if (unlikely(infreq->destroyed != 0)) {
		ret = -1;
		goto done;
	}

	intptr = (uint32_t *)dma_data->vptr;
	n_inputs = *(intptr++);
	n_outputs = *(intptr++);
	config_data_size = *(intptr++);

#ifdef _DEBUG
	if (unlikely(3 * sizeof(uint32_t) +
		     (n_inputs + n_outputs) * sizeof(uint16_t) +
		     config_data_size != dma_data->size)) {
		val = NNP_IPC_DMA_ERROR;
		ret = -EFAULT;
		goto send_error;
	}
#endif

	if (n_inputs != 0) {
		inputs = kcalloc(n_inputs, sizeof(struct inf_devres *),	GFP_KERNEL);
		if (unlikely(inputs == NULL)) {
			val = NNP_IPC_NO_MEMORY;
			ret = -ENOMEM;
			goto send_error;
		}
	} else {
		inputs = NULL;
	}

	outputs = kcalloc(n_outputs, sizeof(struct inf_devres *), GFP_KERNEL);
	if (unlikely(outputs == NULL)) {
		val = NNP_IPC_NO_MEMORY;
		ret = -ENOMEM;
		goto free_in;
	}

	if (config_data_size > 0) {
		config_data = kzalloc(config_data_size, GFP_KERNEL);
		if (unlikely(config_data == NULL)) {
			val = NNP_IPC_NO_MEMORY;
			ret = -ENOMEM;
			goto free_out;
		}
	} else {
		config_data = NULL;
	}

	shortptr = (uint16_t *)intptr;
	for (i = 0; i < n_inputs; i++) {
		inputs[i] = inf_context_find_and_get_devres(infreq->devnet->context,
							    *(shortptr++));
		if (unlikely(inputs[i] == NULL)) {
			val = NNP_IPC_NO_SUCH_DEVRES;
			ret = -EFAULT;
			goto put_inputs;
		}
	}

	for (i = 0; i < n_outputs; i++) {
		outputs[i] = inf_context_find_and_get_devres(infreq->devnet->context,
							     *(shortptr++));
		if (unlikely(outputs[i] == NULL)) {
			val = NNP_IPC_NO_SUCH_DEVRES;
			ret = -EFAULT;
			goto put_outputs;
		}
	}

	if (config_data_size > 0)
		memcpy(config_data, shortptr, config_data_size);


	ret = inf_req_add_resources(infreq,
				    n_inputs,
				    inputs,
				    n_outputs,
				    outputs,
				    config_data_size,
				    config_data);
	for (i = 0; i < n_inputs; ++i)
		inf_devres_put(inputs[i]);
	for (i = 0; i < n_outputs; ++i)
		inf_devres_put(outputs[i]);
	if (unlikely(ret < 0)) {
		val = NNP_IPC_NO_MEMORY;
		goto free_config;
	}

	/* place a create infer request command to runtime */
	cmd_size = sizeof(*cmd_args) +
			n_inputs * sizeof(uint64_t) +
			n_outputs * sizeof(uint64_t) +
			config_data_size;

	cmd_args = kzalloc(cmd_size, GFP_KERNEL);
	if (unlikely(cmd_args == NULL)) {
		val = NNP_IPC_NO_MEMORY;
		ret = -ENOMEM;
		goto send_error;
	}

	cmd_args->infreq_drv_handle = infreq->ptr2id;
	cmd_args->devnet_rt_handle = infreq->devnet->rt_handle;
	cmd_args->n_inputs = n_inputs;
	cmd_args->n_outputs = n_outputs;
	cmd_args->config_data_size = config_data_size;
	cmd_args->infreq_id = (uint32_t)infreq->protocol_id;
	int64ptr = (uint64_t *)(cmd_args + 1);
	for (i = 0; i < n_inputs; i++)
		*(int64ptr++) = inputs[i]->rt_handle;
	for (i = 0; i < n_outputs; i++)
		*(int64ptr++) = outputs[i]->rt_handle;
	memcpy(int64ptr, config_data, config_data_size);

	NNP_SPIN_LOCK_IRQSAVE(&infreq->lock_irq, flags);
	if (unlikely(infreq->destroyed != 0)) {
		NNP_SPIN_UNLOCK_IRQRESTORE(&infreq->lock_irq, flags);
		goto done;
	}
	NNP_ASSERT(infreq->status == CREATE_STARTED);
	infreq->status = DMA_COMPLETED;
	// get kref for RT
	inf_req_get(infreq);
	NNP_SPIN_UNLOCK_IRQRESTORE(&infreq->lock_irq, flags);

	ret = inf_cmd_queue_add(&infreq->devnet->context->cmdq,
				SPHCS_RUNTIME_CMD_CREATE_INFREQ,
				cmd_args,
				cmd_size,
				NULL, NULL);
	kfree(cmd_args);
	if (unlikely(ret < 0)) {
		val = NNP_IPC_NO_MEMORY;
		goto send_error;
	}

	goto done;

put_outputs:
	for (--i; i < n_outputs; --i)
		inf_devres_put(outputs[i]);
	i = n_inputs;
put_inputs:
	for (--i; i < n_inputs; --i)
		inf_devres_put(inputs[i]);
free_config:
	if (config_data_size > 0)
		kfree(config_data);
free_out:
	kfree(outputs);
free_in:
	kfree(inputs);
send_error:
	sphcs_send_event_report_ext(sphcs, NNP_IPC_CREATE_INFREQ_FAILED, val, infreq->devnet->context->chan->respq,
				infreq->devnet->context->protocol_id,
				infreq->protocol_id,
				infreq->devnet->protocol_id);
	destroy_infreq_on_create_failed(infreq);
done:
	// put kref for DMA
	inf_req_put(infreq);
	dma_page_pool_set_page_free(sphcs->dma_page_pool,
				    dma_data->card_dma_page_hndl);
	return ret;
}

int inf_devnet_create_infreq(struct inf_devnet *devnet,
			     uint16_t           protocol_id,
			     dma_addr_t         host_dma_addr,
			     uint16_t           dma_size)
{
	struct infreq_dma_data dma_data;
	struct inf_req *infreq;
	int ret;

	ret = inf_req_create(protocol_id,
			     devnet,
			     &infreq);
	if (unlikely(ret < 0))
		return -ENOMEM;

	NNP_SPIN_LOCK(&devnet->lock);
	hash_add(devnet->infreq_hash, &infreq->hash_node, infreq->protocol_id);
	// get kref for DMA
	inf_req_get(infreq);
	NNP_SPIN_UNLOCK(&devnet->lock);

	ret = dma_page_pool_get_free_page(g_the_sphcs->dma_page_pool,
					  &dma_data.card_dma_page_hndl,
					  &dma_data.vptr,
					  &dma_data.card_dma_addr);

	if (unlikely(ret < 0))
		goto free_infreq;

	dma_data.host_dma_addr = host_dma_addr;
	dma_data.infreq = infreq;
#ifdef _DEBUG
	dma_data.size = dma_size;
#endif

	ret = sphcs_dma_sched_start_xfer_single(g_the_sphcs->dmaSched,
						&devnet->context->chan->h2c_dma_desc,
						dma_data.host_dma_addr,
						dma_data.card_dma_addr,
						dma_size,
						inf_req_create_dma_complete_callback,
						NULL,
						&dma_data,
						sizeof(dma_data));
	if (unlikely(ret < 0))
		goto free_page;

	return 0;

free_page:
	dma_page_pool_set_page_free(g_the_sphcs->dma_page_pool,
				    dma_data.card_dma_page_hndl);
free_infreq:
	destroy_infreq_on_create_failed(infreq);
	// put previously got kref
	inf_req_put(infreq);

	return ret;
}

struct inf_req *inf_devnet_find_infreq(struct inf_devnet *devnet,
				       uint16_t           protocol_id)
{
	struct inf_req *infreq;

	NNP_SPIN_LOCK(&devnet->lock);
	hash_for_each_possible(devnet->infreq_hash,
			       infreq,
			       hash_node,
			       protocol_id)
		if (infreq->protocol_id == protocol_id) {
			NNP_SPIN_UNLOCK(&devnet->lock);
			return infreq;
		}
	NNP_SPIN_UNLOCK(&devnet->lock);

	return NULL;
}

struct inf_req *inf_devnet_find_and_get_infreq(struct inf_devnet *devnet,
					       uint16_t           protocol_id)
{
	struct inf_req *infreq;

	NNP_SPIN_LOCK(&devnet->lock);
	hash_for_each_possible(devnet->infreq_hash,
			       infreq,
			       hash_node,
			       protocol_id)
		if (infreq->protocol_id == protocol_id) {
			if (unlikely(infreq->status != CREATED))
				break;
			if (unlikely(infreq->destroyed || inf_req_get(infreq) == 0))
				break;
			NNP_SPIN_UNLOCK(&devnet->lock);
			return infreq;
		}
	NNP_SPIN_UNLOCK(&devnet->lock);

	return NULL;
}

int inf_devnet_destroy_all_infreq(struct inf_devnet *devnet)
{
	struct inf_req *infreq;
	unsigned long flags;
	int i;
	bool found = true;

	inf_devnet_get(devnet);

	do {
		found = false;
		NNP_SPIN_LOCK(&devnet->lock);
		hash_for_each(devnet->infreq_hash, i, infreq, hash_node) {
			NNP_SPIN_LOCK_IRQSAVE(&infreq->lock_irq, flags);
			if (!infreq->destroyed)
				found = true;
			infreq->destroyed = -1;
			NNP_SPIN_UNLOCK_IRQRESTORE(&infreq->lock_irq, flags);

			if (found) {
				NNP_SPIN_UNLOCK(&devnet->lock);
				inf_req_put(infreq);
				break;
			}
		}
	} while (found);
	NNP_SPIN_UNLOCK(&devnet->lock);

	inf_devnet_put(devnet);

	return 0;
}

int inf_devnet_find_and_destroy_infreq(struct inf_devnet *devnet,
				       uint16_t           infreqID)
{
	struct inf_req *iter, *infreq = NULL;
	unsigned long flags;

	NNP_SPIN_LOCK(&devnet->lock);
	hash_for_each_possible(devnet->infreq_hash, iter, hash_node, infreqID)
		if (iter->protocol_id == infreqID) {
			infreq = iter;
			break;
		}
	if (unlikely(infreq == NULL)) {
		NNP_SPIN_UNLOCK(&devnet->lock);
		return -ENXIO;
	}

	NNP_SPIN_LOCK_IRQSAVE(&infreq->lock_irq, flags);
	if (unlikely(infreq->destroyed != 0)) {
		NNP_SPIN_UNLOCK_IRQRESTORE(&infreq->lock_irq, flags);
		NNP_SPIN_UNLOCK(&devnet->lock);
		return -ENXIO;
	}
	infreq->destroyed = 1;
	NNP_SPIN_UNLOCK_IRQRESTORE(&infreq->lock_irq, flags);
	NNP_SPIN_UNLOCK(&devnet->lock);

	// kref for host
	inf_req_put(infreq);

	return 0;
}
