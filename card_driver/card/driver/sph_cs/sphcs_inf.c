/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#include "sphcs_inf.h"
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/hashtable.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>
#include "sphcs_cs.h"
#include "ioctl_inf.h"
#include "sph_log.h"
#include "nnp_error.h"
#include "inf_cmdq.h"
#include "inf_context.h"
#include "inf_devres.h"
#include "inf_devnet.h"
#include "inf_copy.h"
#include "inf_cpylst.h"
#include "inf_req.h"
#include "nnp_boot_defs.h"
#include "sphcs_trace.h"
#include "sphcs_ctx_uids.h"
#include "sphcs_cmd_chan.h"
#include "safe_mem_lib.h"
#include <linux/module.h>
#include "inf_ptr2id.h"

#define PTR2ID_SLOTS_HASH_BITS 16
static DEFINE_HASHTABLE(ptr2id_slots_hash, PTR2ID_SLOTS_HASH_BITS);
static DEFINE_SPINLOCK(ptr2id_lock);
static unsigned int ptr2id_counter;

struct ptr2id_struct {
	unsigned int id;
	void *ptr;
	struct hlist_node hash_node;
};

static void *id2ptr(unsigned int id)
{
	struct ptr2id_struct *p_id;
	unsigned int lid;

	if (!id)
		return NULL;
	lid = (unsigned int)id;
	NNP_SPIN_LOCK(&ptr2id_lock);
	hash_for_each_possible(ptr2id_slots_hash, p_id, hash_node, lid)
		if (p_id->id == lid) {
			NNP_SPIN_UNLOCK(&ptr2id_lock);
			return p_id->ptr;
		}
	NNP_SPIN_UNLOCK(&ptr2id_lock);
	return NULL;
}

static unsigned int ptr2id(void *ptr)
{
	struct ptr2id_struct *p_id;
	int bkt;

	NNP_SPIN_LOCK(&ptr2id_lock);

	hash_for_each(ptr2id_slots_hash, bkt, p_id, hash_node) {
		if (p_id->ptr == ptr) {
			NNP_SPIN_UNLOCK(&ptr2id_lock);
			return p_id->id;
		}
	}
	NNP_SPIN_UNLOCK(&ptr2id_lock);
	return 0;
}

static unsigned int get_new_id(void)
{
	unsigned int i = 1;
	unsigned int id;

	while (i++ != 0) {
		NNP_SPIN_LOCK(&ptr2id_lock);
		ptr2id_counter++;
		if (ptr2id_counter == 0)
			ptr2id_counter++;//Handle overflow
		id = ptr2id_counter;
		NNP_SPIN_UNLOCK(&ptr2id_lock);
		if (id2ptr(id) == NULL)
			return id;
	}
	return 0; // no free id available
}

unsigned int add_ptr2id(void *ptr)
{
	struct ptr2id_struct *p_id;
	unsigned int id;

	if (!ptr)
		return 0;

	id = ptr2id(ptr);
	if (id)
		return id;

	p_id = kzalloc(sizeof(*p_id), GFP_KERNEL);
	if (WARN_ON(!p_id))
		return 0;

	p_id->ptr = ptr;
	p_id->id = get_new_id();
	if (p_id->id == 0) {
		kfree(p_id);
		return 0;
	}
	NNP_SPIN_LOCK(&ptr2id_lock);
	hash_add(ptr2id_slots_hash, &p_id->hash_node, p_id->id);
	NNP_SPIN_UNLOCK(&ptr2id_lock);
	return p_id->id;
}

void del_ptr2id(void *ptr)
{
	int i;
	struct hlist_node *tmp;
	struct ptr2id_struct *p_id;

	NNP_SPIN_LOCK(&ptr2id_lock);
	hash_for_each_safe(ptr2id_slots_hash, i, tmp, p_id, hash_node) {
		if (p_id->ptr == ptr) {
			hash_del(&p_id->hash_node);
			NNP_SPIN_UNLOCK(&ptr2id_lock);
			kfree(p_id);
			return;
		}
	}
	NNP_SPIN_UNLOCK(&ptr2id_lock);
}


void clean_ptr2id(void)
{
	int i;
	struct hlist_node *tmp;
	struct ptr2id_struct *p_id;

	NNP_SPIN_LOCK(&ptr2id_lock);
	hash_for_each_safe(ptr2id_slots_hash, i, tmp, p_id, hash_node) {
		hash_del(&p_id->hash_node);
		kfree(p_id);
	}
	NNP_SPIN_UNLOCK(&ptr2id_lock);
}

/* min system memory threshold in KB */
static uint32_t mem_thr;
module_param(mem_thr, uint, 0644);

static inline bool check_memory_threshold(void)
{
	if (mem_thr) {
		uint32_t available_ram_kb = si_mem_available() << (NNP_PAGE_SHIFT - 10);

		if (available_ram_kb < mem_thr) {
			sph_log_err(CREATE_COMMAND_LOG, "Available memory (%u KB) below the threshold (%u KB) ", available_ram_kb, mem_thr);
			return false;
		}
	}
	return true;
}

static struct cdev s_cdev;
static dev_t       s_devnum;
static struct class *s_class;
static struct device *s_dev;

struct inf_daemon {
	struct inf_cmd_queue cmdq;
	struct list_head alloc_req_list;
	spinlock_t       lock;
};

struct alloc_req {
	sphcs_alloc_resource_callback cb;
	void                         *context;
	struct list_head              node;
};

struct req_params {
	uint16_t             idx;
	size_t               size;
	//priority 0 == normal, 1 == high
	uint8_t              priority;

	union {
		struct {
			uint16_t           cpy_idx;
		};//cpylst
		//copy does not has specific params
		struct {
			bool              sched_params_is_null;
			uint8_t           debugOn : 1;
			uint8_t           collectInfo : 1;
			uint8_t           reserved : 6;
		};//infreq
	};
};

static int init_daemon(struct inf_data *inf_data)
{
	mutex_lock(&inf_data->io_lock);

	if (unlikely(inf_data->daemon != NULL)) {
		mutex_unlock(&inf_data->io_lock);
		return -EEXIST;
	}

	inf_data->daemon = kzalloc(sizeof(*inf_data->daemon), GFP_NOWAIT);
	if (unlikely(inf_data->daemon == NULL)) {
		mutex_unlock(&inf_data->io_lock);
		return -ENOMEM;
	}

	inf_cmd_queue_init(&inf_data->daemon->cmdq);

	INIT_LIST_HEAD(&inf_data->daemon->alloc_req_list);
	spin_lock_init(&inf_data->daemon->lock);

	// Set card boot state as "Card ready"
	g_the_sphcs->hw_ops->set_card_doorbell_value(g_the_sphcs->hw_handle,
				    (NNP_CARD_BOOT_STATE_CARD_READY <<
				     NNP_CARD_BOOT_STATE_SHIFT));

	mutex_unlock(&inf_data->io_lock);
	return 0;
}

#ifdef ULT
static int switch_daemon(struct inf_data *inf_data)
{
	int ret;

	mutex_lock(&inf_data->io_lock);

	if (unlikely(inf_data->ult_daemon_save != NULL)) {
		mutex_unlock(&inf_data->io_lock);
		return -EEXIST;
	}

	if (likely(inf_data->daemon != NULL)) {
		inf_data->ult_daemon_save = inf_data->daemon;
		inf_data->daemon = NULL;
	}

	mutex_unlock(&inf_data->io_lock);

	ret = init_daemon(inf_data);

	if (unlikely(ret < 0)) {
		mutex_lock(&inf_data->io_lock);
		inf_data->daemon = inf_data->ult_daemon_save;
		inf_data->ult_daemon_save = NULL;
		mutex_unlock(&inf_data->io_lock);
	}

	return ret;
}
#endif

static void release_pending_create_context_reuquests(void *cmd_args);

static void fini_daemon(struct inf_data *inf_data)
{
	struct alloc_req *req;
	struct inf_context *context;
	bool ctx_found = true;
	int i;

	mutex_lock(&inf_data->io_lock);

	/*
	 * if pending allocation requests have not been replied
	 * use the request callback to report error to the requester.
	 */
	NNP_SPIN_LOCK(&inf_data->daemon->lock);
	while (!list_empty(&inf_data->daemon->alloc_req_list)) {
		req = list_first_entry(&inf_data->daemon->alloc_req_list, struct alloc_req, node);
		list_del(&req->node);
		NNP_SPIN_UNLOCK(&inf_data->daemon->lock);
		req->cb(g_the_sphcs,
			req->context,
			-1,
			IOCTL_SPHCS_NO_DEVICE);
		kfree(req);
		NNP_SPIN_LOCK(&inf_data->daemon->lock);
	}
	NNP_SPIN_UNLOCK(&inf_data->daemon->lock);

	sph_log_debug(START_UP_LOG, "Send context failed to all pending requests\n");
	//Delete all pending context request and send failed message to host
	inf_cmd_queue_exe(&inf_data->daemon->cmdq, SPHCS_DAEMON_CMD_CREATE_CONTEXT, release_pending_create_context_reuquests);

	/* Pass through all existing context and release daemon reference
	 * since context could be removed from hash in inf_context_put,
	 * so we need to pass one by one on the hash and release reference
	 */
	do {
		ctx_found = false;
		NNP_SPIN_LOCK_BH(&inf_data->lock_bh);
		hash_for_each(inf_data->context_hash, i, context, hash_node) {
			/* check if context daemon reference didn't released yet, then do it.
			 * this needed in case some runtime died, then daemon got killed
			 */
			if (!context->daemon_ref_released) {
				ctx_found = true;
				NNP_SPIN_UNLOCK_BH(&inf_data->lock_bh);
				context->daemon_ref_released = true;
				inf_context_put(context);
				break;
			}
		}
	} while (ctx_found);
	NNP_SPIN_UNLOCK_BH(&inf_data->lock_bh);

	inf_cmd_queue_fini(&inf_data->daemon->cmdq);

	kfree(inf_data->daemon);
#ifdef ULT
	inf_data->daemon = inf_data->ult_daemon_save;
	inf_data->ult_daemon_save = NULL;
#else
	inf_data->daemon = NULL;
#endif

	// Set card boot state as "Driver ready"
	if (inf_data->daemon == NULL)
		g_the_sphcs->hw_ops->set_card_doorbell_value(g_the_sphcs->hw_handle,
							     (NNP_CARD_BOOT_STATE_DRV_READY <<
							      NNP_CARD_BOOT_STATE_SHIFT));

	mutex_unlock(&inf_data->io_lock);
}

static struct inf_context *find_and_get_context(struct inf_data *inf_data, uint16_t protocol_id)
{
	struct inf_context *context;

	NNP_SPIN_LOCK_BH(&inf_data->lock_bh);
	hash_for_each_possible(inf_data->context_hash,
			       context,
			       hash_node,
			       protocol_id)
		if (context->protocol_id == protocol_id) {
			if (unlikely(inf_context_get(context) == 0))
				break; //release is in progress
			NNP_SPIN_UNLOCK_BH(&inf_data->lock_bh);
			return context;
		}
	NNP_SPIN_UNLOCK_BH(&inf_data->lock_bh);

	return NULL;
}

static void recover_context(struct sphcs *sphcs, struct inf_context *context)
{
	uint8_t event = NNP_IPC_RECOVER_CONTEXT_SUCCESS;
	enum event_val val = NNP_IPC_NO_ERROR;

	NNP_ASSERT(context != NULL);
	sph_log_info(CREATE_COMMAND_LOG, "Attempt to recover context (0x%x) from state: %u\n",
		     context->protocol_id, inf_context_get_state(context));

	switch (inf_context_get_state(context)) {
	case CONTEXT_BROKEN_RECOVERABLE:
		inf_context_set_state(context, CONTEXT_OK);
		break;
	case CONTEXT_BROKEN_NON_RECOVERABLE:
		sph_log_info(CREATE_COMMAND_LOG, "Unable to recover context (0x%x) from non recoverable state\n",
				context->protocol_id);
		event = NNP_IPC_RECOVER_CONTEXT_FAILED;
		val = NNP_IPC_CONTEXT_BROKEN;
		break;
	case CONTEXT_OK:
		sph_log_info(CREATE_COMMAND_LOG, "Got request to recover non-broken context: 0x%x\n",
				context->protocol_id);
		break;
	default:
		sph_log_info(CREATE_COMMAND_LOG, "Unable to recover context (0x%x) which is in unknown state %d\n",
				context->protocol_id, context->state);
		event = NNP_IPC_RECOVER_CONTEXT_FAILED;
		val = NNP_IPC_CONTEXT_BROKEN;
	}
	sphcs_send_event_report(sphcs, event, val, context->chan->respq, context->protocol_id, -1);
}

static inline void destroy_context_on_create_failed(struct sphcs *sphcs, struct inf_context *context)
{
	NNP_SPIN_LOCK_BH(&sphcs->inf_data->lock_bh);
	NNP_ASSERT(context->attached == 0);
	if (unlikely(context->destroyed)) {
		NNP_SPIN_UNLOCK_BH(&sphcs->inf_data->lock_bh);
		return;
	}
	context->destroyed = -1;
	NNP_SPIN_UNLOCK_BH(&sphcs->inf_data->lock_bh);

	inf_context_put(context);
}

static inline int find_and_destroy_context(struct inf_data *inf_data, uint16_t ctxID)
{
	struct inf_context *iter, *context = NULL;

	NNP_SPIN_LOCK_BH(&inf_data->lock_bh);
	hash_for_each_possible(inf_data->context_hash, iter, hash_node, ctxID)
		if (iter->protocol_id == ctxID) {
			context = iter;
			break;
		}

	if (unlikely(context == NULL)) {
		NNP_SPIN_UNLOCK_BH(&inf_data->lock_bh);
		return -ENXIO;
	}

	if (context->destroyed) {
		NNP_SPIN_UNLOCK_BH(&inf_data->lock_bh);
		return 0;
	}

	context->destroyed = 1;
	NNP_SPIN_UNLOCK_BH(&inf_data->lock_bh);

	inf_context_put(context);

	return 0;
}

static void sphcs_inf_context_chan_cleanup(struct sphcs_cmd_chan *chan, void *cb_ctx)
{
	struct inf_context *context = (struct inf_context *)cb_ctx;

	inf_context_destroy_objects(context);
	find_and_destroy_context(g_the_sphcs->inf_data, context->protocol_id);
}

enum event_val create_context(struct sphcs *sphcs, uint16_t protocol_id, uint8_t flags, uint32_t uid, struct sphcs_cmd_chan *chan)
{
	struct inf_context *context;
	struct inf_create_context cmd_args;
	int ret;

	ret = inf_context_create(protocol_id, chan, &context);
	if (unlikely(ret < 0))
		return NNP_IPC_NO_MEMORY;

	CTX_UIDS_SET_UID(context->protocol_id, uid);

	/* place a create context command for the daemon */
	cmd_args.contextID = protocol_id;
	cmd_args.flags = flags;

	mutex_lock(&sphcs->inf_data->io_lock);
	if (unlikely(!sphcs->inf_data->daemon)) {
		mutex_unlock(&sphcs->inf_data->io_lock);
		destroy_context_on_create_failed(sphcs, context);
		return NNP_IPC_NO_DAEMON;
	}
	// Take kref, dedicated to daemon
	inf_context_get(context);
	context->daemon_ref_released = false;

	ret = inf_cmd_queue_add(&sphcs->inf_data->daemon->cmdq,
				SPHCS_DAEMON_CMD_CREATE_CONTEXT,
				&cmd_args,
				sizeof(cmd_args),
				NULL, NULL);

	if (unlikely(ret < 0)) {
		destroy_context_on_create_failed(sphcs, context);
		// release kref dedicated for daemon
		inf_context_put(context);
		mutex_unlock(&sphcs->inf_data->io_lock);
		return NNP_IPC_NO_MEMORY;
	}
	mutex_unlock(&sphcs->inf_data->io_lock);

	chan->destroy_cb = sphcs_inf_context_chan_cleanup;
	chan->destroy_cb_ctx = context;

	return NNP_IPC_NO_ERROR;
}

static void detach_runtime(struct sphcs *sphcs, struct inf_context *context)
{
	if (likely(context->attached > 0)) {

		context->attached = -1; //Lock is not needed here

		if (unlikely(!context->destroyed)) {
			inf_context_set_state(context, CONTEXT_BROKEN_NON_RECOVERABLE);
			sphcs_send_event_report(sphcs,
						NNP_IPC_ERROR_RUNTIME_DIED,
						0,
						context->chan->respq,
						context->protocol_id,
						-1);
		}

		del_all_active_create_and_inf_requests(context);
		// no runtime attached anymore, release kref took for runtime
		inf_context_put(context);
	}
}

void handle_daemon_error(const struct inf_error_ioctl *err_ioctl)
{
	struct inf_context *context;

	if (err_ioctl->errorCode == NNP_IPC_ERROR_RUNTIME_LAUNCH ||
	    err_ioctl->errorCode == NNP_IPC_ERROR_RUNTIME_DIED ||
	    err_ioctl->errorCode == NNP_IPC_RUNTIME_DONE) {

		if (err_ioctl->errorCode != NNP_IPC_RUNTIME_DONE)
			sph_log_err(GENERAL_LOG, "got daemon error %d val=%d\n",
					err_ioctl->errorCode, err_ioctl->errorVal);

		context = find_and_get_context(g_the_sphcs->inf_data,
							   err_ioctl->errorVal);
		if (unlikely(context == NULL)) {
			sph_log_err(GENERAL_LOG, "Got error(%u) for not existing context(%u)\n",
					err_ioctl->errorCode, err_ioctl->errorVal);
			return;
		}
		NNP_ASSERT(!context->daemon_ref_released);
		inf_context_put(context);

		/* if the failure happened during context creation phase
		 * (have not yet attached or detached) destroy the context
		 */
		if (context->attached == 0) {

			enum event_val val;

			if (err_ioctl->errorCode == NNP_IPC_ERROR_RUNTIME_LAUNCH) {
				val = NNP_IPC_RUNTIME_LAUNCH_FAILED;
			} else {
				val = NNP_IPC_RUNTIME_FAILED;
			}

			sphcs_send_event_report(g_the_sphcs,
					NNP_IPC_CREATE_CONTEXT_FAILED,
					val,
					NULL,
					err_ioctl->errorVal,
					-1);
			destroy_context_on_create_failed(g_the_sphcs, context);
		}
		context->daemon_ref_released = true;
		inf_context_put(context);
	} else {
		sph_log_err(GENERAL_LOG, "Got unknown error code from daemon %u\n",
			    err_ioctl->errorCode);
	}
}

void handle_runtime_error(struct inf_context *context,
			  const struct inf_error_ioctl *err_ioctl)
{
}

/*****************************************************************************
 * Inference cdev file operations (interface to daemon/runtime)
 *****************************************************************************/
static inline int is_inf_file(struct file *f);

static int sphcs_inf_open(struct inode *inode, struct file *f)
{
	if (unlikely(!is_inf_file(f)))
		return -EINVAL;

	f->private_data = NULL;

	return 0;
}

static int sphcs_inf_release(struct inode *inode, struct file *f)
{
	if (unlikely(!is_inf_file(f)))
		return -EINVAL;

	if (f->private_data == NULL)
		return 0;

	if (f->private_data == g_the_sphcs->inf_data->daemon) {
		fini_daemon(g_the_sphcs->inf_data);
	} else if (is_inf_context_ptr(f->private_data)) {
		struct inf_context *context = (struct inf_context *)f->private_data;

		detach_runtime(g_the_sphcs, context);
	}

	return 0;
}

static int handle_get_alloc_pgt(void __user *arg)
{
	struct inf_get_alloc_pgt req;
	struct dma_buf   *dma_buf;
	struct dma_buf_attachment *dma_att;
	struct sg_table  *dma_map;
	struct scatterlist *sgl;
	struct inf_alloc_pgt_entry entry;
	uint32_t nchunks = 0;
	int ret = 0;

	ret = copy_from_user(&req, arg, sizeof(req));
	if (ret)
		return -EIO;

	if (req.num_entries < 1)
		return -EINVAL;

	dma_buf = dma_buf_get(req.buf_fd);
	if (PTR_ERR_OR_ZERO(dma_buf))
		return -EINVAL;

	dma_att = dma_buf_attach(dma_buf, g_the_sphcs->hw_device);
	if (PTR_ERR_OR_ZERO(dma_att)) {
		ret = -EINVAL;
		goto fail_attach;
	}

	dma_map = dma_buf_map_attachment(dma_att, DMA_BIDIRECTIONAL);
	if (PTR_ERR_OR_ZERO(dma_map)) {
		ret = -EINVAL;
		goto fail_map;
	}

	sgl = dma_map->sgl;
	while (sgl &&
	       nchunks < req.num_entries) {
		entry.phys = sgl->dma_address;
		entry.size = sgl->length;
		ret = copy_to_user(&req.entries[nchunks], &entry, sizeof(entry));
		if (ret) {
			ret = -EIO;
			goto done;
		}

		nchunks++;
		sgl = sg_next(sgl);
	}

	req.num_entries = nchunks;
	ret = copy_to_user(arg, &req, sizeof(req));
	if (ret)
		ret = -EIO;

done:
	dma_buf_unmap_attachment(dma_att,
				 dma_map,
				 DMA_BIDIRECTIONAL);
fail_map:
	dma_buf_detach(dma_buf, dma_att);
fail_attach:
	dma_buf_put(dma_buf);

	return ret;
}

static long sphcs_inf_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	long ret;
	uint32_t            context_id;
	struct inf_context *context;

	if (unlikely(!is_inf_file(f)))
		return -EINVAL;

	switch (cmd) {
	case IOCTL_INF_ATTACH_DAEMON:
		ret = init_daemon(g_the_sphcs->inf_data);
		if (unlikely(ret < 0))
			return ret;

		f->private_data = g_the_sphcs->inf_data->daemon;
		break;
#ifdef ULT
	case IOCTL_INF_SWITCH_DAEMON:
		ret = switch_daemon(g_the_sphcs->inf_data);
		if (unlikely(ret < 0))
			return ret;

		f->private_data = g_the_sphcs->inf_data->daemon;
		break;
#endif
	case IOCTL_INF_ALLOC_RESOURCE_REPLY: {
		struct inf_alloc_resource_reply reply;
		struct alloc_req *req;

		ret = copy_from_user(&reply,
				     (void __user *)arg,
				     sizeof(reply));
		if (unlikely(ret != 0))
			return -EIO;

		if (unlikely(f->private_data != g_the_sphcs->inf_data->daemon))
			return -EINVAL;

		NNP_SPIN_LOCK(&g_the_sphcs->inf_data->daemon->lock);
		list_for_each_entry(req,
				    &g_the_sphcs->inf_data->daemon->alloc_req_list,
				    node) {
			if ((uint64_t)req ==  (uint64_t)id2ptr(reply.drv_handle)) {
				list_del(&req->node);
				break;
			}
		}
		NNP_SPIN_UNLOCK(&g_the_sphcs->inf_data->daemon->lock);
		if (unlikely(&req->node == &g_the_sphcs->inf_data->daemon->alloc_req_list))
			return -EINVAL;

		req->cb(g_the_sphcs,
			req->context,
			reply.buf_fd,
			reply.i_sphcs_err);
		kfree(req);
		break;
	}

	case IOCTL_INF_ATTACH_CONTEXT:
		if (unlikely(f->private_data != NULL))
			return -EBUSY;

		ret = copy_from_user(&context_id,
				     (void __user *)arg,
				     sizeof(uint32_t));
		if (unlikely(ret != 0))
			return -EIO;

		context = find_and_get_context(g_the_sphcs->inf_data, context_id);
		if (unlikely(context == NULL))
			return -ENXIO;

		ret = inf_context_runtime_attach(context);
		if (unlikely(ret < 0)) {
			if (ret == -EPERM) {
				NNP_ASSERT(context->destroyed == 1);
				// This can happen only if user canceled create
				// that's why no need to send error report here
				destroy_context_on_create_failed(g_the_sphcs, context);
			} else {
				sph_log_debug(GENERAL_LOG, "Context %u was tried to be attached more than once\n", context_id);
			}
			// put for find_and_get_context
			inf_context_put(context);
			return ret;
		}
		sphcs_send_event_report(g_the_sphcs,
					NNP_IPC_CREATE_CONTEXT_SUCCESS,
					0,
					context->chan->respq,
					context_id,
					-1);

		// put for find_and_get_context
		inf_context_put(context);

		f->private_data = context;

		sph_log_debug(GENERAL_LOG, "Context %u attached\n", context_id);

		DO_TRACE(trace_infer_create(SPH_TRACE_INF_CONTEXT, context_id, context_id, SPH_TRACE_OP_STATUS_COMPLETE, -1, -1));
		break;
	case IOCTL_INF_RESOURCE_CREATE_REPLY: {
		struct inf_create_resource_reply reply;
		struct inf_devres *devres;
		enum event_val event_value;
		u16 event_val;
		int obj_id_1;
		int obj_id_2;

		ret = copy_from_user(&reply,
				     (void __user *)arg,
				     sizeof(reply));
		if (unlikely(ret != 0))
			return -EIO;

		devres = (struct inf_devres *)id2ptr(reply.drv_handle);
		if (unlikely(!is_inf_devres_ptr(devres)))
			return -EINVAL;

		if (unlikely(reply.i_sphcs_err != IOCTL_SPHCS_NO_ERROR)) {
			switch (reply.i_sphcs_err) {
			case IOCTL_SPHCS_ALLOC_FAILED:
			case IOCTL_SPHCS_NO_MEMORY:
				event_value = NNP_IPC_NO_MEMORY;
				break;
			default:
				event_value = NNP_IPC_RUNTIME_FAILED;
			}
			sph_log_err(CREATE_COMMAND_LOG, "runtime create_devres failed. err:%u.", reply.i_sphcs_err);
			goto failed_devres;
		}

		devres->rt_handle = reply.rt_handle;
		ret = inf_devres_attach_buf(devres,
					    reply.buf_fd);
		if (unlikely(ret < 0)) {
			event_value = NNP_IPC_NO_MEMORY;
			sph_log_err(CREATE_COMMAND_LOG, "inf_devres_attach_buf failed. err:%ld.", ret);
			goto send_rt_devres_destr;
		}

		DO_TRACE(trace_infer_create(SPH_TRACE_INF_DEVRES, devres->context->protocol_id,
			devres->protocol_id, SPH_TRACE_OP_STATUS_COMPLETE, -1, -1));

		/* Send event */
		event_val = 0;
		obj_id_1 = devres->protocol_id;
		obj_id_2 = -1;

		if (devres->is_p2p_dst)
			obj_id_2 = (sg_dma_address(&devres->dma_map->sgl[0]) - g_the_sphcs->inbound_mem_dma_addr) >> PAGE_SHIFT;

		if (inf_devres_is_p2p(devres))
			event_val = devres->p2p_buf.buf_id;

		sphcs_send_event_report_ext(g_the_sphcs,
					    NNP_IPC_CREATE_DEVRES_SUCCESS,
					    event_val,
					    devres->context->chan->respq,
					    devres->context->protocol_id,
					    obj_id_1,
					    obj_id_2);


		// put kref, taken for waiting for runtime response
		inf_devres_put(devres);

		break;

send_rt_devres_destr:
		send_runtime_destroy_devres(devres);
failed_devres:
		sphcs_send_event_report(g_the_sphcs,
					NNP_IPC_CREATE_DEVRES_FAILED,
					event_value,
					devres->context->chan->respq,
					devres->context->protocol_id,
					devres->protocol_id);
		destroy_devres_on_create_failed(devres);

		break;
	}
	case IOCTL_INF_NETWORK_CREATE_REPLY: {
		struct inf_create_network_reply reply;
		struct inf_devnet *devnet;
		uint8_t event;
		enum event_val event_val = NNP_IPC_NO_ERROR;

		ret = copy_from_user(&reply, (void __user *)arg, sizeof(reply));
		if (unlikely(ret != 0))
			return -EIO;

		devnet = (struct inf_devnet *)id2ptr(reply.devnet_drv_handle);
		if (unlikely(!is_inf_devnet_ptr(devnet)))
			return -EINVAL;

		if (unlikely(reply.i_sphcs_err != IOCTL_SPHCS_NO_ERROR)) {
			switch (reply.i_sphcs_err) {
			case IOCTL_SPHCS_NOT_SUPPORTED: {
				event_val = NNP_IPC_RUNTIME_NOT_SUPPORTED;
				break;
			}
			case IOCTL_SPHCS_INVALID_EXECUTABLE_NETWORK_BINARY: {
				event_val = NNP_IPC_RUNTIME_INVALID_EXECUTABLE_NETWORK_BINARY;
				break;
			}
			case IOCTL_SPHCS_NO_MEMORY: {
				event_val = NNP_IPC_NO_MEMORY;
				break;
			}
			case IOCTL_SPHCS_ECC_ALLOC_FAILED: {
				event_val = NNP_IPC_ECC_ALLOC_FAILED;
				break;
			}
			default: {
				event_val = NNP_IPC_RUNTIME_FAILED;
			}
			}
			if (!devnet->created)
				event = NNP_IPC_CREATE_DEVNET_FAILED;
			else
				event = NNP_IPC_DEVNET_ADD_RES_FAILED;
			sphcs_send_event_report(g_the_sphcs,
						event,
						event_val,
						devnet->context->chan->respq,
						devnet->context->protocol_id,
						devnet->protocol_id);
			goto failed_devnet;
		}
		NNP_SPIN_LOCK(&devnet->lock);
		devnet->edit_status = CREATED;
		NNP_SPIN_UNLOCK(&devnet->lock);

		// If create was canceled (devnet->destroyed is 1,
		// it can be canceled only by the host at this stage),
		// continue regularly.
		// The devnet will be destroyed on kref put
		// and will send destroy cmd to the runtime.
		if (!devnet->created) {
			devnet->rt_handle = reply.devnet_rt_handle;
			devnet->created = true;
			event = NNP_IPC_CREATE_DEVNET_SUCCESS;

			DO_TRACE(trace_infer_create(SPH_TRACE_INF_NETWORK, devnet->context->protocol_id, devnet->protocol_id,
					SPH_TRACE_OP_STATUS_COMPLETE, -1, -1));
		} else {
			/* mark all added resources as "attached" */
			inf_devnet_attach_all_devres(devnet);
			event = NNP_IPC_DEVNET_ADD_RES_SUCCESS;
		}

		sphcs_send_event_report(g_the_sphcs,
					event,
					event_val,
					devnet->context->chan->respq,
					devnet->context->protocol_id,
					devnet->protocol_id);

		// put kref, taken for waiting for runtime response
		inf_devnet_put(devnet);

		break;

failed_devnet:
		inf_devnet_on_create_or_add_res_failed(devnet);

		break;
	}
	case IOCTL_INF_INFREQ_CREATE_REPLY: {
		struct inf_create_infreq_reply reply;
		struct inf_req *infreq;
		enum event_val event_val;

		ret = copy_from_user(&reply, (void __user *)arg, sizeof(reply));
		if (unlikely(ret != 0))
			return -EIO;
		infreq = (struct inf_req *)id2ptr(reply.infreq_drv_handle);
		if (unlikely(!is_inf_req_ptr(infreq)))
			return -EINVAL;

		if (unlikely(reply.i_sphcs_err != IOCTL_SPHCS_NO_ERROR)) {
			switch (reply.i_sphcs_err) {
			case IOCTL_SPHCS_NOT_SUPPORTED: {
				event_val = NNP_IPC_RUNTIME_NOT_SUPPORTED;
				break;
			}
			case IOCTL_SPHCS_INFER_MISSING_RESOURCE: {
				event_val = NNP_IPC_RUNTIME_INFER_MISSING_RESOURCE;
				break;
			}
			case IOCTL_SPHCS_NO_MEMORY: {
				event_val = NNP_IPC_NO_MEMORY;
				break;
			}
			default: {
				event_val = NNP_IPC_RUNTIME_FAILED;
			}
			}
			sphcs_send_event_report_ext(g_the_sphcs,
					NNP_IPC_CREATE_INFREQ_FAILED,
					event_val,
					infreq->devnet->context->chan->respq,
					infreq->devnet->context->protocol_id,
					infreq->protocol_id,
					infreq->devnet->protocol_id);
			goto failed_infreq;
		}

		// If create was canceled (infreq->destroyed is 1, it can be
		// canceled only by the host at this stage) continue regularly.
		// The infreq will be destroyed on kref put
		// and will send destroy cmd to the runtime.
#ifdef _DEBUG
		if (unlikely(infreq->status == CREATED)) {
			sph_log_err(GENERAL_LOG, "Runtime(ctx %u) sent IOCTL_INF_INFREQ_CREATE_REPLY more than once (devnet %u,infreq%u)",
							infreq->devnet->protocol_id, infreq->devnet->context->protocol_id, infreq->protocol_id);
			break;
		}
#endif
		infreq->exec_cmd.infreq_rt_handle = reply.infreq_rt_handle;
		NNP_ASSERT(infreq->status == DMA_COMPLETED);
		infreq->status = CREATED;

		sphcs_send_event_report_ext(g_the_sphcs,
					NNP_IPC_CREATE_INFREQ_SUCCESS,
					0,
					infreq->devnet->context->chan->respq,
					infreq->devnet->context->protocol_id,
					infreq->protocol_id,
					infreq->devnet->protocol_id);
		DO_TRACE(trace_infer_create(SPH_TRACE_INF_INF_REQ, infreq->devnet->context->protocol_id,
				infreq->protocol_id, SPH_TRACE_OP_STATUS_COMPLETE, infreq->devnet->protocol_id, -1));

		// put kref, taken for waiting for runtime response
		inf_req_put(infreq);

		break;

failed_infreq:
		destroy_infreq_on_create_failed(infreq);

		break;
	}
	case IOCTL_INF_INFREQ_EXEC_DONE: {
		struct inf_infreq_exec_done reply;
		struct inf_req *infreq;
		struct inf_exec_req *req;
		int err = 0;

		ret = copy_from_user(&reply,
				     (void __user *)arg,
				     sizeof(reply));
		if (unlikely(ret != 0))
			return -EIO;
		infreq = (struct inf_req *)id2ptr(reply.infreq_drv_handle);
		if (unlikely(!is_inf_req_ptr(infreq)))
			return -EINVAL;

		if (reply.i_error_msg_size > 2*NNP_PAGE_SIZE)
			return -EINVAL;

		req = infreq->active_req;
		NNP_ASSERT(req != NULL);
		if (unlikely(req == NULL))
			return -EINVAL;

#ifdef _DEBUG
		if (unlikely(!is_inf_context_ptr(f->private_data)))
			return -EINVAL;
		if (unlikely(reply.infreq_ctx_id !=
		    ((struct inf_context *)f->private_data)->protocol_id))
			return -EINVAL;
#endif

		switch (reply.i_sphcs_err) {
		case IOCTL_SPHCS_NO_ERROR: {
			err = 0;
			break;
		}
		case IOCTL_SPHCS_NOT_SUPPORTED: {
			err = -NNPER_NOT_SUPPORTED;
			break;
		}
		case IOCTL_SPHCS_INFER_EXEC_ERROR: {
			err = -NNPER_INFER_EXEC_ERROR;
			break;
		}
		case IOCTL_SPHCS_INFER_ICEDRV_ERROR: {
			err = -NNPER_INFER_ICEDRV_ERROR;
			break;
		}
		case IOCTL_SPHCS_INFER_ICEDRV_ERROR_RESET: {
			err = -NNPER_INFER_ICEDRV_ERROR_RESET;
			break;
		}
		case IOCTL_SPHCS_INFER_ICEDRV_ERROR_CARD_RESET: {
			err = -NNPER_INFER_ICEDRV_ERROR_CARD_RESET;
			break;
		}
		case IOCTL_SPHCS_INFER_SCHEDULE_ERROR: {
			err = -NNPER_INFER_SCHEDULE_ERROR;
			break;
		}
		default:
			err = -EFAULT;
		}
		inf_req_complete(req, err,
				 reply.i_error_msg,
				 (reply.i_error_msg_size > 0 ? -reply.i_error_msg_size : 0));

		break;
	}
	case IOCTL_INF_ERROR_EVENT: {
		struct inf_error_ioctl err_ioctl;

		ret = copy_from_user(&err_ioctl,
				     (void __user *)arg,
				     sizeof(err_ioctl));
		if (unlikely(ret != 0))
			return -EIO;

		if (f->private_data == g_the_sphcs->inf_data->daemon)
			handle_daemon_error(&err_ioctl);
		else if (likely(is_inf_context_ptr(f->private_data)))
			handle_runtime_error(f->private_data, &err_ioctl);
		break;
	}
	case IOCTL_INF_DEVNET_RESOURCES_RESERVATION_REPLY: {
		struct inf_devnet_resource_reserve_reply reply;
		struct inf_devnet *devnet;
		uint8_t event;
		enum event_val event_val = NNP_IPC_NO_ERROR;

		ret = copy_from_user(&reply,
				(void __user *)arg,
				sizeof(reply));
		if (unlikely(ret != 0))
			return -EIO;
		devnet = (struct inf_devnet *)id2ptr(reply.devnet_drv_handle);
		if (unlikely(!is_inf_devnet_ptr(devnet)))
			return -EINVAL;

		NNP_SPIN_LOCK(&devnet->lock);
		devnet->edit_status = CREATED;
		NNP_SPIN_UNLOCK(&devnet->lock);

		if (unlikely(reply.i_sphcs_err != IOCTL_SPHCS_NO_ERROR)) {
			switch (reply.i_sphcs_err) {
			case IOCTL_SPHCS_INSUFFICIENT_RESOURCES: {
				event_val = NNP_IPC_DEVNET_RESERVE_INSUFFICIENT_RESOURCES;
				break;
			}
			case IOCTL_SPHCS_TIMED_OUT: {
				event_val = NNP_IPC_TIMEOUT_EXCEEDED;
				break;
			}
			default: {
				event_val = NNP_IPC_RUNTIME_FAILED;
			}
			}
			if (reply.reserve_resource)
				event = NNP_IPC_DEVNET_RESOURCES_RESERVATION_FAILED;
			else
				event = NNP_IPC_DEVNET_RESOURCES_RELEASE_FAILED;

		} else {
			if (reply.reserve_resource)
				event = NNP_IPC_DEVNET_RESOURCES_RESERVATION_SUCCESS;
			else
				event = NNP_IPC_DEVNET_RESOURCES_RELEASE_SUCCESS;
		}

		sphcs_send_event_report(g_the_sphcs, event, event_val, devnet->context->chan->respq,
				devnet->context->protocol_id, devnet->protocol_id);

		// put kref, taken for waiting for runtime response
		inf_devnet_put(devnet);
		break;
	}
	case IOCTL_INF_DEVNET_RESET_REPLY: {
		struct inf_devnet_reset_reply reply;
		struct inf_devnet *devnet;
		struct inf_cmd_list *cmdlist;

		ret = copy_from_user(&reply,
				(void __user *)arg,
				sizeof(reply));
		if (unlikely(ret != 0))
			return -EIO;
		devnet = (struct inf_devnet *)id2ptr(reply.devnet_drv_handle);
		if (unlikely(!is_inf_devnet_ptr(devnet)))
			return -EINVAL;

		if (reply.cmdlist_drv_handle != 0) {
			cmdlist = (struct inf_cmd_list *)id2ptr(reply.cmdlist_drv_handle);
			if (unlikely(!is_inf_cmd_ptr(cmdlist)))
				return -EINVAL;
			inf_exec_error_list_devnet_reset_done(&cmdlist->error_list,
							      devnet->protocol_id,
							      cmdlist,
							      reply.i_sphcs_err != IOCTL_SPHCS_NO_ERROR);
		} else {
			context = (struct inf_context *)f->private_data;
			if (unlikely(!is_inf_context_ptr(f->private_data)))
				return -EINVAL;
			inf_exec_error_list_devnet_reset_done(&context->error_list,
							      devnet->protocol_id,
							      NULL,
							      reply.i_sphcs_err != IOCTL_SPHCS_NO_ERROR);
		}
		break;
	}
	case IOCTL_INF_GET_ALLOC_PGT:
		return handle_get_alloc_pgt((void __user *)arg);
	default:
		return -EINVAL;
	}

	return 0;
}


static unsigned int sphcs_inf_poll(struct file *f, struct poll_table_struct *pt)
{
	unsigned int mask = 0;
	struct inf_daemon *daemon;

	if (unlikely(!is_inf_file(f)))
		return -EINVAL;

	daemon = g_the_sphcs->inf_data->daemon;

	if (f->private_data == daemon)
		mask = inf_cmd_queue_poll(&daemon->cmdq, f, pt);
	else if (is_inf_context_ptr(f->private_data)) {
		struct inf_context *context = (struct inf_context *)f->private_data;

		mask = inf_cmd_queue_poll(&context->cmdq, f, pt);
	}

	return mask;

}


static ssize_t sphcs_inf_read(struct file *f,
			      char __user *buf,
			      size_t       size,
			      loff_t      *off)
{
	struct inf_daemon *daemon;

	if (unlikely(!is_inf_file(f) || !f->private_data))
		return -EINVAL;

	daemon = g_the_sphcs->inf_data->daemon;

	if (f->private_data == daemon) {
		return inf_cmd_queue_read(&daemon->cmdq,
					  buf, size, off);
	} else if (is_inf_context_ptr(f->private_data)) {
		struct inf_context *context = (struct inf_context *)f->private_data;

		return inf_cmd_queue_read(&context->cmdq, buf, size, off);
	}

	return 0;
}

struct context_op_work {
	struct work_struct           work;
	union h2c_ChanInferenceContextOp cmd;
	struct sphcs_cmd_chan       *chan;
};

static void context_op_work_handler(struct work_struct *work)
{
	struct context_op_work *op = container_of(work,
						  struct context_op_work,
						  work);
	struct sphcs *sphcs = g_the_sphcs;
	struct inf_context *context;
	uint8_t event;
	enum event_val val = NNP_IPC_NO_ERROR;
	int ret;

	if (!op->cmd.recover && !op->cmd.destroy)
		if (!check_memory_threshold()) {
			event = NNP_IPC_CREATE_CONTEXT_FAILED;
			val = NNP_IPC_NO_MEMORY;
			goto send_error;
		}

	if (op->cmd.destroy) {
		ret = find_and_destroy_context(sphcs->inf_data, op->cmd.chan_id);
		if (unlikely(ret < 0)) {
			event = NNP_IPC_DESTROY_CONTEXT_FAILED;
			val = NNP_IPC_NO_SUCH_CONTEXT;
			goto send_error;
		}
		if (op->chan)
			sphcs_cmd_chan_put(op->chan);
	} else {
		context = find_and_get_context(sphcs->inf_data, op->cmd.chan_id);
		if (op->cmd.recover) {
			if (unlikely(context == NULL || context->destroyed != 0)) {
				if (context != NULL)
					inf_context_put(context);
				event = NNP_IPC_RECOVER_CONTEXT_FAILED;
				val = NNP_IPC_NO_SUCH_CONTEXT;
				goto send_error;
			}

			recover_context(sphcs, context);
			inf_context_put(context);
			if (op->chan)
				sphcs_cmd_chan_put(op->chan);
		} else {
			if (unlikely(context != NULL)) {
				inf_context_put(context);
				event = NNP_IPC_CREATE_CONTEXT_FAILED;
				val = NNP_IPC_ALREADY_EXIST;
				goto send_error;
			}

			DO_TRACE(trace_infer_create(SPH_TRACE_INF_CONTEXT, op->cmd.chan_id, op->cmd.chan_id, SPH_TRACE_OP_STATUS_START, -1, -1));

			val = create_context(sphcs, op->cmd.chan_id, op->cmd.cflags, op->chan->uid, op->chan);
			if (unlikely(val != 0)) {
				event = NNP_IPC_CREATE_CONTEXT_FAILED;
				goto send_error;
			}
		}
	}

	goto done;

send_error:
	sphcs_send_event_report(sphcs, event, val, op->chan->respq, op->cmd.chan_id, -1);
	sphcs_cmd_chan_put(op->chan);
done:
	kfree(op);
}

void IPC_OPCODE_HANDLER(CHAN_INF_CONTEXT)(struct sphcs *sphcs,
					  union h2c_ChanInferenceContextOp *cmd)
{
	struct context_op_work *work;
	uint8_t event;
	struct sphcs_cmd_chan *chan;

	chan = sphcs_find_channel(sphcs, cmd->chan_id);

	work = kzalloc(sizeof(*work), GFP_NOWAIT);
	if (unlikely(work == NULL || chan == NULL)) {
		if (cmd->recover)
			event = NNP_IPC_RECOVER_CONTEXT_FAILED;
		else if (cmd->destroy)
			event = NNP_IPC_DESTROY_CONTEXT_FAILED;
		else
			event = NNP_IPC_CREATE_CONTEXT_FAILED;

		sphcs_send_event_report(sphcs,
					event,
					NNP_IPC_NO_MEMORY,
					chan != NULL ? chan->respq : NULL,
					cmd->chan_id,
					-1);

		if (chan != NULL)
			sphcs_cmd_chan_put(chan);
		if (work != NULL)
			kfree(work);
		return;
	}

	work->cmd.value = cmd->value;
	work->chan = chan;
	INIT_WORK(&work->work, context_op_work_handler);

	DO_TRACE_IF(!cmd->destroy && !cmd->recover, trace_infer_create(SPH_TRACE_INF_CONTEXT,
			cmd->chan_id, cmd->chan_id, SPH_TRACE_OP_STATUS_QUEUED, -1, -1));

	queue_work(chan->wq, &work->work);
}

void IPC_OPCODE_HANDLER(CHAN_SYNC)(struct sphcs   *sphcs,
				   union h2c_ChanSync *cmd)
{
	struct inf_context *context;

	DO_TRACE(trace_infer_create(SPH_TRACE_INF_INF_SYNC, cmd->chan_id, cmd->syncSeq, SPH_TRACE_OP_STATUS_QUEUED, -1, -1));

	context = find_and_get_context(sphcs->inf_data, cmd->chan_id);
	if (unlikely(context == NULL || context->destroyed != 0)) {
		sphcs_send_event_report(sphcs,
					NNP_IPC_CREATE_SYNC_FAILED,
					NNP_IPC_NO_SUCH_CONTEXT,
					context != NULL ? context->chan->respq : NULL,
					cmd->chan_id,
					cmd->syncSeq);

		if (context != NULL)
			inf_context_put(context);
		return;
	}

	inf_context_add_sync_point(context, cmd->syncSeq);
	inf_context_put(context);

	DO_TRACE(trace_infer_create(SPH_TRACE_INF_INF_SYNC, cmd->chan_id, cmd->syncSeq, SPH_TRACE_OP_STATUS_COMPLETE, -1, -1));
}

struct resource_op_work {
	struct work_struct           work;
	struct inf_context          *context;
	union h2c_ChanInferenceResourceOp cmd;
};

static void resource_op_work_handler(struct work_struct *work)
{
	struct resource_op_work *op = container_of(work,
						   struct resource_op_work,
						   work);
	struct inf_devres *devres;
	uint8_t event;
	enum event_val val = NNP_IPC_NO_ERROR;
	uint32_t usage_flags;
	int ret;

	if (!op->cmd.destroy)
		if (!check_memory_threshold()) {
			event = NNP_IPC_CREATE_DEVRES_FAILED;
			val = NNP_IPC_NO_MEMORY;
			goto send_error;
		}

	if (op->cmd.destroy) {
		ret = inf_context_find_and_destroy_devres(op->context, op->cmd.resID);
		if (unlikely(ret < 0)) {
			event = NNP_IPC_DESTROY_DEVRES_FAILED;
			val = NNP_IPC_NO_SUCH_DEVRES;
			goto send_error;
		}
	} else {
		event = NNP_IPC_CREATE_DEVRES_FAILED;
		if (unlikely(op->context->destroyed != 0)) {
			val = NNP_IPC_NO_SUCH_CONTEXT;
			goto send_error;
		}
		devres = inf_context_find_devres(op->context, op->cmd.resID);
		if (unlikely(devres != NULL)) {
			val = NNP_IPC_ALREADY_EXIST;
			goto send_error;
		}

		DO_TRACE(trace_infer_create(SPH_TRACE_INF_DEVRES, op->cmd.chan_id, op->cmd.resID, SPH_TRACE_OP_STATUS_START, -1, -1));

		usage_flags = 0;
		if (op->cmd.is_input || op->cmd.is_network)
			usage_flags |= IOCTL_INF_RES_INPUT;
		if (op->cmd.is_output)
			usage_flags |= IOCTL_INF_RES_OUTPUT;
		if (op->cmd.is_network)
			usage_flags |= IOCTL_INF_RES_NETWORK;
		if (op->cmd.is_force_4G)
			usage_flags |= IOCTL_INF_RES_FORCE_4G_ALLOC;
		if (op->cmd.is_ecc)
			usage_flags |= IOCTL_INF_RES_ECC;
		if (op->cmd.is_p2p_dst)
			usage_flags |= IOCTL_INF_RES_P2P_DST;
		if (op->cmd.is_p2p_src)
			usage_flags |= IOCTL_INF_RES_P2P_SRC;

		ret = inf_context_create_devres(op->context,
						op->cmd.resID,
						op->cmd.size,
						op->cmd.depth,
						op->cmd.align << NNP_PAGE_SHIFT,
						usage_flags,
						&devres);
		if (unlikely(ret < 0)) {
			val = NNP_IPC_NO_MEMORY;
			goto send_error;
		}
	}

	goto done;

send_error:
	sphcs_send_event_report(g_the_sphcs, event, val, op->context->chan->respq, op->cmd.chan_id, op->cmd.resID);

done:
	inf_context_put(op->context);
	kfree(op);
}

void IPC_OPCODE_HANDLER(CHAN_INF_RESOURCE)(struct sphcs                  *sphcs,
					   union h2c_ChanInferenceResourceOp     *cmd)
{
	struct resource_op_work *work;
	struct inf_context *context;
	uint8_t event;
	enum event_val val;

	if (cmd->destroy)
		event = NNP_IPC_DESTROY_DEVRES_FAILED;
	else
		event = NNP_IPC_CREATE_DEVRES_FAILED;

	context = find_and_get_context(sphcs->inf_data, cmd->chan_id);
	if (unlikely(context == NULL)) {
		val = NNP_IPC_NO_SUCH_CONTEXT;
		goto send_error;
	}

	if (unlikely(context->chan == NULL || context->chan->protocol_id != cmd->chan_id)) {
		val = NNP_IPC_NO_SUCH_CONTEXT;
		goto send_error;
	}

	work = kzalloc(sizeof(*work), GFP_NOWAIT);
	if (unlikely(work == NULL)) {
		val = NNP_IPC_NO_MEMORY;
		goto send_error;
	}

	work->cmd.value[0] = cmd->value[0];
	work->cmd.value[1] = cmd->value[1];
	work->context = context;
	INIT_WORK(&work->work, resource_op_work_handler);

	DO_TRACE_IF(!cmd->destroy, trace_infer_create(SPH_TRACE_INF_DEVRES, cmd->chan_id, cmd->resID, SPH_TRACE_OP_STATUS_QUEUED, -1, -1));

	queue_work(context->chan->wq, &work->work);

	return;

send_error:
	if (context != NULL && context->chan != NULL) {
		sphcs_send_event_report(sphcs, event, val, context->chan->respq, cmd->chan_id, cmd->resID);
		inf_context_put(context);
	} else {
		sphcs_send_event_report(sphcs, event, val, NULL, cmd->chan_id, cmd->resID);
	}
}


struct mark_resource_work {
	struct work_struct work;
	struct inf_context *context;
	union h2c_ChanMarkInferenceResource cmd;
};

static void mark_resource_work_handler(struct work_struct *work)
{
	struct mark_resource_work *op = container_of(work,
						   struct mark_resource_work,
						   work);
	struct inf_devres *devres;
	unsigned long flags;

	devres = inf_context_find_and_get_devres(op->context, op->cmd.resID);
	if (unlikely(devres == NULL)) {
		sph_log_err(GENERAL_LOG, "Couldn't find the dev res\n");
		goto put_ctx;
	}

	/* Only p2p destination resource can be marked */
	if (!devres->is_p2p_dst) {
		sph_log_err(GENERAL_LOG, "Only p2p destination resource can be marked\n");
		goto put_devres;
	}

	NNP_SPIN_LOCK_IRQSAVE(&devres->lock_irq, flags);
	inf_devres_set_dirty(devres, true);
	devres->p2p_buf.ready = true;
	NNP_SPIN_UNLOCK_IRQRESTORE(&devres->lock_irq, flags);

	/* advance sched tick and try execute next requests */
	atomic_add(2, &devres->context->sched_tick);
	inf_devres_try_execute(devres);

put_devres:
	inf_devres_put(devres);
put_ctx:
	inf_context_put(op->context);
	kfree(op);
}

/* NNP_IPC_H2C_OP_CHAN_MARK_INF_RESOURCE */
void IPC_OPCODE_HANDLER(CHAN_MARK_INF_RESOURCE)(struct sphcs *sphcs, union h2c_ChanMarkInferenceResource *cmd)
{
	struct mark_resource_work *work;
	struct inf_context *context;

	context = find_and_get_context(sphcs->inf_data, cmd->chan_id);
	if (unlikely(context == NULL)) {
		sph_log_err(GENERAL_LOG, "Couldn't find the context\n");
		return;
	}

	if (unlikely(context->chan == NULL || context->chan->protocol_id != cmd->chan_id)) {
		sph_log_err(GENERAL_LOG, "Bad context\n");
		return;
	}

	work = kzalloc(sizeof(*work), GFP_NOWAIT);
	if (unlikely(work == NULL)) {
		sph_log_err(GENERAL_LOG, "Couldn't allocate memory\n");
		return;
	}

	work->cmd.value = cmd->value;
	work->context = context;
	INIT_WORK(&work->work, mark_resource_work_handler);
	queue_work(context->chan->wq, &work->work);
}
void IPC_OPCODE_HANDLER(CHAN_TRACE_USER_DATA)(struct sphcs                *sphcs,
					      union h2c_ChanTraceUserData *cmd)
{
	DO_TRACE(trace_user_data(cmd->key, cmd->chan_id, cmd->user_data));
}

void IPC_OPCODE_HANDLER(CHAN_IDS_MAP)(struct sphcs         *sphcs,
				      union h2c_ChanIdsMap *cmd)
{
	struct inf_context *context;
	int trace_type;

	context = find_and_get_context(sphcs->inf_data, cmd->chan_id);
	if (context == NULL)
		return;

	if (cmd->objType == INF_OBJ_TYPE_CONTEXT) {
		context->user_handle = cmd->user_handle;
		trace_type = SPH_TRACE_INF_CONTEXT;
	} else if (cmd->objType == INF_OBJ_TYPE_COPY) {
		if (cmd->val2 == COPY_USER_HANDLE_TYPE_COPY) {
			struct inf_copy *copy = inf_context_find_and_get_copy(context, cmd->val1);

			if (copy == NULL)
				goto end;
			copy->user_handle = cmd->user_handle;
			inf_copy_put(copy);
			trace_type = SPH_TRACE_INF_COPY;
		} else if (cmd->val2 == COPY_USER_HANDLE_TYPE_HOSTRES) {
			uint16_t hostres_map_id = cmd->val1;
			struct sphcs_hostres_map *hostres_map;

			hostres_map = sphcs_cmd_chan_find_hostres(context->chan, hostres_map_id);
			if (unlikely(hostres_map == NULL))
				goto end;
			hostres_map->user_handle = cmd->user_handle;
			trace_type = SPH_TRACE_INF_HOSTRES;
		} else
			goto end;
		cmd->val2 = 0;
	} else if (cmd->objType == INF_OBJ_TYPE_DEVRES) {
		struct inf_devres *devres = inf_context_find_and_get_devres(context, cmd->val1);

		if (devres == NULL)
			goto end;
		devres->user_handle = cmd->user_handle;
		inf_devres_put(devres);
		trace_type = SPH_TRACE_INF_DEVRES;
	} else if (cmd->objType == INF_OBJ_TYPE_DEVNET || cmd->objType == INF_OBJ_TYPE_INFREQ) {
		struct inf_devnet *devnet = inf_context_find_and_get_devnet(context, cmd->val1, false, true);

		if (devnet == NULL)
			goto end;
		if (cmd->objType == INF_OBJ_TYPE_INFREQ) {
			struct inf_req *infreq = inf_devnet_find_and_get_infreq(devnet, cmd->val2);

			if (infreq == NULL) {
				inf_devnet_put(devnet);
				goto end;
			}
			infreq->user_handle = cmd->user_handle;
			inf_req_put(infreq);
			trace_type = SPH_TRACE_INF_INF_REQ;
		} else { // means that cmd->objType == INF_OBJ_TYPE_DEVNET
			devnet->user_handle = cmd->user_handle;
			trace_type = SPH_TRACE_INF_NETWORK;
		}
		inf_devnet_put(devnet);
	} else if (cmd->objType == INF_OBJ_TYPE_CMD) {
		struct inf_cmd_list *cmdlist = inf_context_find_cmd(context, cmd->val1);

		if (cmdlist == NULL)
			goto end;
		cmdlist->user_handle = cmd->user_handle;
		trace_type = SPH_TRACE_INF_COMMAND_LIST;
	} else
		goto end;

	DO_TRACE(trace_ids_map(trace_type, cmd->chan_id, cmd->val1, cmd->val2, cmd->user_handle));

end:
	inf_context_put(context);
}

#define POP_VALUE(ptr, type, var)	\
do {					\
	type *__x = (type *)(ptr);	\
					\
	*(var) = *__x;			\
	++__x;				\
	(ptr) = (void *)__x;		\
} while (false)

struct cmdlist_op_work {
	struct work_struct           work;
	struct inf_context          *context;
	union h2c_ChanInferenceCmdListOp cmd;
};

struct cmdlist_dma_data {
	struct inf_cmd_list *cmd;
	uint16_t data_size;
	page_handle dma_page_hndl;
	uint8_t host_page_hdl;
	void *vptr;
	bool is_first;
	bool is_last;
	bool opt_dependencies;
};

static int cmdlist_create_dma_complete(struct sphcs *sphcs,
					void *ctx,
					const void *user_data,
					int status,
					u32 xferTimeUS)
{
	struct cmdlist_dma_data *data = (struct cmdlist_dma_data *)ctx;
	uint8_t event = NNP_IPC_CREATE_CMD_FAILED;
	enum event_val val = NNP_IPC_NO_MEMORY;
	unsigned long flags;
	int ret = 0;
	struct inf_cmd_list *cmd = data->cmd;
	struct inf_copy *copy;
	struct inf_cpylst *cpylst;
	struct inf_devnet *devnet;
	struct inf_req *infreq;
	uint16_t protID;
	uint32_t cmdlist_len, cmd_index;
	size_t size;
	uint8_t cmd_type, priority = 0;
	uint16_t ncopies, batchSize = 0;
	uint8_t debugOn = 0, collectInfo = 0, sched_params_are_null;
	uint8_t *begin;

	sphcs_cmd_chan_update_cmd_head(cmd->context->chan, 0, PAGE_SIZE);

	if (unlikely(status == SPHCS_DMA_STATUS_FAILED)) {
		val = NNP_IPC_DMA_ERROR;
		ret = -EFAULT;
		goto destroy_cmd;
	}
	if (unlikely(cmd->destroyed != 0)) {
		val = NNP_IPC_NO_SUCH_CMD;
		ret = -1;
		goto done;
	}

	if (data->is_first) {
		POP_VALUE(data->vptr, uint32_t, &cmdlist_len);
		data->data_size -= sizeof(uint32_t);
		if (unlikely(cmdlist_len == 0)) {
			val = NNP_IPC_RUNTIME_NOT_SUPPORTED;
			ret = -EINVAL;
			goto destroy_cmd;
		}
		cmd->req_list = kmalloc_array(cmdlist_len, sizeof(struct inf_exec_req), GFP_KERNEL);
		if (unlikely(cmd->req_list == NULL)) {
			ret = -ENOMEM;
			goto destroy_cmd;
		}
		// Makr as not inited
		for (cmd_index = 0; cmd_index < cmdlist_len; ++cmd_index)
			cmd->req_list[cmd_index].f = NULL;
	}

	while (data->data_size > 0) {
		begin = data->vptr;
		POP_VALUE(data->vptr, uint32_t, &cmd_index);//not used here
		POP_VALUE(data->vptr, uint8_t, &cmd_type);
		switch (cmd_type) {
		case CMDLIST_CMD_COPY:
			POP_VALUE(data->vptr, uint16_t, &protID);
			copy = inf_context_find_and_get_copy(cmd->context, protID);
			if (copy == NULL) {
				val = NNP_IPC_NO_SUCH_COPY;
				ret = -ENOENT;
				goto destroy_cmd;
			}
			POP_VALUE(data->vptr, uint8_t, &priority);
			POP_VALUE(data->vptr, uint64_t, &size);
			if (atomic_read(&cmd->num_left) == 0) {// standalone copy
				//kref is taken in find
				inf_copy_req_init(&cmd->req_list[cmd->num_reqs], copy, cmd, size, priority);
				++cmd->num_reqs;
			} else { // copy in cpylst
				ret = inf_cpylst_add_copy(cmd->req_list[cmd->num_reqs].cpylst, copy, size, priority);
				inf_copy_put(copy);
				if (ret < 0)
					goto destroy_cmd;

				DO_TRACE(trace_infer_create(SPH_TRACE_INF_ADD_TO_COPY_LIST,
						copy->context->protocol_id,
						copy->protocol_id, SPH_TRACE_OP_STATUS_QUEUED, cmd->protocol_id, cmd->num_reqs));

				DO_TRACE(trace_infer_create(SPH_TRACE_INF_ADD_TO_COPY_LIST,
						copy->context->protocol_id,
						copy->protocol_id, SPH_TRACE_OP_STATUS_START, cmd->protocol_id, cmd->num_reqs));

				DO_TRACE(trace_infer_create(SPH_TRACE_INF_ADD_TO_COPY_LIST,
						copy->context->protocol_id,
						copy->protocol_id, SPH_TRACE_OP_STATUS_COMPLETE, cmd->protocol_id, cmd->num_reqs));

				//TODO CPYLST treat different priorities
				if (priority != 0 && cmd->req_list[cmd->num_reqs].priority == 0)
					cmd->req_list[cmd->num_reqs].priority = priority;

				if (atomic_dec_and_test(&cmd->num_left)) {//after finilize is done
					cmd->req_list[cmd->num_reqs].size = cmd->req_list[cmd->num_reqs].cpylst->size;
					DO_TRACE(trace_cpylist_create(SPH_TRACE_OP_STATUS_COMPLETE,
							 cmd->context->protocol_id, cmd->protocol_id, cmd->num_reqs));
					++cmd->num_reqs;
				}
			}
			++cmd->edits_idx;//count max edits possible
			break;
		case CMDLIST_CMD_INFREQ:
			NNP_ASSERT(atomic_read(&cmd->num_left) == 0);
			POP_VALUE(data->vptr, uint16_t, &protID);
			devnet = inf_context_find_and_get_devnet(cmd->context, protID, true, true);
			if (unlikely(devnet == NULL)) {
				val = NNP_IPC_NO_SUCH_NET;
				ret = -ENOENT;
				goto destroy_cmd;
			}
			POP_VALUE(data->vptr, uint16_t, &protID);
			infreq = inf_devnet_find_and_get_infreq(devnet, protID);
			inf_devnet_put(devnet);
			if (infreq == NULL) {
				val = NNP_IPC_NO_SUCH_INFREQ;
				ret = -ENOENT;
				goto destroy_cmd;
			}
			POP_VALUE(data->vptr, uint8_t, &sched_params_are_null);
			if (sched_params_are_null == 0) {
				POP_VALUE(data->vptr, uint16_t, &batchSize);
				POP_VALUE(data->vptr, uint8_t, &priority);
				POP_VALUE(data->vptr, uint8_t, &debugOn);
				POP_VALUE(data->vptr, uint8_t, &collectInfo);
			} else {
				priority = 0;
			}
			infreq_req_init(&cmd->req_list[cmd->num_reqs],
					infreq,
					cmd,
					priority,
					sched_params_are_null != 0,
					batchSize,
					debugOn,
					collectInfo);
			++cmd->num_reqs;
			++cmd->edits_idx;//count max edits possible
			break;
		case CMDLIST_CMD_COPYLIST:
			NNP_ASSERT(atomic_read(&cmd->num_left) == 0);
			POP_VALUE(data->vptr, uint16_t, &ncopies);
			NNP_ASSERT(ncopies > 0);

			DO_TRACE(trace_cpylist_create(SPH_TRACE_OP_STATUS_START, cmd->context->protocol_id, cmd->protocol_id, cmd->num_reqs));

			ret = inf_cpylst_create(cmd, cmd->num_reqs, ncopies, &cpylst);
			if (ret < 0) {
				ret = -ENOMEM;
				goto destroy_cmd;
			}
			inf_cpylst_req_init(&cmd->req_list[cmd->num_reqs], cpylst, cmd);
			atomic_set(&cmd->num_left, ncopies);
			break;
		default:
			//NOT supported
			val = NNP_IPC_RUNTIME_NOT_SUPPORTED;
			ret = -EINVAL;
			goto destroy_cmd;
		}
		data->data_size -= ((uint8_t *)data->vptr - begin);
	}

	// Do not send reply and mark create completed if not last create
	// packet.
	if (!data->is_last)
		goto done;

	cmd->edits = kmalloc_array(cmd->edits_idx, sizeof(struct req_params), GFP_KERNEL);
	if (unlikely(cmd->edits == NULL)) {
		ret = -ENOMEM;
		goto destroy_cmd;
	}
	cmd->edits_idx = 0;

	NNP_SPIN_LOCK_IRQSAVE(&cmd->lock_irq, flags);
	if (unlikely(cmd->destroyed != 0)) {
		NNP_SPIN_UNLOCK_IRQRESTORE(&cmd->lock_irq, flags);
		goto done;
	}
	NNP_ASSERT(cmd->status == CREATE_STARTED);

	// skip this stage cmd->status = DMA_COMPLETED;
	cmd->status = CREATED;
	// ready to schedule
	NNP_ASSERT(atomic_read(&cmd->num_left) == 0);
	NNP_SPIN_UNLOCK_IRQRESTORE(&cmd->lock_irq, flags);

	if (data->opt_dependencies)
		inf_cmd_optimize_group_devres(cmd);

	DO_TRACE(trace_infer_create(SPH_TRACE_INF_COMMAND_LIST,
			cmd->context->protocol_id,
			cmd->protocol_id,
			SPH_TRACE_OP_STATUS_COMPLETE, -1, -1));

	event = NNP_IPC_CREATE_CMD_SUCCESS;
	val = 0;

	goto send_report;

destroy_cmd:
	destroy_cmd_on_create_failed(cmd);
send_report:
	sphcs_send_event_report(g_the_sphcs,
				event,
				val,
				cmd->context->chan->respq,
				cmd->context->protocol_id,
				cmd->protocol_id);
done:
	// put kref for DMA
	inf_cmd_put(cmd);
	dma_page_pool_set_page_free(sphcs->dma_page_pool,
				    data->dma_page_hndl);
	kfree(data);
	return ret;
}

static void cmdlist_op_work_handler(struct work_struct *work)
{
	struct cmdlist_op_work *op = container_of(work,
						  struct cmdlist_op_work,
						  work);
	struct inf_cmd_list *cmd;
	uint8_t event;
	enum event_val val;
	int ret;
	struct cmdlist_dma_data *dma_data;
	dma_addr_t dma_addr;
	dma_addr_t host_dma_addr;
	struct sphcs_host_rb *cmd_data_rb = &op->context->chan->h2c_rb[0];
	u32 host_chunk_size;
	int n;

	if (op->cmd.destroy) {
		ret = inf_context_find_and_destroy_cmd(op->context, op->cmd.cmdID);
		if (unlikely(ret < 0)) {
			event = NNP_IPC_DESTROY_CMD_FAILED;
			val = NNP_IPC_NO_SUCH_CMD;
			goto send_error;
		}
		goto done;
	}

	event = NNP_IPC_CREATE_CMD_FAILED;

	/* need to advance h2c ring buffer by one page */
	host_rb_update_free_space(cmd_data_rb, NNP_PAGE_SIZE);
	n = host_rb_get_avail_space(cmd_data_rb,
				    NNP_PAGE_SIZE,
				    1,
				    &host_dma_addr,
				    &host_chunk_size);

	NNP_ASSERT(n == 1);
	NNP_ASSERT((host_dma_addr & NNP_IPC_DMA_ADDR_ALIGN_MASK) == 0);
	if (unlikely(n != 1 || (host_dma_addr & NNP_IPC_DMA_ADDR_ALIGN_MASK) != 0)) {
		val = NNP_IPC_DMA_ERROR;
		goto send_error;
	}

	host_rb_update_avail_space(cmd_data_rb, NNP_PAGE_SIZE);

	if (unlikely(op->context->destroyed != 0)) {
		val = NNP_IPC_NO_SUCH_CONTEXT;
		goto send_error;
	}
	cmd = inf_context_find_cmd(op->context, op->cmd.cmdID);
	if (op->cmd.is_first) {
		if (unlikely(cmd != NULL)) {
			val = NNP_IPC_ALREADY_EXIST;
			goto send_error;
		}

		DO_TRACE(trace_infer_create(SPH_TRACE_INF_COMMAND_LIST, op->context->protocol_id, op->cmd.cmdID, SPH_TRACE_OP_STATUS_START, -1, -1));

		ret = inf_context_create_cmd(op->context, op->cmd.cmdID, &cmd);
		if (unlikely(ret < 0)) {
			val = NNP_IPC_NO_MEMORY;
			goto send_error;
		}

	} else if (unlikely(cmd == NULL)) {
		val = NNP_IPC_NO_SUCH_CMD;
		goto send_error;
	}

	NNP_SPIN_LOCK(&op->context->lock);
	if (op->cmd.is_first)
		hash_add(op->context->cmd_hash, &cmd->hash_node, cmd->protocol_id);

	NNP_ASSERT(cmd->status != CREATED);
	// get kref to prevent the cmd list to be destroyed,
	// when it is waiting for dma to complete
	inf_cmd_get(cmd);
	NNP_SPIN_UNLOCK(&op->context->lock);

	dma_data = kmalloc(sizeof(struct cmdlist_dma_data), GFP_KERNEL);
	if (unlikely(dma_data == NULL)) {
		val = NNP_IPC_NO_MEMORY;
		goto destroy_cmd;
	}

	dma_data->cmd = cmd;
	dma_data->data_size = op->cmd.size;
	dma_data->is_last = op->cmd.is_last;
	dma_data->is_first = op->cmd.is_first;
	dma_data->opt_dependencies = op->cmd.opt_dependencies;
	NNP_ASSERT(dma_data->data_size <= NNP_PAGE_SIZE);

	ret = dma_page_pool_get_free_page(g_the_sphcs->dma_page_pool,
					  &dma_data->dma_page_hndl,
					  &dma_data->vptr,
					  &dma_addr);
	if (unlikely(ret < 0)) {
		val = NNP_IPC_NO_MEMORY;
		goto free_dma_data;
	}

	ret = sphcs_dma_sched_start_xfer_single(g_the_sphcs->dmaSched,
						&op->context->chan->h2c_dma_desc,
						host_dma_addr,
						dma_addr,
						dma_data->data_size,
						cmdlist_create_dma_complete,
						dma_data,
						NULL,
						0);

	if (unlikely(ret < 0)) {
		val = NNP_IPC_NO_MEMORY;
		goto free_page;
	}

	goto done;

free_page:
	dma_page_pool_set_page_free(g_the_sphcs->dma_page_pool,
				    dma_data->dma_page_hndl);
free_dma_data:
	kfree(dma_data);
destroy_cmd:
	destroy_cmd_on_create_failed(cmd);
	// put kref for DMA
	inf_cmd_put(cmd);
send_error:
	sphcs_cmd_chan_update_cmd_head(op->context->chan, 0, PAGE_SIZE);
	sphcs_send_event_report(g_the_sphcs, event, val, op->context->chan->respq, op->cmd.chan_id, op->cmd.cmdID);
done:
	inf_context_put(op->context);
	kfree(op);
}

/* NNP_IPC_H2C_OP_CHAN_INF_CMDLIST */
void IPC_OPCODE_HANDLER(CHAN_INF_CMDLIST)(struct sphcs                      *sphcs,
					  union h2c_ChanInferenceCmdListOp  *cmd)
{
	struct cmdlist_op_work *work;
	struct inf_context *context;
	uint8_t event;
	enum event_val val;

	if (cmd->destroy)
		event = NNP_IPC_DESTROY_CMD_FAILED;
	else
		event = NNP_IPC_CREATE_CMD_FAILED;

	context = find_and_get_context(sphcs->inf_data, cmd->chan_id);
	if (unlikely(context == NULL)) {
		val = NNP_IPC_NO_SUCH_CONTEXT;
		goto send_error;
	}

	work = kzalloc(sizeof(*work), GFP_NOWAIT);
	if (unlikely(work == NULL)) {
		val = NNP_IPC_NO_MEMORY;
		goto send_error;
	}

	work->cmd.value = cmd->value;
	work->context = context;
	INIT_WORK(&work->work, cmdlist_op_work_handler);

	DO_TRACE_IF(!cmd->destroy, trace_infer_create(SPH_TRACE_INF_COMMAND_LIST, cmd->chan_id, cmd->cmdID, SPH_TRACE_OP_STATUS_QUEUED, -1, -1));

	queue_work(context->chan->wq, &work->work);

	return;

send_error:
	if (context != NULL && context->chan != NULL) {
		sphcs_send_event_report(sphcs, event, val, context->chan->respq, cmd->chan_id, cmd->cmdID);
		inf_context_put(context);
	} else {
		sphcs_send_event_report(sphcs, event, val, NULL, cmd->chan_id, cmd->cmdID);
	}
}

struct network_op_work {
	struct work_struct work;
	struct inf_context *context;
	union h2c_ChanInferenceNetworkOp cmd;
};

struct subres_op_work {
	struct work_struct work;
	struct sphcs *sphcs;
	struct inf_context *context;
	union h2c_ChanInferenceSchedCopySubres cmd;
};

struct network_dma_data {
	bool create;
	bool chained;
	uint32_t num_res;
	uint32_t curr_num_res;
	uint16_t config_data_size;
	int rb_id;

	dma_addr_t host_dma_addr;

	page_handle dma_page_hndl;
	void *vptr;
	dma_addr_t dma_addr;
	struct inf_devnet *devnet;
};

struct network_edit_data {
	struct inf_create_network cmd;
};

static int network_op_dma_complete(struct sphcs *sphcs,
				   void *ctx,
				   const void *user_data,
				   int status,
				   u32 xferTimeUS)
{
	struct network_dma_data *data = (struct network_dma_data *)ctx;
	uint8_t event;
	enum event_val val;
	int ret = 0;
	uint16_t *packet_ptr;
	struct inf_devnet *devnet = data->devnet;
	struct network_edit_data *edit_data = (struct network_edit_data *)devnet->edit_data;
	struct inf_devres *devres;
	uint32_t cmd_size;
	uint64_t *int64ptr;
	uint32_t j, max_entries_per_page = data->chained ? (NNP_PAGE_SIZE - sizeof(u64)) / sizeof(uint16_t) : data->num_res;


	sphcs_cmd_chan_update_cmd_head(devnet->context->chan,
				       data->rb_id,
				       NNP_PAGE_SIZE);
	max_entries_per_page = data->chained ? NNP_PAGE_SIZE / sizeof(uint16_t) : data->num_res;

	if (unlikely(status == SPHCS_DMA_STATUS_FAILED)) {
		val = NNP_IPC_DMA_ERROR;
		ret = -EFAULT;
		goto send_error;
	}
	if (unlikely(devnet->destroyed != 0)) {
		ret = -1;
		goto done;
	}

	packet_ptr = (uint16_t *)data->vptr;
	int64ptr = (uint64_t *)(&edit_data->cmd + 1);
	int64ptr = int64ptr + data->curr_num_res;
	for (j = 0; data->curr_num_res < data->num_res && j < max_entries_per_page; ++j) {
		devres = inf_context_find_and_get_devres(devnet->context,
							  *(packet_ptr++));
		if (unlikely(devres == NULL)) {
			val = NNP_IPC_NO_SUCH_DEVRES;
			ret = -ENXIO;
			goto delete_devnet;
		}

		ret = inf_devnet_add_devres(devnet, devres);
		inf_devres_put(devres);
		if (unlikely(ret)) {
			val = NNP_IPC_NO_MEMORY;
			goto delete_devnet;
		}
		*(int64ptr++) = devres->rt_handle;
		data->curr_num_res++;
	}

	if (data->curr_num_res < data->num_res) {
		/* We will get another command to
		 * start the next dma
		 */
		ret = 0;
		goto done_curr_packet;
	}

	cmd_size = sizeof(edit_data->cmd) +
		   data->num_res * sizeof(uint64_t) +
		   data->config_data_size;

	edit_data->cmd.devnet_rt_handle = (uint64_t)devnet->rt_handle;
	edit_data->cmd.devnet_drv_handle = (uint64_t)devnet->ptr2id;
	edit_data->cmd.num_devres_rt_handles = data->num_res;
	edit_data->cmd.config_data_size = data->config_data_size;
	edit_data->cmd.network_id = (uint32_t)devnet->protocol_id;
	if (data->config_data_size > 0)
		memcpy(int64ptr, packet_ptr, data->config_data_size);

	NNP_SPIN_LOCK(&devnet->lock);
	if (unlikely(devnet->destroyed != 0)) {
		NNP_SPIN_UNLOCK(&devnet->lock);
		goto done;
	}
	if (unlikely(devnet->created && devnet->context->attached < 0)) { //RT died
		NNP_SPIN_UNLOCK(&devnet->lock);
		goto done;
	}

	NNP_ASSERT(devnet->edit_status == CREATE_STARTED);
	devnet->edit_status = DMA_COMPLETED;
	// get kref for RT
	inf_devnet_get(devnet);
	NNP_SPIN_UNLOCK(&devnet->lock);

	ret = inf_cmd_queue_add(&devnet->context->cmdq,
				SPHCS_RUNTIME_CMD_CREATE_NETWORK,
				&edit_data->cmd,
				cmd_size,
				NULL, NULL);
	if (unlikely(ret < 0)) {
		val = NNP_IPC_NO_MEMORY;
		goto delete_devnet;
	}

	goto done;

delete_devnet:
	inf_devnet_on_create_or_add_res_failed(data->devnet);
send_error:
	if (data->create)
		event = NNP_IPC_CREATE_DEVNET_FAILED;
	else
		event = NNP_IPC_DEVNET_ADD_RES_FAILED;

	sphcs_send_event_report(g_the_sphcs,
				event,
				val,
				devnet->context->chan->respq,
				devnet->context->protocol_id,
				devnet->protocol_id);
done:
	if (unlikely(devnet->created && devnet->context->attached < 0)) //RT died
		inf_devnet_delete_devres(devnet, false);
	kfree(devnet->edit_data);
	devnet->edit_data = NULL;
done_curr_packet:
	// put kref for DMA
	inf_devnet_put(devnet);
	dma_page_pool_set_page_free(sphcs->dma_page_pool,
				    data->dma_page_hndl);
	kfree(data);
	return ret;
}

static void network_op_work_handler(struct work_struct *work)
{
	struct network_op_work
	*op = container_of(work,
			struct network_op_work,
			work);
	struct network_dma_data *dma_data;
	struct inf_devnet *devnet;
	uint16_t config_data_size;
	dma_addr_t host_dma_addr;
	uint8_t event;
	enum event_val val;
	struct sphcs_host_rb *cmd_data_rb = &op->context->chan->h2c_rb[op->cmd.rb_id];
	u32 host_chunk_size;
	int n;
	int ret;

	if (op->cmd.destroy) {
		ret = inf_context_find_and_destroy_devnet(op->context, op->cmd.netID);
		if (unlikely(ret < 0)) {
			event = NNP_IPC_DESTROY_DEVNET_FAILED;
			val = NNP_IPC_NO_SUCH_NET;
			goto send_error;
		}
		goto done;
	} else {
		/* need to advance h2c ring buffer by one page */
		host_rb_update_free_space(cmd_data_rb, NNP_PAGE_SIZE);
		n = host_rb_get_avail_space(cmd_data_rb,
					    NNP_PAGE_SIZE,
					    1,
					    &host_dma_addr,
					    &host_chunk_size);

		NNP_ASSERT(n == 1);
		NNP_ASSERT((host_dma_addr & NNP_IPC_DMA_ADDR_ALIGN_MASK) == 0);
		if (unlikely(n != 1 || (host_dma_addr & NNP_IPC_DMA_ADDR_ALIGN_MASK) != 0)) {
			event = NNP_IPC_CREATE_DEVNET_FAILED;
			val = NNP_IPC_DMA_ERROR;
			goto send_error;
		}

		host_rb_update_avail_space(cmd_data_rb, NNP_PAGE_SIZE);

		if (!check_memory_threshold()) {
			event = NNP_IPC_CREATE_DEVNET_FAILED;
			val = NNP_IPC_NO_MEMORY;
			goto send_error;
		}
	}

	if (op->cmd.create)
		event = NNP_IPC_CREATE_DEVNET_FAILED;
	else
		event = NNP_IPC_DEVNET_ADD_RES_FAILED;

	if (unlikely(op->context->destroyed != 0)) {
		val = NNP_IPC_NO_SUCH_CONTEXT;
		goto send_error;
	}

	if (op->cmd.create && op->cmd.start_res_idx == 0) {
		devnet = inf_context_find_devnet(op->context, op->cmd.netID);
		if (unlikely(devnet != NULL)) {
			val = NNP_IPC_ALREADY_EXIST;
			goto send_error;
		}

		DO_TRACE(trace_infer_create(SPH_TRACE_INF_NETWORK,
			 op->context->chan->protocol_id, op->cmd.netID,
			 SPH_TRACE_OP_STATUS_START, -1, -1));

		ret = inf_devnet_create(op->cmd.netID,
					op->context,
					&devnet);
		if (unlikely(ret)) {
			val = NNP_IPC_NO_MEMORY;
			goto send_error;
		}
	} else {
		devnet = inf_context_find_and_get_devnet(op->context, op->cmd.netID, true, false);
		if (unlikely(devnet == NULL)) {
			val = NNP_IPC_NO_SUCH_NET;
			goto send_error;
		}

		if (unlikely(op->cmd.create && devnet->created)) {
			val = NNP_IPC_ALREADY_EXIST;
			inf_devnet_put(devnet);
			goto send_error;
		}
	}

	NNP_SPIN_LOCK(&devnet->lock);
	/* Add resource operation cannot run while network editing still in progress */
	if (unlikely((!op->cmd.create) && (devnet->edit_status != CREATED))) {
		NNP_SPIN_UNLOCK(&devnet->lock);
		inf_devnet_put(devnet);
		val = NNP_IPC_NOT_SUPPORTED;
		goto send_error;
	}
	devnet->edit_status = CREATE_STARTED;
	// kref for DMA is taken in find or in create
	NNP_SPIN_UNLOCK(&devnet->lock);

	config_data_size = op->cmd.size + 1
			   - (op->cmd.num_res * sizeof(uint16_t));

	if (op->cmd.start_res_idx == 0) {
		if (devnet->edit_data != NULL) {
			val = NNP_IPC_DEVNET_EDIT_BUSY;
			goto destroy_devnet;
		}

		devnet->edit_data = kmalloc(sizeof(struct network_edit_data) +
					    op->cmd.num_res * sizeof(uint64_t) + config_data_size,
					    GFP_KERNEL);
		if (!devnet->edit_data) {
			val = NNP_IPC_NO_MEMORY;
			goto destroy_devnet;
		}
	} else if (devnet->edit_data == NULL) {
		val = NNP_IPC_DEVNET_EDIT_ERROR;
		goto destroy_devnet;
	}

	dma_data = kmalloc(sizeof(struct network_dma_data), GFP_KERNEL);
	if (unlikely(dma_data == NULL)) {
		val = NNP_IPC_NO_MEMORY;
		goto destroy_devnet;
	}

	dma_data->devnet = devnet;
	dma_data->create = op->cmd.create;
	dma_data->num_res = op->cmd.num_res;
	dma_data->curr_num_res = op->cmd.start_res_idx;
	dma_data->config_data_size = config_data_size;
	dma_data->chained = op->cmd.chained;
	dma_data->host_dma_addr = host_dma_addr;

	ret = dma_page_pool_get_free_page(g_the_sphcs->dma_page_pool,
					  &dma_data->dma_page_hndl,
					  &dma_data->vptr,
					  &dma_data->dma_addr);
	if (unlikely(ret < 0)) {
		val = NNP_IPC_NO_MEMORY;
		goto free_dma_data;
	}

	dma_data->rb_id = op->cmd.rb_id;

	if (unlikely(devnet->destroyed)) { // RT died
		val = NNP_IPC_CONTEXT_BROKEN;
		goto free_page;
	}
	ret = sphcs_dma_sched_start_xfer_single(g_the_sphcs->dmaSched,
						&op->context->chan->h2c_dma_desc,
						dma_data->host_dma_addr,
						dma_data->dma_addr,
						op->cmd.chained ? NNP_PAGE_SIZE : op->cmd.size + 1,
						network_op_dma_complete,
						dma_data,
						NULL,
						0);

	if (unlikely(ret < 0)) {
		val = NNP_IPC_NO_MEMORY;
		goto free_page;
	}

	goto done;

free_page:
	dma_page_pool_set_page_free(g_the_sphcs->dma_page_pool,
				    dma_data->dma_page_hndl);
free_dma_data:
	kfree(dma_data);
destroy_devnet:
	inf_devnet_on_create_or_add_res_failed(devnet);
	// put kref for DMA
	inf_devnet_put(devnet);
send_error:
	sphcs_cmd_chan_update_cmd_head(op->context->chan,
				       op->cmd.rb_id,
				       NNP_PAGE_SIZE);
	sphcs_send_event_report(g_the_sphcs, event, val, op->context->chan->respq,
				op->context->chan->protocol_id, op->cmd.netID);
done:
	inf_context_put(op->context);
	kfree(op);
}

void IPC_OPCODE_HANDLER(CHAN_INF_NETWORK)(struct sphcs *sphcs, union h2c_ChanInferenceNetworkOp *cmd)
{
	struct network_op_work *work;
	struct inf_context *context;
	uint8_t event;
	enum event_val val;

	if (cmd->destroy)
		event = NNP_IPC_DESTROY_DEVNET_FAILED;
	else if (cmd->create)
		event = NNP_IPC_CREATE_DEVNET_FAILED;
	else
		event = NNP_IPC_DEVNET_ADD_RES_FAILED;

	context = find_and_get_context(sphcs->inf_data, cmd->chan_id);
	if (unlikely(context == NULL)) {
		val = NNP_IPC_NO_SUCH_CONTEXT;
		goto send_error;
	}

	work = kzalloc(sizeof(*work), GFP_NOWAIT);
	if (unlikely(work == NULL)) {
		val = NNP_IPC_NO_MEMORY;
		goto send_error;
	}

	work->cmd.value[0] = cmd->value[0];
	work->cmd.value[1] = cmd->value[1];
	work->context = context;
	INIT_WORK(&work->work, network_op_work_handler);

	DO_TRACE_IF(!cmd->destroy, trace_infer_create(SPH_TRACE_INF_NETWORK, cmd->chan_id, cmd->netID, SPH_TRACE_OP_STATUS_QUEUED, -1, -1));

	queue_work(context->chan->wq, &work->work);

	return;

send_error:
	if (context != NULL && context->chan != NULL) {
		sphcs_send_event_report(sphcs, event, val, context->chan->respq, cmd->chan_id, cmd->netID);
		inf_context_put(context);
	} else {
		sphcs_send_event_report(sphcs, event, val, NULL, cmd->chan_id, cmd->netID);
	}
}

struct copy_op_work {
	struct work_struct           work;
	struct inf_context          *context;
	union h2c_ChanInferenceCopyOp    cmd;
};

static void copy_op_work_handler(struct work_struct *work)
{
	struct copy_op_work *op = container_of(work,
					       struct copy_op_work,
					       work);
	struct inf_devres *devres;
	struct inf_copy *copy;
	uint8_t event;
	enum event_val val;
	int ret;

	if (!op->cmd.destroy)
		if (!check_memory_threshold()) {
			event = NNP_IPC_CREATE_COPY_FAILED;
			val = NNP_IPC_NO_MEMORY;
			goto send_error;
		}

	if (op->cmd.destroy) {
		ret = inf_context_find_and_destroy_copy(op->context, op->cmd.protCopyID);
		if (unlikely(ret < 0)) {
			event = NNP_IPC_DESTROY_COPY_FAILED;
			val = NNP_IPC_NO_SUCH_COPY;
			goto send_error;
		}
	} else { // Create copy
		event = NNP_IPC_CREATE_COPY_FAILED;

		if (unlikely(op->context->destroyed != 0)) {
			val = NNP_IPC_NO_SUCH_CONTEXT;
			goto send_error;
		}

		devres = inf_context_find_and_get_devres(op->context, op->cmd.protResID);
		if (unlikely(devres == NULL)) {
			val = NNP_IPC_NO_SUCH_DEVRES;
			goto send_error;
		}

		copy = inf_context_find_copy(op->context, op->cmd.protCopyID);
		if (unlikely(copy != NULL)) {
			inf_devres_put(devres);
			val = NNP_IPC_ALREADY_EXIST;
			goto send_error;
		}

		DO_TRACE_IF(!op->cmd.subres_copy,
			    trace_copy_create(op->cmd.c2h,
					      op->cmd.d2d,
					      op->cmd.chan_id,
					      op->cmd.protCopyID,
					      SPH_TRACE_OP_STATUS_START,
					      op->cmd.protResID,
					      op->cmd.hostres,
					      op->cmd.peerProtResID,
					      op->cmd.peerChanID,
					      op->cmd.peerDevID));
		if (op->cmd.d2d) {
			ret = inf_d2d_copy_create(&(op->cmd),
						  op->context,
						  devres,
						  &copy);
		} else {
			NNP_ASSERT(op->cmd.hostres <= 0xFFFF);

			ret = inf_copy_create(&(op->cmd),
						op->context,
						devres,
						&copy);
		}
		inf_devres_put(devres);
		if (unlikely(ret < 0)) {
			if (ret == -ENOENT)
				val = NNP_IPC_NO_SUCH_HOSTRES;
			else
				val = NNP_IPC_NO_MEMORY;
			goto send_error;
		}
	}

	goto done;

send_error:
	sphcs_send_event_report(g_the_sphcs, event, val, op->context->chan->respq, op->cmd.chan_id, op->cmd.protCopyID);
done:
	inf_context_put(op->context);
	kfree(op);
}

void IPC_OPCODE_HANDLER(CHAN_COPY_OP)(struct sphcs                  *sphcs,
				      union h2c_ChanInferenceCopyOp *cmd)
{
	struct copy_op_work *work;
	struct inf_context *context;
	uint8_t event;
	enum event_val val;

	if (cmd->destroy)
		event = NNP_IPC_DESTROY_COPY_FAILED;
	else
		event = NNP_IPC_CREATE_COPY_FAILED;

	context = find_and_get_context(g_the_sphcs->inf_data, cmd->chan_id);
	if (unlikely(context == NULL)) {
		val = NNP_IPC_NO_SUCH_CONTEXT;
		goto send_error;
	}

	if (unlikely(context->chan == NULL || context->chan->protocol_id != cmd->chan_id)) {
		val = NNP_IPC_NO_SUCH_CONTEXT;
		goto send_error;
	}

	work = kzalloc(sizeof(*work), GFP_NOWAIT);
	if (unlikely(work == NULL)) {
		val = NNP_IPC_NO_MEMORY;
		goto send_error;
	}

	work->cmd.value[0] = cmd->value[0];
	work->cmd.value[1] = cmd->value[1];
	work->context = context;
	INIT_WORK(&work->work, copy_op_work_handler);

	DO_TRACE_IF(!cmd->subres_copy && !cmd->destroy,
			trace_copy_create(cmd->c2h,
					cmd->d2d,
					cmd->chan_id,
					cmd->protCopyID,
					SPH_TRACE_OP_STATUS_QUEUED,
					cmd->protResID,
					cmd->hostres,
					cmd->peerProtResID,
					cmd->peerChanID,
					cmd->peerDevID));

	queue_work(context->chan->wq, &work->work);

	return;

send_error:
	if (context != NULL && context->chan != NULL) {
		sphcs_send_event_report(sphcs, event, val, context->chan->respq, cmd->chan_id, cmd->protCopyID);
		inf_context_put(context);
	} else {
		sphcs_send_event_report(sphcs, event, val, NULL, cmd->chan_id, cmd->protCopyID);
	}
}

static void send_exec_error_cmd_error(union h2c_ExecErrorList   *cmd,
				      uint16_t                   error_val,
				      uint16_t                   pkt_size)
{
	union c2h_ExecErrorList msg;

	msg.value = 0;
	msg.opcode = NNP_IPC_C2H_OP_CHAN_EXEC_ERROR_LIST;
	msg.chan_id = cmd->chan_id;
	msg.cmdID = cmd->cmdID;
	msg.cmdID_valid = cmd->cmdID_valid;
	msg.is_error = 1;
	msg.pkt_size = pkt_size;
	msg.total_size = error_val;

	sphcs_msg_scheduler_queue_add_msg(g_the_sphcs->public_respq, &msg.value, 1);
}

struct error_list_work {
	struct work_struct           work;
	struct inf_context          *context;
	union h2c_ExecErrorList      cmd;
	struct inf_cmd_list         *cmdlist;
	void                        *err_buffer;
	uint16_t                     err_buffer_size;
	uint32_t                     total_sent;
	page_handle                  dma_page_hndl;
	dma_addr_t                   dma_page_addr;
	void                        *dma_page_vptr;
	uint32_t                     curr_xfer_size;
};

static int error_list_send_next_packet(struct error_list_work *op);

static int error_list_dma_completed(struct sphcs *sphcs, void *ctx, const void *user_data, int status, u32 timeUS)
{
	struct error_list_work *op = (struct error_list_work *)ctx;
	union c2h_ExecErrorList reply;
	int ret;

	reply.value = 0;
	reply.opcode = NNP_IPC_C2H_OP_CHAN_EXEC_ERROR_LIST;
	reply.chan_id = op->cmd.chan_id;
	reply.cmdID = op->cmd.cmdID;
	reply.cmdID_valid = op->cmd.cmdID_valid;
	reply.pkt_size = (op->curr_xfer_size - 1);

	if (status == SPHCS_DMA_STATUS_FAILED) {
		reply.is_error = 1;
		reply.total_size = NNP_IPC_DMA_ERROR;
	} else {
		reply.total_size = op->err_buffer_size;
	}

	sphcs_msg_scheduler_queue_add_msg(g_the_sphcs->public_respq, &reply.value, 1);

	if (!reply.is_error && op->total_sent < op->err_buffer_size) {
		op->curr_xfer_size = 0;
		ret = error_list_send_next_packet(op);
		if (ret == 0)
			return 0;
	}

	dma_page_pool_set_page_free(sphcs->dma_page_pool, op->dma_page_hndl);
	if (op->cmdlist != NULL)
		inf_cmd_put(op->cmdlist);
	inf_context_put(op->context);
	kfree(op);

	return 0;
}

static int error_list_send_next_packet(struct error_list_work *op)
{
	dma_addr_t host_dma_page_addr;
	struct sphcs_host_rb *resp_data_rb = &op->context->chan->c2h_rb[0];
	uint32_t chunk_size;
	enum event_val err_val;
	int n;
	int ret;

	if (op->total_sent >= op->err_buffer_size)
		return -EINVAL;

	n = host_rb_wait_free_space(resp_data_rb,
				    NNP_PAGE_SIZE,
				    1,
				    &host_dma_page_addr,
				    &chunk_size);
	if (n != 1 || chunk_size != NNP_PAGE_SIZE) {
		err_val = NNP_IPC_NOT_SUPPORTED;
		goto send_error;
	}
	host_rb_update_free_space(resp_data_rb, NNP_PAGE_SIZE);

	op->curr_xfer_size = op->err_buffer_size - op->total_sent;
	if (op->curr_xfer_size > NNP_PAGE_SIZE)
		op->curr_xfer_size = NNP_PAGE_SIZE;

	memcpy(op->dma_page_vptr,
	       (void *)((uintptr_t)op->err_buffer + op->total_sent),
	       op->curr_xfer_size);

	op->total_sent += op->curr_xfer_size;

	ret = sphcs_dma_sched_start_xfer_single(g_the_sphcs->dmaSched,
						&op->context->chan->c2h_dma_desc,
						op->dma_page_addr,
						host_dma_page_addr,
						op->curr_xfer_size,
						error_list_dma_completed,
						op,
						NULL, 0);
	if (ret != 0) {
		err_val = NNP_IPC_NO_MEMORY;
		goto send_error;
	}

	return 0;

send_error:
	send_exec_error_cmd_error(&op->cmd, err_val, op->curr_xfer_size);
	return -1;
}

static void error_list_work_handler(struct work_struct *work)
{
	struct error_list_work *op = container_of(work,
						  struct error_list_work,
						  work);
	enum event_val err_val;
	int ret;

	if (op->cmd.cmdID_valid) {
		op->cmdlist = inf_context_find_cmd(op->context, op->cmd.cmdID);
		if (unlikely(op->cmdlist == NULL)) {
			err_val = NNP_IPC_NO_SUCH_CMD;
			goto send_error;
		}
		inf_cmd_get(op->cmdlist);
		if (unlikely(op->cmdlist->sched_failed == NNP_IPC_NO_ERROR &&
			     (atomic_read(&op->cmdlist->num_left) != 0 || // in flight
			      op->cmdlist->edits_idx != 0))) { // sched in progress
			err_val = NNP_IPC_RUNTIME_NOT_SUPPORTED;
			goto send_error;
		}
	} else
		op->cmdlist = NULL;

	if (op->cmd.clear) {
		if (op->cmdlist == NULL) {
			if (op->context->destroyed != 0) {
				err_val = NNP_IPC_NO_SUCH_CONTEXT;
				goto send_error;
			}

			switch (inf_context_get_state(op->context)) {
			case CONTEXT_BROKEN_NON_RECOVERABLE:
				err_val = NNP_IPC_CONTEXT_BROKEN;
				goto send_error;
			case CONTEXT_OK:
				sph_log_info(CREATE_COMMAND_LOG, "Got request to recover non-broken context: 0x%x\n",
					     op->context->protocol_id);
			default:
				break;
			}
		} else if (op->cmdlist->destroyed != 0) {
			err_val = NNP_IPC_NO_SUCH_CMD;
			goto send_error;
		}

		inf_exec_error_list_clear(op->cmdlist != NULL ? &op->cmdlist->error_list :
								&op->context->error_list,
					  op->cmdlist);
		goto done;
	}

	ret = inf_exec_error_list_buffer_pack(op->cmdlist != NULL ? &op->cmdlist->error_list :
								    &op->context->error_list,
					      &op->err_buffer,
					      &op->err_buffer_size);

	if (ret != 0) {
		switch (ret) {
		case -ENOENT:
			err_val = NNP_IPC_NO_EXEC_ERRORS;
			break;

		case -ENOSPC:
		case -ENOMEM:
		default:
			err_val = NNP_IPC_NO_MEMORY;
		}
		goto send_error;
	}

	ret = dma_page_pool_get_free_page(g_the_sphcs->dma_page_pool,
					  &op->dma_page_hndl,
					  &op->dma_page_vptr,
					  &op->dma_page_addr);
	if (unlikely(ret < 0)) {
		err_val = NNP_IPC_NO_MEMORY;
		goto send_error;
	}

	op->total_sent = 0;
	op->curr_xfer_size = 0;

	ret = error_list_send_next_packet(op);
	if (unlikely(ret != 0)) {
		err_val = NNP_IPC_NO_MEMORY;
		goto send_error;
	}
	return;

send_error:
	send_exec_error_cmd_error(&op->cmd, err_val, 0);
done:
	if (op->cmdlist != NULL)
		inf_cmd_put(op->cmdlist);
	inf_context_put(op->context);
	kfree(op);
}

void IPC_OPCODE_HANDLER(CHAN_EXEC_ERROR_LIST)(struct sphcs              *sphcs,
					      union h2c_ExecErrorList   *cmd)
{
	struct error_list_work *work;
	struct inf_context *context;
	enum event_val error_val;

	context = find_and_get_context(g_the_sphcs->inf_data, cmd->chan_id);
	if (unlikely(context == NULL)) {
		error_val = NNP_IPC_NO_SUCH_CONTEXT;
		goto send_error;
	}

	if (unlikely(context->chan == NULL || context->chan->protocol_id != cmd->chan_id)) {
		inf_context_put(context);
		error_val = NNP_IPC_NO_SUCH_CONTEXT;
		goto send_error;
	}

	work = kzalloc(sizeof(*work), GFP_NOWAIT);
	if (unlikely(work == NULL)) {
		inf_context_put(context);
		error_val = NNP_IPC_NO_MEMORY;
		goto send_error;
	}

	work->cmd.value = cmd->value;
	work->context = context;
	INIT_WORK(&work->work, error_list_work_handler);
	queue_work(context->chan->wq, &work->work);

	return;

send_error:
	send_exec_error_cmd_error(cmd, error_val, 0);
}

void IPC_OPCODE_HANDLER(CHAN_SCHEDULE_COPY)(struct sphcs                 *sphcs,
					    union h2c_ChanInferenceSchedCopy *cmd)
{
	struct inf_context *context;
	struct inf_copy *copy;
	struct inf_exec_req *req;
	enum event_val val;
	int ret;

	context = find_and_get_context(sphcs->inf_data, cmd->chan_id);
	if (unlikely(context == NULL)) {
		val = NNP_IPC_NO_SUCH_CONTEXT;
		goto send_error;
	}

	if (unlikely(context->chan == NULL || context->chan->protocol_id != cmd->chan_id)) {
		val = NNP_IPC_NO_SUCH_CONTEXT;
		goto send_error;
	}

	if (unlikely(inf_context_get_state(context) != CONTEXT_OK)) {
		val = NNP_IPC_CONTEXT_BROKEN;
		goto send_error;
	}

	copy = inf_context_find_and_get_copy(context, cmd->protCopyID);
	if (unlikely(copy == NULL)) {
		val = NNP_IPC_NO_SUCH_COPY;
		goto send_error;
	}

	req = kmem_cache_alloc(copy->context->exec_req_slab_cache, GFP_NOWAIT);
	if (unlikely(req == NULL)) {
		val = NNP_IPC_NO_MEMORY;
		goto put_copy;
	}

	inf_copy_req_init(req, copy, NULL, cmd->copySize, cmd->priority);

	ret = inf_copy_req_sched(req);
	if (unlikely(ret < 0)) {
		kmem_cache_free(copy->context->exec_req_slab_cache, req);
		val = NNP_IPC_NO_MEMORY;
		goto put_copy;
	}

	inf_copy_put(copy);
	inf_context_put(context);

	return;

put_copy:
	inf_copy_put(copy);
send_error:
	if (context != NULL && context->chan != NULL) {
		sphcs_send_event_report(sphcs, NNP_IPC_EXECUTE_COPY_FAILED, val, context->chan->respq, cmd->chan_id, cmd->protCopyID);
		inf_context_put(context);
	} else {
		sphcs_send_event_report(sphcs, NNP_IPC_EXECUTE_COPY_FAILED, val, NULL, cmd->chan_id, cmd->protCopyID);
	}
}

void IPC_OPCODE_HANDLER(CHAN_SCHEDULE_COPY_LARGE)(struct sphcs                 *sphcs,
						  union h2c_ChanInferenceSchedCopyLarge *cmd)
{
	struct inf_context *context;
	struct inf_copy *copy;
	struct inf_exec_req *req;
	enum event_val val;
	int ret;

	context = find_and_get_context(sphcs->inf_data, cmd->chan_id);
	if (unlikely(context == NULL)) {
		val = NNP_IPC_NO_SUCH_CONTEXT;
		goto send_error;
	}

	if (unlikely(context->chan == NULL || context->chan->protocol_id != cmd->chan_id)) {
		val = NNP_IPC_NO_SUCH_CONTEXT;
		goto send_error;
	}

	if (unlikely(inf_context_get_state(context) != CONTEXT_OK)) {
		val = NNP_IPC_CONTEXT_BROKEN;
		goto send_error;
	}

	copy = inf_context_find_and_get_copy(context, cmd->protCopyID);
	if (unlikely(copy == NULL)) {
		val = NNP_IPC_NO_SUCH_COPY;
		goto send_error;
	}

	req = kmem_cache_alloc(copy->context->exec_req_slab_cache, GFP_NOWAIT);
	if (unlikely(req == NULL)) {
		val = NNP_IPC_NO_MEMORY;
		goto put_copy;
	}

	inf_copy_req_init(req, copy, NULL, cmd->copySize, cmd->priority);

	ret = inf_copy_req_sched(req);
	if (unlikely(ret < 0)) {
		kmem_cache_free(copy->context->exec_req_slab_cache, req);
		val = NNP_IPC_NO_MEMORY;
		goto put_copy;
	}

	inf_copy_put(copy);
	inf_context_put(context);

	return;

put_copy:
	inf_copy_put(copy);
send_error:
	if (context != NULL && context->chan != NULL) {
		sphcs_send_event_report(sphcs, NNP_IPC_EXECUTE_COPY_FAILED, val, context->chan->respq, cmd->chan_id, cmd->protCopyID);
		inf_context_put(context);
	} else {
		sphcs_send_event_report(sphcs, NNP_IPC_EXECUTE_COPY_FAILED, val, NULL, cmd->chan_id, cmd->protCopyID);
	}
}

static void copy_subres_op_work_handler(struct work_struct *work)
{
	struct subres_op_work *op = container_of(work,
			struct subres_op_work,
			work);
	struct inf_copy *copy;
	struct inf_exec_req *req;
	enum event_val val;
	int ret;

	copy = inf_context_find_and_get_copy(op->context, op->cmd.protCopyID);
	if (unlikely(copy == NULL)) {
		val = NNP_IPC_NO_SUCH_COPY;
		goto put_ctx;
	}

	if (unlikely((op->cmd.dstOffset + (op->cmd.copySize + 1)) > copy->devres->size)) {
		val = NNP_IPC_IO_ERROR;
		goto put_copy;
	}


	req = kmem_cache_alloc(copy->context->exec_req_slab_cache, GFP_NOWAIT);
	if (unlikely(req == NULL)) {
		val = NNP_IPC_NO_MEMORY;
		goto put_copy;
	}
	ret = inf_copy_req_init_subres_copy(req,
					    copy,
					    op->cmd.hostres_id,
					    op->cmd.dstOffset,
					    op->cmd.copySize + 1);
	if (ret) {
		kmem_cache_free(copy->context->exec_req_slab_cache, req);
		val = NNP_IPC_NO_MEMORY;
		goto put_copy;
	}

	ret = inf_copy_req_sched(req);
	if (unlikely(ret < 0)) {
		kmem_cache_free(copy->context->exec_req_slab_cache, req);
		val = NNP_IPC_NO_MEMORY;
		goto put_copy;
	}

	inf_copy_put(copy);
	inf_context_put(op->context);

	kfree(op);

	return;

put_copy:
	inf_copy_put(copy);
put_ctx:

	sphcs_send_event_report(op->sphcs, NNP_IPC_EXECUTE_COPY_SUBRES_FAILED, val, op->context->chan->respq, op->cmd.chan_id, op->cmd.protCopyID);
	inf_context_put(op->context);

	kfree(op);
}

/* NNP_IPC_H2C_OP_CHAN_SCHEDULE_COPY_SUBRES */
void IPC_OPCODE_HANDLER(CHAN_SCHEDULE_COPY_SUBRES)(struct sphcs                 *sphcs,
						   union h2c_ChanInferenceSchedCopySubres *cmd)
{
	struct subres_op_work *work;
	enum event_val val;
	struct inf_context *context;

	context = find_and_get_context(sphcs->inf_data, cmd->chan_id);
	if (unlikely(context == NULL)) {
		val = NNP_IPC_NO_SUCH_CONTEXT;
		goto send_error;
	}

	if (unlikely(context->chan == NULL || context->chan->protocol_id != cmd->chan_id)) {
		val = NNP_IPC_NO_SUCH_CONTEXT;
		goto send_error;
	}

	if (unlikely(inf_context_get_state(context) != CONTEXT_OK)) {
		val = NNP_IPC_CONTEXT_BROKEN;
		goto send_error;
	}

	work = kzalloc(sizeof(*work), GFP_NOWAIT);
	if (unlikely(work == NULL)) {
		val = NNP_IPC_NO_MEMORY;
		goto send_error;
	}

	work->sphcs = sphcs;
	work->context = context;
	memcpy(work->cmd.value, cmd->value, sizeof(cmd->value));

	INIT_WORK(&work->work, copy_subres_op_work_handler);
	queue_work(context->chan->wq, &work->work);

	return;

send_error:
	if (context != NULL && context->chan != NULL) {
		sphcs_send_event_report(sphcs, NNP_IPC_EXECUTE_COPY_SUBRES_FAILED, val, context->chan->respq, cmd->chan_id, cmd->protCopyID);
		inf_context_put(context);
	} else {
		sphcs_send_event_report(sphcs, NNP_IPC_EXECUTE_COPY_SUBRES_FAILED, val, NULL, cmd->chan_id, cmd->protCopyID);
	}
	return;
}

static inline void cmdlst_send_fail_reports(struct inf_cmd_list *cmd,
					    enum event_val val,
					    bool send_completion,
					    uint16_t start_idx)
{
	char const * const msg = "Schedule failed";
	int i;
	unsigned long flags;

	NNP_SPIN_LOCK_IRQSAVE(&cmd->lock_irq, flags);
	if (cmd->sched_failed == NNP_IPC_NO_ERROR) {
		cmd->sched_failed = val;
		NNP_SPIN_UNLOCK_IRQRESTORE(&cmd->lock_irq, flags);
		for (i = start_idx; i < cmd->num_reqs; ++i) {
			cmd->req_list[i].f->treat_req_failure(&cmd->req_list[i],
							val,
							msg,
							strlen(msg) + 1);
			cmd->req_list[i].f->send_report(&cmd->req_list[i], val);
		}
	} else {
		val = cmd->sched_failed;
		NNP_SPIN_UNLOCK_IRQRESTORE(&cmd->lock_irq, flags);
	}
	if (send_completion)
		sphcs_send_event_report(g_the_sphcs, NNP_IPC_EXECUTE_CMD_COMPLETE, val, cmd->context->chan->respq, cmd->context->protocol_id, cmd->protocol_id);

}

struct cmdlist_sched_dma_data {
	void *vptr;
	uint16_t data_size;
	page_handle dma_page_hndl;
	bool is_last;
};

struct cmdlst_op_work {
	struct work_struct work;
	struct inf_cmd_list *cmd;
	dma_addr_t host_dma_addr;
	struct cmdlist_sched_dma_data dma_data;
};

static void handle_sched_cmdlist(struct inf_cmd_list *cmdlist,
				 struct req_params   *params,
				 uint16_t             num_params)
{
	struct inf_context  *context = cmdlist->context;
	struct inf_exec_req *req;
	int ret = 0;
	uint16_t i, k, j = 0;

	NNP_ASSERT(params != NULL || num_params == 0);

	NNP_ASSERT(atomic_read(&cmdlist->num_left) == 0);
	atomic_inc(&cmdlist->num_left); // to prevent completion reports in time of schedule

	// for schedule
	inf_cmd_get(cmdlist);

	DO_TRACE(trace_cmdlist(SPH_TRACE_OP_STATUS_START, context->protocol_id, cmdlist->protocol_id));

	for (i = 0; i < cmdlist->num_reqs; ++i) {
		req = kmem_cache_alloc(context->exec_req_slab_cache, GFP_NOWAIT);
		if (unlikely(req == NULL))
			break;

		memcpy(req, &cmdlist->req_list[i], sizeof(struct inf_exec_req));

		k = 0;
		for ( ; j < num_params && i == params[j].idx; ++j) {
			switch (req->cmd_type) {
			case CMDLIST_CMD_COPYLIST:
				NNP_ASSERT(params[j].cpy_idx < req->cpylst->n_copies);
				if (unlikely(params[j].cpy_idx >= req->cpylst->n_copies))
					break;
				/* recompute priority */
				if (k == 0)
					req->priority = 0;
				for ( ; req->priority == 0 && k < params[j].cpy_idx; ++k)
					if (req->cpylst->priorities[k] == 1)
						req->priority = 1;
				if (req->priority == 0 && params[j].priority == 1) {
					req->priority = 1;
					++k;
				}
				NNP_ASSERT(params[j].size <= req->cpylst->devreses[params[j].cpy_idx]->size);
				req->cpylst->cur_sizes[params[j].cpy_idx] = params[j].size <= req->cpylst->devreses[params[j].cpy_idx]->size ?
									    params[j].size : req->cpylst->devreses[params[j].cpy_idx]->size;
				req->size -= req->cpylst->sizes[params[j].cpy_idx];
				req->size += req->cpylst->cur_sizes[params[j].cpy_idx];
				break;
			case CMDLIST_CMD_COPY:
				req->priority = params[j].priority;
				NNP_ASSERT(params[j].size <= req->copy->devres->size);
				req->size = params[j].size <= req->copy->devres->size ?
					    params[j].size : req->copy->devres->size;
				break;
			case CMDLIST_CMD_INFREQ:
				req->sched_params_is_null = params[j].sched_params_is_null;
				if (!req->sched_params_is_null) {
					req->priority = params[j].priority;
					req->size = params[j].size;
					req->debugOn = params[j].debugOn;
					req->collectInfo = params[j].collectInfo;
				}
				break;
			};
		}
		if (k != 0) { //cpylist params were overwritten
			for ( ; req->priority == 0 && k < req->cpylst->n_copies; ++k) {
				if (req->cpylst->priorities[k] == 1)
					req->priority = 1;
			}
			if (inf_cpylst_build_cur_lli(req->cpylst) != 0) {
				kmem_cache_free(context->exec_req_slab_cache, req);
				break;
			}
			req->lli = &req->cpylst->cur_lli;
		}

		atomic_inc(&cmdlist->num_left);

		ret = req->f->schedule(req);
		if (unlikely(ret < 0)) {
			atomic_dec(&cmdlist->num_left);
			kmem_cache_free(context->exec_req_slab_cache, req);
			break;
		}
	}
	if (unlikely(i < cmdlist->num_reqs))
		cmdlst_send_fail_reports(cmdlist, NNP_IPC_NO_MEMORY, false, i);

	if (atomic_dec_and_test(&cmdlist->num_left))// schedule finished
		goto send_completion;

	goto done;

send_completion:
	// for schedule
	inf_cmd_put(cmdlist);
	sphcs_send_event_report(g_the_sphcs, NNP_IPC_EXECUTE_CMD_COMPLETE, cmdlist->sched_failed, context->chan->respq,
				context->protocol_id, cmdlist->protocol_id);
done:
	cmdlist->edits_idx = 0;
}

static int cmdlist_schedule_dma_complete(struct sphcs *sphcs,
					 void *ctx,
					 const void *user_data,
					 int status,
					 u32 xferTimeUS)
{
	struct inf_cmd_list *cmd;
	uint32_t num_edits, cmd_index;
	uint8_t byte;
	uint16_t i, protID, ncopies;
	uint8_t sched_params_are_null;
	uint8_t *begin, *p;
	uint16_t sched_dma_size;
	enum event_val val;
	struct cmdlist_sched_dma_data *data;
	struct cmdlst_op_work *op;
	int ret = 0;

	if (ctx == NULL) { //from opwork
		op = *((struct cmdlst_op_work **)user_data);
		cmd = op->cmd;
		data = &op->dma_data;
	} else { // from bottom half
		op = NULL;
		cmd = (struct inf_cmd_list *)ctx;
		data = (struct cmdlist_sched_dma_data *)user_data;
	}
	p = data->vptr;
	sched_dma_size = data->data_size;

	sphcs_cmd_chan_update_cmd_head(cmd->context->chan, 1, PAGE_SIZE);

	if (unlikely(status == SPHCS_DMA_STATUS_FAILED)) {
		val = NNP_IPC_DMA_ERROR;
		ret = -EFAULT;
		goto finish;
	}

	if (unlikely(cmd->sched_failed != NNP_IPC_NO_ERROR)) {
		val = cmd->sched_failed;
		ret = -EPERM;
		goto finish;
	}

	if (cmd->edits_idx == 0) { //First DMA
		NNP_ASSERT(atomic_read(&cmd->num_left) == 0);
		POP_VALUE(p, uint32_t, &num_edits);//We don't need it, "edits" is allocated on create
		sched_dma_size -= sizeof(uint32_t);
		if (unlikely(num_edits == 0)) {
			val = NNP_IPC_RUNTIME_NOT_SUPPORTED;
			ret = -EINVAL;
			goto finish;
		}
	}

	while (sched_dma_size > 0) {
		begin = p;
		POP_VALUE(p, uint32_t, &cmd_index);
		POP_VALUE(p, uint8_t, &byte);
		switch (byte) {
		case CMDLIST_CMD_COPY:
			POP_VALUE(p, uint16_t, &protID); //not used here
			POP_VALUE(p, uint8_t, &cmd->edits[cmd->edits_idx].priority);
			POP_VALUE(p, uint64_t, &cmd->edits[cmd->edits_idx].size);
			if (atomic_read(&cmd->num_left) == 0) {// standalone copy
				NNP_ASSERT(cmd->req_list[cmd_index].cmd_type == CMDLIST_CMD_COPY);
				cmd->edits[cmd->edits_idx].idx = cmd_index;
			} else { // copy in cpylst
				NNP_ASSERT(cmd->req_list[cmd->edits[cmd->edits_idx].idx].cmd_type == CMDLIST_CMD_COPYLIST);
				// cmd->edits[cmd->edits_idx].idx is already uptodate
				cmd->edits[cmd->edits_idx].cpy_idx = cmd_index;
				atomic_dec(&cmd->num_left);
			}
			++cmd->edits_idx;
			break;
		case CMDLIST_CMD_INFREQ:
			NNP_ASSERT(cmd->req_list[cmd_index].cmd_type == CMDLIST_CMD_INFREQ);
			NNP_ASSERT(atomic_read(&cmd->num_left) == 0);
			POP_VALUE(p, uint16_t, &protID); //not used here
			POP_VALUE(p, uint16_t, &protID); //not used here
			cmd->edits[cmd->edits_idx].idx = cmd_index;
			POP_VALUE(p, uint8_t, &sched_params_are_null);
			cmd->req_list[cmd_index].sched_params_is_null = sched_params_are_null;
			if (sched_params_are_null == 0) {
				POP_VALUE(p, uint16_t, &cmd->req_list[cmd_index].size);
				POP_VALUE(p, uint8_t, &cmd->req_list[cmd_index].priority);
				POP_VALUE(p, uint8_t, &byte); cmd->req_list[cmd_index].debugOn = byte;
				POP_VALUE(p, uint8_t, &byte); cmd->req_list[cmd_index].collectInfo = byte;
			}
			++cmd->edits_idx;
			break;
		case CMDLIST_CMD_COPYLIST:
			NNP_ASSERT(cmd->req_list[cmd_index].cmd_type == CMDLIST_CMD_COPYLIST);
			NNP_ASSERT(atomic_read(&cmd->num_left) == 0);
			POP_VALUE(p, uint16_t, &ncopies);
			NNP_ASSERT(ncopies > 0);
			for (i = cmd->edits_idx; i < cmd->edits_idx + ncopies; ++i)
				cmd->edits[i].idx = cmd_index;
			atomic_set(&cmd->num_left, ncopies);
			break;
		default:
			//NOT supported
			val = NNP_IPC_RUNTIME_NOT_SUPPORTED;
			ret = -EINVAL;
			goto finish;
		}
		sched_dma_size -= ((uint8_t *)p - begin);
	}

	// Do not start schedule if not last packet
	if (!data->is_last)
		goto finish;

	NNP_ASSERT(cmd->sched_failed == NNP_IPC_NO_ERROR);
	NNP_ASSERT(atomic_read(&cmd->num_left) == 0);
	NNP_ASSERT(cmd->edits_idx != 0);

	handle_sched_cmdlist(cmd, cmd->edits, cmd->edits_idx);

finish:
	// put kref for DMA
	inf_cmd_put(cmd);

	if (op != NULL) // from opwork
		kfree(op);

	dma_page_pool_set_page_free(g_the_sphcs->dma_page_pool,
				    data->dma_page_hndl);

	if (unlikely(ret < 0)) {
		cmd->edits_idx = 0;
		atomic_set(&cmd->num_left, 0);
		cmdlst_send_fail_reports(cmd, val, data->is_last, 0);
	}

	return ret;
}

static void cmd_sched_op_work_handler(struct work_struct *work)
{
	struct cmdlst_op_work *op = container_of(work,
			struct cmdlst_op_work,
			work);
	dma_addr_t dma_addr;
	enum event_val val;
	struct inf_cmd_list *cmd = op->cmd;
	int ret;

	NNP_ASSERT(is_inf_cmd_ptr(cmd));

	if (unlikely(cmd->sched_failed != NNP_IPC_NO_ERROR)) {
		val = cmd->sched_failed;
		goto send_error;
	}

	ret = dma_page_pool_get_free_page(g_the_sphcs->dma_page_pool,
					  &op->dma_data.dma_page_hndl,
					  &op->dma_data.vptr,
					  &dma_addr);
	if (unlikely(ret < 0)) {
		val = NNP_IPC_NO_MEMORY;
		goto send_error;
	}

	// for DMA
	inf_cmd_get(cmd);

	ret = sphcs_dma_sched_start_xfer_single(g_the_sphcs->dmaSched,
						&cmd->context->chan->h2c_dma_exec_desc,
						op->host_dma_addr,
						dma_addr,
						op->dma_data.data_size,
						cmdlist_schedule_dma_complete,
						NULL,
						&op,
						sizeof(op));
	if (unlikely(ret < 0)) {
		val = NNP_IPC_NO_MEMORY;
		goto free_page;
	}

	goto done;

free_page:
	// put kref for DMA
	inf_cmd_put(cmd);
	dma_page_pool_set_page_free(g_the_sphcs->dma_page_pool,
				    op->dma_data.dma_page_hndl);
send_error:
	cmdlst_send_fail_reports(cmd, val, op->dma_data.is_last, 0);
	sphcs_cmd_chan_update_cmd_head(cmd->context->chan, 1, PAGE_SIZE);
	kfree(op);
done:
	atomic_dec(&cmd->context->chan->sched_queued);
	// for opwork
	inf_cmd_put(cmd);
}

/* NNP_IPC_H2C_OP_CHAN_SCHEDULE_CMDLIST */
void IPC_OPCODE_HANDLER(CHAN_SCHEDULE_CMDLIST)(struct sphcs                    *sphcs,
					       union h2c_ChanInferenceCmdListOp *cmd)
{
	struct inf_context *context;
	struct inf_cmd_list *cmdlist;
	enum event_val val;
	dma_addr_t host_dma_addr;
	struct sphcs_host_rb *cmd_data_rb;
	u32 host_chunk_size;
	struct cmdlist_sched_dma_data dma_data;
	dma_addr_t dma_addr;
	struct cmdlst_op_work *work;
	int ret;

	context = find_and_get_context(sphcs->inf_data, cmd->chan_id);
	if (unlikely(context == NULL || context->chan == NULL)) {
		sphcs_send_event_report(sphcs, NNP_IPC_EXECUTE_CMD_COMPLETE, NNP_IPC_NO_SUCH_CONTEXT, NULL, cmd->chan_id, cmd->cmdID);
		return;
	}

	cmdlist = inf_context_find_cmd(context, cmd->cmdID);
	if (unlikely(cmdlist == NULL || cmdlist->status != CREATED)) {
		sphcs_send_event_report(sphcs, NNP_IPC_EXECUTE_CMD_COMPLETE, NNP_IPC_NO_SUCH_CMD, context->chan->respq, cmd->chan_id, cmd->cmdID);
		goto cmd_not_found;
	}

	if (cmd->size > 0) {
		cmd_data_rb = &context->chan->h2c_rb[1];
		/* need to advance h2c ring buffer by one page */
		host_rb_update_free_space(cmd_data_rb, NNP_PAGE_SIZE);
		ret = host_rb_get_avail_space(cmd_data_rb,
					      NNP_PAGE_SIZE,
					      1,
					      &host_dma_addr,
					      &host_chunk_size);

		NNP_ASSERT(ret == 1);
		NNP_ASSERT((host_dma_addr & NNP_IPC_DMA_ADDR_ALIGN_MASK) == 0);
		if (unlikely(ret != 1 || (host_dma_addr & NNP_IPC_DMA_ADDR_ALIGN_MASK) != 0)) {
			val = NNP_IPC_DMA_ERROR;
			goto send_error;
		}

		host_rb_update_avail_space(cmd_data_rb, NNP_PAGE_SIZE);
	}

	if (unlikely(inf_context_get_state(context) != CONTEXT_OK)) {
		val = NNP_IPC_CONTEXT_BROKEN;
		goto send_error;
	}

	if (cmd->is_first) {
		NNP_ASSERT(cmdlist->sched_failed == NNP_IPC_NO_ERROR);
		NNP_ASSERT(cmdlist->edits_idx == 0);
		NNP_ASSERT(atomic_read(&cmdlist->num_left) == 0);
		if (unlikely(atomic_read(&cmdlist->num_left) != 0 || // in flight
			     cmdlist->edits_idx != 0 || // previous sched in progress
			     cmdlist->sched_failed != NNP_IPC_NO_ERROR)) { // not cleared failure
			val = NNP_IPC_RUNTIME_NOT_SUPPORTED;
			goto send_error;
		}
		DO_TRACE(trace_cmdlist(SPH_TRACE_OP_STATUS_QUEUED, cmdlist->context->protocol_id, cmdlist->protocol_id));
		if (cmd->size == 0) { //No overwritten parameters
			NNP_ASSERT(cmd->is_last == 1);
			handle_sched_cmdlist(cmdlist, NULL, 0);

			goto done;
		}
	} else if (unlikely(cmdlist->sched_failed != NNP_IPC_NO_ERROR)) {
		val = cmdlist->sched_failed;
		goto send_error;
	}

	NNP_ASSERT(cmd->size > 0);
	if (unlikely(cmd->size == 0)) {
		val = NNP_IPC_RUNTIME_NOT_SUPPORTED;
		goto send_error;
	}

	if (atomic_read(&cmdlist->context->chan->sched_queued) == 0)
		ret = dma_page_pool_get_free_page_nowait(g_the_sphcs->dma_page_pool,
						&dma_data.dma_page_hndl,
						&dma_data.vptr,
						&dma_addr);
	else
		ret = -EXFULL; // at least 1 work ALREADY queued

	if (likely(ret == 0)) {
		dma_data.data_size = cmd->size;
		dma_data.is_last = cmd->is_last;

		// for DMA
		inf_cmd_get(cmdlist);

		ret = sphcs_dma_sched_start_xfer_single(g_the_sphcs->dmaSched,
							&context->chan->h2c_dma_exec_desc,
							host_dma_addr,
							dma_addr,
							cmd->size,
							cmdlist_schedule_dma_complete,
							cmdlist,
							&dma_data,
							sizeof(dma_data));

		if (unlikely(ret < 0)) {
			val = NNP_IPC_NO_MEMORY;
			goto free_page;
		}

		goto done;
	} else if (unlikely(ret != -EXFULL)) {
		val = NNP_IPC_NO_MEMORY;
		goto send_error;
	}

	//Add opwork
	work = kmalloc(sizeof(*work), GFP_NOWAIT);
	if (unlikely(work == NULL)) {
		val = NNP_IPC_NO_MEMORY;
		goto send_error;
	}

	atomic_inc(&cmdlist->context->chan->sched_queued);
	// put kref for opwork
	inf_cmd_get(cmdlist);

	work->cmd = cmdlist;
	work->host_dma_addr = host_dma_addr;
	work->dma_data.data_size = cmd->size;
	work->dma_data.is_last = cmd->is_last;

	INIT_WORK(&work->work, cmd_sched_op_work_handler);
	queue_work(context->chan->wq_exec, &work->work);

	goto done;

free_page:
	// put kref for DMA
	inf_cmd_put(cmdlist);
	dma_page_pool_set_page_free(g_the_sphcs->dma_page_pool,
				    dma_data.dma_page_hndl);
send_error:
	cmdlst_send_fail_reports(cmdlist, val, cmd->is_last, 0);
cmd_not_found:
	if (cmd->size > 0)
		sphcs_cmd_chan_update_cmd_head(context->chan, 0, PAGE_SIZE);
done:
	inf_context_put(context);
}


struct inf_req_op_work {
	struct work_struct           work;
	struct inf_context          *context;
	union  h2c_ChanInferenceReqOp    cmd;
};

static void inf_req_op_work_handler(struct work_struct *work)
{
	struct inf_req_op_work *op = container_of(work,
						  struct inf_req_op_work,
						  work);
	struct inf_devnet *devnet;
	struct inf_req *infreq;
	uint8_t event;
	enum event_val val;
	dma_addr_t host_dma_addr;
	int ret;

	if (op->cmd.destroy)
		event = NNP_IPC_DESTROY_INFREQ_FAILED;
	else
		event = NNP_IPC_CREATE_INFREQ_FAILED;

	if (!op->cmd.destroy) {
		struct sphcs_host_rb *cmd_data_rb = &op->context->chan->h2c_rb[op->cmd.rb_id];
		u32 host_chunk_size;
		int n;

		/* need to advance h2c ring buffer by one page */
		host_rb_update_free_space(cmd_data_rb, NNP_PAGE_SIZE);
		n = host_rb_get_avail_space(cmd_data_rb,
					    NNP_PAGE_SIZE,
					    1,
					    &host_dma_addr,
					    &host_chunk_size);

		NNP_ASSERT(n == 1);
		NNP_ASSERT((host_dma_addr & NNP_IPC_DMA_ADDR_ALIGN_MASK) == 0);
		if (unlikely(n != 1 || (host_dma_addr & NNP_IPC_DMA_ADDR_ALIGN_MASK) != 0)) {
			val = NNP_IPC_DMA_ERROR;
			goto send_error;
		}

		host_rb_update_avail_space(cmd_data_rb, NNP_PAGE_SIZE);

		if (!check_memory_threshold()) {
			val = NNP_IPC_NO_MEMORY;
			goto send_error;
		}
	}

	devnet = inf_context_find_and_get_devnet(op->context, op->cmd.netID, false, true);
	if (unlikely(devnet == NULL)) {
		val = NNP_IPC_NO_SUCH_NET;
		goto send_error;
	}

	if (op->cmd.destroy) {
		ret = inf_devnet_find_and_destroy_infreq(devnet, op->cmd.infreqID);
		if (unlikely(ret < 0)) {
			val = NNP_IPC_NO_SUCH_INFREQ;
			goto error_put_devnet;
		}
		inf_devnet_put(devnet);
		goto done;
	}

	if (unlikely(devnet->destroyed)) {
		val = NNP_IPC_NO_SUCH_NET;
		goto error_put_devnet;
	}

	infreq = inf_devnet_find_infreq(devnet, op->cmd.infreqID);
	if (unlikely(infreq != NULL)) {
		val = NNP_IPC_ALREADY_EXIST;
		goto error_put_devnet;
	}

	DO_TRACE(trace_infer_create(SPH_TRACE_INF_INF_REQ, op->cmd.chan_id, op->cmd.infreqID, SPH_TRACE_OP_STATUS_START, op->cmd.netID, -1));

	if (unlikely(op->cmd.size > NNP_PAGE_SIZE)) {
		val = NNP_IPC_DMA_ERROR;
		goto error_put_devnet;
	}


	ret = inf_devnet_create_infreq(devnet,
				       op->cmd.infreqID,
				       host_dma_addr,
				       op->cmd.size);
	if (unlikely(ret < 0)) {
		val = NNP_IPC_NO_MEMORY;
		goto error_put_devnet;
	}

	inf_devnet_put(devnet);
	goto done;

error_put_devnet:
	inf_devnet_put(devnet);
send_error:
	sphcs_cmd_chan_update_cmd_head(op->context->chan, 0, NNP_PAGE_SIZE);
	sphcs_send_event_report_ext(g_the_sphcs, event, val, op->context->chan->respq,
				op->cmd.chan_id,
				op->cmd.infreqID,
				op->cmd.netID);
done:
	inf_context_put(op->context);
	kfree(op);
}

void IPC_OPCODE_HANDLER(CHAN_INF_REQ_OP)(struct sphcs             *sphcs,
					 union h2c_ChanInferenceReqOp *cmd)
{
	struct inf_req_op_work *work;
	struct inf_context *context;
	uint8_t event;
	enum event_val val;

	if (cmd->destroy)
		event = NNP_IPC_DESTROY_INFREQ_FAILED;
	else
		event = NNP_IPC_CREATE_INFREQ_FAILED;

	context = find_and_get_context(g_the_sphcs->inf_data, cmd->chan_id);
	if (unlikely(context == NULL)) {
		val = NNP_IPC_NO_SUCH_CONTEXT;
		goto send_error;
	}

	work = kzalloc(sizeof(*work), GFP_NOWAIT);
	if (unlikely(work == NULL)) {
		val = NNP_IPC_NO_MEMORY;
		goto send_error;
	}

	work->cmd.value = cmd->value;
	work->context = context;
	INIT_WORK(&work->work, inf_req_op_work_handler);

	DO_TRACE_IF(!cmd->destroy, trace_infer_create(SPH_TRACE_INF_INF_REQ, cmd->chan_id, cmd->infreqID, SPH_TRACE_OP_STATUS_QUEUED, cmd->netID, -1));

	queue_work(context->chan->wq, &work->work);

	return;

send_error:
	if (context != NULL && context->chan != NULL) {
		sphcs_send_event_report_ext(sphcs, event, val, context->chan->respq,
					    cmd->chan_id, cmd->infreqID, cmd->netID);
		inf_context_put(context);
	} else {
		sphcs_send_event_report_ext(sphcs, event, val, NULL,
					    cmd->chan_id, cmd->infreqID, cmd->netID);
	}
}

void IPC_OPCODE_HANDLER(CHAN_SCHEDULE_INF_REQ)(struct sphcs                   *sphcs,
					       union h2c_ChanInferenceReqSchedule *cmd)
{
	struct inf_context *context;
	struct inf_devnet *devnet;
	struct inf_req *infreq;
	struct inf_exec_req *req;
	int ret;
	enum event_val val;

	context = find_and_get_context(sphcs->inf_data, cmd->chan_id);
	if (unlikely(context == NULL)) {
		val = NNP_IPC_NO_SUCH_CONTEXT;
		goto send_error;
	}

	if (unlikely(inf_context_get_state(context) != CONTEXT_OK)) {
		val = NNP_IPC_CONTEXT_BROKEN;
		goto send_error;
	}

	if (unlikely(context->num_optimized_cmd_lists > 0)) {
		val = NNP_IPC_NOT_SUPPORTED;
		goto send_error;
	}

	devnet = inf_context_find_and_get_devnet(context, cmd->netID, false, true);
	if (unlikely(devnet == NULL)) {
		val = NNP_IPC_NO_SUCH_NET;
		goto send_error;
	}
	inf_context_put(context);

	infreq = inf_devnet_find_and_get_infreq(devnet, cmd->infreqID);
	inf_devnet_put(devnet);
	if (unlikely(infreq == NULL)) {
		val = NNP_IPC_NO_SUCH_INFREQ;
		goto send_error;
	}

	req = kmem_cache_alloc(context->exec_req_slab_cache, GFP_NOWAIT);
	if (unlikely(req == NULL)) {
		inf_req_put(infreq);
		val = NNP_IPC_NO_MEMORY;
		goto send_error;
	}

	infreq_req_init(req,
			infreq,
			NULL,//cmdlist ptr
			cmd->schedParamsIsNull != 0 ? 0 : cmd->priority,
			cmd->schedParamsIsNull != 0,
			cmd->batchSize,
			cmd->debugOn,
			cmd->collectInfo);

	ret = infreq_req_sched(req);
	inf_req_put(infreq);
	if (unlikely(ret < 0)) {
		kmem_cache_free(context->exec_req_slab_cache, req);
		val = NNP_IPC_NO_MEMORY;
		goto send_error;
	}

	return;

send_error:
	if (context != NULL && context->chan != NULL) {
		sphcs_send_event_report_ext(sphcs,
					NNP_IPC_SCHEDULE_INFREQ_FAILED,
					val,
					context->chan->respq,
					cmd->chan_id,
					cmd->infreqID,
					cmd->netID);
		inf_context_put(context);
	} else {
		sphcs_send_event_report_ext(sphcs,
					NNP_IPC_SCHEDULE_INFREQ_FAILED,
					val,
					NULL,
					cmd->chan_id,
					cmd->infreqID,
					cmd->netID);
	}
}

struct network_property_op_work {
	struct work_struct work;
	struct inf_context *context;
	union h2c_ChanInferenceNetworkSetProperty cmd;
};

static void network_property_op_work_handler(struct work_struct *work)
{
	struct network_property_op_work	*op = container_of(work,
			struct network_property_op_work,
			work);
	struct inf_devnet *devnet;
	enum event_val event_val = NNP_IPC_NO_ERROR;

	devnet = inf_context_find_and_get_devnet(op->context, op->cmd.netID, true, true);
	if (unlikely(devnet == NULL)) {
		sphcs_send_event_report(g_the_sphcs,
				NNP_IPC_DEVNET_SET_PROPERTY_FAILED,
				NNP_IPC_NO_SUCH_NET,
				op->context->chan->respq,
				op->cmd.chan_id,
				op->cmd.netID);
		goto free_op;
	}

	switch (op->cmd.property) {
	case NNP_SERIAL_INF_EXECUTION: {
		NNP_SPIN_LOCK(&devnet->lock);
		devnet->serial_infreq_exec = op->cmd.property_val;
		NNP_SPIN_UNLOCK(&devnet->lock);

		inf_devnet_put(devnet);

		sphcs_send_event_report(g_the_sphcs,
					NNP_IPC_DEVNET_SET_PROPERTY_SUCCESS,
					event_val,
					op->context->chan->respq,
					op->cmd.chan_id,
					op->cmd.netID);
		break;
	}
	case NNP_NETWORK_RESOURCES_RESERVATION: {
		struct inf_devnet_resource_reserve cmd_args;
		int ret;

		/* Network reservation operation cannot run while network editing still in progress */
		NNP_SPIN_LOCK(&devnet->lock);
		if (unlikely(devnet->edit_status != CREATED)) {
			NNP_SPIN_UNLOCK(&devnet->lock);
			inf_devnet_put(devnet);
			sphcs_send_event_report(g_the_sphcs,
					NNP_IPC_DEVNET_SET_PROPERTY_FAILED,
					NNP_IPC_NOT_SUPPORTED,
					op->context->chan->respq,
					op->cmd.chan_id,
					op->cmd.netID);
			goto free_op;
		}
		/* Change edit_status of the network to DMA_COMPLETED
		 * in case runtime crashed before finish handling the network reservation,
		 * we need to be able to release the network ref count acquired.
		 */
		devnet->edit_status = DMA_COMPLETED;
		NNP_SPIN_UNLOCK(&devnet->lock);

		memset(&cmd_args, 0, sizeof(cmd_args));
		cmd_args.devnet_rt_handle = (uint64_t)devnet->rt_handle;
		cmd_args.devnet_drv_handle = (uint64_t)devnet->ptr2id;
		cmd_args.reserve_resource = op->cmd.property_val;
		if (op->cmd.property_val)
			cmd_args.timeout = op->cmd.timeout;

		// kref for RT is taken in find

		ret = inf_cmd_queue_add(&devnet->context->cmdq,
					SPHCS_RUNTIME_CMD_DEVNET_RESOURCES_RESERVATION,
					&cmd_args,
					sizeof(cmd_args),
					NULL, NULL);
		if (unlikely(ret < 0)) {
			sphcs_send_event_report(g_the_sphcs,
						op->cmd.property_val ? NNP_IPC_DEVNET_RESOURCES_RESERVATION_FAILED : NNP_IPC_DEVNET_RESOURCES_RELEASE_FAILED,
						NNP_IPC_NO_MEMORY,
						op->context->chan->respq,
						op->cmd.chan_id,
						op->cmd.netID);
			inf_devnet_put(devnet);
		}
		break;
	}
	default:
		inf_devnet_put(devnet);
		sph_log_err(CREATE_COMMAND_LOG, "unexpected network property (%u)\n", op->cmd.property);
		sphcs_send_event_report(g_the_sphcs,
					NNP_IPC_DEVNET_SET_PROPERTY_FAILED,
					NNP_IPC_NOT_SUPPORTED,
					op->context->chan->respq,
					op->cmd.chan_id,
					op->cmd.netID);
	}

free_op:
	inf_context_put(op->context);
	kfree(op);
}

void IPC_OPCODE_HANDLER(CHAN_NETWORK_PROPERTY)(struct sphcs *sphcs,
		union h2c_ChanInferenceNetworkSetProperty *cmd) {
	struct network_property_op_work *work;
	struct inf_context *context;
	enum event_val val;

	context = find_and_get_context(sphcs->inf_data, cmd->chan_id);
	if (unlikely(context == NULL)) {
		val = NNP_IPC_NO_SUCH_CONTEXT;
		goto send_error;
	}

	work = kzalloc(sizeof(*work), GFP_NOWAIT);
	if (unlikely(work == NULL)) {
		val = NNP_IPC_NO_MEMORY;
		goto send_error;
	}

	memcpy(work->cmd.value, cmd->value, sizeof(work->cmd.value));
	work->context = context;

	INIT_WORK(&work->work, network_property_op_work_handler);
	queue_work(context->chan->wq, &work->work);

	return;

send_error:
	if (context != NULL && context->chan != NULL) {
		sphcs_send_event_report(sphcs, NNP_IPC_DEVNET_SET_PROPERTY_FAILED,
					val, context->chan->respq, cmd->chan_id, cmd->netID);
		inf_context_put(context);
	} else {
		sphcs_send_event_report(sphcs, NNP_IPC_DEVNET_SET_PROPERTY_FAILED,
					val, NULL, cmd->chan_id, cmd->netID);
	}
}

static const struct file_operations sphcs_inf_fops = {
	.owner = THIS_MODULE,
	.open = sphcs_inf_open,
	.release = sphcs_inf_release,
	.unlocked_ioctl = sphcs_inf_ioctl,
	.compat_ioctl = sphcs_inf_ioctl,
	.poll = sphcs_inf_poll,
	.read = sphcs_inf_read
};

static inline int is_inf_file(struct file *f)
{
	return f->f_op == &sphcs_inf_fops;
}

int sphcs_alloc_resource(struct sphcs                 *sphcs,
			 uint64_t                      size,
			 uint32_t                      page_size,
			 sphcs_alloc_resource_callback cb,
			 void                          *ctx)
{
	struct inf_alloc_resource cmd_args;
	struct alloc_req *alloc_req;
	int rc;

	if (unlikely(sphcs == NULL))
		return -EINVAL;

	if (unlikely(sphcs->inf_data == NULL))
		return -ENODEV;

	mutex_lock(&sphcs->inf_data->io_lock);
	if (unlikely(sphcs->inf_data->daemon == NULL)) {
		mutex_unlock(&sphcs->inf_data->io_lock);
		return -ENODEV;
	}

	alloc_req = kzalloc(sizeof(*alloc_req), GFP_KERNEL);
	if (unlikely(alloc_req == NULL)) {
		mutex_unlock(&sphcs->inf_data->io_lock);
		return -ENOMEM;
	}
	alloc_req->cb = cb;
	alloc_req->context = ctx;

	NNP_SPIN_LOCK(&sphcs->inf_data->daemon->lock);
	list_add_tail(&alloc_req->node, &sphcs->inf_data->daemon->alloc_req_list);
	NNP_SPIN_UNLOCK(&sphcs->inf_data->daemon->lock);

	cmd_args.drv_handle = (uint64_t)add_ptr2id(alloc_req);
	cmd_args.size = size;
	cmd_args.page_size = page_size;

	rc = inf_cmd_queue_add(&sphcs->inf_data->daemon->cmdq,
			       SPHCS_DAEMON_CMD_ALLOC_RESOURCE,
			       &cmd_args,
			       sizeof(cmd_args),
			       NULL, NULL);

	if (unlikely(rc < 0)) {
		NNP_SPIN_LOCK(&sphcs->inf_data->daemon->lock);
		list_del(&alloc_req->node);
		NNP_SPIN_UNLOCK(&sphcs->inf_data->daemon->lock);
		mutex_unlock(&sphcs->inf_data->io_lock);
		del_ptr2id(alloc_req);
		kfree(alloc_req);
	}

	mutex_unlock(&sphcs->inf_data->io_lock);

	return rc;
}

int sphcs_free_resource(struct sphcs  *sphcs,
			int            dmabuf_fd)
{
	struct inf_free_resource cmd_args;
	int rc;

	if (unlikely(sphcs == NULL))
		return -EINVAL;

	if (unlikely(sphcs->inf_data == NULL))
		return -ENODEV;

	mutex_lock(&sphcs->inf_data->io_lock);
	if (unlikely(sphcs->inf_data->daemon == NULL)) {
		mutex_unlock(&sphcs->inf_data->io_lock);
		return -ENODEV;
	}

	cmd_args.buf_fd = dmabuf_fd;

	rc = inf_cmd_queue_add(&sphcs->inf_data->daemon->cmdq,
			       SPHCS_DAEMON_CMD_FREE_RESOURCE,
			       &cmd_args,
			       sizeof(cmd_args),
			       NULL, NULL);

	mutex_unlock(&sphcs->inf_data->io_lock);

	return rc;
}

static void sphcs_inf_new_data_arrived(struct sphcs_p2p_buf *buf)
{
	struct inf_devres *devres;
	unsigned long flags;

	sph_log_debug(START_UP_LOG, "New data arrived (buf id %u)\n", buf->buf_id);

	devres = container_of(buf, struct inf_devres, p2p_buf);
	DO_TRACE(trace_credit(devres->context->protocol_id,
			      devres->protocol_id,
			      buf->buf_id,
			      sphcs_p2p_get_peer_dev_id(buf)));

	/* Update should be atomic */
	NNP_SPIN_LOCK_IRQSAVE(&devres->lock_irq, flags);
	inf_devres_set_dirty(devres, false);
	devres->p2p_buf.ready = true;
	NNP_SPIN_UNLOCK_IRQRESTORE(&devres->lock_irq, flags);

	/* advance sched tick and try execute next requests */
	atomic_add(2, &devres->context->sched_tick);
	inf_devres_try_execute(devres);
}

static void sphcs_inf_data_consumed(struct sphcs_p2p_buf *buf)
{
	struct inf_devres *devres;

	sph_log_debug(START_UP_LOG, "Data consumed (buf id %u)\n", buf->buf_id);

	devres = container_of(buf, struct inf_devres, p2p_buf);

	devres->p2p_buf.ready = true;

	/* advance sched tick and try execute next requests */
	atomic_add(2, &devres->context->sched_tick);
	inf_devres_try_execute(devres);
}

static struct sphcs_p2p_cbs s_p2p_cbs = {
		.new_data_arrived = sphcs_inf_new_data_arrived,
		.data_consumed = sphcs_inf_data_consumed,
};

int inference_init(struct sphcs *sphcs)
{
	struct inf_data *inf_data = NULL;
	int ret;

	ret = alloc_chrdev_region(&s_devnum, 0, 1, SPHCS_INF_DEV_NAME);
	if (unlikely(ret < 0)) {
		sph_log_err(START_UP_LOG, "failed to allocate devnum %d\n", ret);
		return ret;
	}

	cdev_init(&s_cdev, &sphcs_inf_fops);
	s_cdev.owner = THIS_MODULE;

	ret = cdev_add(&s_cdev, s_devnum, 1);
	if (unlikely(ret < 0)) {
		sph_log_err(START_UP_LOG, "failed to add cdev %d\n", ret);
		goto unreg;
	}

	s_class = class_create(THIS_MODULE, SPHCS_INF_DEV_NAME);
	if (unlikely(IS_ERR(s_class))) {
		ret = PTR_ERR(s_class);
		sph_log_err(START_UP_LOG, "failed to register class %d\n", ret);
		goto free_cdev;
	}

	s_dev = device_create(s_class, NULL, s_devnum, NULL, SPHCS_INF_DEV_NAME);
	if (unlikely(IS_ERR(s_dev))) {
		ret = PTR_ERR(s_dev);
		goto free_class;
	}

	inf_data = kzalloc(sizeof(*inf_data), GFP_KERNEL);
	if (unlikely(inf_data == NULL)) {
		ret = -ENOMEM;
		goto free_dev;
	}

	spin_lock_init(&inf_data->lock_bh);
	mutex_init(&inf_data->io_lock);
	hash_init(inf_data->context_hash);

	ret = sphcs_ctx_uids_init();
	if (ret) {
		sph_log_err(START_UP_LOG, "Failed to initialize ctx_uids sysfs counters");
		goto free_mutex;
	}

	inf_data->inf_wq = create_singlethread_workqueue("sphcs_inf_wq");
	if (!inf_data->inf_wq) {
		sph_log_err(START_UP_LOG, "Failed to initialize ctx create/destroy workqueue");
		goto free_ctx_uids;
	}

	sphcs->inf_data = inf_data;

	ret = sphcs_p2p_init(sphcs, &s_p2p_cbs);
	if (ret) {
		sph_log_err(START_UP_LOG, "Failed to initialize p2p");
		goto destroy_wq;
	}

	return 0;

destroy_wq:
	destroy_workqueue(sphcs->inf_data->inf_wq);
free_ctx_uids:
	sphcs_ctx_uids_fini();
free_mutex:
	mutex_destroy(&sphcs->inf_data->io_lock);
free_dev:
	device_destroy(s_class, s_devnum);
free_class:
	class_destroy(s_class);
free_cdev:
	cdev_del(&s_cdev);
unreg:
	unregister_chrdev_region(s_devnum, 1);
	kfree(inf_data);

	return ret;
}

int inference_fini(struct sphcs *sphcs)
{
	clean_ptr2id();
	sphcs_p2p_fini(sphcs);
	sphcs_ctx_uids_fini();
	destroy_workqueue(sphcs->inf_data->inf_wq);
	device_destroy(s_class, s_devnum);
	class_destroy(s_class);
	cdev_del(&s_cdev);
	unregister_chrdev_region(s_devnum, 1);

	// TODO: remove resources
	mutex_destroy(&sphcs->inf_data->io_lock);
	kfree(sphcs->inf_data);
	return 0;
}

static void release_pending_create_context_reuquests(void *cmd_args)
{
	struct inf_create_context *ctx_cmd_args = cmd_args;
	struct inf_context *context = find_and_get_context(g_the_sphcs->inf_data, ctx_cmd_args->contextID);

	if (unlikely(context == NULL)) {
		NNP_ASSERT(0);
		return;
	}

	NNP_ASSERT(!context->daemon_ref_released);
	inf_context_put(context);

	sph_log_debug(START_UP_LOG, "Release pending create context requests ID %d\n", ctx_cmd_args->contextID);
	sphcs_send_event_report(g_the_sphcs,
				NNP_IPC_CREATE_CONTEXT_FAILED,
				NNP_IPC_NO_DAEMON,
				context->chan->respq,
				ctx_cmd_args->contextID,
				-1);

	destroy_context_on_create_failed(g_the_sphcs, context);
	context->daemon_ref_released = true;
	inf_context_put(context);
}

static int sched_status_show(struct seq_file *m, void *v)
{
	struct inf_data *inf_data;
	struct inf_context *context;
	struct inf_req_sequence *seq;
	struct inf_exec_req *req;
	u64 curr_time;
	int i;
	int num_contexts = 0;
	struct sysinfo sinfo;

	if (!g_the_sphcs)
		return -1;

	curr_time = nnp_time_us();
	inf_data = g_the_sphcs->inf_data;
	NNP_SPIN_LOCK_BH(&inf_data->lock_bh);
	hash_for_each(inf_data->context_hash, i, context, hash_node) {
		num_contexts++;
		NNP_SPIN_LOCK(&context->lock);
		if (!context->attached || context->destroyed || context->runtime_detach_sent)
			seq_printf(m, "Context %d attach state: attached=%d destroyed=%d runtime_detach_sent=%d\n",
				   context->protocol_id,
				   context->attached,
				   context->destroyed,
				   context->runtime_detach_sent);
		if (list_empty(&context->active_seq_list)) {
			seq_printf(m, "Context %d: No scheduled commands, state=%d\n", context->protocol_id, context->state);
		} else {
			seq_printf(m, "Context %d: state=%d\n", context->protocol_id, context->state);
			list_for_each_entry(seq, &context->active_seq_list, node) {
				req = container_of(seq,
						   struct inf_exec_req,
						   seq);
				if (req->cmd_type == CMDLIST_CMD_INFREQ) {
					seq_printf(m, "\tinfer command %d network %d\n",
						  req->infreq->protocol_id,
						  req->infreq->devnet->protocol_id);
					if (req->cmd != NULL)
						seq_printf(m, "\t\tcommand list %d\n", req->cmd->protocol_id);
					seq_printf(m, "\t\tin_progress: %d\n", req->in_progress);
					seq_printf(m, "\t\tpriority: %d\n", req->priority);
					seq_printf(m, "\t\ttime: %lld\n", curr_time - req->time);
				} else if (req->cmd_type == CMDLIST_CMD_COPY) {
					seq_printf(m, "\tcopy command %d\n", req->copy->protocol_id);
					if (req->cmd != NULL)
						seq_printf(m, "\t\tcommand list %d\n", req->cmd->protocol_id);
					seq_printf(m, "\t\tin_progress: %d\n", req->in_progress);
					seq_printf(m, "\t\tpriority: %d\n", req->priority);
					seq_printf(m, "\t\ttime: %lld\n", curr_time - req->time);
				} else if (req->cmd_type == CMDLIST_CMD_COPYLIST) {
					seq_printf(m, "\tcopy list command idx=%d, n_copies=%d\n",
						   req->cpylst->idx_in_cmd,
						   req->cpylst->n_copies);
					if (req->cmd != NULL)
						seq_printf(m, "\t\tcommand list %d\n", req->cmd->protocol_id);
					seq_printf(m, "\t\tin_progress: %d\n", req->in_progress);
					seq_printf(m, "\t\tpriority: %d\n", req->priority);
					seq_printf(m, "\t\ttime: %lld\n", curr_time - req->time);
				} else {
					seq_printf(m, "\tUNKNWON COMMAND TYPE %d !!!\n", req->cmd_type);
				}
			}
		}
		NNP_SPIN_UNLOCK(&context->lock);
	}
	NNP_SPIN_UNLOCK_BH(&inf_data->lock_bh);

	if (num_contexts == 0)
		seq_puts(m, "No active contexts\n");

	si_meminfo(&sinfo);
	seq_puts(m, "\nMemory Info:\n");
	seq_printf(m, "TotalRam: %lu KB\n", sinfo.totalram * (sinfo.mem_unit >> 10));
	seq_printf(m, "FreeRam: %lu KB\n", sinfo.freeram * (sinfo.mem_unit >> 10));

	return 0;
}

static int sched_status_open(struct inode *inode, struct file *filp)
{
	return single_open(filp, sched_status_show, inode->i_private);
}

static const struct file_operations sched_status_fops = {
	.open		= sched_status_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int ctx_status_show(struct seq_file *m, void *v)
{
	struct inf_data *inf_data;
	struct inf_context *context;
	struct inf_devres *devres;
	struct inf_copy *copy;
	struct inf_devnet *devnet;
	struct inf_req *infreq;
	struct inf_cmd_list *cmd;
	struct inf_sync_point *sync_point;
	int i, j, k;
	int num_contexts = 0;

	if (!g_the_sphcs)
		return -1;

	inf_data = g_the_sphcs->inf_data;
	//NNP_SPIN_LOCK_BH(&inf_data->lock_bh);
	hash_for_each(inf_data->context_hash, i, context, hash_node) {
		num_contexts++;
		seq_printf(m, "Context %d attach state: attached=%d destroyed=%d runtime_detach_sent=%d ref_count=%d\n",
			   context->protocol_id,
			   context->attached,
			   context->destroyed,
			   context->runtime_detach_sent,
			   kref_read(&context->ref));

		//NNP_SPIN_LOCK(&context->lock);
		hash_for_each(context->cmd_hash, j, cmd, hash_node)
			seq_printf(m, "\tcmdlist %d destroyed=%d\n", cmd->protocol_id, cmd->destroyed);
		hash_for_each(context->copy_hash, j, copy, hash_node)
			seq_printf(m, "\tcopy %d destroyed=%d\n", copy->protocol_id, copy->destroyed);
		hash_for_each(context->devnet_hash, j, devnet, hash_node) {
			seq_printf(m, "\tdevnet %d destroyed=%d\n", devnet->protocol_id, devnet->destroyed);
			//NNP_SPIN_LOCK(&devnet->lock);
			hash_for_each(devnet->infreq_hash, k, infreq, hash_node)
				seq_printf(m, "\t\tinfreq %d destroyed=%d\n", infreq->protocol_id, infreq->destroyed);
			//NNP_SPIN_UNLOCK(&devnet->lock);
		}
		hash_for_each(context->devres_hash, j, devres, hash_node)
			seq_printf(m, "\tdevres %d destroyed=%d\n", devres->protocol_id, devres->destroyed);
		list_for_each_entry(sync_point, &context->sync_points, node)
			seq_printf(m, "\tsync_point %d host_sync_id=%d\n", sync_point->seq_id, sync_point->host_sync_id);
		//NNP_SPIN_UNLOCK(&context->lock);
	}
	//NNP_SPIN_UNLOCK_BH(&inf_data->lock_bh);

	if (num_contexts == 0)
		seq_puts(m, "No active contexts\n");

	return 0;
}

static int ctx_status_open(struct inode *inode, struct file *filp)
{
	return single_open(filp, ctx_status_show, inode->i_private);
}

static const struct file_operations ctx_status_fops = {
	.open		= ctx_status_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int ids_map_trace_show(struct seq_file *m, void *v)
{
	struct inf_data *inf_data;
	struct inf_context *context;
	int i, j, k;
	struct inf_devres *devres;
	struct inf_copy *copy;
	struct inf_devnet *devnet;
	struct inf_req *infreq;
	struct inf_cmd_list *cmd;
	struct sphcs_hostres_map *hostres_map;
	uint32_t num_contexts = 0, num_copies = 0, num_cmds = 0, num_devres = 0, num_devnets = 0, num_infreqs = 0, num_hostres_map = 0;

	if (!g_the_sphcs)
		return -1;

	inf_data = g_the_sphcs->inf_data;
	NNP_SPIN_LOCK_BH(&inf_data->lock_bh);
	hash_for_each(inf_data->context_hash, i, context, hash_node) {
		num_contexts++;
		DO_TRACE(trace_ids_map(SPH_TRACE_INF_CONTEXT, context->protocol_id, 0, 0, context->user_handle));


		NNP_SPIN_LOCK(&context->lock);
		hash_for_each(context->cmd_hash, j, cmd, hash_node) {
			num_cmds++;
			DO_TRACE(trace_ids_map(SPH_TRACE_INF_COMMAND_LIST, context->protocol_id, cmd->protocol_id, 0, cmd->user_handle));
		}
		hash_for_each(context->copy_hash, j, copy, hash_node) {
			num_copies++;
			DO_TRACE(trace_ids_map(SPH_TRACE_INF_COPY, context->protocol_id, copy->protocol_id, 0, copy->user_handle));
		}
		hash_for_each(context->devnet_hash, j, devnet, hash_node) {
			num_devnets++;
			DO_TRACE(trace_ids_map(SPH_TRACE_INF_NETWORK, context->protocol_id, devnet->protocol_id, 0, devnet->user_handle));
			NNP_SPIN_LOCK(&devnet->lock);
			hash_for_each(devnet->infreq_hash, k, infreq, hash_node) {
				num_infreqs++;
				DO_TRACE(trace_ids_map(SPH_TRACE_INF_INF_REQ, context->protocol_id,
							devnet->protocol_id, infreq->protocol_id, infreq->user_handle));
			}
			NNP_SPIN_UNLOCK(&devnet->lock);
		}
		hash_for_each(context->devres_hash, j, devres, hash_node) {
			num_devres++;
			DO_TRACE(trace_ids_map(SPH_TRACE_INF_DEVRES, context->protocol_id, devres->protocol_id, 0, devres->user_handle));
		}
		hash_for_each(context->chan->hostres_hash, j, hostres_map, hash_node) {
			num_hostres_map++;
			DO_TRACE(trace_ids_map(SPH_TRACE_INF_HOSTRES, context->protocol_id, hostres_map->protocol_id, 0, hostres_map->user_handle));
		}
		NNP_SPIN_UNLOCK(&context->lock);
	}
	NNP_SPIN_UNLOCK_BH(&inf_data->lock_bh);

	seq_printf(m, "Num contexts:           %u\n", num_contexts);
	seq_printf(m, "Num cmd lists:          %u\n", num_cmds);
	seq_printf(m, "Num copy objects:       %u\n", num_copies);
	seq_printf(m, "Num device resources:   %u\n", num_devres);
	seq_printf(m, "Num host resource maps: %u\n", num_hostres_map);
	seq_printf(m, "Num device networks:    %u\n", num_devnets);
	seq_printf(m, "Num infer requests:     %u\n", num_infreqs);


	return 0;
}

static int ids_map_trace_open(struct inode *inode, struct file *filp)
{
	return single_open(filp, ids_map_trace_show, inode->i_private);
}

static const struct file_operations ids_map_trace_fops = {
	.open		= ids_map_trace_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

void sphcs_inf_init_debugfs(struct dentry *parent)
{
	debugfs_create_file("sched_status",
			    0444,
			    parent,
			    NULL,
			    &sched_status_fops);

	debugfs_create_file("ctx_status",
			    0444,
			    parent,
			    NULL,
			    &ctx_status_fops);

	debugfs_create_file("ids_map_trace",
			    0444,
			    parent,
			    NULL,
			    &ids_map_trace_fops);
}
