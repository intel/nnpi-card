/********************************************
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/poll.h>
#include <linux/uaccess.h>
#include <linux/wait.h>
#include <linux/slab.h>
#include <linux/idr.h>
#include <linux/list.h>
#include <linux/anon_inodes.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/interrupt.h>
#include <linux/workqueue.h>
#include <linux/file.h>
#include <linux/hashtable.h>
#include <linux/atomic.h>
#include "dma_page_pool.h"
#include "sphcs_cs.h"
#include "sphcs_response_page_pool.h"
#include "ipc_protocol.h"
#include "sph_debug.h"
#include "sph_log.h"
#include "ioctl_genmsg.h"
#include "sphcs_dma_sched.h"


static struct cdev s_cdev;
static dev_t       s_devnum;
static struct class *s_class;
static struct device *s_dev;

struct genmsg_global_data {
	DECLARE_HASHTABLE(channel_hash, 5);
	struct ida        channel_ida;
	spinlock_t        lock;
};
static struct genmsg_global_data s_genmsg;

struct genmsg_command_entry {
	union h2c_GenericMessaging msg;
	struct list_head node;
};

static struct list_head s_pending_commands;
static spinlock_t       s_pending_commands_lock_bh;
static struct work_struct s_pending_commands_work;
static uint32_t         s_num_pending_commands;

struct channel_data;

struct genmsg_dma_command_data {
	void       *vptr;
	page_handle dma_page_hndl;
	dma_addr_t  dma_addr;
	dma_addr_t  host_dma_addr;
	struct channel_data *channel;
	union h2c_GenericMessaging msg;
};

struct pending_packet {
	struct genmsg_dma_command_data dma_data;
	int                            is_hangup_command;
	struct list_head               node;
};

struct channel_data {
	u16               host_client_id;
	int               fd;
	bool              is_privileged;
	struct file      *file;
	struct list_head  pending_read_packets;
	spinlock_t        read_lock;
	struct pending_packet *current_read_packet;
	u32                    current_read_size;
	u32               n_read_dma_req;

	u16                channel_id;
	struct hlist_node  hash_node;

	struct msg_scheduler_queue *respq;
	struct sphcs_dma_desc c2h_dma_desc;
	struct sphcs_dma_desc h2c_dma_desc;

	int               closing;
	int               hanging_up;
	bool              io_error;

	wait_queue_head_t read_waitq;

	int               write_host_page_valid;
	page_handle       write_host_page_hndl;
	dma_addr_t        write_host_page_addr;
	page_handle       write_page_hndl;
	dma_addr_t        write_page_addr;
	void             *write_page_vptr;
	wait_queue_head_t write_waitq;
	atomic_t          n_write_dma_req;
	struct mutex      write_lock;
};

struct service_data {
	int              id;
	u64              host_client_handle;
	struct list_head pending_connections;
	spinlock_t       lock;

	wait_queue_head_t waitq;
};

static struct sphcs_genmsg_service_list {
	struct ida       ida;
	struct mutex     lock;
	const char      *service_name[SPH_MAX_GENERIC_SERVICES];
	int              service_name_len[SPH_MAX_GENERIC_SERVICES];
	struct service_data *service_data[SPH_MAX_GENERIC_SERVICES];
	int              num_services;
} *s_service_list = NULL;

struct dma_req_user_data {
	page_handle dma_page_hndl;
	page_handle host_dma_page_hndl;
	void       *dma_vptr;
	u32         xfer_size;
	u32         param1;
	struct channel_data *channel;
};

static struct channel_data *find_channel(u16 channel_id)
{
	struct channel_data *channel;

	SPH_SPIN_LOCK(&s_genmsg.lock);
	hash_for_each_possible(s_genmsg.channel_hash,
			       channel,
			       hash_node,
			       channel_id)
		if (channel->channel_id == channel_id) {
			SPH_SPIN_UNLOCK(&s_genmsg.lock);
			return channel;
		}

	SPH_SPIN_UNLOCK(&s_genmsg.lock);
	return NULL;
}

static void free_channel(struct channel_data *channel)
{
	SPH_ASSERT(channel->closing == 2 && channel->hanging_up);

	mutex_destroy(&channel->write_lock);
	msg_scheduler_queue_flush(channel->respq);
	sphcs_destroy_response_queue(g_the_sphcs, channel->respq);
	SPH_SPIN_LOCK(&s_genmsg.lock);
	hash_del(&channel->hash_node);
	SPH_SPIN_UNLOCK(&s_genmsg.lock);
	ida_simple_remove(&s_genmsg.channel_ida, channel->channel_id);

	kfree(channel);
}

static int chan_response_dma_completed(struct sphcs *sphcs,
				       void *ctx,
				       const void *user_data,
				       int status,
				       u32 timeUS);

/***************************************************************************
 * Connected Channel file descriptor operations
 ***************************************************************************/
static inline int is_channel_file(struct file *f);

static int sphcs_genmsg_chan_release(struct inode *inode, struct file *f)
{
	struct channel_data *channel = (struct channel_data *)f->private_data;
	struct pending_packet *pend;
	struct list_head pending_read_packets;
	union c2h_GenericMessaging msg;

	if (!is_channel_file(f))
		return -EINVAL;

	/* move pending read packets to a list on local stack */
	SPH_SPIN_LOCK(&channel->read_lock);
	channel->closing = 1;
	INIT_LIST_HEAD(&pending_read_packets);
	list_splice_init(&channel->pending_read_packets, &pending_read_packets);
	if (channel->current_read_packet) {
		/* add the current read packet if exist */
		list_add_tail(&channel->current_read_packet->node, &pending_read_packets);
		channel->current_read_packet = NULL;
	}
	SPH_SPIN_UNLOCK(&channel->read_lock);

	/* release all packets in the pending read list */
	while (!list_empty(&pending_read_packets)) {
		pend = list_first_entry(&pending_read_packets, struct pending_packet, node);
		list_del(&pend->node);

		if (!pend->is_hangup_command)
			dma_page_pool_set_page_free(g_the_sphcs->dma_page_pool, pend->dma_data.dma_page_hndl);
		kfree(pend);
	}

	/*
	 * Wait for all pending write dma requests to complete before sending
	 * the hangup packet
	 */
	wait_event_interruptible(channel->write_waitq,
				 atomic_read(&channel->n_write_dma_req) == 0);

	/* return write pages back to pool if we still hold it */
	mutex_lock(&channel->write_lock);
	if (channel->write_page_vptr)
		dma_page_pool_set_page_free(g_the_sphcs->dma_page_pool, channel->write_page_hndl);

	if (channel->write_host_page_valid)
		sphcs_response_pool_put_back_response_page(0,
						  channel->write_host_page_addr,
						  channel->write_host_page_hndl);

	mutex_unlock(&channel->write_lock);

	/*
	 * Send hangup message to host
	 */
	msg.value = 0LL;
	msg.opcode = SPH_IPC_C2H_OP_GENERIC_MSG_PACKET;
	msg.size = 0;
	msg.hangup = 1;
	msg.card_client_id = channel->channel_id;
	msg.host_client_id = channel->host_client_id;

	sphcs_msg_scheduler_queue_add_msg(channel->respq, &msg.value, 1);

	/* free the channel if we aleady got hangup message from host
	 * otherwise, it will be freed once a hangup message is arrived
	 */
	SPH_SPIN_LOCK(&channel->read_lock);
	channel->closing = 2;
	if (channel->hanging_up) {
		SPH_SPIN_UNLOCK(&channel->read_lock);
		free_channel(channel);
	} else {
		SPH_SPIN_UNLOCK(&channel->read_lock);
	}

	return 0;
}

static ssize_t sphcs_genmsg_chan_read(struct file *f,
				      char __user *buf,
				      size_t       size,
				      loff_t      *off)
{
	struct channel_data *channel = (struct channel_data *)f->private_data;
	size_t read_size;
	ssize_t ret;

	if (unlikely(!is_channel_file(f)))
		return -EINVAL;

	if (channel->io_error)
		return -EIO;

	if (!channel->current_read_packet) {

		/* wait for a pending read packets */
		ret = wait_event_interruptible(channel->read_waitq,
				!list_empty(&channel->pending_read_packets));
		if (unlikely(ret < 0))
			return ret;

		SPH_SPIN_LOCK(&channel->read_lock);
		SPH_ASSERT(!list_empty(&channel->pending_read_packets));
		channel->current_read_packet = list_first_entry(
						&channel->pending_read_packets,
						struct pending_packet, node);
		list_del(&channel->current_read_packet->node);
		SPH_SPIN_UNLOCK(&channel->read_lock);

		channel->current_read_size = 0;
	}

	read_size = channel->current_read_packet->dma_data.msg.size + 1 -
		    channel->current_read_size;

	if (read_size == 0 || !channel->current_read_packet->dma_data.vptr) {
		/* it must be a hangup packet */
		SPH_ASSERT(channel->current_read_packet->is_hangup_command);
		kfree(channel->current_read_packet);
		channel->current_read_packet = NULL;
		channel->current_read_size = 0;
		return 0;
	}

	if (size < read_size)
		read_size = size;

	ret = copy_to_user(buf,
			   channel->current_read_packet->dma_data.vptr +
			   channel->current_read_size,
			   read_size);
	ret = read_size - ret;
	channel->current_read_size += ret;

	/* free the current read packet if all was read */
	if (channel->current_read_size >=
	    channel->current_read_packet->dma_data.msg.size + 1) {
		/* return the local dma page back to the dma pool */
		dma_page_pool_set_page_free(g_the_sphcs->dma_page_pool,
			channel->current_read_packet->dma_data.dma_page_hndl);
		kfree(channel->current_read_packet);
		channel->current_read_packet = NULL;
		channel->current_read_size = 0;
	}

	if (unlikely(ret == 0))
		return -EFAULT;

	return ret;
}

static ssize_t sphcs_genmsg_chan_write(struct file       *f,
				       const char __user *buf,
				       size_t             size,
				       loff_t            *off)
{
	struct channel_data *channel = (struct channel_data *)f->private_data;
	ssize_t n_written = 0;
	size_t write_size, max_write_size;
	struct dma_req_user_data dma_req_data;
	int ret;

	if (unlikely(!is_channel_file(f)))
		return -EINVAL;

	if (channel->io_error)
		return -EIO;

	/* do not send a zero size data packet */
	if (unlikely(size == 0))
		return 0;

	max_write_size = SPH_PAGE_SIZE;

	mutex_lock(&channel->write_lock);

	do {
		if (channel->hanging_up) {
			ret = -EPIPE;
			break;
		}

		// Need to have a host response page for sending data to host
		if (!channel->write_host_page_valid) {
			ret = sphcs_response_pool_get_response_page_wait(SPH_MAIN_RESPONSE_POOL_INDEX,
					&channel->write_host_page_addr,
					&channel->write_host_page_hndl);
			if (unlikely(ret < 0)) {
				sph_log_err(SERVICE_LOG, "Failed to get host response page for write ret=%d\n", ret);
				/* end the write loop and return */
				break;
			}
			channel->write_host_page_valid = 1;
		}

		/* need to have local dma address for copying data from user */
		if (!channel->write_page_vptr) {
			ret = dma_page_pool_get_free_page(
						g_the_sphcs->dma_page_pool,
						&channel->write_page_hndl,
						&channel->write_page_vptr,
						&channel->write_page_addr);
			if (unlikely(ret < 0)) {
				sph_log_err(SERVICE_LOG, "Failed to get free dma page for write ret=%d\n", ret);
				/* end the write loop and return */
				break;
			}
		}

		write_size = min(size - n_written, max_write_size);

		ret = copy_from_user(channel->write_page_vptr, buf + n_written, write_size);
		if (unlikely(ret != 0)) {
			sph_log_err(SERVICE_LOG, "Failed to read data from user\n");
			/* end the write loop and return */
			break;
		}

		/* start DMA for transfering the copied packet to host */
		dma_req_data.dma_page_hndl = channel->write_page_hndl;
		dma_req_data.host_dma_page_hndl = channel->write_host_page_hndl;
		dma_req_data.dma_vptr = channel->write_page_vptr;
		dma_req_data.xfer_size = write_size;
		dma_req_data.channel = channel;

		/* Increment number of write dma requests */
		atomic_inc(&channel->n_write_dma_req);

		ret = sphcs_dma_sched_start_xfer_single(g_the_sphcs->dmaSched,
						&channel->c2h_dma_desc,
						channel->write_page_addr,
						channel->write_host_page_addr,
						dma_req_data.xfer_size,
						chan_response_dma_completed,
						NULL,
						&dma_req_data,
						sizeof(dma_req_data));
		if (unlikely(ret < 0)) {
			sph_log_err(SERVICE_LOG, "Failed to schedule DMA transfer\n");
			/* end the write loop and return */
			break;
		}

		n_written += write_size;

		/* mark that we used the local and host write pages */
		channel->write_page_vptr = NULL;
		channel->write_host_page_valid = 0;

	} while (n_written < size);

	mutex_unlock(&channel->write_lock);

	if (n_written == 0)
		return ret;

	return n_written;
}

static unsigned int sphcs_genmsg_chan_poll(struct file              *f,
					   struct poll_table_struct *pt)
{
	struct channel_data *channel = (struct channel_data *)f->private_data;
	unsigned int mask = (POLLOUT | POLLWRNORM);

	if (!is_channel_file(f))
		return -EINVAL;

	if (channel) {
		/* check for ready to read */
		if (channel->current_read_packet != NULL) {
			mask |= (POLLIN | POLLRDNORM);
		} else {
			poll_wait(f, &channel->read_waitq, pt);
			SPH_SPIN_LOCK(&channel->read_lock);
			if (!list_empty(&channel->pending_read_packets))
				mask |= (POLLIN | POLLRDNORM);
			SPH_SPIN_UNLOCK(&channel->read_lock);
		}
	}

	return mask;
}

static long write_response_wait(struct file *f, void __user *arg)
{
	struct channel_data *channel = (struct channel_data *)f->private_data;
	int ret = 0;

	mutex_lock(&channel->write_lock);

	/* need local free dma page */
	if (!channel->write_page_vptr) {

		mutex_unlock(&channel->write_lock);
		ret = dma_page_pool_get_free_page(g_the_sphcs->dma_page_pool,
				&channel->write_page_hndl,
				&channel->write_page_vptr,
				&channel->write_page_addr);
		mutex_lock(&channel->write_lock);
	}

	/* need host response page */
	if (!channel->write_host_page_valid) {

		mutex_unlock(&channel->write_lock);
		ret = sphcs_response_pool_get_response_page_wait(SPH_MAIN_RESPONSE_POOL_INDEX,
				&channel->write_host_page_addr,
				&channel->write_host_page_hndl);
		mutex_lock(&channel->write_lock);
		if (!ret)
			channel->write_host_page_valid = 1;
	}

	mutex_unlock(&channel->write_lock);

	return ret;
}

static long chan_is_privileged(struct file *f, void __user *arg)
{
	struct channel_data *channel = (struct channel_data *)f->private_data;
	int is_privileged = 0;
	int rc;

	if (!is_channel_file(f))
		return -EINVAL;

	if (channel->is_privileged)
		is_privileged = 1;

	rc = copy_to_user(arg, &is_privileged, sizeof(int));
	if (rc)
		return -EIO;

	return 0;
}

static long sphcs_genmsg_chan_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	long ret = 0;

	if (!is_channel_file(f))
		return -EINVAL;

	switch (cmd) {
	case IOCTL_GENMSG_WRITE_RESPONSE_WAIT:
		ret = write_response_wait(f, (void __user *)arg);
		break;
	case IOCTL_GENMSG_IS_PRIVILEGED:
		ret = chan_is_privileged(f, (void __user *)arg);
		break;
	default:
		sph_log_err(SERVICE_LOG, "Unsupported genmsg chan IOCTL 0x%x\n", cmd);
		ret = -EINVAL;
	}

	return ret;
}

static const struct file_operations sphcs_genmsg_chan_fops = {
	.owner = THIS_MODULE,
	.release = sphcs_genmsg_chan_release,
	.read = sphcs_genmsg_chan_read,
	.write = sphcs_genmsg_chan_write,
	.unlocked_ioctl = sphcs_genmsg_chan_ioctl,
	.compat_ioctl = sphcs_genmsg_chan_ioctl,
	.poll = sphcs_genmsg_chan_poll
};

static inline int is_channel_file(struct file *f)
{
	return f->f_op == &sphcs_genmsg_chan_fops;
}
static inline int is_channel_ptr(struct channel_data *channel)
{
	return (channel != NULL) && is_channel_file(channel->file);
}

/***************************************************************************
 * Global service list handling routines
 ***************************************************************************/
static int init_service_list(void)
{
	s_service_list = kzalloc(sizeof(*s_service_list), GFP_KERNEL);
	if (!s_service_list)
		return -ENOMEM;

	ida_init(&s_service_list->ida);
	mutex_init(&s_service_list->lock);

	s_service_list->num_services = 0;

	return 0;
}

static void release_service_list(void)
{
	if (s_service_list) {
		int i;

		for (i = 0; i < SPH_MAX_GENERIC_SERVICES; i++) {
			kfree(s_service_list->service_name[i]);
		}

		ida_destroy(&s_service_list->ida);
		mutex_destroy(&s_service_list->lock);
		kfree(s_service_list);
	}
}

static int add_service(const char *service_name, int service_name_len, struct service_data *service)
{
	int service_id;
	unsigned int i;

	service_id = ida_simple_get(&s_service_list->ida, 0, SPH_MAX_GENERIC_SERVICES, GFP_KERNEL);
	if (unlikely(service_id < 0)) {
		sph_log_err(SERVICE_LOG, "Failed to generate service id\n");
		return service_id;
	}

	mutex_lock(&s_service_list->lock);
	//if service with same name already exists, return error
	for (i = 0; i < SPH_MAX_GENERIC_SERVICES; i++) {
		if (s_service_list->service_name[i] != NULL &&
		    !memcmp(s_service_list->service_name[i], service_name, service_name_len + 1)) {
			SPH_ASSERT(s_service_list->service_data[i] != NULL);
			mutex_unlock(&s_service_list->lock);
			ida_simple_remove(&s_service_list->ida, service_id);
			return -EEXIST;
		}
	}
	s_service_list->service_name[service_id] = service_name;
	s_service_list->service_name_len[service_id] = service_name_len;
	s_service_list->service_data[service_id] = service;
	s_service_list->num_services++;
	mutex_unlock(&s_service_list->lock);

	return service_id;
}

static void delete_service(int service_id)
{
	mutex_lock(&s_service_list->lock);
	if (s_service_list->service_name[service_id]) {
		s_service_list->service_data[service_id] = NULL;

		kfree(s_service_list->service_name[service_id]);
		s_service_list->service_name[service_id] = NULL;
		s_service_list->service_name_len[service_id] = 0;

		s_service_list->num_services--;
	}
	mutex_unlock(&s_service_list->lock);

	ida_simple_remove(&s_service_list->ida, service_id);
}

static struct service_data *find_service(const char *service_name, u32 name_len)
{
	struct service_data *ret = NULL;
	int i;

	mutex_lock(&s_service_list->lock);
	for (i = 0; i < SPH_MAX_GENERIC_SERVICES; i++) {
		if (s_service_list->service_name[i] != NULL &&
		    s_service_list->service_name_len[i] == name_len &&
		    !memcmp(s_service_list->service_name[i], service_name, name_len)) {
			SPH_ASSERT(s_service_list->service_data[i] != NULL);
			ret = s_service_list->service_data[i];
			break;
		}
	}
	mutex_unlock(&s_service_list->lock);

	return ret;
}

static int build_service_list_packet(void *buf, int bufsize, u32 *out_service_count)
{
	int ret = 0;

	mutex_lock(&s_service_list->lock);

	{
		char *name_ptr = (char *)buf;
		int   i, n = 0;
		int   needed_size = 0;

		/* First, calculate how much space we need in the buffer */
		for (i = 0; i < SPH_MAX_GENERIC_SERVICES; i++) {
			if (s_service_list->service_name[i])
				needed_size += (s_service_list->service_name_len[i] + 1);
		}

		if (bufsize >= needed_size) {
			for (i = 0; i < SPH_MAX_GENERIC_SERVICES; i++) {
				if (s_service_list->service_name[i]) {
					memcpy(name_ptr, s_service_list->service_name[i], (s_service_list->service_name_len[i] + 1));
					name_ptr += (s_service_list->service_name_len[i] + 1);
					n++;
				}
			}

			*out_service_count = n;

			/* return the number of bytes filled in the buffer */
			ret = (name_ptr - (char *)buf);
		} else {
			/* buffer is too small - return the negative value of the size needed */
			ret = -needed_size;
		}
	}

	mutex_unlock(&s_service_list->lock);

	return ret;
}

static int send_service_list_dma_completed(struct sphcs *sphcs, void *ctx, const void *user_data, int status, u32 timeUS)
{
	const struct dma_req_user_data *dma_req_user_data = (const struct dma_req_user_data *)user_data;
	union c2h_ServiceListMsg msg;

	if (status == SPHCS_DMA_STATUS_FAILED) {
		/* dma failed */
		msg.value = 0LL;
		msg.opcode = SPH_IPC_C2H_OP_SERVICE_LIST;
		msg.failure = 1;
	} else {
		/* if it is not an error - it must be done */
		SPH_ASSERT(status == SPHCS_DMA_STATUS_DONE);

		msg.value = 0LL;
		msg.opcode = SPH_IPC_C2H_OP_SERVICE_LIST;
		msg.num_services = dma_req_user_data->param1;
		msg.size = dma_req_user_data->xfer_size - 1;
		msg.resp_page_handle = dma_req_user_data->host_dma_page_hndl;
	}

	/* send the host services response message to host */
	sphcs_msg_scheduler_queue_add_msg(sphcs->public_respq, &msg.value, 1);

	/* return the local dma page back to the dma pool */
	dma_page_pool_set_page_free(sphcs->dma_page_pool, dma_req_user_data->dma_page_hndl);

	return 0;
}

static int send_service_list_to_host(struct sphcs *sphcs)
{
	dma_addr_t  dma_addr;
	dma_addr_t  host_dma_addr;
	int         ret;
	struct dma_req_user_data dma_req_data;
	union c2h_ServiceListMsg msg;
	u32         fail_code = 0;

	if (s_service_list->num_services < 1) {
		union c2h_ServiceListMsg msg;

		/* send empty service list response message to host */
		msg.value = 0LL;
		msg.opcode = SPH_IPC_C2H_OP_SERVICE_LIST;
		msg.num_services = 0;
		msg.resp_page_handle = 0;

		sphcs_msg_scheduler_queue_add_msg(sphcs->public_respq, &msg.value, 1);
		return 0;
	}

	/* get local DMA page for transfering the list to host */
	ret = dma_page_pool_get_free_page(sphcs->dma_page_pool, &dma_req_data.dma_page_hndl, &dma_req_data.dma_vptr, &dma_addr);
	if (ret) {
		sph_log_err(SERVICE_LOG, "Failed to get free DMA page\n");
		fail_code = 2;
		goto fail;
	}

	/* fill the local page with the service list packet */
	dma_req_data.xfer_size = build_service_list_packet(dma_req_data.dma_vptr,
							   SPH_PAGE_SIZE,
							   &dma_req_data.param1);
	if (dma_req_data.xfer_size < 0) {
		sph_log_err(SERVICE_LOG, "Service list too big\n");
		ret = -ENOSPC;
		fail_code = 3;
		goto fail;
	}

	/* get host response page to be filled with the service list packet */
	ret = sphcs_response_pool_get_response_page(SPH_MAIN_RESPONSE_POOL_INDEX, &host_dma_addr, &dma_req_data.host_dma_page_hndl);
	if (ret) {
		sph_log_err(SERVICE_LOG, "Failed to get free DMA page\n");
		dma_page_pool_set_page_free(sphcs->dma_page_pool, dma_req_data.dma_page_hndl);
		fail_code = 2;
		goto fail;
	}

	/* start the DMA transfer to host */
	sphcs_dma_sched_start_xfer_single(sphcs->dmaSched,
					  &g_dma_desc_c2h_low,
					  dma_addr,
					  host_dma_addr,
					  dma_req_data.xfer_size,
					  send_service_list_dma_completed,
					  NULL,
					  &dma_req_data,
					  sizeof(dma_req_data));

	return 0;

fail:
	/* send failed services response message to host */
	msg.value = 0LL;
	msg.opcode = SPH_IPC_C2H_OP_SERVICE_LIST;
	msg.failure = fail_code;

	sphcs_msg_scheduler_queue_add_msg(sphcs->public_respq, &msg.value, 1);

	return ret;
}

/*****************************************************************************
 * service file ops operations
 *****************************************************************************/
static inline int is_service_file(struct file *f);

static int sphcs_genmsg_open(struct inode *inode, struct file *f)
{
	if (!is_service_file(f))
		return -EINVAL;

	return 0;
}

static int sphcs_genmsg_release(struct inode *inode, struct file *f)
{
	struct service_data *service = (struct service_data *)f->private_data;

	if (!is_service_file(f))
		return -EINVAL;

	sph_log_debug(SERVICE_LOG, "Closing genmsg client\n");

	if (service) {
		delete_service(service->id);
		kfree(service);
	}

	return 0;
}

static long process_register_service(struct file *f, void __user *arg)
{
	struct ioctl_register_service req;
	int ret;
	char *service_name;
	struct service_data *service;

	/* Fail of the command streamer object has not been created yet */
	if (unlikely(g_the_sphcs == NULL))
		return -ENODEV;

	ret = copy_from_user(&req, arg, sizeof(req));
	if (unlikely(ret != 0))
		return -EFAULT;

	if (unlikely(req.name_len == 0))
		return -EINVAL;

	service_name = kmalloc(req.name_len+1, GFP_KERNEL);
	if (unlikely(service_name == NULL))
		return -ENOMEM;

	ret = copy_from_user(service_name, arg + sizeof(req), req.name_len);
	if (unlikely(ret != 0)) {
		kfree(service_name);
		return -EIO;
	}

	service_name[req.name_len] = '\0';

	if (unlikely(strlen(service_name) != req.name_len)) {
		kfree(service_name);
		return -EINVAL;
	}

	service = kzalloc(sizeof(*service), GFP_KERNEL);
	if (unlikely(service == NULL)) {
		kfree(service_name);
		return -ENOMEM;
	}

	ret = add_service(service_name, req.name_len, service);
	if (unlikely(ret < 0)) {
		kfree(service);
		kfree(service_name);
		return ret;
	}

	service->id = ret;
	spin_lock_init(&service->lock);
	INIT_LIST_HEAD(&service->pending_connections);
	init_waitqueue_head(&service->waitq);

	f->private_data = service;

	return 0;
}

static long process_accept_client(struct file *f, void __user *arg)
{
	struct service_data *service = f->private_data;
	struct sphcs *sphcs = g_the_sphcs;
	struct pending_packet *pend;
	struct channel_data *channel;
	union c2h_GenericMessaging msg;
	int ret, rc;
	struct fd sfd;

	if (!service)
		return -EBADF;

	/* wait for a pending connection */
	ret = wait_event_interruptible(service->waitq, !list_empty(&service->pending_connections));
	if (ret)
		return ret;

	SPH_SPIN_LOCK(&service->lock);
	pend = list_first_entry(&service->pending_connections, struct pending_packet, node);
	list_del(&pend->node);
	SPH_SPIN_UNLOCK(&service->lock);

	channel = kzalloc(sizeof(*channel), GFP_KERNEL);
	if (!channel) {
		sph_log_err(SERVICE_LOG, "Failed to allocate space for channel\n");
		ret = -ENOMEM;
		goto err_done;
	}

	ret = ida_simple_get(&s_genmsg.channel_ida,
			     1,    /* 0==uninitialized */
			     SPH_IPC_GENMSG_BAD_CLIENT_ID-1,
			     GFP_KERNEL);
	if (ret < 0) {
		sph_log_err(SERVICE_LOG, "Failed to generate channel id\n");
		goto err_done;
	}

	channel->channel_id = ret;

	SPH_SPIN_LOCK(&s_genmsg.lock);
	hash_add(s_genmsg.channel_hash,
		 &channel->hash_node,
		 channel->channel_id);
	SPH_SPIN_UNLOCK(&s_genmsg.lock);

	channel->host_client_id = pend->dma_data.msg.host_client_id;
	channel->is_privileged = pend->dma_data.msg.privileged;

	channel->fd = anon_inode_getfd("sphchan",
				       &sphcs_genmsg_chan_fops,
				       channel,
				       O_RDWR);
	if (channel->fd < 0) {
		sph_log_err(SERVICE_LOG, "Failed to create channel file descriptor\n");
		ret = channel->fd;
		goto free_id;
	}

	sfd = fdget(channel->fd);
	channel->file = sfd.file;
	fdput(sfd);

	channel->respq = sphcs_create_response_queue(g_the_sphcs, 1);
	if (!channel->respq) {
		sph_log_err(SERVICE_LOG, "Failed to create response q\n");
		ret = -ENOMEM;
		goto free_id;
	}

	INIT_LIST_HEAD(&channel->pending_read_packets);
	spin_lock_init(&channel->read_lock);
	init_waitqueue_head(&channel->read_waitq);
	init_waitqueue_head(&channel->write_waitq);
	mutex_init(&channel->write_lock);
	atomic_set(&channel->n_write_dma_req, 0);

	channel->c2h_dma_desc.dma_direction = SPHCS_DMA_DIRECTION_CARD_TO_HOST;
	channel->c2h_dma_desc.dma_priority = SPHCS_DMA_PRIORITY_LOW;
	channel->c2h_dma_desc.flags = 0;
	channel->c2h_dma_desc.serial_channel =
		sphcs_dma_sched_create_serial_channel(g_the_sphcs->dmaSched);

	channel->h2c_dma_desc.dma_direction = SPHCS_DMA_DIRECTION_HOST_TO_CARD;
	channel->h2c_dma_desc.dma_priority = SPHCS_DMA_PRIORITY_LOW;
	channel->h2c_dma_desc.flags = 0;
	channel->h2c_dma_desc.serial_channel =
		sphcs_dma_sched_create_serial_channel(g_the_sphcs->dmaSched);

	ret = copy_to_user(arg, &channel->fd, sizeof(int));
	if (ret) {
		sph_log_err(SERVICE_LOG, "Failed to copy fd back to user\n");
		goto free_all;
	}

	goto done;

free_all:
	mutex_destroy(&channel->write_lock);
	sphcs_destroy_response_queue(g_the_sphcs, channel->respq);
free_id:
	SPH_SPIN_LOCK(&s_genmsg.lock);
	hash_del(&channel->hash_node);
	SPH_SPIN_UNLOCK(&s_genmsg.lock);
	ida_simple_remove(&s_genmsg.channel_ida, channel->channel_id);
err_done:
	kfree(channel);
	channel = NULL;
done:
	/* send connect reply message back to host */
	msg.value = 0;
	msg.opcode = SPH_IPC_C2H_OP_GENERIC_MSG_PACKET;
	msg.connect = 1;
	msg.host_page_hndl = pend->dma_data.msg.host_page_hndl;
	msg.host_client_id = pend->dma_data.msg.host_client_id;
	msg.card_client_id = channel ? channel->channel_id :
		SPH_IPC_GENMSG_BAD_CLIENT_ID;

	sphcs_msg_scheduler_queue_add_msg(sphcs->public_respq, &msg.value, 1);

	rc = dma_page_pool_set_page_free(sphcs->dma_page_pool, pend->dma_data.dma_page_hndl);
	if (rc)
		sph_log_err(SERVICE_LOG, "Failed to return dma page back to pool\n");

	kfree(pend);

	return ret;
}

static long sphcs_genmsg_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	long     ret = 0;

	if (!is_service_file(f))
		return -EINVAL;

	switch (cmd) {
	case IOCTL_GENMSG_REGISTER_SERVICE:
		ret = process_register_service(f, (void __user *)arg);
		break;

	case IOCTL_GENMSG_ACCEPT_CLIENT:
		ret = process_accept_client(f, (void __user *)arg);
		break;

	default:
		sph_log_err(SERVICE_LOG, "Unsupported genmsg IOCTL 0x%x\n", cmd);
		ret = -EINVAL;
	}

	return ret;
}

static unsigned int sphcs_genmsg_poll(struct file *f, struct poll_table_struct *pt)
{
	struct service_data *service = f->private_data;
	unsigned int mask = 0;

	if (!is_service_file(f))
		return 0;

	if (service) {
		poll_wait(f, &service->waitq, pt);

		SPH_SPIN_LOCK(&service->lock);
		if (!list_empty(&service->pending_connections))
			mask |= POLLIN;
		SPH_SPIN_UNLOCK(&service->lock);
	}

	return mask;
}

static const struct file_operations sphcs_genmsg_fops = {
	.owner = THIS_MODULE,
	.open = sphcs_genmsg_open,
	.release = sphcs_genmsg_release,
	.unlocked_ioctl = sphcs_genmsg_ioctl,
	.compat_ioctl = sphcs_genmsg_ioctl,
	.poll = sphcs_genmsg_poll
};

static inline int is_service_file(struct file *f)
{
	return f->f_op == &sphcs_genmsg_fops;
}

/*****************************************************************************
 * DMA completion callbacks
 *****************************************************************************/

/*
 * called when a C2H dma transfer of the generic packet is completed
 */
static int chan_response_dma_completed(struct sphcs *sphcs,
				       void *ctx,
				       const void *user_data,
				       int status,
				       u32 timeUS)
{
	const struct dma_req_user_data *dma_req_user_data = (const struct dma_req_user_data *)user_data;

	if (status == SPHCS_DMA_STATUS_FAILED) {
		/* dma failed */
		/*
		 * mark io_error on channel - next read/write will fail
		 * and app will close the channel
		 */
		dma_req_user_data->channel->io_error = true;
	} else {
		union c2h_GenericMessaging msg;

		/* if it is not an error - it must be done */
		SPH_ASSERT(status == SPHCS_DMA_STATUS_DONE);

		/* send the packet to host */
		msg.value = 0LL;
		msg.opcode = SPH_IPC_C2H_OP_GENERIC_MSG_PACKET;
		msg.size = dma_req_user_data->xfer_size - 1;
		msg.host_page_hndl = dma_req_user_data->host_dma_page_hndl;
		msg.card_client_id = dma_req_user_data->channel->channel_id;
		msg.host_client_id = dma_req_user_data->channel->host_client_id;

		sphcs_msg_scheduler_queue_add_msg(dma_req_user_data->channel->respq,
					    &msg.value, 1);
	}

	/* return the local dma page back to the dma pool */
	dma_page_pool_set_page_free(sphcs->dma_page_pool, dma_req_user_data->dma_page_hndl);

	/* Decrement pending write dma requests - wake threads waiting for it */
	atomic_dec_if_positive(&dma_req_user_data->channel->n_write_dma_req);
	wake_up_all(&dma_req_user_data->channel->write_waitq);

	return 0;
}

static void handle_cmd_dma_failed(struct genmsg_dma_command_data *dma_data)
{
	union c2h_GenericMessaging msg;

	if (dma_data->msg.connect) {
		msg.value = 0;
		msg.opcode = SPH_IPC_C2H_OP_GENERIC_MSG_PACKET;
		msg.connect = 1;
		msg.no_such_service = 1;
		msg.host_page_hndl = dma_data->msg.host_page_hndl;
		msg.host_client_id = dma_data->msg.host_client_id;
		msg.card_client_id = SPH_IPC_GENMSG_BAD_CLIENT_ID;

		sphcs_msg_scheduler_queue_add_msg(g_the_sphcs->public_respq,
						  &msg.value, 1);
	} else if (dma_data->channel) {
		/*
		 * mark io_error on channel - next read/write will fail
		 * and app will close the channel
		 */
		if (is_channel_ptr(dma_data->channel) && !dma_data->channel->closing)
			dma_data->channel->io_error = true;
	}

	/* return back dma page to pool */
	dma_page_pool_set_page_free(g_the_sphcs->dma_page_pool, dma_data->dma_page_hndl);
}

/*
 * called when a H2C dma transfer of the generic packet is completed
 */
int sphcs_genmsg_cmd_dma_complete_callback(struct sphcs *sphcs, void *ctx, const void *user_data, int status, u32 xferTimeUS)
{
	struct genmsg_dma_command_data *dma_data = (struct genmsg_dma_command_data *)user_data;

	/*
	 * send a reply to host to free the xmited dma page
	 * in case of connect command, it will happen on the connect response
	 * after the service client will reply to the connect request
	 */
	if (!dma_data->msg.connect) {
		union c2h_GenericMessaging msg;

		msg.value = 0;
		msg.opcode = SPH_IPC_C2H_OP_GENERIC_MSG_PACKET;
		msg.free_page = 1;
		msg.host_page_hndl = dma_data->msg.host_page_hndl;
		msg.host_client_id = dma_data->msg.host_client_id;
		msg.card_client_id = dma_data->msg.card_client_id;

		sphcs_msg_scheduler_queue_add_msg(sphcs->public_respq, &msg.value, 1);
	}

	if (status == SPHCS_DMA_STATUS_FAILED) {
		sph_log_err(SERVICE_LOG, "Dma error\n");
		/* dma failed */
		handle_cmd_dma_failed(dma_data);
	} else {
		/* if it is not an error - it must be done */
		SPH_ASSERT(status == SPHCS_DMA_STATUS_DONE);

		if (dma_data->msg.connect) {
			/* This is a connect request - route to a service */
			struct service_data *service;
			u32 *name_len = (u32 *)(dma_data->vptr);
			const char *name = (const char *)(name_len+1);

			service = find_service(name, *name_len);

			if (service != NULL) {
				struct pending_packet *pend;

				pend = kzalloc(sizeof(*pend), GFP_NOWAIT);
				if (unlikely(pend == NULL)) {
					sph_log_err(SERVICE_LOG, "Failed to allocate pending connection struct!!\n");
				} else {
					/* insert into the connection pending list */
					memcpy(&pend->dma_data, dma_data, sizeof(*dma_data));
					SPH_SPIN_LOCK(&service->lock);
					list_add_tail(&pend->node, &service->pending_connections);
					SPH_SPIN_UNLOCK(&service->lock);
					wake_up_all(&service->waitq);
				}
			} else {
				/* service not found -
				 * send connect failed reply message back to host
				 */
				handle_cmd_dma_failed(dma_data);
			}
		} else {
			/* this is a generic packet - route to a channel */
			struct channel_data *channel;

			channel = dma_data->channel;
			if (is_channel_ptr(channel) && !channel->closing) {
				struct pending_packet *pend;

				pend = kzalloc(sizeof(*pend), GFP_NOWAIT);
				if (!pend) {
					sph_log_err(SERVICE_LOG, "Failed to allocate pending packet struct!!\n");
				} else {
					/* insert into the channel's pending read packets */
					INIT_LIST_HEAD(&pend->node);
					memcpy(&pend->dma_data, dma_data, sizeof(*dma_data));
					SPH_SPIN_LOCK(&channel->read_lock);
					list_add_tail(&pend->node, &channel->pending_read_packets);
					SPH_SPIN_UNLOCK(&channel->read_lock);
					wake_up_all(&channel->read_waitq);
				}
			} else {
				sph_log_err(SERVICE_LOG, "Got generic message with NULL or closing channel handle!!!\n");

				/* return back dma page to pool */
				dma_page_pool_set_page_free(sphcs->dma_page_pool, dma_data->dma_page_hndl);
			}

			if (is_channel_ptr(channel)) {
				SPH_SPIN_LOCK(&channel->read_lock);
				if (channel->n_read_dma_req)
					channel->n_read_dma_req--;
				SPH_SPIN_UNLOCK(&channel->read_lock);
				if (!channel->n_read_dma_req)
					wake_up_all(&channel->read_waitq);
			}
		}
	}

	return 0;
}

/*
 * process_genmsg_command is called to process a
 * SPH_IPC_H2C_OP_GENERIC_MSG_PACKET message receviced from host.
 */
static int process_genmsg_command(struct sphcs *sphcs,
				  union h2c_GenericMessaging *req)
{
	struct genmsg_dma_command_data dma_data;
	dma_addr_t dma_addr;
	int ret;

	if (!req->hangup && !req->service_list_req && !req->host_pfn) {
		/* This is a protocol error - should not happen!!! */
		sph_log_err(SERVICE_LOG, "Got generic message packet from host connect=%d with NULL host pfn\n", req->connect);
		return 0;
	}

	if (req->service_list_req) {
		/* send host updated service list */
		send_service_list_to_host(g_the_sphcs);
		return 0;
	}

	if (!req->connect) {
		struct channel_data *channel;

		channel = find_channel(req->card_client_id);
		if (!channel) {
			/* This is a protocol error - should not happen!!! */
			sph_log_err(SERVICE_LOG, "Got packet with no card, card_client_id= %u, host_client_id= %u\n", req->card_client_id, req->host_client_id);
			return 0;
		}
		dma_data.channel = channel;

		/* handle hangup packet */
		if (req->hangup) {
			struct pending_packet *pend;
			/* channel is not yet closing add empty read packet */
			/* but only after all pending read dma requests are done*/
			wait_event_interruptible(channel->read_waitq,
						 channel->n_read_dma_req == 0);

			pend = kzalloc(sizeof(*pend), GFP_NOWAIT);
			if (!pend) {
				sph_log_err(SERVICE_LOG, "Failed to allocate pending packet struct!!\n");
			} else {
				/* insert into the channel's pending read packets */
				memcpy(pend->dma_data.msg.value,
				       req->value,
				       sizeof(req->value));
				pend->is_hangup_command = 1;
			}

			SPH_SPIN_LOCK(&channel->read_lock);
			channel->hanging_up = 1;

			if (channel->closing == 0) {
				/* channel is not yet closing add empty read packet */
				/* but only after all pending read dma requests are done*/
				if (pend) {
					list_add_tail(&pend->node, &channel->pending_read_packets);
					wake_up_all(&channel->read_waitq);
				}

				SPH_SPIN_UNLOCK(&channel->read_lock);
			} else {
				if (channel->closing == 1) {
					SPH_SPIN_UNLOCK(&channel->read_lock);
				} else {
					SPH_ASSERT(channel->closing == 2);
					SPH_SPIN_UNLOCK(&channel->read_lock);
					free_channel(channel);
				}

				kfree(pend);
			}

			return 0;
		}
	} else
		dma_data.channel = NULL;

	ret = dma_page_pool_get_free_page(sphcs->dma_page_pool,
					  &dma_data.dma_page_hndl,
					  &dma_data.vptr,
					  &dma_addr);
	if (ret) {
		sph_log_err(SERVICE_LOG, "Failed to get free page (err: %d)\n", ret);
		return ret;
	}

	memcpy(dma_data.msg.value,
	       req->value,
	       sizeof(req->value));
	dma_data.host_dma_addr = SPH_IPC_DMA_PFN_TO_ADDR(req->host_pfn);
	dma_data.dma_addr = dma_addr;

	if (dma_data.channel) {
		SPH_SPIN_LOCK(&dma_data.channel->read_lock);
		dma_data.channel->n_read_dma_req++;
		SPH_SPIN_UNLOCK(&dma_data.channel->read_lock);
	}

	/* start DMA xfer to bring the packet */
	ret = sphcs_dma_sched_start_xfer_single(sphcs->dmaSched,
						dma_data.channel ?
						    &dma_data.channel->h2c_dma_desc :
						    &g_dma_desc_h2c_normal,
						dma_data.host_dma_addr,
						dma_addr,
						req->size + 1,
						sphcs_genmsg_cmd_dma_complete_callback, NULL,
						&dma_data,
						sizeof(dma_data));
	if (ret) {
		sph_log_err(SERVICE_LOG, "Failed to start DMA xfer!\n");
		handle_cmd_dma_failed(&dma_data);
	}

	return 0;
}

/*
 * called to handle a
 * SPH_IPC_H2C_OP_GENERIC_MSG_PACKET message receviced from host.
 */
void IPC_OPCODE_HANDLER(GENERIC_MSG_PACKET)(struct sphcs               *sphcs,
					    union h2c_GenericMessaging *msg)
{
	struct genmsg_command_entry *entry;

	/*
	 * place the command in pending list and schedule the pending work to handle it
	 */
	entry = kzalloc(sizeof(*entry), GFP_NOWAIT);
	if (!entry) {
		sph_log_err(SERVICE_LOG, "No memory for pending command entry!!!\n");
		return;
	}

	memcpy(entry->msg.value,
	       msg->value,
	       sizeof(msg->value));
	INIT_LIST_HEAD(&entry->node);

	SPH_SPIN_LOCK_BH(&s_pending_commands_lock_bh);
	list_add_tail(&entry->node, &s_pending_commands);
	s_num_pending_commands++;
	if (s_num_pending_commands == 1) {
		queue_work(system_wq, &s_pending_commands_work);
	}
	SPH_SPIN_UNLOCK_BH(&s_pending_commands_lock_bh);
}

/*
 * workqueue work function - process pending messages
 * received from h/w Q while dma page pool does not have pre-allocated pages
 */
static void sphcs_genmsg_process_pending(struct work_struct *work)
{
	struct genmsg_command_entry *entry;
	int rc;

	SPH_SPIN_LOCK_BH(&s_pending_commands_lock_bh);
	while (s_num_pending_commands) {
		entry = list_first_entry(&s_pending_commands,
					 struct genmsg_command_entry,
					 node);
		SPH_SPIN_UNLOCK_BH(&s_pending_commands_lock_bh);

		rc = process_genmsg_command(g_the_sphcs, &entry->msg);
		if (rc)
			sph_log_err(SERVICE_LOG, "FATAL: process_genmsg failed rc=%d\n", rc);

		SPH_SPIN_LOCK_BH(&s_pending_commands_lock_bh);
		list_del(&entry->node);
		kfree(entry);
		s_num_pending_commands--;
	}
	SPH_SPIN_UNLOCK_BH(&s_pending_commands_lock_bh);
}

/*
 * generic messaging sub-module initialization routine.
 * called on kernel module load time.
 */
int sphcs_init_genmsg_interface(void)
{
	int ret;

	ret = alloc_chrdev_region(&s_devnum, 0, 1, SPHCS_GENMSG_DEV_NAME);
	if (ret < 0) {
		sph_log_err(START_UP_LOG, "failed to allocate devnum %d\n", ret);
		return ret;
	}

	cdev_init(&s_cdev, &sphcs_genmsg_fops);
	s_cdev.owner = THIS_MODULE;

	ret = cdev_add(&s_cdev, s_devnum, 1);
	if (ret < 0) {
		sph_log_err(START_UP_LOG, "failed to add cdev %d\n", ret);
		unregister_chrdev_region(s_devnum, 1);
		return ret;
	}

	s_class = class_create(THIS_MODULE, SPHCS_GENMSG_DEV_NAME);
	if (IS_ERR(s_class)) {
		ret = PTR_ERR(s_class);
		sph_log_err(START_UP_LOG, "failed to register class %d\n", ret);
		cdev_del(&s_cdev);
		unregister_chrdev_region(s_devnum, 1);
		return ret;
	}

	s_dev = device_create(s_class, NULL, s_devnum, NULL, SPHCS_GENMSG_DEV_NAME);
	if (IS_ERR(s_dev)) {
		ret = PTR_ERR(s_dev);
		class_destroy(s_class);
		cdev_del(&s_cdev);
		unregister_chrdev_region(s_devnum, 1);
		return ret;
	}

	ret = init_service_list();
	if (ret) {
		device_destroy(s_class, s_devnum);
		class_destroy(s_class);
		cdev_del(&s_cdev);
		unregister_chrdev_region(s_devnum, 1);
		return ret;
	}

	INIT_LIST_HEAD(&s_pending_commands);
	spin_lock_init(&s_pending_commands_lock_bh);
	INIT_WORK(&s_pending_commands_work, sphcs_genmsg_process_pending);
	s_num_pending_commands = 0;

	hash_init(s_genmsg.channel_hash);
	ida_init(&s_genmsg.channel_ida);
	spin_lock_init(&s_genmsg.lock);

	sph_log_info(START_UP_LOG, "chardev inited at MAJOR=%d\n", MAJOR(s_devnum));
	return 0;
}

/*
 * generic messaging sub-module cleanup function.
 * called during kernel module unload time.
 */
void sphcs_release_genmsg_interface(void)
{
	release_service_list();
	device_destroy(s_class, s_devnum);
	class_destroy(s_class);
	cdev_del(&s_cdev);
	unregister_chrdev_region(s_devnum, 1);
}