// SPDX-License-Identifier: GPL-2.0-or-later

/********************************************
 * Copyright (C) 2019-2021 Intel Corporation
 ********************************************/

#include "cmd_chan.h"
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/anon_inodes.h>
#include "ipc_protocol.h"
#include "nnp_log.h"
#include "host_chardev.h"
#include "nnp_ringbuf.h"
#include "ipc_c2h_events.h"

struct respq_elem {
	struct nnp_ringbuf rb;
	struct list_head  node;
	u8                buf[4096 - 16 - sizeof(struct list_head)];
};

static inline int is_cmd_chan_file(struct file *f);

static int cmd_chan_file_release(struct inode *inode, struct file *f)
{
	struct nnpdrv_cmd_chan *chan =
		(struct nnpdrv_cmd_chan *)f->private_data;
	struct file *host_file;

	if (unlikely(!is_cmd_chan_file(f)))
		return -EINVAL;

	nnpdrv_cmd_chan_send_destroy(chan);

	host_file = chan->host_file;
	nnpdrv_cmd_chan_put(chan);
	fput(host_file);

	return 0;
}

static ssize_t cmd_chan_file_read(struct file *f,
				  char __user *buf,
				  size_t       size,
				  loff_t      *off)
{
	struct nnpdrv_cmd_chan *chan =
		(struct nnpdrv_cmd_chan *)f->private_data;
	struct respq_elem *respq;
	u32 packet_size;
	u64 msg[16];  /* maximum possible message in the response queue */
	bool from_list = false;
	bool removed_from_list = false;
	int ret;

	if (unlikely(!is_cmd_chan_file(f)))
		return -EINVAL;

	ret = wait_event_interruptible(chan->resp_waitq,
			!list_empty(&chan->respq_list) ||
			chan->closing ||
			nnp_ringbuf_avail_bytes(&chan->curr_respq->rb) >
			sizeof(u32));
	if (unlikely(ret < 0)) {
		if (ret == -ERESTARTSYS)
			return -EINTR;
		return ret;
	}

	if (chan->closing)
		return 0;

	spin_lock_bh(&chan->resp_lock_bh);
	if (!list_empty(&chan->respq_list)) {
		respq = list_first_entry(&chan->respq_list,
					 struct respq_elem,
					 node);
		from_list = true;
	} else {
		respq = chan->curr_respq;
	}

	nnp_ringbuf_pop(&respq->rb, (u8 *)&packet_size, sizeof(u32));
	/* Check packet_size does not overrun msg size */
	if (packet_size > sizeof(msg))
		return -EINVAL;
	nnp_ringbuf_pop(&respq->rb, (u8 *)msg, packet_size);

	if (from_list && nnp_ringbuf_avail_bytes(&respq->rb) == 0) {
		list_del(&respq->node);
		removed_from_list = true;
	}
	spin_unlock_bh(&chan->resp_lock_bh);

	if (removed_from_list)
		kfree(respq);

	ret = copy_to_user(buf, msg, packet_size);
	if (unlikely(ret))
		return -EIO;

	return packet_size;
}

static ssize_t cmd_chan_file_write(struct file       *f,
				   const char __user *buf,
				   size_t             size,
				   loff_t            *off)
{
	struct nnpdrv_cmd_chan *chan =
		(struct nnpdrv_cmd_chan *)f->private_data;
	u64 msg[MSG_SCHED_MAX_MSG_SIZE];
	union h2c_chan_msg_header *hdr;
	int ret;

	if (unlikely(!is_cmd_chan_file(f)))
		return -EINVAL;

	if (chan->closing)
		return 0;

	if (size == 1) {
		u8 b;

		ret = copy_from_user(&b, buf, 1);
		if (unlikely(ret != 0))
			return -EIO;

		if (b == 4) {
			nnpdrv_cmd_chan_set_closing(chan);
			return 1;
		}
	}

	/*
	 * size must be multiple of 8 bytes and cannot exceed maximum message
	 * size
	 */
	if ((size > MSG_SCHED_MAX_MSG_SIZE * 8) ||
	    (size &  0x7) != 0)
		return -EINVAL;

	ret = copy_from_user(msg, buf, size);
	if (unlikely(ret != 0))
		return -EIO;

	/*
	 * Check chan_id, opcode and message size are valid
	 */
	hdr = (union h2c_chan_msg_header *)&msg[0];
	if (hdr->chan_id != chan->protocol_id)
		return -EINVAL;
	if (hdr->opcode < 32 || hdr->opcode > 63)
		return -EINVAL;
	if (size != (chan->nnpdev->ipc_chan_cmd_op_size[hdr->opcode - 32] * 8))
		return -EINVAL;

	if (unlikely(!is_card_fatal_drv_event(
				chan->card_critical_error.event_code)))
		ret  = msg_scheduler_queue_add_msg(chan->cmdq,
						   msg,
						   size >> 3);
	else
		ret = -EPIPE;

	if (unlikely(ret < 0))
		return ret;
	else
		return size;
}

static unsigned int cmd_chan_file_poll(struct file              *f,
				       struct poll_table_struct *pt)
{
	struct nnpdrv_cmd_chan *chan =
		(struct nnpdrv_cmd_chan *)f->private_data;
	unsigned int mask = (POLLOUT | POLLWRNORM);

	if (!is_cmd_chan_file(f))
		return 0;

	poll_wait(f, &chan->resp_waitq, pt);
	spin_lock_bh(&chan->resp_lock_bh);
	if (!list_empty(&chan->respq_list) ||
	    nnp_ringbuf_avail_bytes(&chan->curr_respq->rb) > sizeof(u32))
		mask |= (POLLIN | POLLRDNORM);
	spin_unlock_bh(&chan->resp_lock_bh);

	return mask;
}

static const struct file_operations nnpdrv_cmd_chan_fops = {
	.owner = THIS_MODULE,
	.release = cmd_chan_file_release,
	.read = cmd_chan_file_read,
	.write = cmd_chan_file_write,
	.poll = cmd_chan_file_poll
};

static inline int is_cmd_chan_file(struct file *f)
{
	return f->f_op == &nnpdrv_cmd_chan_fops;
}

int nnpdrv_cmd_chan_create(struct nnp_device       *nnpdev,
			   int                      host_fd,
			   u32                      weight,
			   unsigned int             min_id,
			   unsigned int             max_id,
			   bool                     get_device_events,
			   struct nnpdrv_cmd_chan **out_cmd_chan)
{
	struct nnpdrv_cmd_chan *cmd_chan;
	u16 protocol_id;
	int ret;
	unsigned int max_proto_id = (1 << NNP_IPC_CHANNEL_BITS) - 1;

	if (min_id > max_proto_id)
		return -EINVAL;
	if (max_id > max_proto_id)
		max_id = max_proto_id;

	ret = ida_simple_get(&nnpdev->cmd_chan_ida,
			     min_id,
			     max_id,
			     GFP_KERNEL);
	if (unlikely(ret < 0))
		return ret;
	protocol_id = ret;

	cmd_chan = kzalloc(sizeof(*cmd_chan), GFP_KERNEL);
	if (unlikely(!cmd_chan)) {
		nnp_log_err(CREATE_COMMAND_LOG,
			    "FATAL: %s():%u failed to allocate command channel object\n",
			    __func__, __LINE__);
		ida_simple_remove(&nnpdev->cmd_chan_ida, protocol_id);
		return -ENOMEM;
	}

	cmd_chan->host_file = nnpdrv_host_file_get(host_fd);
	if (unlikely(!cmd_chan->host_file)) {
		ida_simple_remove(&nnpdev->cmd_chan_ida, protocol_id);
		kfree(cmd_chan);
		return -EINVAL;
	}

	cmd_chan->cmdq = nnpdrv_create_cmd_queue(nnpdev, weight);
	if (unlikely(!cmd_chan->cmdq)) {
		nnp_log_err(CREATE_COMMAND_LOG,
			    "FATAL: %s():%u failed to create cmd queue channel object\n",
			    __func__, __LINE__);
		fput(cmd_chan->host_file);
		ida_simple_remove(&nnpdev->cmd_chan_ida, protocol_id);
		kfree(cmd_chan);
		return -ENOMEM;
	}

	cmd_chan->curr_respq = kzalloc(sizeof(*cmd_chan->curr_respq),
				       GFP_KERNEL);
	if (unlikely(!cmd_chan->curr_respq)) {
		nnp_log_err(CREATE_COMMAND_LOG,
			    "FATAL: %s():%u failed to create resp1 element\n",
			    __func__, __LINE__);
		nnpdrv_destroy_cmd_queue(nnpdev, cmd_chan->cmdq);
		fput(cmd_chan->host_file);
		ida_simple_remove(&nnpdev->cmd_chan_ida, protocol_id);
		kfree(cmd_chan);
		return -ENOMEM;
	}

	kref_init(&cmd_chan->ref);
	cmd_chan->magic = nnpdrv_cmd_chan_create;
	cmd_chan->protocol_id = protocol_id;
	atomic_set(&cmd_chan->destroyed, 0);
	nnpdrv_device_get(nnpdev);
	cmd_chan->nnpdev = nnpdev;
	cmd_chan->fd = -1;
	cmd_chan->get_device_events = get_device_events;

	cmd_chan->proc_info =
		(struct inf_process_info *)cmd_chan->host_file->private_data;
	inf_proc_get(cmd_chan->proc_info);

	init_waitqueue_head(&cmd_chan->resp_waitq);
	spin_lock_init(&cmd_chan->resp_lock_bh);
	INIT_LIST_HEAD(&cmd_chan->respq_list);

	spin_lock_init(&cmd_chan->lock);
	ida_init(&cmd_chan->hostres_map_ida);
	hash_init(cmd_chan->hostres_hash);

	INIT_LIST_HEAD(&cmd_chan->curr_respq->node);
	nnp_ringbuf_init(&cmd_chan->curr_respq->rb,
			 cmd_chan->curr_respq->buf,
			 sizeof(cmd_chan->curr_respq->buf));

	/*
	 * Add channel to the channel hash
	 */
	spin_lock(&nnpdev->lock);
	hash_add(nnpdev->cmd_chan_hash,
		 &cmd_chan->hash_node,
		 cmd_chan->protocol_id);

	/*
	 * Channel with id <= 255 is an inference context channel
	 */
	if (cmd_chan->protocol_id <= 255)
		nnpdev->num_active_contexts++;
	spin_unlock(&nnpdev->lock);

	*out_cmd_chan = cmd_chan;

	return 0;
}

static void cmd_chan_release(struct kref *kref)
{
	struct nnpdrv_cmd_chan *cmd_chan;
	struct nnp_device *nnpdev;
	int i;

	cmd_chan = container_of(kref, struct nnpdrv_cmd_chan, ref);
	nnpdev = cmd_chan->nnpdev;

	msg_scheduler_queue_flush(cmd_chan->cmdq);
	nnpdrv_destroy_cmd_queue(nnpdev, cmd_chan->cmdq);

	spin_lock(&nnpdev->lock);
	hash_del(&cmd_chan->hash_node);
	/*
	 * Channel with id <= 255 is an inference context channel
	 */
	if (cmd_chan->protocol_id <= 255)
		nnpdev->num_active_contexts--;
	spin_unlock(&nnpdev->lock);
	ida_simple_remove(&cmd_chan->nnpdev->cmd_chan_ida,
			  cmd_chan->protocol_id);

	nnpdrv_chan_unmap_hostres_all(cmd_chan);
	ida_destroy(&cmd_chan->hostres_map_ida);

	for (i = 0; i < NNP_IPC_MAX_CHANNEL_RB; i++) {
		nnpdrv_cmd_chan_set_ringbuf(cmd_chan, true, i, NULL);
		nnpdrv_cmd_chan_set_ringbuf(cmd_chan, false, i, NULL);
	}

	if (unlikely(cmd_chan->fd < 0))
		fput(cmd_chan->host_file);

	inf_proc_put(cmd_chan->proc_info);

	kfree(cmd_chan->curr_respq);
	kfree(cmd_chan);

	nnpdrv_device_put(nnpdev);
}

int is_cmd_chan_ptr(void *ptr)
{
	struct nnpdrv_cmd_chan *cmd_chan = (struct nnpdrv_cmd_chan *)ptr;

	return (ptr && cmd_chan->magic == nnpdrv_cmd_chan_create);
}

bool nnpdrv_cmd_chan_get(struct nnpdrv_cmd_chan *cmd_chan)
{
	int ret;

	ret = kref_get_unless_zero(&cmd_chan->ref);
	return ret != 0;
}

int nnpdrv_cmd_chan_put(struct nnpdrv_cmd_chan *cmd_chan)
{
	return kref_put(&cmd_chan->ref, cmd_chan_release);
}

void nnpdrv_cmd_chan_set_closing(struct nnpdrv_cmd_chan *cmd_chan)
{
	if (cmd_chan && !cmd_chan->closing) {
		cmd_chan->closing = 1;
		wake_up_all(&cmd_chan->resp_waitq);
	}
}

int nnpdrv_cmd_chan_create_file(struct nnpdrv_cmd_chan *cmd_chan)
{
	if (cmd_chan->fd != -1)
		return -EINVAL;

	if (unlikely(!nnpdrv_cmd_chan_get(cmd_chan))) {
		nnp_log_err(GENERAL_LOG, "failed to get chan refcount during create!!!\n");
		return -EFAULT;
	}

	cmd_chan->fd = anon_inode_getfd("nnpi_chan",
					&nnpdrv_cmd_chan_fops,
					cmd_chan,
					O_RDWR);
	if (unlikely(cmd_chan->fd < 0)) {
		nnp_log_err(GENERAL_LOG, "failed to create channel file descriptor\n");
		nnpdrv_cmd_chan_put(cmd_chan);
	}

	return cmd_chan->fd;
}

int nnpdrv_cmd_chan_send_destroy(struct nnpdrv_cmd_chan *chan)
{
	union h2c_channel_op msg;

	if (atomic_read(&chan->destroyed) != 0)
		return 0;

	msg.value = 0;
	msg.opcode = NNP_IPC_H2C_OP_CHANNEL_OP;
	msg.protocol_id = chan->protocol_id;
	msg.destroy = 1;

	chan->event_msg.value = 0;

	/*
	 * If card is in critical state (or was during the channel lifetime)
	 * we destroy the channel.
	 * otherwise, we send a destroy command to card and will destroy when
	 * the destroy reply arrives.
	 */
	if (unlikely(is_card_fatal_drv_event(
				chan->card_critical_error.event_code))) {
		if (atomic_xchg(&chan->destroyed, 1) == 0)
			nnpdrv_cmd_chan_put(chan);
		return 0;
	}

	return nnpdrv_msg_scheduler_queue_add_msg(chan->nnpdev->public_cmdq,
						  &msg.value,
						  1);
}

int nnpdrv_cmd_chan_add_response(struct nnpdrv_cmd_chan *cmd_chan,
				 u64                    *hw_msg,
				 u32                     byte_size)
{
	struct respq_elem *respq = cmd_chan->curr_respq;

	spin_lock_bh(&cmd_chan->resp_lock_bh);
	if (nnp_ringbuf_free_bytes(&respq->rb) < (byte_size + sizeof(u32))) {
		spin_unlock_bh(&cmd_chan->resp_lock_bh);
		respq = kmalloc(sizeof(*respq), GFP_NOWAIT);
		if (unlikely(!respq)) {
			nnp_log_err(GENERAL_LOG,
				    "FATAL: failed to allocate response queue for channel %d losing response\n",
				    cmd_chan->protocol_id);
			return -EFAULT;
		}
		nnp_ringbuf_init(&respq->rb,
				 respq->buf,
				 sizeof(respq->buf));

		spin_lock_bh(&cmd_chan->resp_lock_bh);
		list_add_tail(&cmd_chan->curr_respq->node,
			      &cmd_chan->respq_list);
		cmd_chan->curr_respq = respq;
	}

	nnp_ringbuf_push(&respq->rb, (u8 *)&byte_size, sizeof(u32));
	nnp_ringbuf_push(&respq->rb, (u8 *)hw_msg, byte_size);

	spin_unlock_bh(&cmd_chan->resp_lock_bh);

	wake_up_all(&cmd_chan->resp_waitq);

	return 0;
}

int nnpdrv_cmd_chan_set_ringbuf(struct nnpdrv_cmd_chan *chan,
				bool                    h2c,
				u8                      id,
				struct nnpdrv_host_resource *hostres)
{
	if (id >= NNP_IPC_MAX_CHANNEL_RB)
		return -EINVAL;

	if (h2c) {
		if (chan->h2c_rb_hostres[id])
			nnpdrv_hostres_unmap_device(chan->h2c_rb_hostres[id],
						    chan->nnpdev);
		chan->h2c_rb_hostres[id] = hostres;
	} else {
		if (chan->c2h_rb_hostres[id])
			nnpdrv_hostres_unmap_device(chan->c2h_rb_hostres[id],
						    chan->nnpdev);
		chan->c2h_rb_hostres[id] = hostres;
	}

	return 0;
}

struct chan_hostres_map *nnpdrv_cmd_chan_find_hostres(
					struct nnpdrv_cmd_chan *chan,
					u16                     protocol_id)
{
	struct chan_hostres_map *hostres_map;

	spin_lock(&chan->lock);
	hash_for_each_possible(chan->hostres_hash,
			       hostres_map,
			       hash_node,
			       protocol_id)
		if (hostres_map->protocol_id == protocol_id) {
			spin_unlock(&chan->lock);
			return hostres_map;
		}
	spin_unlock(&chan->lock);

	return NULL;
}

int nnpdrv_chan_unmap_hostres(struct nnpdrv_cmd_chan *chan, u16 protocol_id)
{
	struct chan_hostres_map *hostres_map;
	bool found = false;

	spin_lock(&chan->lock);
	hash_for_each_possible(chan->hostres_hash,
			       hostres_map,
			       hash_node,
			       protocol_id)
		if (hostres_map->protocol_id == protocol_id) {
			found = true;
			hash_del(&hostres_map->hash_node);
			break;
		}
	spin_unlock(&chan->lock);

	if (!found)
		return -ENXIO;

	ida_simple_remove(&chan->hostres_map_ida,
			  hostres_map->protocol_id);
	nnpdrv_hostres_unmap_device(hostres_map->hostres, chan->nnpdev);
	kfree(hostres_map);

	return 0;
}

void nnpdrv_chan_unmap_hostres_all(struct nnpdrv_cmd_chan *chan)
{
	struct chan_hostres_map *hostres_map;
	bool found = true;
	int i;

	do {
		found = false;
		spin_lock(&chan->lock);
		hash_for_each(chan->hostres_hash, i, hostres_map, hash_node) {
			hash_del(&hostres_map->hash_node);
			spin_unlock(&chan->lock);
			ida_simple_remove(&chan->hostres_map_ida,
					  hostres_map->protocol_id);
			nnpdrv_hostres_unmap_device(hostres_map->hostres,
						    chan->nnpdev);
			kfree(hostres_map);
			found = true;
			break;
		}
	} while (found);
	spin_unlock(&chan->lock);
}
