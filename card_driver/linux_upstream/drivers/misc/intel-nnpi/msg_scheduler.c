// SPDX-License-Identifier: GPL-2.0-or-later

/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 ********************************************/

/*
 * [Desciption]: message scheduler implementation.
 * create scheduler to handle message sending of some device.
 * This program allow device to create scheduler and manage several
 * queues of messages which will be handled in RR scheduling scheme.
 */

#include "msg_scheduler.h"
#include <linux/slab.h>
#include <linux/err.h>
#include <linux/interrupt.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/spinlock.h>
#include "nnp_debug.h"
#include "nnp_log.h"
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/jiffies.h>
#include <linux/kthread.h>
#include <linux/seq_file.h>

struct msg_entry {
	u64 msg[MSG_SCHED_MAX_MSG_SIZE];
	u32 size;
	struct list_head node;
};

/*
 * [Description]: messages scheduler main thread function.
 * loop over all the queues lists of messages in RR fashion,
 * [in] data :  shceduler data
 */
int msg_scheduler_thread_func(void *data)
{
	struct msg_scheduler *dev_sched = (struct msg_scheduler *)data;
	struct msg_scheduler_queue *queue_node;
	struct msg_entry *msg_list_node;
	int ret;
	int i;
	int is_empty;
	u32 local_total_msgs_num = 0;
	u32 left = 0;

	nnp_log_debug(GENERAL_LOG, "msg scheduler thread started\n");

	while (!kthread_should_stop()) {
		mutex_lock(&dev_sched->destroy_lock);
		spin_lock_bh(&dev_sched->queue_lock_bh);
		set_current_state(TASK_INTERRUPTIBLE);
		if (dev_sched->total_msgs_num == local_total_msgs_num &&
		    left == 0) {
			mutex_unlock(&dev_sched->destroy_lock);
			spin_unlock_bh(&dev_sched->queue_lock_bh);
			/* wait until messages arrive to some queue */
			schedule();
			mutex_lock(&dev_sched->destroy_lock);
			spin_lock_bh(&dev_sched->queue_lock_bh);
		}
		set_current_state(TASK_RUNNING);

		local_total_msgs_num = dev_sched->total_msgs_num;
		left = 0;

		is_empty = list_empty(&dev_sched->queues_list_head);
		if (likely(!is_empty))
			queue_node =
				list_first_entry(&dev_sched->queues_list_head,
						 struct msg_scheduler_queue,
						 queues_list_node);

		spin_unlock_bh(&dev_sched->queue_lock_bh);

		if (unlikely(is_empty)) {
			mutex_unlock(&dev_sched->destroy_lock);
			continue;
		}

		ret = 0;

		while (&queue_node->queues_list_node !=
		       &dev_sched->queues_list_head) {
			if (queue_node->msgs_num == 0)
				goto skip_queue;

			for (i = 0; i < queue_node->handle_cont; i++) {
				spin_lock_bh(&queue_node->list_lock_bh);
#ifdef DEBUG
				queue_node->sched_count++;
#endif
				is_empty =
					list_empty(&queue_node->msgs_list_head);
				if (!is_empty) {
					msg_list_node = list_first_entry(
						&queue_node->msgs_list_head,
						struct msg_entry, node);
#ifdef DEBUG
					queue_node->pre_send_count++;
#endif
				}
				spin_unlock_bh(&queue_node->list_lock_bh);

				if (is_empty)
					break;

				ret = queue_node->msg_handle(msg_list_node->msg,
						msg_list_node->size,
						queue_node->device_hw_data);
				if (ret) {
#ifdef DEBUG
					queue_node->send_failed_count++;
#endif
					break;
				}

				spin_lock_bh(&queue_node->list_lock_bh);
#ifdef DEBUG
				queue_node->post_send_count++;
#endif
				list_del(&msg_list_node->node);
				queue_node->msgs_num--;
				spin_unlock_bh(&queue_node->list_lock_bh);
				kmem_cache_free(dev_sched->slab_cache_ptr,
						msg_list_node);

				if (!queue_node->msgs_num)
					wake_up_all(&queue_node->flush_waitq);
			}

			/*
			 * if failed to write into command queue, no point
			 * trying rest of the message queues
			 */
			if (ret)
				break;

			left += queue_node->msgs_num;
skip_queue:
			spin_lock_bh(&dev_sched->queue_lock_bh);
			queue_node = list_next_entry(queue_node,
						     queues_list_node);
			spin_unlock_bh(&dev_sched->queue_lock_bh);
		}

		mutex_unlock(&dev_sched->destroy_lock);

		if (ret) {
			nnp_log_err(GENERAL_LOG,
				    "FATAL: failed writing to command queue - invalidating all queues\n");
			msg_scheduler_invalidate_all(dev_sched);
		}
	}

	nnp_log_debug(GENERAL_LOG, "Thread Stopping\n");

	do_exit(0);
}

/*
 * [Description]: create new message queue.
 *
 * [in] scheduler
 * [in] msg_handle
 * [in] conti_msgs
 */
struct msg_scheduler_queue *msg_scheduler_queue_create(
				struct msg_scheduler *scheduler,
				void                 *device_hw_data,
				hw_handle_msg         msg_handle,
				u32                   conti_msgs)
{
	struct msg_scheduler_queue *queue;

	if (!msg_handle) {
		nnp_log_err(START_UP_LOG, "FATAL: NULL pointer as msg handler\n");
		return NULL;
	}

	queue = kzalloc(sizeof(*queue), GFP_NOWAIT);
	if (!queue)
		return NULL;

	INIT_LIST_HEAD(&queue->msgs_list_head);
	spin_lock_init(&queue->list_lock_bh);
	queue->msgs_num = 0;

	if (!conti_msgs)
		queue->handle_cont = 1;
	else
		queue->handle_cont = conti_msgs;

	queue->device_hw_data = device_hw_data;
	queue->msg_handle = msg_handle;
	queue->scheduler = scheduler;
	init_waitqueue_head(&queue->flush_waitq);

	spin_lock_bh(&scheduler->queue_lock_bh);
	list_add_tail(&queue->queues_list_node, &scheduler->queues_list_head);
	spin_unlock_bh(&scheduler->queue_lock_bh);

	return queue;
}

/*
 * [description]: remove queue from scheduler.
 * - free all messages of the queue
 * - free queue node from queues list
 * [in]: scheduler
 * [in]: queue :  queue
 */
int msg_scheduler_queue_destroy(struct msg_scheduler       *scheduler,
				struct msg_scheduler_queue *queue)
{
	struct msg_entry *msg_list_node;

	if (!queue || queue->scheduler != scheduler) {
		nnp_log_err(GO_DOWN_LOG, "NULL pointer or wrong scheduler\n");
		return -EINVAL;
	}

	mutex_lock(&scheduler->destroy_lock);

	/* destroy all the messages of the queue */
	spin_lock_bh(&queue->list_lock_bh);
	while (!list_empty(&queue->msgs_list_head)) {
		msg_list_node = list_first_entry(&queue->msgs_list_head,
						 struct msg_entry, node);
		list_del(&msg_list_node->node);
		kmem_cache_free(scheduler->slab_cache_ptr, msg_list_node);
	}
	spin_unlock_bh(&queue->list_lock_bh);

	/* destroy the queue */
	spin_lock_bh(&queue->scheduler->queue_lock_bh);
	list_del(&queue->queues_list_node);
	spin_unlock_bh(&queue->scheduler->queue_lock_bh);
	kfree(queue);
	mutex_unlock(&scheduler->destroy_lock);

	return 0;
}

/*
 * [Description]: wait until a message queue is flushed out and empty
 * [in] queue
 */
int msg_scheduler_queue_flush(struct msg_scheduler_queue *queue)
{
	int ret;

	/* Wait for the queue to be empty */
	ret = wait_event_interruptible(queue->flush_waitq,
				       list_empty(&queue->msgs_list_head));

	return ret;
}

/*
 * [Description]: add message to existing queue.
 * [in] queue
 * [in] msg
 * [in] size
 */
int msg_scheduler_queue_add_msg(struct msg_scheduler_queue *queue,
				u64                        *msg,
				unsigned int               size)
{
	unsigned int i;
	struct msg_entry *msg_list_node;
	u32 invalid_queue;

	if (!queue || !msg) {
		nnp_log_err(GENERAL_LOG,
			    "NULL pointer received as queue list/msg\n");
		return -EINVAL;
	}

	if (size > MSG_SCHED_MAX_MSG_SIZE) {
		nnp_log_err(GENERAL_LOG,
			    "invalid message size received, size: %u.\n",
			    size);
		return -EINVAL;
	}

	/* if queue flaged as invalid - silently ignore the message */
	if (queue->invalid)
		return 0;

	msg_list_node = kmem_cache_alloc(queue->scheduler->slab_cache_ptr,
					 GFP_NOWAIT);
	if (!msg_list_node) {
		nnp_log_err(GENERAL_LOG, "No memory for message list\n");
		return -ENOMEM;
	}

	for (i = 0; i < size; i++)
		msg_list_node->msg[i] = *(msg + i);
#ifdef _DEBUG
	for (i = size; i < MSG_SCHED_MAX_MSG_SIZE; i++)
		msg_list_node->msg[i] = 0xdeadbeefdeadbeefLLU;
#endif

	msg_list_node->size = size;

	spin_lock_bh(&queue->list_lock_bh);
	invalid_queue = queue->invalid;
	if (!invalid_queue) {
		list_add_tail(&msg_list_node->node, &queue->msgs_list_head);
		queue->msgs_num++;
	}
	spin_unlock_bh(&queue->list_lock_bh);

	/* if queue flaged as invalid - silently ignore the message */
	if (unlikely(invalid_queue)) {
		kmem_cache_free(queue->scheduler->slab_cache_ptr,
				msg_list_node);
		return 0;
	}

	spin_lock_bh(&queue->scheduler->queue_lock_bh);
	queue->scheduler->total_msgs_num++;
	spin_unlock_bh(&queue->scheduler->queue_lock_bh);
	wake_up_process(queue->scheduler->scheduler_thread);

	return 0;
}

void msg_scheduler_queue_make_valid(struct msg_scheduler_queue *queue)
{
	spin_lock_bh(&queue->list_lock_bh);
	queue->invalid = 0;
	spin_unlock_bh(&queue->list_lock_bh);
}

/*
 * [Description]: start dedicate thread to handle message scheduling
 * - create and start thread.
 * - allcoate Hw handlers memory
 */
struct msg_scheduler *msg_scheduler_create(void)
{
	struct msg_scheduler *dev_sched;

	dev_sched = kzalloc(sizeof(*dev_sched), GFP_NOWAIT);
	if (!dev_sched)
		goto out;

	dev_sched->slab_cache_ptr = kmem_cache_create("msg_scheduler_slabCache",
						      sizeof(struct msg_entry),
						      0, 0, NULL);
	if (!dev_sched->slab_cache_ptr) {
		nnp_log_err(START_UP_LOG, "failed to create message scheduler slab cache\n");
		kfree(dev_sched);
		dev_sched = NULL;
		goto out;
	}

	INIT_LIST_HEAD(&dev_sched->queues_list_head);

	spin_lock_init(&dev_sched->queue_lock_bh);

	mutex_init(&dev_sched->destroy_lock);

	dev_sched->scheduler_thread = kthread_run(msg_scheduler_thread_func,
						  dev_sched,
						  "msg_scheduler_thread");
	if (!dev_sched->scheduler_thread) {
		nnp_log_err(START_UP_LOG, "failed to create message scheduler thread\n");
		kmem_cache_destroy(dev_sched->slab_cache_ptr);
		mutex_destroy(&dev_sched->destroy_lock);
		kfree(dev_sched);
		dev_sched = NULL;
	}

out:
	return dev_sched;
}

/*
 * [Description]: stop scheduler thread, and release all allocated memory
 *                that still allocated.
 *
 * [in] scheduler
 */
int msg_scheduler_destroy(struct msg_scheduler *scheduler)
{
	struct msg_scheduler_queue *queue_node;
	int rc;

	msg_scheduler_invalidate_all(scheduler);

	if (scheduler->scheduler_thread) {
		rc = kthread_stop(scheduler->scheduler_thread);
		if (rc) {
			nnp_log_err(GO_DOWN_LOG,
				    "thread exit code is: %d\n", rc);
			return -ENOMSG;
		}
	}

	spin_lock_bh(&scheduler->queue_lock_bh);
	while (!list_empty(&scheduler->queues_list_head)) {
		queue_node =
			list_first_entry(&scheduler->queues_list_head,
					 struct msg_scheduler_queue,
					 queues_list_node);

		/* destroy the queue */
		list_del(&queue_node->queues_list_node);
		spin_unlock_bh(&scheduler->queue_lock_bh);
		kfree(queue_node);
		spin_lock_bh(&scheduler->queue_lock_bh);
	}
	spin_unlock_bh(&scheduler->queue_lock_bh);

	kmem_cache_destroy(scheduler->slab_cache_ptr);

	mutex_destroy(&scheduler->destroy_lock);
	kfree(scheduler);

	nnp_log_debug(GO_DOWN_LOG, "destroy done\n");

	return 0;
}

int msg_scheduler_invalidate_all(struct msg_scheduler *scheduler)
{
	struct msg_scheduler_queue *queue_node;
	struct msg_entry *msg_list_node;
	u32 nq = 0, nmsg = 0;

	mutex_lock(&scheduler->destroy_lock);

	/*
	 * For each queue:
	 * 1) invalidate the queue, so that no more messages will be inserted
	 * 2) delete all existing messages
	 */
	spin_lock_bh(&scheduler->queue_lock_bh);
	list_for_each_entry(queue_node,
			    &scheduler->queues_list_head,
			    queues_list_node) {
		spin_lock_bh(&queue_node->list_lock_bh);
		queue_node->invalid = 1;
		while (!list_empty(&queue_node->msgs_list_head)) {
			msg_list_node =
				list_first_entry(&queue_node->msgs_list_head,
						 struct msg_entry, node);
			list_del(&msg_list_node->node);
			kmem_cache_free(scheduler->slab_cache_ptr,
					msg_list_node);
			nmsg++;
		}
		queue_node->msgs_num = 0;
		spin_unlock_bh(&queue_node->list_lock_bh);
		wake_up_all(&queue_node->flush_waitq);
		nq++;
	}
	spin_unlock_bh(&scheduler->queue_lock_bh);

	mutex_unlock(&scheduler->destroy_lock);

	nnp_log_debug(GENERAL_LOG,
		      "Invalidated %d msg queues, total messages lost %d\n",
		      nq, nmsg);

	return 0;
}

static int debug_status_show(struct seq_file *m, void *v)
{
	struct msg_scheduler *scheduler = m->private;
	struct msg_scheduler_queue *queue_node;
	struct msg_entry *msg_list_node;
	u32 nq = 0, tmsgs = 0;

	spin_lock_bh(&scheduler->queue_lock_bh);
	list_for_each_entry(queue_node,
			    &scheduler->queues_list_head,
			    queues_list_node) {
		u32 nmsg = 0;

		spin_lock_bh(&queue_node->list_lock_bh);
		list_for_each_entry(msg_list_node,
				    &queue_node->msgs_list_head,
				    node) {
			nmsg++;
		}
		spin_unlock_bh(&queue_node->list_lock_bh);
#ifdef DEBUG
		seq_printf(m, "queue 0x%lx: handle_cont=%u msgs_num=%u actual_msgs_num=%u scheds=%u pre=%u post=%u failed=%u\n",
			   (uintptr_t)queue_node,
			   queue_node->handle_cont,
			   queue_node->msgs_num,
			   nmsg,
			   queue_node->sched_count,
			   queue_node->pre_send_count,
			   queue_node->post_send_count,
			   queue_node->send_failed_count);
#else
		seq_printf(m, "queue 0x%lx: handle_cont=%u msgs_num=%u actual_msgs_num=%u\n",
			   (uintptr_t)queue_node,
			   queue_node->handle_cont,
			   queue_node->msgs_num,
			   nmsg);
#endif
		nq++;
		tmsgs += nmsg;
	}
	seq_printf(m, "%u queues total_msgs=%u actual_total_msgs=%u\n",
		   nq, scheduler->total_msgs_num, tmsgs);
	spin_unlock_bh(&scheduler->queue_lock_bh);

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

void msg_scheduler_init_debugfs(struct msg_scheduler *scheduler,
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
				    (void *)scheduler,
				    &debug_status_fops);
	if (IS_ERR_OR_NULL(stats)) {
		debugfs_remove(dir);
		return;
	}
}
