/********************************************
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/
/*
 * [Desciption]: message scheduler implementation.
 * create scheduler to handle message sending of some device.
 * This program allow device to create scheduler and manage several queues of messages
 * which will be handled in RR scheduling scheme.
 */

#include "msg_scheduler.h"
#include <linux/slab.h>
#include <linux/err.h>
#include <linux/interrupt.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/spinlock.h>
#include "sph_debug.h"
#include "sph_log.h"
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
 * loop over all the queues lists of messages in RR fashion, taking into consideration the
 * queue requirement of the number of messages to handle when scheduler reach out the queue.
 * [in] data :  shceduler data
 */
int msg_scheduler_thread_func(void *data)
{
	struct msg_scheduler *dev_sched = (struct msg_scheduler *)data;
	struct msg_scheduler_queue *queue_node;
	struct msg_entry *msgList_node;
	int ret;
	int i;
	int is_empty;
	unsigned long flags;
	u32 local_total_msgs_num = 0;
	u32 left = 0;

	sph_log_debug(GENERAL_LOG, "msg scheduler thread started\n");

	while (!kthread_should_stop()) {
		mutex_lock(&dev_sched->destroy_lock);
		SPH_SPIN_LOCK_IRQSAVE(&dev_sched->queue_lock_irq, flags);
		set_current_state(TASK_INTERRUPTIBLE);
		if (dev_sched->total_msgs_num == local_total_msgs_num && left == 0) {
			mutex_unlock(&dev_sched->destroy_lock);
			SPH_SPIN_UNLOCK_IRQRESTORE(&dev_sched->queue_lock_irq, flags);
			/* wait until messages arrive to some queue */
			schedule();
			mutex_lock(&dev_sched->destroy_lock);
			SPH_SPIN_LOCK_IRQSAVE(&dev_sched->queue_lock_irq, flags);
		}
		set_current_state(TASK_RUNNING);

		local_total_msgs_num = dev_sched->total_msgs_num;
		left = 0;

		is_empty = list_empty(&dev_sched->queues_list_head);
		if (likely(!is_empty))
			queue_node = list_first_entry(&dev_sched->queues_list_head,
						      struct msg_scheduler_queue,
						      queues_list_node);

		SPH_SPIN_UNLOCK_IRQRESTORE(&dev_sched->queue_lock_irq, flags);

		if (unlikely(is_empty)) {
			mutex_unlock(&dev_sched->destroy_lock);
			continue;
		}

		while (&queue_node->queues_list_node != &dev_sched->queues_list_head) {
			if (queue_node->msgs_num == 0)
				goto skip_queue;

			for (i = 0; i < queue_node->handleCont; i++) {
				SPH_SPIN_LOCK_IRQSAVE(&queue_node->list_lock_irq, flags);
#ifdef ULT
				queue_node->sched_count++;
#endif
				is_empty = list_empty(&queue_node->msgs_list_head);
				if (!is_empty) {
					msgList_node = list_first_entry(&queue_node->msgs_list_head, struct msg_entry, node);
#ifdef ULT
					queue_node->pre_send_count++;
#endif
				}
				SPH_SPIN_UNLOCK_IRQRESTORE(&queue_node->list_lock_irq, flags);

				if (is_empty)
					break;

				ret = queue_node->msg_handle(msgList_node->msg, msgList_node->size, queue_node->device_hw_data);
				if (ret) {
#ifdef ULT
					queue_node->send_failed_count++;
#endif
					break;
				}

				SPH_SPIN_LOCK_IRQSAVE(&queue_node->list_lock_irq, flags);
#ifdef ULT
				queue_node->post_send_count++;
#endif
				list_del(&msgList_node->node);
				queue_node->msgs_num--;
				SPH_SPIN_UNLOCK_IRQRESTORE(&queue_node->list_lock_irq, flags);
				kmem_cache_free(dev_sched->slab_cache_ptr, msgList_node);

				if (!queue_node->msgs_num)
					wake_up_all(&queue_node->flush_waitq);
			}

			left += queue_node->msgs_num;
skip_queue:
			SPH_SPIN_LOCK_IRQSAVE(&dev_sched->queue_lock_irq, flags);
			queue_node = list_next_entry(queue_node, queues_list_node);
			SPH_SPIN_UNLOCK_IRQRESTORE(&dev_sched->queue_lock_irq, flags);
		}

		mutex_unlock(&dev_sched->destroy_lock);
	}

	sph_log_debug(GENERAL_LOG, "Thread Stopping\n");

	do_exit(0);
}

/*
 * [Description]: create new message queue.
 *
 * [in] scheduler
 * [in] msg_handle
 * [in] contiMsgs
 */
struct msg_scheduler_queue *msg_scheduler_queue_create(struct msg_scheduler *scheduler, void *device_hw_data, hw_handle_msg msg_handle, u32 contiMsgs)
{
	struct msg_scheduler_queue *queue;
	unsigned long flags;

	if (!msg_handle) {
		sph_log_err(START_UP_LOG, "FATAL: NULL pointer as msg handler\n");
		return NULL;
	}

	queue = kzalloc(sizeof(*queue), GFP_NOWAIT);
	if (!queue) {
		sph_log_err(START_UP_LOG, "No memory for queue message list\n");
		return NULL;
	}

	INIT_LIST_HEAD(&queue->msgs_list_head);
	spin_lock_init(&queue->list_lock_irq);
	queue->msgs_num = 0;

	if (!contiMsgs)
		queue->handleCont = 1;
	else
		queue->handleCont = contiMsgs;

	queue->device_hw_data = device_hw_data;
	queue->msg_handle = msg_handle;
	queue->scheduler = scheduler;
	init_waitqueue_head(&queue->flush_waitq);

	SPH_SPIN_LOCK_IRQSAVE(&scheduler->queue_lock_irq, flags);
	list_add_tail(&queue->queues_list_node, &scheduler->queues_list_head);
	SPH_SPIN_UNLOCK_IRQRESTORE(&scheduler->queue_lock_irq, flags);

	return queue;
}

/*
 * [description]: remove queue from scheduler.
 * - free all messages of the queue
 * - free queue node from queues list
 * [in]: scheduler
 * [in]: queue :  queue
 */
int msg_scheduler_queue_destroy(struct msg_scheduler *scheduler, struct msg_scheduler_queue *queue)
{
	struct msg_entry *msgList_node;
	unsigned long flags;

	if (!queue || queue->scheduler != scheduler) {
		sph_log_err(GO_DOWN_LOG, "msg_scheduler_queue_destroy NULL pointer or wrong scheduler\n");
		return -EINVAL;
	}

	mutex_lock(&scheduler->destroy_lock);

	/* destroy all the messages of the queue */
	SPH_SPIN_LOCK_IRQSAVE(&queue->list_lock_irq, flags);
	while (!list_empty(&queue->msgs_list_head)) {
		msgList_node = list_first_entry(&queue->msgs_list_head, struct msg_entry, node);
		list_del(&msgList_node->node);
		kmem_cache_free(scheduler->slab_cache_ptr, msgList_node);
	}
	SPH_SPIN_UNLOCK_IRQRESTORE(&queue->list_lock_irq, flags);

	/* destroy the queue */
	SPH_SPIN_LOCK_IRQSAVE(&queue->scheduler->queue_lock_irq, flags);
	list_del(&queue->queues_list_node);
	SPH_SPIN_UNLOCK_IRQRESTORE(&queue->scheduler->queue_lock_irq, flags);
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
int msg_scheduler_queue_add_msg(struct msg_scheduler_queue *queue, u64 *msg, unsigned int size)
{
	unsigned int i;
	struct msg_entry *msg_list_node;
	unsigned long flags;
	uint32_t invalid_queue;

	if (!queue || !msg) {
		sph_log_err(GENERAL_LOG, "NULL pointer received as queue list/msg\n");
		return -EINVAL;
	}

	if (size > MSG_SCHED_MAX_MSG_SIZE) {
		sph_log_err(GENERAL_LOG, "invalid message size received, size: %u.\n", size);
		return -EINVAL;
	}

	/* if queue flaged as invalid - silently ignore the message */
	if (queue->invalid)
		return 0;

	msg_list_node = kmem_cache_alloc(queue->scheduler->slab_cache_ptr, GFP_NOWAIT);
	if (!msg_list_node) {
		sph_log_err(GENERAL_LOG, "No memory for message list\n");
		return -ENOMEM;
	}

	for (i = 0; i < size; i++)
		msg_list_node->msg[i] = *(msg + i);
#ifdef _DEBUG
	for (i = size; i < MSG_SCHED_MAX_MSG_SIZE; i++)
		msg_list_node->msg[i] = 0xdeadbeefdeadbeefLLU;
#endif

	msg_list_node->size = size;

	SPH_SPIN_LOCK_IRQSAVE(&queue->list_lock_irq, flags);
	invalid_queue = queue->invalid;
	if (!invalid_queue) {
		list_add_tail(&msg_list_node->node, &queue->msgs_list_head);
		queue->msgs_num++;
	}
	SPH_SPIN_UNLOCK_IRQRESTORE(&queue->list_lock_irq, flags);

	/* if queue flaged as invalid - silently ignore the message */
	if (unlikely(invalid_queue)) {
		kmem_cache_free(queue->scheduler->slab_cache_ptr, msg_list_node);
		return 0;
	}

	SPH_SPIN_LOCK_IRQSAVE(&queue->scheduler->queue_lock_irq, flags);
	queue->scheduler->total_msgs_num++;
	SPH_SPIN_UNLOCK_IRQRESTORE(&queue->scheduler->queue_lock_irq, flags);
	wake_up_process(queue->scheduler->scheduler_thread);


	return 0;
}

void msg_scheduler_queue_make_valid(struct msg_scheduler_queue *queue)
{
	unsigned long flags;

	SPH_SPIN_LOCK_IRQSAVE(&queue->list_lock_irq, flags);
	queue->invalid = 0;
	SPH_SPIN_UNLOCK_IRQRESTORE(&queue->list_lock_irq, flags);
}

/*
 * [Description]: start dedicate thread to handle message scheduling in RR fashion.
 * - create and start thread.
 * - allcoate Hw handlers memory
 */
struct msg_scheduler *msg_scheduler_create(void)
{
	struct msg_scheduler *dev_sched;

	dev_sched = kzalloc(sizeof(struct msg_scheduler), GFP_NOWAIT);
	if (!dev_sched) {
		sph_log_err(START_UP_LOG, "memory allocation failed for msg scheduler\n");
		goto out;
	}

	dev_sched->slab_cache_ptr = kmem_cache_create("msg_scheduler_slabCache", sizeof(struct msg_entry),
													 0, 0, NULL);
	if (!dev_sched->slab_cache_ptr) {
		sph_log_err(START_UP_LOG, "failed to create message scheduler slab cache\n");
		kfree(dev_sched);
		dev_sched = NULL;
		goto out;
	}

	INIT_LIST_HEAD(&dev_sched->queues_list_head);

	spin_lock_init(&dev_sched->queue_lock_irq);

	mutex_init(&dev_sched->destroy_lock);

	dev_sched->scheduler_thread = kthread_run(msg_scheduler_thread_func, dev_sched, "msg_scheduler_thread");
	if (!dev_sched->scheduler_thread) {
		sph_log_err(START_UP_LOG, "failed to create message scheduler thread\n");
		kmem_cache_destroy(dev_sched->slab_cache_ptr);
		mutex_destroy(&dev_sched->destroy_lock);
		kfree(dev_sched);
		dev_sched = NULL;
	}

out:
	return dev_sched;
}

/*
 * [Description]: stop scheduler thread, and release all allocated memory that still allocated.
 *
 * [in] scheduler
 */
int msg_scheduler_destroy(struct msg_scheduler *scheduler)
{
	struct msg_scheduler_queue *queue_node;
	struct msg_entry *msgList_node;
	int rc;

	if (scheduler->scheduler_thread) {
		rc = kthread_stop(scheduler->scheduler_thread);
		if (rc) {
			sph_log_err(GO_DOWN_LOG, "thread exit code is: %d\n", rc);
			return -ENOMSG;
		}
	}

	while (!list_empty(&scheduler->queues_list_head)) {
		queue_node = list_first_entry(&scheduler->queues_list_head, struct msg_scheduler_queue, queues_list_node);

		while (!list_empty(&queue_node->msgs_list_head)) {
			msgList_node = list_first_entry(&queue_node->msgs_list_head, struct msg_entry, node);
			list_del(&msgList_node->node);
			kmem_cache_free(scheduler->slab_cache_ptr, msgList_node);
		}
		/* destroy the queue */
		list_del(&queue_node->queues_list_node);
		kfree(queue_node);
	}

	kmem_cache_destroy(scheduler->slab_cache_ptr);

	mutex_destroy(&scheduler->destroy_lock);
	kfree(scheduler);

	sph_log_debug(GO_DOWN_LOG, "destroy done\n");

	return 0;
}

int msg_scheduler_invalidate_all(struct msg_scheduler *scheduler)
{
	struct msg_scheduler_queue *queue_node;
	struct msg_entry *msgList_node;
	unsigned long flags;
	unsigned long flags2;
	u32 nq = 0, nmsg = 0;

	mutex_lock(&scheduler->destroy_lock);

	/*
	 * For each queue:
	 * 1) invalidate the queue, so that no more messages will be inserted
	 * 2) delete all existing messages
	 */
	SPH_SPIN_LOCK_IRQSAVE(&scheduler->queue_lock_irq, flags);
	list_for_each_entry(queue_node,
			    &scheduler->queues_list_head,
			    queues_list_node) {
		SPH_SPIN_LOCK_IRQSAVE(&queue_node->list_lock_irq, flags2);
		queue_node->invalid = 1;
		while (!list_empty(&queue_node->msgs_list_head)) {
			msgList_node = list_first_entry(&queue_node->msgs_list_head, struct msg_entry, node);
			list_del(&msgList_node->node);
			kmem_cache_free(scheduler->slab_cache_ptr, msgList_node);
			nmsg++;
		}
		SPH_SPIN_UNLOCK_IRQRESTORE(&queue_node->list_lock_irq, flags2);
		nq++;
	}
	SPH_SPIN_UNLOCK_IRQRESTORE(&scheduler->queue_lock_irq, flags);

	mutex_unlock(&scheduler->destroy_lock);

	sph_log_debug(GENERAL_LOG, "Invalidated %d msg queues, total messages lost %d\n", nq, nmsg);

	return 0;
}

static int debug_status_show(struct seq_file *m, void *v)
{
	struct msg_scheduler *scheduler = m->private;
	struct msg_scheduler_queue *queue_node;
	struct msg_entry *msgList_node;
	//unsigned long flags;
	//unsigned long flags2;
	u32 nq = 0, tmsgs = 0;

	//SPH_SPIN_LOCK_IRQSAVE(&scheduler->queue_lock_irq, flags);
	list_for_each_entry(queue_node,
			    &scheduler->queues_list_head,
			    queues_list_node) {
		u32 nmsg = 0;
		//SPH_SPIN_LOCK_IRQSAVE(&queue_node->list_lock_irq, flags2);
		list_for_each_entry(msgList_node,
				    &queue_node->msgs_list_head,
				    node) {
			nmsg++;
		}
		//SPH_SPIN_UNLOCK_IRQRESTORE(&queue_node->list_lock_irq, flags2);
#ifdef ULT
		seq_printf(m, "queue 0x%lx: handleCont=%u msgs_num=%u actual_msgs_num=%u scheds=%u pre=%u post=%u failed=%u\n",
			   (uintptr_t)queue_node,
			   queue_node->handleCont,
			   queue_node->msgs_num,
			   nmsg,
			   queue_node->sched_count,
			   queue_node->pre_send_count,
			   queue_node->post_send_count,
			   queue_node->send_failed_count);
#else
		seq_printf(m, "queue 0x%lx: handleCont=%u msgs_num=%u actual_msgs_num=%u\n",
			   (uintptr_t)queue_node,
			   queue_node->handleCont,
			   queue_node->msgs_num,
			   nmsg);
#endif
		nq++;
		tmsgs += nmsg;
	}
	seq_printf(m, "%u queues total_msgs=%u actual_total_msgs=%u\n",
		   nq, scheduler->total_msgs_num, tmsgs);
	//SPH_SPIN_UNLOCK_IRQRESTORE(&scheduler->queue_lock_irq, flags);

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
