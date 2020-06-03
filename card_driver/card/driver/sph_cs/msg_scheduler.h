/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#ifndef AIPG_INFERENCE_PLATFORM_SW_SRC_DRIVER_INCLUDE_MSG_SCHEDULER_H_
#define AIPG_INFERENCE_PLATFORM_SW_SRC_DRIVER_INCLUDE_MSG_SCHEDULER_H_

#include <linux/fs.h>
#include <linux/poll.h>
#include <linux/workqueue.h>
#include "ipc_protocol.h"
#include <linux/mutex.h>
#include <linux/debugfs.h>

#define MSG_SCHED_MAX_MSG_SIZE 3

/* [Description]: HW handler called by the scheduler to send a message.
 * [in]: msg: message.
 * [in]: size[1-2]: size of message.
 * [in]: data: pointer to device specific hw data attached (e.g: struct nnp_device).
 * [return]: status.
 */
typedef int (*hw_handle_msg)(u64 *msg, int size, void *hw_data);

struct msg_scheduler {
	struct task_struct *scheduler_thread;
	struct list_head queues_list_head;
	spinlock_t queue_lock_irq;
	struct mutex destroy_lock;
	u32 total_msgs_num;
	struct kmem_cache *slab_cache_ptr;
};

struct msg_scheduler_queue {
	struct msg_scheduler *scheduler;
	struct list_head queues_list_node;
	struct list_head msgs_list_head;
	wait_queue_head_t  flush_waitq;
	u32 invalid;
	uint32_t msgs_num;
	spinlock_t list_lock_irq;
	u32 handle_cont;
	void *device_hw_data;
	hw_handle_msg msg_handle;
#ifdef ULT
	// Debug statistics counters
	u32 sched_count;
	u32 pre_send_count;
	u32 post_send_count;
	u32 send_failed_count;
#endif
};

/*********************************************************************
 *  [Brief]: create messages scheduler
 *           malloc DB and start dedicated scheduling thread.
 *
 *  [return] : dev_scheduler, NULL-failed.
 ********************************************************************/
struct msg_scheduler *msg_scheduler_create(void);

/*
 * @brief - initializes debugfs status entry
 */
void msg_scheduler_init_debugfs(struct msg_scheduler *scheduler,
				struct dentry *parent,
				const char    *dirname);

/*********************************************************************
 *  [Brief]: destroy messages scheduler created after calling "msg_scheduler_create"
 *         free all remaining messages and queues and stop scheduler running thread.
 *
 *  [in] scheduler: scheduler data returned from msg_scheduler_create.
 *  [return] : 0 - success, otherwise- failed.
 ********************************************************************/
int msg_scheduler_destroy(struct msg_scheduler *scheduler);

/**
 * @brief Remove all messages from all queues and mark all queues
 *  invalid. invalid queues can only be destroyed, no messages can be added to
 *  an invalid queue.
 *  This function is called just before a card reset to prevent any new messages
 *  to be sent on the h/w queue.
 */
int msg_scheduler_invalidate_all(struct msg_scheduler *scheduler);

/*********************************************************************
 *  [Brief]: create messages queue handled by scheduler.
 *
 *  [in] scheduler: scheduler data  returned by "msg_scheduler_create".
 *  [in] device_hw_data: device specific hw data (e.g: struct nnp_device).
 *  [in] hw_handle_msg: function pointer to HW message handler.
 *  [in] conti_msgs: number of messages scheduler may handle contineously before
 *       moving to next queue.
 *  [return] : queue - success, NULL-failed.
 ********************************************************************/
struct msg_scheduler_queue *msg_scheduler_queue_create(struct msg_scheduler *scheduler, void *device_hw_data, hw_handle_msg msg_handle, u32 conti_msgs);

/*********************************************************************
 *  [Brief]: destroy messages queue created by "msg_scheduler_queue_create".
 *
 *  [in] scheduler: scheduler data returned by msg_scheduler_create.
 *  [in] queue: data pointer returned by "msg_scheduler_queue_create".
 *  [return] : 0 - success, otherwise- failed.
 ********************************************************************/
int msg_scheduler_queue_destroy(struct msg_scheduler *scheduler, struct msg_scheduler_queue *queue);

/*********************************************************************
 *  [Brief]: wait until a message queue is flushed out and empty
 *
 *  [in] queue: data pointer of queue returned by "msg_scheduler_queue_create".
 *  [return] : 0 - success, otherwise- failed.
 ********************************************************************/
int msg_scheduler_queue_flush(struct msg_scheduler_queue *queue);

/*********************************************************************
 *  [Brief]: add message to queue created in "msg_scheduler_queue_create".
 *
 *  [in] queue: data pointer of queue returned by "msg_scheduler_queue_create".
 *  [in] msg: message value.
 *  [in] size[1-2]: message size, one/two u64 message/s.
 *  [return] : 0 - success, otherwise- failed.
 ********************************************************************/
int msg_scheduler_queue_add_msg(struct msg_scheduler_queue *queue, u64 *msg, unsigned int size);

/*********************************************************************
 *  [Brief]: Marks a queue as valid
 *
 *  This function marks a queue as valid again after it made invalid
 *  by a call to msg_scheduler_invalidate_all.
 *
 *  [in] queue: data pointer of queue returned by "msg_scheduler_queue_create".
 *  [in] msg: message value.
 ********************************************************************/
void msg_scheduler_queue_make_valid(struct msg_scheduler_queue *queue);

#endif /* AIPG_INFERENCE_PLATFORM_SW_SRC_DRIVER_INCLUDE_MSG_SCHEDULER_H_ */
