/********************************************
 * Copyright (C) 2019-2021 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/



#ifndef _OS_INTERFACE_IMPL_H_
#define _OS_INTERFACE_IMPL_H_

#include <linux/irqreturn.h>
#include <linux/wait.h>
#include <linux/jiffies.h>
#include <linux/semaphore.h>
#include <linux/sched.h>
#include <linux/scatterlist.h>
#include <linux/stringify.h>
#include <linux/debugfs.h>
#include <linux/kthread.h>
#include <linux/time.h>
#include "cve_driver_internal_macros.h"

/* events */
typedef wait_queue_head_t cve_os_wait_que_t;
#define cve_os_block_interruptible_infinite(_que, _predicate) \
	wait_event_interruptible((*(_que)), (_predicate))

#define terminate_thread(device_group) \
	kthread_should_stop()

#define cve_os_block_timeout(_que, _predicate, timeout_msec) \
	wait_event_timeout((*(_que)), \
			(_predicate), \
			msecs_to_jiffies(timeout_msec))

#define cve_os_block_interruptible_timeout(_que, _predicate, timeout_msec) \
	wait_event_interruptible_timeout((*(_que)), \
			(_predicate), \
			msecs_to_jiffies(timeout_msec))

#define cve_os_stringify(x) __stringify(x)

/* semaphores */
typedef struct semaphore cve_os_lock_t;

/* interrupts */
typedef irqreturn_t cve_isr_retval_t;

/* memory */
typedef dma_addr_t cve_dma_addr_t;

#endif /* _OS_INTERFACE_IMPL_H_ */
