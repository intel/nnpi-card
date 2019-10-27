/********************************************
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#ifndef AIPG_INFERENCE_PLATFORM_SW_SRC_DRIVER_INCLUDE_PERIODIC_TIMER_H_
#define AIPG_INFERENCE_PLATFORM_SW_SRC_DRIVER_INCLUDE_PERIODIC_TIMER_H_

#include <linux/fs.h>
#include <linux/poll.h>
#include <linux/timer.h>
#include <linux/spinlock.h>

struct periodic_timer_data {
	void (*timer_callback)(void *ctx);
	void *timer_callback_ctx;
	struct list_head node;
	bool   removed;
};

struct periodic_timer {
	struct timer_list periodic_timer;
	int timer_interval_ms; //milliseconds
	struct list_head cb_data_list;
	spinlock_t         lock_irq;
};

uint64_t periodic_timer_init(struct periodic_timer *timer, struct periodic_timer_data *data);

uint64_t periodic_timer_add_data(struct periodic_timer *timer, struct periodic_timer_data *data);

void periodic_timer_remove_data(struct periodic_timer *timer, uint64_t data_handler);

void periodic_timer_delete(struct periodic_timer *timer);

#endif /* AIPG_INFERENCE_PLATFORM_SW_SRC_DRIVER_INCLUDE_PERIODIC_TIMER_H_ */
