/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/
/*
 * [Desciption]: periodic timer implementation.
 * create periodic timer with adjustable time interval.
 * Timer callback can call multiple pre defined callbacks.
 */

#include "periodic_timer.h"
#include <linux/kernel.h>
#include <linux/slab.h>
#include "sph_debug.h"
#include "sph_log.h"


#ifdef setup_timer
static void periodic_timer_handler(unsigned long cb_data)
#else  // timer_setup starting linux kernel V4.15
static void periodic_timer_handler(struct timer_list *timer)
#endif
{
	struct periodic_timer *timer_data;
	struct periodic_timer_data *data;
	struct periodic_timer_data *m;
	unsigned long flags;

#ifdef setup_timer
	timer_data = (struct periodic_timer *)(uintptr_t)cb_data;
#else  // timer_setup starting linux kernel V4.15
	timer_data = from_timer(timer_data, timer, periodic_timer);
#endif
	SPH_SPIN_LOCK_IRQSAVE(&timer_data->lock_irq, flags);
	if (list_empty(&timer_data->cb_data_list)) {
		SPH_SPIN_UNLOCK_IRQRESTORE(&timer_data->lock_irq, flags);
		return;
	}

	list_for_each_entry_safe(data, m, &timer_data->cb_data_list, node) {
		if (data->removed) {
			list_del(&data->node);
			SPH_SPIN_UNLOCK_IRQRESTORE(&timer_data->lock_irq, flags);
			kfree(data); //TODO GLEB: not safe unlock in list iteration
			SPH_SPIN_LOCK_IRQSAVE(&timer_data->lock_irq, flags);
		}
	}

	if (list_empty(&timer_data->cb_data_list)) {
		SPH_SPIN_UNLOCK_IRQRESTORE(&timer_data->lock_irq, flags);
		return;
	}

	SPH_SPIN_UNLOCK_IRQRESTORE(&timer_data->lock_irq, flags);


	list_for_each_entry(data, &timer_data->cb_data_list, node) {
		data->timer_callback(data->timer_callback_ctx);
	}

	/*Restarting the timer...*/
	mod_timer(&timer_data->periodic_timer, jiffies + msecs_to_jiffies(timer_data->timer_interval_ms));
}

static uint64_t add_cb_data(struct periodic_timer *timer, struct periodic_timer_data *data)
{
	unsigned long flags;
	struct periodic_timer_data *new_data =  kzalloc(sizeof(*data), GFP_KERNEL);

	if (!new_data)
		return 0;
	memcpy(new_data, data, sizeof(*data));
	new_data->removed = false;

	SPH_SPIN_LOCK_IRQSAVE(&timer->lock_irq, flags);
	list_add_tail(&new_data->node, &timer->cb_data_list);
	SPH_SPIN_UNLOCK_IRQRESTORE(&timer->lock_irq, flags);

	return (uint64_t)(uintptr_t)new_data;
}


uint64_t periodic_timer_init(struct periodic_timer *timer, struct periodic_timer_data *data)
{
	uint64_t data_handler = 0;

	INIT_LIST_HEAD(&timer->cb_data_list);
	spin_lock_init(&timer->lock_irq);

	if (data != NULL)
		data_handler = add_cb_data(timer, data);
#ifdef setup_timer
	setup_timer(&timer->periodic_timer, periodic_timer_handler, (unsigned long)(uintptr_t)timer);
#else // timer_setup starting linux kernel V4.15
	timer_setup(&timer->periodic_timer, periodic_timer_handler, 0);
#endif
	mod_timer(&timer->periodic_timer, jiffies + msecs_to_jiffies(timer->timer_interval_ms));

	return data_handler;
}

uint64_t periodic_timer_add_data(struct periodic_timer *timer, struct periodic_timer_data *data)
{
	bool start_timer = false;
	uint64_t data_handler;

	if (list_empty(&timer->cb_data_list))
		start_timer = true;

	data_handler = add_cb_data(timer, data);

	if (start_timer)
		mod_timer(&timer->periodic_timer, jiffies + msecs_to_jiffies(timer->timer_interval_ms));

	return data_handler;
}

void periodic_timer_remove_data(struct periodic_timer *timer, uint64_t data_handler)
{
	unsigned long flags;
	struct periodic_timer_data *data;
	bool   allDataRemoved = true;

	SPH_SPIN_LOCK_IRQSAVE(&timer->lock_irq, flags);
	list_for_each_entry(data, &timer->cb_data_list, node) {
		if ((uint64_t)(uintptr_t)data == data_handler)
			data->removed = true;
		allDataRemoved &= data->removed;
	}
	SPH_SPIN_UNLOCK_IRQRESTORE(&timer->lock_irq, flags);

	if (allDataRemoved) //call timer handler immediately
		mod_timer(&timer->periodic_timer, jiffies);
}

void periodic_timer_delete(struct periodic_timer *timer)
{
	struct periodic_timer_data *data;

	del_timer(&timer->periodic_timer);

	while (!list_empty(&timer->cb_data_list)) {
		data = list_first_entry(&timer->cb_data_list, struct periodic_timer_data, node);
		list_del(&data->node);
		kfree(data);
	}
}
