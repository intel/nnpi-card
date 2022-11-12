/*
 * NNP-I Linux Driver
 * Copyright (c) 2018-2021, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 */

#include "dummy_icedc.h"
#include <linux/kthread.h>
#include <linux/semaphore.h>
#include <linux/signal.h>

dummy_irq_handler interrupt_top_half;
dummy_Interrupt_Entry *intr_entry;

uint64_t ioaddr_bar[MAX_BARS_PCI_DEV] = {0};
static struct task_struct *null_dev_kthread;
struct semaphore thread_sem;

int create_dummy_threaded_irq(void *addr)
{
	sema_init(&thread_sem, 0);
	intr_entry = (struct dummy_Interrupt_Entry *)kmalloc
				(sizeof(struct dummy_Interrupt_Entry),
								GFP_KERNEL);
	intr_entry->k_data.intr_handler = interrupt_top_half;
	intr_entry->k_data.status = false;
	intr_entry->k_data.ice_id = 0;
	intr_entry->k_data.linuxDeviceAddr = addr;
	strcpy(intr_entry->thread_name, "null_dev_kthread");
	null_dev_kthread = kthread_run(send_interrupt,
				(void *)&intr_entry->k_data,
				"null_dev_kthread");
	if (!null_dev_kthread)
		null_device_log("null_dev_kthread error\n");

	return 0;
}

int send_interrupt(void *ptr)
{
	null_dev_kthread_data *data = (null_dev_kthread_data *)ptr;

	while (!kthread_should_stop()) {
		down(&thread_sem);
		if (data->intr_handler) {
			data->intr_handler(INTERRUPT_VAL,
					data->linuxDeviceAddr);
			data->status = true;
		}
	}

	do_exit(0);
}
uint32_t dummy_ioread32(uint32_t *mmio_address)
{
	uint64_t val;
	int ret;
	uint64_t addr = (uint64_t)  mmio_address - ioaddr_bar[0];

	ret = read_mmio(addr, &val);

	return (uint32_t)val;
}

uint32_t dummy_iowrite32(uint64_t value, uint32_t *mmio_address)
{
	int ret;
	uint64_t addr = (uint64_t) mmio_address - ioaddr_bar[0];

	ret = write_mmio(addr);

	return ret;
}

uint64_t dummy_ioread64(uint64_t *mmio_address)
{
	uint64_t val;
	int ret;
	uint64_t addr = (uint64_t)  mmio_address - ioaddr_bar[0];

	ret = read_mmio(addr, &val);

	return val;
}

void dummy_iowrite64(uint64_t value, uint64_t *mmio_address)
{
	int ret;
	uint64_t addr = (uint64_t) mmio_address - ioaddr_bar[0];

	ret = write_mmio(addr);
}



int null_dev_irq(int ice_val)
{
	up(&thread_sem);
	return 0;
}
void remove_threaded_irq_null(void)
{
	intr_entry->k_data.intr_handler = NULL;
	kthread_stop(null_dev_kthread);

}
