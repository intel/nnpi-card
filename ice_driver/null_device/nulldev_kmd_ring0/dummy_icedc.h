/*
 * NNP-I Linux Driver
 * Copyright (c) 2018-2019, Intel Corporation.
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
#ifndef _DUMMY_ICEDC_H_
#define _DUMMY_ICEDC_H_

#include "null_dev.h"
#include <linux/irqreturn.h>
#include <linux/slab.h>
#define MAX_BARS_PCI_DEV 6
#define INTERRUPT_VAL 123

#define ioread64(addr) dummy_ioread64(addr)

typedef irqreturn_t (*dummy_irq_handler) (int, void*);

extern dummy_irq_handler interrupt_top_half;

uint32_t dummy_ioread32(uint32_t *mmio_address);

uint32_t dummy_iowrite32(uint64_t value, uint32_t *mmio_address);

uint64_t dummy_ioread64(uint64_t *mmio_address);

void dummy_iowrite64(uint64_t val, uint32_t *addr);

extern uint64_t ioaddr_bar[MAX_BARS_PCI_DEV];

int create_dummy_threaded_irq(void *addr);

int send_interrupt(void *ptr);

int null_dev_irq(int ice_num);

void remove_threaded_irq_null(void);

typedef struct null_dev_kthread_data {
	dummy_irq_handler intr_handler;
	bool status;
	uint32_t ice_id;
	void *linuxDeviceAddr;
} null_dev_kthread_data;

typedef struct dummy_Interrupt_Entry {
	char thread_name[17];
	null_dev_kthread_data k_data;
} dummy_Interrupt_Entry;

#endif
