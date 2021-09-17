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
#include <string.h>
#include <stdarg.h>
#include <null_dev.h>

#ifndef _DUMMY_CORAL_H_
#define _DUMMY_CORAL_H_

#define ICE_MMIO_GP_RESET_REG_ADDR 0x198
typedef struct Thread_Data {
	ftype_interrupt_handler intr_handler;
	bool status;
	uint32_t ice_id;
} Thread_Data;

typedef struct Interrupt_Entry {
	pthread_t p_thread;
	Thread_Data p_data;
} Interrupt_Entry;

void null_device_fini(void);
#endif
