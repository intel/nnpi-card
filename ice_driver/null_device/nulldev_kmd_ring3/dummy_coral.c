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

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <pthread.h>
#include <stdbool.h>
#include "coral.h"
#include "dummy_coral.h"
#include <unistd.h>
#include <semaphore.h>

ftype_interrupt_handler coral_intr;
Interrupt_Entry *intr_entry;
bool stop_thread = false;
sem_t thread_sem;

static void *coral_send_interrupt(void *ptr)
{
	Thread_Data *data = (Thread_Data *)ptr;

	while (!stop_thread) {
		sem_wait(&thread_sem);
		data->intr_handler(0, (void *)&data->ice_id, NULL);
		data->status = true;
	}
	pthread_exit(0);
	free(ptr);
	sem_destroy(&thread_sem);
}

void delay(uint64_t milli_secs)
{
	usleep(milli_secs * 1000);
}

int coral_init_multi(const char *cfg_name,
		ftype_interrupt_handler pfn, uint32_t num_instances)
{
	coral_intr = pfn;
	idc_error = getenv("IDC_REGS_MEM_IDCINTST_VALUE");
	ice_error = getenv("CVE_INTERRUPT_STATUS_VALUE");
	interrupt_delay = getenv("INTERRUPT_DELAY");

	sem_init(&thread_sem, 0, 0);
	intr_entry = (struct Interrupt_Entry *)malloc
			(sizeof(struct Interrupt_Entry));
	intr_entry->p_data.intr_handler = coral_intr;
	intr_entry->p_data.status = false;
	intr_entry->p_data.ice_id = 0;
	int status = pthread_create(&intr_entry->p_thread, NULL,
				&coral_send_interrupt,
				(void *)&intr_entry->p_data);
	null_device_log("coral_init successful\n");
	return 0;
}

uint64_t *coral_get_bar1_base()
{
	uint64_t *ret_addr = malloc(sizeof(uint64_t *));
	return ret_addr;
}

void coral_trigger_simulation(void)
{
/* If INTERRUPT_DELAY env variable is set
 * interrupt is sent after the delay.
 * Interrupt is sent once per coral_trigger_simulation call
 * with interrupt status of all scheduled ices in that
 * call.If none is scheduled in current call
 * no interrupt is sent.
 */
	if (interrupt_delay != NULL) {
		null_device_log("Requested Interrupt delay: %s milliseconds\n",
							interrupt_delay);
		delay(strtol(interrupt_delay, NULL, 10));
	}

	for (int i = 0; i < MAX_ICE_COUNT; i++) {

		if (scheduled_ice[i]) {

			sem_post(&thread_sem);
		break;
		}
	}

}
int coral_reset_multi(uint32_t instance_id)
{
	return 0;
}

int coral_mmio_write_multi_offset(uint64_t reg_offset,
		uint64_t value, Reg_Space space, uint32_t instance_id)
{
	int ret = write_mmio(reg_offset);

	return ret;
}

int coral_mmio_read_multi_offset(uint64_t reg_offset, uint64_t *value,
					Reg_Space space, uint32_t instance_id)
{
	int ret = read_mmio(reg_offset, value);
	return ret;
}
void null_device_fini(void)
{
	stop_thread = true;
}

