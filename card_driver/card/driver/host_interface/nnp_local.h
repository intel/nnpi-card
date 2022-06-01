/********************************************
 * Copyright (C) 2019-2021 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/
#include <linux/kernel.h>    // included for KERN_INFO

enum QUEUE_TYPE {
	QUEUE_H2C = 0,
	QUEUE_C2H = 1,
	NUM_OF_QUEUES
};

#define NUM_H2C_CHANNELS 8
#define NUM_C2H_CHANNELS 8

enum DOORBELL_TYPE {
	HOST_PCI = 0,
	PCI_HOST = 1,
	NUM_DOORBELLS
};

/* DMA status */
#define HW_SIM_DMA_STATUS_DONE 0
#define HW_SIM_DMA_STATUS_FATAL_ERROR 1
#define HW_SIM_DMA_STATUS_NON_FATAL_ERROR 2

/* Scatter gather list is a physically contiguous array of data elements.
 * The first data element contains the number of data elements flowing it
 */

union sgl_data_element {
	/* first data element in the list */
	struct {
		u64 num_of_elements;
		/* Used for partial copy.
		 * Specify size to copy or MAX_SIZE for entire SGL
		 */
		size_t bytes_to_copy;
	};
	/* non first data element in the list */
	struct {
		dma_addr_t src;
		dma_addr_t dst;
		size_t size;
	};
};

int send_message(enum QUEUE_TYPE queue, u64 data);
void set_callback(enum QUEUE_TYPE queue, int (*cb)(u64 data));
void remove_callback(enum QUEUE_TYPE queue);

void post_dma_req_h2c(int channel_num,
		dma_addr_t src,
		dma_addr_t dest,
		size_t size);

void post_dma_req_c2h(int channel_num,
		dma_addr_t src,
		dma_addr_t dest,
		size_t size);

void post_dma_sgl_h2c(int channel_num,
		dma_addr_t sgl);

void post_dma_sgl_c2h(int channel_num,
		dma_addr_t sql);

void set_dma_channel_callback_h2c(int channel_num,
		int (*cb)(int channel_num, int status));

void set_dma_channel_callback_c2h(int channel_num,
		int (*cb)(int channel_num, int status));

void execute_dma_req(dma_addr_t src, dma_addr_t dest,  size_t size);

void set_doorbell_callback(enum DOORBELL_TYPE db,
			   void (*cb)(u32 value));
u32 get_doorbell_value(enum DOORBELL_TYPE db);
void set_doorbell_value(enum DOORBELL_TYPE db, u32 val);

struct device *get_ep_device(void);
