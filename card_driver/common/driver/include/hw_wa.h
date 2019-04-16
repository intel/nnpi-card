//
// INTEL CORPORATION CONFIDENTIAL Copyright(c) 2019 Intel Corporation. All Rights Reserved.
//

// FIFO_RTL_WA - use "new" HAS FIFO description (that matches RTL)
#define FIFO_RTL_WA

// Disable use of C2H DMA channel 1 due since it getting hang after FLR reset.
#define DMA_DISABLE_C2H_CHANNEL_1_WA
