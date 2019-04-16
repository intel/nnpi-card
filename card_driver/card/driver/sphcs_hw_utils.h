/********************************************
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#ifndef SRC_DRIVER_CARD_SPHCS_HW_UTILS_H_
#define SRC_DRIVER_CARD_SPHCS_HW_UTILS_H_

u32 dma_calc_and_gen_lli(struct sg_table *srcSgt,
		struct sg_table *dstSgt,
		void *lliPtr,
		uint64_t dst_offset,
		void *(*set_data_elem)(void *sgl, dma_addr_t src, dma_addr_t dst, uint32_t size),
		uint32_t *transfer_size);

#endif /* SRC_DRIVER_CARD_SPHCS_HW_UTILS_H_ */
