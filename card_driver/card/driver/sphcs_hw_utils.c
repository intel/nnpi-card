/********************************************
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/
#include <linux/scatterlist.h>
#include "sphcs_pcie.h"
#include "sph_log.h"
#include "sph_local.h"
#include "sph_debug.h"
#include "sphcs_hw_utils.h"

u32 dma_calc_and_gen_lli(struct sg_table *srcSgt,
		struct sg_table *dstSgt,
		void *lliPtr,
		uint64_t dst_offset,
		void *(*set_data_elem)(void *sgl, dma_addr_t src, dma_addr_t dst, uint32_t size),
		uint32_t *transfer_size)
{
	u32 num_of_elements = 0;
	void *lliBuf = lliPtr;
	struct scatterlist *next_srcSgl = srcSgt->sgl;
	struct scatterlist *next_dstSgl = dstSgt->sgl;
	unsigned int curr_dst_offset;
	struct region {
		dma_addr_t   dma_address;
		unsigned int length;
	} src_reg = {0}, dst_reg = {0};

	if (transfer_size)
		*transfer_size = 0;

	src_reg.length = 0;
	dst_reg.length = 0;

	/* setup first dst region according to dst_offset */
	if (dst_offset > 0) {
		curr_dst_offset = 0;
		while (next_dstSgl &&
		       curr_dst_offset + next_dstSgl->length < dst_offset) {
			curr_dst_offset += next_dstSgl->length;
			next_dstSgl = sg_next(next_dstSgl);
		}

		/* done if dst_offset is larger than dst sg_table size */
		if (!next_dstSgl)
			return 0;

		dst_reg.dma_address = next_dstSgl->dma_address +
				      (dst_offset - curr_dst_offset);
		dst_reg.length = next_dstSgl->length -
				 (dst_offset - curr_dst_offset);
		next_dstSgl = sg_next(next_dstSgl);
	}

	/* loop over sg tables and generate data elements until
	 * the end of one of the sg tables (src or dst).
	 */
	do {
		/* setup next src region if current is at end */
		if (src_reg.length == 0) {
			if (!next_srcSgl)
				break;

			src_reg.dma_address = next_srcSgl->dma_address;
			src_reg.length = next_srcSgl->length;
			next_srcSgl = sg_next(next_srcSgl);

			/* try to join adjucent regions */
			while (next_srcSgl != NULL &&
			       next_srcSgl->dma_address ==
			       src_reg.dma_address + src_reg.length) {
				src_reg.length += next_srcSgl->length;
				next_srcSgl = sg_next(next_srcSgl);
			}
		}

		/* setup next dst region if current is at end */
		if (dst_reg.length == 0) {
			if (!next_dstSgl)
				break;

			dst_reg.dma_address = next_dstSgl->dma_address;
			dst_reg.length = next_dstSgl->length;
			next_dstSgl = sg_next(next_dstSgl);

			/* try to join adjucent regions */
			while (next_dstSgl != NULL &&
			       next_dstSgl->dma_address ==
			       dst_reg.dma_address + dst_reg.length) {
				dst_reg.length += next_dstSgl->length;
				next_dstSgl = sg_next(next_dstSgl);
			}
		}

		/* build next data element from the smaller chunk */
		num_of_elements++;
		if (src_reg.length < dst_reg.length) {
			if (lliBuf)
				lliBuf = set_data_elem(lliBuf,
						       src_reg.dma_address,
						       dst_reg.dma_address,
						       src_reg.length);
			if (transfer_size)
				*transfer_size += src_reg.length;
			dst_reg.dma_address += src_reg.length;
			dst_reg.length -= src_reg.length;
			src_reg.length = 0;
		} else {
			if (lliBuf)
				lliBuf = set_data_elem(lliBuf,
						       src_reg.dma_address,
						       dst_reg.dma_address,
						       dst_reg.length);
			if (transfer_size)
				*transfer_size += dst_reg.length;
			src_reg.dma_address += dst_reg.length;
			src_reg.length -= dst_reg.length;
			dst_reg.length = 0;
		}
	} while (1);

	return num_of_elements;
}
