/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#include <linux/module.h>
#include <linux/pci.h>
#include <linux/scatterlist.h>
#include "sphcs_pcie.h"
#include "sph_log.h"
#include "nnp_local.h"
#include "nnp_debug.h"
#include "sphcs_hw_utils.h"

struct hw_sim_descriptor {
	struct device *dev;
	int (*send_message_p)(enum QUEUE_TYPE queue, u64 data);
	void (*set_callback_p)(enum QUEUE_TYPE queue, int (*cb)(u64 data));
	void (*remove_callback_p)(enum QUEUE_TYPE queue);

	void (*post_dma_req_h2c_p)(int channel_num,
			dma_addr_t src,
			dma_addr_t dest,
			size_t size);

	void (*post_dma_req_c2h_p)(int channel_num,
			dma_addr_t src,
			dma_addr_t dest,
			size_t size);

	void (*post_dma_sgl_h2c_p)(int channel_num,
			dma_addr_t sgl);

	void (*post_dma_sgl_c2h_p)(int channel_num,
			dma_addr_t sql);

	void (*set_dma_channel_callback_h2c_p)(int channel_num,
			int (*cb)(int channel_num, int status));

	void (*set_dma_channel_callback_c2h_p)(int channel_num,
			int (*cb)(int channel_num, int status));

	void (*execute_dma_req_p)(dma_addr_t src, dma_addr_t dest,  size_t size);

	struct device* (*get_ep_device_p)(void);

	void (*set_doorbell_callback_p)(enum DOORBELL_TYPE db,
					void (*cb)(u32 value));
	u32 (*get_doorbell_value_p)(enum DOORBELL_TYPE db);
	void (*set_doorbell_value_p)(enum DOORBELL_TYPE db, u32 val);

	struct sphcs *sphcs;
	struct sphcs_dma_sched *dma_sched;
} hw_sim_descriptor;

static struct sphcs_pcie_callbacks *s_callbacks;

static int hw_sim_write_mesg(void *hw_handle, u64 *msg, u32 size)
{
	u32 i;

	for (i = 0; i < size; i++)
		hw_sim_descriptor.send_message_p(QUEUE_C2H, msg[i]);

	return 0;
}

static int hw_sim_init_dma_engine(void *hw_handle)
{
	return 0;
}

static void hw_sim_reset_rd_dma_engine(void *hw_handle)
{

}

static void hw_sim_reset_wr_dma_engine(void *hw_handle)
{

}

static void *dma_set_lli_data_element(void *sgl, dma_addr_t src, dma_addr_t dst, uint32_t size)
{
	union sgl_data_element *current_data_element = (union sgl_data_element *)sgl;

	current_data_element->size = size;
	current_data_element->src = src;
	current_data_element->dst = dst;

	return (sgl + sizeof(union sgl_data_element));
}

static int hw_sim_dma_init_lli(void *hw_handle, struct lli_desc *outLli, struct sg_table *src, struct sg_table *dst, uint64_t dst_offset, bool single_list)
{
	outLli->num_elements = dma_calc_and_gen_lli(src, dst, NULL, dst_offset, 0, NULL, NULL);
	outLli->num_filled = 0;
	outLli->num_lists = 1;
	outLli->offsets[0] = 0;
	outLli->size = (outLli->num_elements + 1) * sizeof(union sgl_data_element);
	return 0;
}

static u64 hw_sim_dma_gen_lli(void *hw_handle, struct sg_table *src, struct sg_table *dst, struct lli_desc *outLli, uint64_t dst_offset)
{
	u32 num_of_elements;
	uint64_t transfer_size = 0;
	union sgl_data_element *current_data_element;
	union sgl_data_element *header;

	if (hw_handle == NULL || src == NULL || dst == NULL || outLli == NULL)
		return -1;

	if (outLli->vptr == NULL)
		return -1;

	header = (union sgl_data_element *)outLli->vptr;
	current_data_element = header + 1;

	/* Fill SGL */
	num_of_elements = dma_calc_and_gen_lli(src, dst, current_data_element, dst_offset, 0, dma_set_lli_data_element, &transfer_size);

	/* Set header */
	header->num_of_elements = num_of_elements;
	header->bytes_to_copy = SIZE_MAX;

	outLli->xfer_size[0] = transfer_size;

	return transfer_size;
}

static int hw_sim_dma_init_lli_vec(void *hw_handle, struct lli_desc *outLli, uint64_t dst_offset, genlli_get_next_cb cb, void *cb_ctx)
{
	struct sg_table *src;
	struct sg_table *dst;
	u64              max_size;
	u32              nelem = 0;

	if (hw_handle == NULL || cb == NULL || outLli == NULL)
		return -EINVAL;

	while ((*cb)(cb_ctx, &src, &dst, &max_size)) {
		nelem += dma_calc_and_gen_lli(src, dst, NULL, dst_offset, max_size, NULL, NULL);
		dst_offset = 0;
	}

	outLli->num_elements = nelem;
	outLli->num_filled = 0;
	outLli->num_lists = 1;
	outLli->offsets[0] = 0;
	outLli->size = (outLli->num_elements + 1) * sizeof(union sgl_data_element);

	return 0;
}

static u64 hw_sim_dma_gen_lli_vec(void *hw_handle, struct lli_desc *outLli, uint64_t dst_offset, genlli_get_next_cb cb, void *cb_ctx)
{
	struct sg_table *src;
	struct sg_table *dst;
	u64              max_size;
	u32 num_of_elements;
	u32 nelem = 0;
	uint64_t transfer_size = 0;
	uint64_t total_transfer_size = 0;
	union sgl_data_element *current_data_element;
	union sgl_data_element *header;

	if (hw_handle == NULL || outLli == NULL || cb == NULL)
		return -1;

	if (outLli->vptr == NULL)
		return -1;

	header = (union sgl_data_element *)outLli->vptr;
	current_data_element = header + 1;

	/* Fill SGL */
	while ((*cb)(cb_ctx, &src, &dst, &max_size)) {
		num_of_elements = dma_calc_and_gen_lli(src, dst, current_data_element, dst_offset, max_size, dma_set_lli_data_element, &transfer_size);
		dst_offset = 0;
		current_data_element += num_of_elements;
		nelem += num_of_elements;
		total_transfer_size += transfer_size;
	}

	/* Set header */
	header->num_of_elements = nelem;
	header->bytes_to_copy = SIZE_MAX;

	outLli->xfer_size[0] = total_transfer_size;

	return total_transfer_size;
}

static int hw_sim_dma_edit_lli(void *hw_handle, struct lli_desc *outLli, uint32_t size)
{
	/* Set header */
	((union sgl_data_element *)outLli->vptr)->bytes_to_copy = (size > 0) ? size : SIZE_MAX;

	return 0;
}

static int hw_sim_dma_start_xfer_h2c(void *hw_handle, int channel, u32 priority, dma_addr_t lli_addr)
{
	hw_sim_descriptor.post_dma_sgl_h2c_p(channel, lli_addr);
	return 0;
}

static int hw_sim_dma_start_xfer_c2h(void *hw_handle, int channel, u32 priority, dma_addr_t lli_addr)
{
	hw_sim_descriptor.post_dma_sgl_c2h_p(channel, lli_addr);
	return 0;
}

static int hw_sim_dma_start_xfer_h2c_single(void *hw_handle, int channel, u32 priority, dma_addr_t src, dma_addr_t dst, u32 size)
{
	hw_sim_descriptor.post_dma_req_h2c_p(channel, src, dst, size);
	return 0;
}

static int hw_sim_dma_start_xfer_c2h_single(void *hw_handle, int channel, u32 priority, dma_addr_t src, dma_addr_t dst, u32 size)
{
	hw_sim_descriptor.post_dma_req_c2h_p(channel, src, dst, size);
	return 0;
}

int hw_sim_dma_xfer_c2h_single(void *hw_handle, dma_addr_t src, dma_addr_t dst, u32 size, u32 timeout_ms, int *status, u32 *time_us)
{
	hw_sim_descriptor.execute_dma_req_p(src, dst, size);

	*status = SPHCS_DMA_STATUS_DONE;
	*time_us = 0;

	return 0;
}

static u32 hw_sim_get_host_doorbell_value(void *hw_handle)
{
	return hw_sim_descriptor.get_doorbell_value_p(PCI_HOST);
}

static int hw_sim_set_card_doorbell_value(void *hw_handle, u32 value)
{
	hw_sim_descriptor.set_doorbell_value_p(HOST_PCI, value);
	return 0;
}

static struct sphcs_pcie_hw_ops s_hw_sim_ops = {
	.write_mesg = hw_sim_write_mesg,
	.get_host_doorbell_value = hw_sim_get_host_doorbell_value,
	.set_card_doorbell_value = hw_sim_set_card_doorbell_value,

	.dma.reset_rd_dma_engine = hw_sim_reset_rd_dma_engine,
	.dma.reset_wr_dma_engine = hw_sim_reset_wr_dma_engine,
	.dma.init_dma_engine = hw_sim_init_dma_engine,
	.dma.init_lli = hw_sim_dma_init_lli,
	.dma.gen_lli = hw_sim_dma_gen_lli,
	.dma.edit_lli = hw_sim_dma_edit_lli,
	.dma.init_lli_vec = hw_sim_dma_init_lli_vec,
	.dma.gen_lli_vec = hw_sim_dma_gen_lli_vec,
	.dma.start_xfer_h2c = hw_sim_dma_start_xfer_h2c,
	.dma.start_xfer_c2h = hw_sim_dma_start_xfer_c2h,
	.dma.start_xfer_h2c_single = hw_sim_dma_start_xfer_h2c_single,
	.dma.start_xfer_c2h_single = hw_sim_dma_start_xfer_c2h_single,
	.dma.xfer_c2h_single = hw_sim_dma_xfer_c2h_single
};

static int h2c_cb(u64 data)
{

	s_callbacks->process_messages(hw_sim_descriptor.sphcs, &data, 1);
	return 0;
};

static int h2c_dma_cb(int channel, int status)
{
	s_callbacks->dma.h2c_xfer_complete_int(hw_sim_descriptor.dma_sched,
			channel,
			(status == HW_SIM_DMA_STATUS_DONE) ? SPHCS_DMA_STATUS_DONE : SPHCS_DMA_STATUS_FAILED,
			(status == HW_SIM_DMA_STATUS_DONE) ? SPHCS_RA_NONE :
					(status == HW_SIM_DMA_STATUS_NON_FATAL_ERROR) ?
							SPHCS_RA_RETRY_DMA : SPHCS_RA_RESET_DMA,
			0);
	return 0;
};

static int c2h_dma_cb(int channel, int status)
{

	s_callbacks->dma.c2h_xfer_complete_int(hw_sim_descriptor.dma_sched,
			channel,
			(status == HW_SIM_DMA_STATUS_DONE) ? SPHCS_DMA_STATUS_DONE : SPHCS_DMA_STATUS_FAILED,
			(status == HW_SIM_DMA_STATUS_DONE) ? SPHCS_RA_NONE :
					(status == HW_SIM_DMA_STATUS_NON_FATAL_ERROR) ?
							SPHCS_RA_RETRY_DMA : SPHCS_RA_RESET_DMA,
			0);
	return 0;
};

static void doorbell_cb(u32 value)
{
	s_callbacks->host_doorbell_value_changed(hw_sim_descriptor.sphcs,
						 value);
}

int sphcs_hw_init(struct sphcs_pcie_callbacks *callbacks)
{
	int i;

	hw_sim_descriptor.send_message_p = symbol_request(send_message);
	hw_sim_descriptor.set_callback_p = symbol_request(set_callback);
	hw_sim_descriptor.remove_callback_p = symbol_request(remove_callback);

	hw_sim_descriptor.post_dma_req_h2c_p = symbol_request(post_dma_req_h2c);
	hw_sim_descriptor.post_dma_req_c2h_p = symbol_request(post_dma_req_c2h);
	hw_sim_descriptor.post_dma_sgl_h2c_p = symbol_request(post_dma_sgl_h2c);
	hw_sim_descriptor.post_dma_sgl_c2h_p = symbol_request(post_dma_sgl_c2h);
	hw_sim_descriptor.set_dma_channel_callback_h2c_p = symbol_request(set_dma_channel_callback_h2c);
	hw_sim_descriptor.set_dma_channel_callback_c2h_p = symbol_request(set_dma_channel_callback_c2h);
	hw_sim_descriptor.execute_dma_req_p = symbol_request(execute_dma_req);
	hw_sim_descriptor.get_ep_device_p = symbol_request(get_ep_device);
	hw_sim_descriptor.set_doorbell_callback_p = symbol_request(set_doorbell_callback);
	hw_sim_descriptor.get_doorbell_value_p = symbol_request(get_doorbell_value);
	hw_sim_descriptor.set_doorbell_value_p = symbol_request(set_doorbell_value);
	hw_sim_descriptor.dev = hw_sim_descriptor.get_ep_device_p();

	s_callbacks = callbacks;

	for (i = 0; i < NUM_H2C_CHANNELS; i++)
		hw_sim_descriptor.set_dma_channel_callback_h2c_p(i, h2c_dma_cb);
	for (i = 0; i < NUM_C2H_CHANNELS; i++)
		hw_sim_descriptor.set_dma_channel_callback_c2h_p(i, c2h_dma_cb);

	hw_sim_descriptor.set_doorbell_callback_p(PCI_HOST, doorbell_cb);

	s_callbacks->create_sphcs(&hw_sim_descriptor,
			hw_sim_descriptor.dev,
			&s_hw_sim_ops,
			&hw_sim_descriptor.sphcs,
			&hw_sim_descriptor.dma_sched);

	hw_sim_descriptor.set_callback_p(QUEUE_H2C, h2c_cb);

	/* update sphcs with current host doorbell value */
	s_callbacks->host_doorbell_value_changed(hw_sim_descriptor.sphcs,
						 hw_sim_descriptor.get_doorbell_value_p(PCI_HOST));

	return 0;
}

int sphcs_hw_cleanup(void)
{
	hw_sim_descriptor.remove_callback_p(QUEUE_H2C);
	hw_sim_descriptor.set_doorbell_callback_p(PCI_HOST, NULL);

	s_callbacks->destroy_sphcs(hw_sim_descriptor.sphcs);

	symbol_put(send_message);
	symbol_put(set_callback);
	symbol_put(remove_callback);

	symbol_put(post_dma_req_h2c);
	symbol_put(post_dma_req_c2h);
	symbol_put(post_dma_sgl_h2c);
	symbol_put(post_dma_sgl_c2h);
	symbol_put(set_dma_channel_callback_h2c);
	symbol_put(set_dma_channel_callback_c2h);
	symbol_put(execute_dma_req);
	symbol_put(set_doorbell_callback);
	symbol_put(get_doorbell_value);
	symbol_put(set_doorbell_value);
	symbol_put(get_ep_device);

	return 0;
}

