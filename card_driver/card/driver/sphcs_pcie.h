/********************************************
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#ifndef _SPHCS_PCIE_H
#define _SPHCS_PCIE_H

#include <sph_types.h>
#include <linux/scatterlist.h>

struct device;
struct sphcs;
struct sphcs_dma_sched;

struct sphcs_dma_hw_ops {
	/* called on error recovery */
	void (*reset_rd_dma_engine)(void *hw_handle);
	void (*reset_wr_dma_engine)(void *hw_handle);
	/* called once on start up*/
	int (*init_dma_engine)(void *hw_handle);
	u32 (*calc_lli_size)(void *hw_handle, struct sg_table *src, struct sg_table *dst, uint64_t dst_offset);
	u64 (*gen_lli)(void *hw_handle, struct sg_table *src, struct sg_table *dst, void *outLli, uint64_t dst_offset);
	int (*edit_lli)(void *hw_handle, void *outLli, uint32_t size);
	int (*start_xfer_h2c)(void *hw_handle, int channel, u32 priority, dma_addr_t lli_addr);
	int (*start_xfer_c2h)(void *hw_handle, int channel, u32 priority, dma_addr_t lli_addr);
	int (*start_xfer_h2c_single)(void *hw_handle, int channel, u32 priority, dma_addr_t src, dma_addr_t dst, u32 size);
	int (*start_xfer_c2h_single)(void *hw_handle, int channel, u32 priority, dma_addr_t src, dma_addr_t dst, u32 size);
	int (*xfer_c2h_single)(void *hw_handle, dma_addr_t src, dma_addr_t dst, u32 size, u32 timeout_ms, int *status, u32 *time_us);

};

struct sphcs_dma_hw_callbacks {
	int (*h2c_xfer_complete_int)(struct sphcs_dma_sched *dmaSched, int channel, int status, int recovery_action, u32 timeUS);
	int (*c2h_xfer_complete_int)(struct sphcs_dma_sched *dmaSched, int channel, int status, int recovery_action, u32 timeUS);
};

struct sphcs_pcie_hw_ops {
	int (*write_mesg)(void *hw_handle, u64 *msg, u32 size);
	u32 (*get_host_doorbell_value)(void *hw_handle);
	int (*set_card_doorbell_value)(void *hw_handle, u32 value);
	int (*map_inbound_mem)(void      *hw_handle,
			       dma_addr_t host_address,
			       dma_addr_t target_address,
			       uint64_t   size);

	struct sphcs_dma_hw_ops dma;
};

struct sphcs_pcie_callbacks {
	int (*create_sphcs)(void                           *hw_handle,
			    struct device                  *hw_device,
			    const struct sphcs_pcie_hw_ops *hw_ops,
			    struct sphcs                  **out_sphcs,
			    struct sphcs_dma_sched        **out_dmaSched);

	void (*host_doorbell_value_changed)(struct sphcs *sphcs,
					    u32           doorbell_value);

	int (*destroy_sphcs)(struct sphcs *sphcs);

	int (*process_messages)(struct sphcs *sphcs,
				u64          *msg,
				u32          size);


	struct sphcs_dma_hw_callbacks dma;
};

/* recovery action required */
#define SPHCS_RA_NONE BIT(0)
#define SPHCS_RA_RETRY_DMA BIT(1)
#define SPHCS_RA_RESET_DMA BIT(2)

/* DMA status */
#define SPHCS_DMA_STATUS_DONE BIT(0)
#define SPHCS_DMA_STATUS_FAILED BIT(1)

#define SPHCS_DMA_HW_PRIORITY_LOW    1
#define SPHCS_DMA_HW_PRIORITY_MEDIUM 2
#define SPHCS_DMA_HW_PRIORITY_HIGH   4
#define SPHCS_DMA_PRIORITY_FACTOR 4

int sphcs_hw_init(struct sphcs_pcie_callbacks *callbacks);
int sphcs_hw_cleanup(void);

#endif
