/********************************************
 * Copyright (C) 2019-2021 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/
#ifndef _SPHCS_DMA_SCHED_H
#define _SPHCS_DMA_SCHED_H

#include "sphcs_pcie.h"
#include <linux/atomic.h>
#include <linux/debugfs.h>

struct sphcs_dma_sched;
struct sphcs;

/*
 * IMPORTANT: Upon adding new priority codes, make sure that
 * SPHCS_DMA_PRIORITY_MAX stays equal to the last priority code.
 */
enum sphcs_dma_priority_request {
	SPHCS_DMA_PRIORITY_HIGH = 0,
	SPHCS_DMA_PRIORITY_NORMAL,
	SPHCS_DMA_PRIORITY_LOW,
	SPHCS_DMA_PRIORITY_DTF,
	SPHCS_DMA_PRIORITY_MAX = SPHCS_DMA_PRIORITY_DTF
};

#define SPHCS_DMA_NUM_PRIORITIES (SPHCS_DMA_PRIORITY_MAX+1)

enum sphcs_dma_direction {
	SPHCS_DMA_DIRECTION_CARD_TO_HOST,
	SPHCS_DMA_DIRECTION_HOST_TO_CARD,
	SPHCS_DMA_NUM_DIRECTIONS
};

struct sphcs_dma_desc {
	enum sphcs_dma_direction        dma_direction;
	enum sphcs_dma_priority_request dma_priority;
	u32                             serial_channel;
	u32                             flags;
};

/*
 * pre-defined global dma_desc structs which are commonly
 * used.
 */
extern const struct sphcs_dma_desc g_dma_desc_h2c_low;
extern const struct sphcs_dma_desc g_dma_desc_h2c_low_nowait;
extern const struct sphcs_dma_desc g_dma_desc_h2c_normal;
extern const struct sphcs_dma_desc g_dma_desc_h2c_normal_nowait;
extern const struct sphcs_dma_desc g_dma_desc_h2c_high;
extern const struct sphcs_dma_desc g_dma_desc_h2c_high_nowait;
extern const struct sphcs_dma_desc g_dma_desc_c2h_low;
extern const struct sphcs_dma_desc g_dma_desc_c2h_low_nowait;
extern const struct sphcs_dma_desc g_dma_desc_c2h_normal;
extern const struct sphcs_dma_desc g_dma_desc_c2h_normal_nowait;
extern const struct sphcs_dma_desc g_dma_desc_c2h_high;
extern const struct sphcs_dma_desc g_dma_desc_c2h_high_nowait;

/* u32 flaf for sphcs_dma_sched_start_xfer_single */
#define SPHCS_DMA_START_XFER_COMPLETION_NO_WAIT 0x00000001 /* response for completion handler return immidiatly on completion */

typedef int (*sphcs_dma_sched_completion_callback)(struct sphcs *sphcs,
						   void *ctx,
						   const void *user_data,
						   int status,
						   u32 xferTimeUS);

struct sphcs_dma_multi_xfer_handle {
	atomic_t num_xfers;
	atomic_t num_inflight;
	int status;
	sphcs_dma_sched_completion_callback cb;
	void                               *cb_ctx;
};

static inline enum sphcs_dma_direction sph_dma_direction(bool card2host)
{
	return card2host ? SPHCS_DMA_DIRECTION_CARD_TO_HOST : SPHCS_DMA_DIRECTION_HOST_TO_CARD;
}

static inline enum sphcs_dma_priority_request sph_dma_priority(uint8_t protocol_priority)
{
	if (protocol_priority != 0)
		return SPHCS_DMA_PRIORITY_HIGH;
	else
		return SPHCS_DMA_PRIORITY_NORMAL;
}

int sphcs_dma_sched_create(struct sphcs *sphcs,
			   const struct sphcs_dma_hw_ops *hw_ops,
			   void *hw_handle,
			   struct sphcs_dma_sched **out_dmaSched);

void sphcs_dma_sched_init_debugfs(struct sphcs_dma_sched *dmaSched,
				  struct dentry          *parent,
				  const char             *dirname);

void sphcs_dma_sched_destroy(struct sphcs_dma_sched *dmaSched);

u32 sphcs_dma_sched_create_serial_channel(struct sphcs_dma_sched *dmaSched);

int sphcs_dma_sched_reserve_channel_for_dtf(struct sphcs_dma_sched *dmaSched,
					   bool lock_dtf_channel);

int sphcs_dma_sched_update_priority(struct sphcs_dma_sched      *dmaSched,
				    enum sphcs_dma_direction    direction,
				    enum sphcs_dma_priority_request src_priority,
				    enum sphcs_dma_priority_request dst_priority,
				    dma_addr_t                   req_src);

int sphcs_dma_sched_start_xfer_single(struct sphcs_dma_sched *dmaSched,
				      const struct sphcs_dma_desc *desc,
				      dma_addr_t src,
				      dma_addr_t dst,
				      u32 size,
				      sphcs_dma_sched_completion_callback callback,
				      void *callback_ctx,
				      const void *user_data,
				      u32 user_data_size);

void sphcs_dma_multi_xfer_handle_init(struct sphcs_dma_multi_xfer_handle *handle);

int sphcs_dma_sched_start_xfer_multi(struct sphcs_dma_sched      *dmaSched,
				     struct sphcs_dma_multi_xfer_handle *handle,
				     const struct sphcs_dma_desc *desc,
				     struct lli_desc             *lli,
				     uint64_t                     transfer_size,
				     sphcs_dma_sched_completion_callback callback,
				     void                        *callback_ctx);

int sphcs_dma_sched_h2c_xfer_complete_int(struct sphcs_dma_sched *dmaSched,
					  int channel,
					  int status,
					  int recovery_action,
					  u32 xferTimeUS);

int sphcs_dma_sched_c2h_xfer_complete_int(struct sphcs_dma_sched *dmaSched,
					  int channel,
					  int status,
					  int recovery_action,
					  u32 xferTimeUS);

int sphcs_dma_sched_stop_and_xfer(struct sphcs_dma_sched *dmaSched,
				      dma_addr_t src,
				      dma_addr_t dst,
				      u32 size,
				      int *dma_status,
				      u32 *time_us);

#endif
