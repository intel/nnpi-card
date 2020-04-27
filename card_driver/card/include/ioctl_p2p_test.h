/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/
#ifndef _SPHCS_IOCTL_P2P_TEST_H
#define _SPHCS_IOCTL_P2P_TEST_H

#include <linux/ioctl.h>
#include <linux/types.h>

struct ioctl_p2p_test_dma {
	__u64 peer_buf_host_addr;
	__u32 peer_buf_size;
	__u64 user_buffer;
};

#define IOCTL_P2P_DMA_WR _IOW('H', 0, struct ioctl_p2p_test_dma)
#define IOCTL_P2P_DMA_RD _IOW('H', 1, struct ioctl_p2p_test_dma)


#endif
