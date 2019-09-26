/*******************************************************************************
 * INTEL CORPORATION CONFIDENTIAL Copyright(c) 2017-2019 Intel Corporation. All Rights Reserved.
 *
 * The source code contained or described herein and all documents related to the
 * source code ("Material") are owned by Intel Corporation or its suppliers or
 * licensors. Title to the Material remains with Intel Corporation or its suppliers
 * and licensors. The Material contains trade secrets and proprietary and
 * confidential information of Intel or its suppliers and licensors. The Material
 * is protected by worldwide copyright and trade secret laws and treaty provisions.
 * No part of the Material may be used, copied, reproduced, modified, published,
 * uploaded, posted, transmitted, distributed, or disclosed in any way without
 * Intel's prior express written permission.
 *
 * No license under any patent, copyright, trade secret or other intellectual
 * property right is granted to or conferred upon you by disclosure or delivery of
 * the Materials, either expressly, by implication, inducement, estoppel or
 * otherwise. Any license under such intellectual property rights must be express
 * and approved by Intel in writing.
 ********************************************************************************/
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
