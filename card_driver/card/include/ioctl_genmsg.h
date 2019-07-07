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
#ifndef _SPHCS_IOCTL_GENMSG_H
#define _SPHCS_IOCTL_GENMSG_H

#include <linux/ioctl.h>
#ifndef __KERNEL__
#include <stdint.h>
#else
#include <linux/types.h>
#endif

#define SPHCS_GENMSG_DEV_NAME "sphcs_genmsg"

#define IOCTL_GENMSG_REGISTER_SERVICE	_IOW('G', 0, struct ioctl_register_service)
#define IOCTL_GENMSG_ACCEPT_CLIENT	_IOR('G', 1, int)
#define IOCTL_GENMSG_WRITE_RESPONSE_WAIT _IO('G', 2)
#define IOCTL_GENMSG_IS_PRIVILEGED      _IOR('G', 3, int)

struct ioctl_register_service {
	uint32_t name_len;
};

#endif
