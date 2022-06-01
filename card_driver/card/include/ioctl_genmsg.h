/********************************************
 * Copyright (C) 2019-2021 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/
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
