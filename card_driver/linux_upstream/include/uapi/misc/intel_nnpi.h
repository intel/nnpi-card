/* SPDX-License-Identifier: GPL-2.0-or-later WITH Linux-syscall-note */

/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 ********************************************/
#ifndef _NNP_UAPI_H
#define _NNP_UAPI_H

#include <linux/ioctl.h>
#include <stdbool.h>
#ifndef __KERNEL__
#include <stdint.h>
#else
#include <linux/types.h>
#endif

#define NNPDRV_INF_HOST_DEV_NAME "nnpi_host"
#define NNPI_IOCTL_INTERFACE_VERSION 0x00010100

/*
 * ioctls for /dev/nnpi_host device
 */
#define IOCTL_INF_CREATE_HOST_RESOURCE      \
	_IOWR('h', 0, struct nnpdrv_ioctl_create_hostres)

#define IOCTL_INF_DESTROY_HOST_RESOURCE     \
	_IOWR('h', 2, struct nnpdrv_ioctl_destroy_hostres)

#define IOCTL_INF_LOCK_HOST_RESOURCE        \
	_IOWR('h', 3, struct nnpdrv_ioctl_lock_hostres)

#define IOCTL_INF_UNLOCK_HOST_RESOURCE      \
	_IOWR('h', 4, struct nnpdrv_ioctl_lock_hostres)

/* Resource usage_flags bits */
#define IOCTL_INF_RES_INPUT          1
#define IOCTL_INF_RES_OUTPUT         2
#define IOCTL_INF_RES_NETWORK        4
#define IOCTL_INF_RES_FORCE_4G_ALLOC 8
#define IOCTL_INF_RES_ECC            16
#define IOCTL_INF_RES_P2P_DST        32
#define IOCTL_INF_RES_P2P_SRC        64

struct nnpdrv_ioctl_create_hostres {
	__u64 byte_size;
	__u32 dma_buf;
	__u32 usage_flags;
	__u64 user_handle;
	__u32 version;
	__u8  o_errno;
};

struct nnpdrv_ioctl_lock_hostres {
	__u64 user_handle;
	__u32 timeout_us;
	__u8  o_errno;
};

struct nnpdrv_ioctl_destroy_hostres {
	__u64 user_handle;
	__u8  o_errno;
};

/*
 * ioctls for /dev/nnpi%d device
 */
#define NNPI_DEVICE_DEV_FMT "nnpi%u"
#define IOCTL_NNPI_DEVICE_CREATE_CHANNEL      \
	_IOWR('D', 0, struct ioctl_nnpi_create_channel)

#define IOCTL_NNPI_DEVICE_CREATE_CHANNEL_RB   \
	_IOWR('D', 1, struct ioctl_nnpi_create_channel_data_ringbuf)

#define IOCTL_NNPI_DEVICE_DESTROY_CHANNEL_RB  \
	_IOWR('D', 2, struct ioctl_nnpi_destroy_channel_data_ringbuf)

#define IOCTL_NNPI_DEVICE_CHANNEL_MAP_HOSTRES \
	_IOWR('D', 3, struct ioctl_nnpi_channel_map_hostres)

#define IOCTL_NNPI_DEVICE_CHANNEL_UNMAP_HOSTRES \
	_IOWR('D', 4, struct ioctl_nnpi_channel_unmap_hostres)

struct ioctl_nnpi_create_channel {
	__u32 i_weight;
	s32      i_host_fd;
	s32      i_min_id;
	s32      i_max_id;
	s32      i_get_device_events;
	__u32 i_version;
	__u16 i_protocol_version;
	s32      o_fd;
	__u16 o_channel_id;
	s32      o_privileged;
	__u8  o_errno;
};

struct ioctl_nnpi_create_channel_data_ringbuf {
	__u16 i_channel_id;
	__u8  i_id;
	__u8  i_h2c;
	__u64 i_hostres_handle;
	__u8  o_errno;
};

struct ioctl_nnpi_destroy_channel_data_ringbuf {
	__u16 i_channel_id;
	__u8  i_id;
	__u8  i_h2c;
	__u8  o_errno;
};

struct ioctl_nnpi_channel_map_hostres {
	__u16 i_channel_id;
	__u64 i_hostres_handle;
	__u16 o_map_id;
	__u8  o_sync_needed;
	__u8  o_errno;
};

struct ioctl_nnpi_channel_unmap_hostres {
	__u16 i_channel_id;
	__u16 i_map_id;
	__u8  o_errno;
};

/****************************************************************
 * Error code values - errors returned in o_errno fields of
 * above structures may be base linux errno values as well as
 * the below error codes.
 ****************************************************************/
#define	NNP_ERRNO_BASE	                        200
#define	NNPER_DEVICE_NOT_READY			(NNP_ERRNO_BASE + 1)
#define	NNPER_NO_SUCH_RESOURCE			(NNP_ERRNO_BASE + 2)
#define	NNPER_INCOMPATIBLE_RESOURCES		(NNP_ERRNO_BASE + 3)
#define	NNPER_DEVICE_ERROR			(NNP_ERRNO_BASE + 4)
#define NNPER_NO_SUCH_CHANNEL                   (NNP_ERRNO_BASE + 5)
#define NNPER_NO_SUCH_HOSTRES_MAP               (NNP_ERRNO_BASE + 6)
#define NNPER_VERSIONS_MISMATCH                 (NNP_ERRNO_BASE + 7)

#endif /* of _NNP_UAPI_H */
