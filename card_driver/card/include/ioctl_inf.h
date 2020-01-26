



/*******************************************************************************
 * INTEL CORPORATION CONFIDENTIAL Copyright(c) 2017-2020 Intel Corporation. All Rights Reserved.
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
#ifndef _SPHCS_IOCTL_INF_H
#define _SPHCS_IOCTL_INF_H

#include <linux/ioctl.h>
#ifndef __KERNEL__
#include <stdint.h>
#else
#include <linux/types.h>
#endif

#define SPHCS_INF_DEV_NAME "sphcs_inf"

/*
 * IOCTL codes
 */
#define IOCTL_INF_ATTACH_DAEMON            _IO('I', 0)
#define IOCTL_INF_ATTACH_CONTEXT          _IOW('I', 1, uint32_t)
#define IOCTL_INF_ERROR_EVENT             _IOW('I', 2, struct inf_error_ioctl)
#define IOCTL_INF_RESOURCE_CREATE_REPLY   _IOW('I', 3, struct inf_create_resource_reply)
#define IOCTL_INF_NETWORK_CREATE_REPLY    _IOW('I', 4, struct inf_create_network_reply)
#define IOCTL_INF_INFREQ_CREATE_REPLY     _IOW('I', 5, struct inf_create_infreq_reply)
#define IOCTL_INF_INFREQ_EXEC_DONE        _IOW('I', 6, struct inf_infreq_exec_done)
#define IOCTL_INF_ALLOC_RESOURCE_REPLY    _IOW('I', 7, struct inf_alloc_resource_reply)
#define IOCTL_INF_DEVNET_RESOURCES_RESERVATION_REPLY _IOW('I', 8, struct inf_devnet_resource_reserve_reply)
#define IOCTL_INF_GET_ALLOC_PGT          _IOWR('I', 10, struct inf_get_alloc_pgt)
#define IOCTL_INF_DEVNET_RESET_REPLY      _IOW('I', 11, struct inf_devnet_reset_reply)
#ifdef ULT
#define IOCTL_INF_SWITCH_DAEMON            _IO('I', 9)
#endif

struct inf_error_ioctl {
	uint32_t errorCode;
	uint32_t errorVal;
};

/**
 * fix size struct for inference request config data
 * sizeof(inferRequestSchedParams) = sizeof(uint32_t),
 * equivalent to inferRequestSchedParams from runtime api
 */
struct inf_sched_params {
	uint16_t batchSize;
	uint8_t  priority; /* 0 == normal, 1 == high */
	uint8_t  debugOn : 1;
	uint8_t  collectInfo : 1;
	uint8_t  reserved : 6;
};

/* Max size of daemon command - including the header */
#define SPHCS_DAEMON_MAX_COMMAND_SIZE      64

/* Daemon/Runtime command opcodes */
#define SPHCS_CMD_EOF                       0
#define SPHCS_DAEMON_CMD_CREATE_CONTEXT     1
#define SPHCS_DAEMON_CMD_ALLOC_RESOURCE     2
#define SPHCS_DAEMON_CMD_FREE_RESOURCE      3
#define SPHCS_RUNTIME_CMD_CREATE_RESOURCE   4
#define SPHCS_RUNTIME_CMD_DESTROY_RESOURCE  5
#define SPHCS_RUNTIME_CMD_CREATE_NETWORK    6
#define SPHCS_RUNTIME_CMD_DESTROY_NETWORK   7
#define SPHCS_RUNTIME_CMD_CREATE_INFREQ     8
#define SPHCS_RUNTIME_CMD_EXECUTE_INFREQ    9
#define SPHCS_RUNTIME_CMD_DESTROY_INFREQ    10
#define SPHCS_RUNTIME_CMD_DEVNET_RESOURCES_RESERVATION  11
#define SPHCS_RUNTIME_CMD_DEVNET_RESET  12

/* IoctlSphcsError should be EQUAL to SphcsError!! */
typedef enum {
	IOCTL_SPHCS_NO_ERROR                          = 0,
	IOCTL_SPHCS_UNKNOWN_ERROR                     = 1,
	IOCTL_SPHCS_NO_CONTEXT                        = 2,
	IOCTL_SPHCS_CONTEXT_BUSY                      = 3,
	IOCTL_SPHCS_NO_DEVICE                         = 4,
	IOCTL_SPHCS_TIMED_OUT                         = 5,
	IOCTL_SPHCS_ALLOC_FAILED                      = 6,
	IOCTL_SPHCS_NOT_SUPPORTED                     = 7,
	IOCTL_SPHCS_INVALID_HANDLE                    = 8,
	IOCTL_SPHCS_INVALID_PARAMS                    = 9,
	IOCTL_SPHCS_INVALID_EXECUTABLE_NETWORK_BINARY = 10,
	IOCTL_SPHCS_INFER_MISSING_RESOURCE            = 11,
	IOCTL_SPHCS_INFER_EXEC_ERROR                  = 12,
	IOCTL_SPHCS_INFER_SCHEDULE_ERROR              = 13,
	IOCTL_SPHCS_NO_MEMORY                         = 14,
	IOCTL_SPHCS_INSUFFICIENT_RESOURCES            = 15,
	IOCTL_SPHCS_ECC_ALLOC_FAILED                  = 16,
	IOCTL_SPHCS_FILE_WAS_NOT_FOUND                = 17,
	IOCTL_SPHCS_INFER_ICEDRV_ERROR                = 18,
	IOCTL_SPHCS_INFER_ICEDRV_ERROR_RESET          = 19,
	IOCTL_SPHCS_INFER_ICEDRV_ERROR_CARD_RESET     = 20,
} IoctlSphcsError;

/* Resource usage_flags bits */
#define IOCTL_INF_RES_INPUT          1
#define IOCTL_INF_RES_OUTPUT         2
#define IOCTL_INF_RES_NETWORK        4
#define IOCTL_INF_RES_FORCE_4G_ALLOC 8
#define IOCTL_INF_RES_ECC            16
#define IOCTL_INF_RES_P2P_DST        32
#define IOCTL_INF_RES_P2P_SRC        64

struct inf_cmd_header {
	uint32_t opcode;
	uint32_t size;
};

struct inf_create_context {
	uint32_t contextID;
	uint32_t flags;
};

struct inf_create_resource {
	uint64_t drv_handle;
	uint64_t size;
	uint64_t align;
	uint32_t usage_flags;
};

struct inf_create_resource_reply {
	uint64_t drv_handle;
	int      buf_fd;
	uint64_t rt_handle;
	IoctlSphcsError i_sphcs_err;
};

struct inf_destroy_resource {
	uint64_t drv_handle;
	uint64_t rt_handle;
};

struct inf_create_network {
	uint64_t devnet_drv_handle;
	uint64_t devnet_rt_handle;
	uint32_t config_data_size;
	uint32_t num_devres_rt_handles;
	uint32_t network_id;
};

struct inf_create_network_reply {
	uint64_t devnet_drv_handle;
	uint64_t devnet_rt_handle;
	IoctlSphcsError	 i_sphcs_err;
};

struct inf_destroy_network {
	uint64_t devnet_rt_handle;
};

struct inf_create_infreq {
	uint64_t infreq_drv_handle;
	uint64_t devnet_rt_handle;
	uint32_t n_inputs;
	uint32_t n_outputs;
	uint32_t config_data_size;
	uint32_t infreq_id;
};

struct inf_destroy_infreq {
	uint64_t devnet_rt_handle;
	uint64_t infreq_rt_handle;
};

struct inf_create_infreq_reply {
	uint64_t infreq_drv_handle;
	uint64_t infreq_rt_handle;
	IoctlSphcsError	 i_sphcs_err;
};

struct inf_exec_infreq {
	uint64_t infreq_drv_handle;
	uint64_t infreq_rt_handle;
	uint32_t ready_flags;
	struct inf_sched_params   sched_params;
	uint8_t  sched_params_is_null;
};

struct inf_infreq_exec_done {
	uint64_t	infreq_drv_handle;
	uint32_t	infreq_ctx_id;
	const void     *i_error_msg;
	int32_t         i_error_msg_size;
	IoctlSphcsError i_sphcs_err;
};

struct inf_alloc_resource {
	uint64_t drv_handle;
	uint32_t size;
	uint32_t page_size;
};

struct inf_alloc_resource_reply {
	uint64_t drv_handle;
	int      buf_fd;
	IoctlSphcsError i_sphcs_err;
};

struct inf_free_resource {
	int      buf_fd;
};

struct inf_devnet_resource_reserve {
	uint64_t devnet_drv_handle;
	uint64_t devnet_rt_handle;
	uint8_t reserve_resource; //1 = reserve, 0 = release
	uint32_t timeout;
};

struct inf_devnet_resource_reserve_reply {
	uint64_t devnet_drv_handle;
	uint8_t reserve_resource; //1 = reserve, 0 = release
	IoctlSphcsError i_sphcs_err;
};

struct inf_alloc_pgt_entry {
	uint64_t phys;
	uint64_t size;
};

struct inf_get_alloc_pgt {
	int                         buf_fd;
	struct inf_alloc_pgt_entry *entries;
	uint32_t                    num_entries;
};

struct inf_devnet_reset {
	uint64_t devnet_drv_handle;
	uint64_t cmdlist_drv_handle;
	uint64_t devnet_rt_handle;
	uint32_t flags;
};

struct inf_devnet_reset_reply {
	uint64_t devnet_drv_handle;
	uint64_t cmdlist_drv_handle;
	IoctlSphcsError i_sphcs_err;
};

#endif
