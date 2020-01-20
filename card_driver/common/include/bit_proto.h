



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

#pragma once

#include <stdint.h>

#pragma pack(push, 1)

#define BIT_PROTO_MAX_PACKET_SIZE   4096
#define BIT_PROTO_MAX_NAME_LEN  64
#define BIT_PROTO_MAX_PARAM_LEN 256

enum bit_proto_request_type {
	BIT_START_INSTANCE       = 1,
	BIT_WAIT_INSTANCE        = 2,
	BIT_LIST_INSTANCES       = 3,
	BIT_DELETE_INSTANCE      = 4,
	BIT_READ_OUTPUT          = 5
};

enum bit_proto_reply_type {
	BIT_SUCCESS = 1,
	BIT_NO_PERM = 2,
	BIT_ERROR   = 3,
	BIT_TIMEOUT = 4,
	BIT_TOO_SMALL = 5
};

struct bit_proto_header {
	bit_proto_request_type  req;
	uint32_t                packet_size;
};

struct bit_proto_wait_instance_cmd {
	uint32_t  instance_id;
	uint32_t  should_kill;
	uint32_t  timeout_us;
};

struct bit_proto_delete_instance_cmd {
	uint32_t  instance_id;
};

struct bit_proto_read_outbuf_cmd {
	uint32_t  instance_id;
	uint32_t  max_size;
};

struct bit_proto_reply_header {
	enum bit_proto_reply_type status;
	uint32_t instance_id;
	uint32_t packet_size;
	uint32_t is_last;
};

struct bit_proto_instance_state {
	uint32_t instance_id;
	uint32_t is_running;
	int      exit_value;
	uint32_t output_buffer_size;
	char     test_name[BIT_PROTO_MAX_NAME_LEN];
	char     test_params[BIT_PROTO_MAX_PARAM_LEN];
};

#pragma pack(pop)
