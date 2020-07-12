



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
#include <semaphore.h>
#include "um_shm_list.h"

#define UM_SHM_NAME_SIZE    32

struct um_shm_group_info {
	uintptr_t  name_off;    // offset to group name string
};

struct um_shm_counter_info {
	uint32_t     group_idx;
	uint32_t    offset;
	uintptr_t   name_off;    // offset to name string
	uintptr_t   desc_off;    // offset to description string
};

struct um_shm_sync_client {
	uint64_t                last_sync_point;
	struct um_shm_list_head node;
};

struct um_shm_counters_set {
	uintptr_t    name_off;             // offset to name string
	bool         perID;
	uintptr_t    group_info_array_off; // offset to start of group info array
	uint32_t     group_info_array_size;
	uintptr_t    info_array_off;       // offset to start of counter info array
	uint32_t     info_array_size;
	uintptr_t    children_array_off;   // offset to start of children array
	uint32_t     children_array_size;
	char         values_shm_name[UM_SHM_NAME_SIZE];  // name of values shm object or null string

	sem_t        lock;
	uintptr_t    groups_off;           // offset to uint32_t[ngroups] array
	                                   // which is enable count for each
					   // group

	uintptr_t    extra_data_size;      // Additional size allocated after the set for set-global data

	//
	// The following entries are valid only for the root
	// counter set struct (at offset 0 in the shared memory).
	// It holds a counter which increment whenever any values object
	// is created or destroyed and a list of attached report clients
	// which needs to be synced with the change count in order to
	// not delete values objects before all clients mapped it.
	//
	uint64_t     values_changed_count;       // increments when values
						 // object is created or destroyed
	int64_t      next_obj_id;
	uint64_t           min_sync_point;
	struct um_shm_list sync_clients;
};

struct um_shm_values_block {
	int64_t          obj_id;
	uint32_t         orig_obj_id;
	uint32_t         mapped_count;

	struct {
		uint32_t is_stale     : 1;
		uint32_t in_free_list : 1;
		uint32_t persist      : 1;
		uint32_t reserved     :29;
	}                flags;

	uint64_t         changed_count_at_remove;
	sem_t            lock;
	struct um_shm_list_head node;
	//char           child_values_shm_name[nchilds * UM_SHM_NAME_SIZE]
	//uint32_t       groups[ngroups];
	//uint64_t       values[nvals];
};

struct um_shm_values_header {
	uint32_t         allocated_blocks;
	uint32_t         free_blocks;
	uint32_t         block_size;
	uint32_t         dirty_count;
	char             next_values_shm_name[UM_SHM_NAME_SIZE];  // link to next values shm object or null string
	                                                          // used when block_list is full
	sem_t            lock;

	// following this header a list of um_shm_values_block
	// structs of the same ngroups and nvals values.
	struct um_shm_list block_list;
};
