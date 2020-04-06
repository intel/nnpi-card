/*******************************************************************************
INTEL CORPORATION CONFIDENTIAL Copyright(c) 2015-2019 Intel Corporation. All Rights Reserved.

The source code contained or described herein and all documents related to the
source code ("Material") are owned by Intel Corporation or its suppliers or
licensors. Title to the Material remains with Intel Corporation or its suppliers
and licensors. The Material contains trade secrets and proprietary and
confidential information of Intel or its suppliers and licensors. The Material
is protected by worldwide copyright and trade secret laws and treaty provisions.
No part of the Material may be used, copied, reproduced, modified, published,
uploaded, posted, transmitted, distributed, or disclosed in any way without
Intel's prior express written permission.

No license under any patent, copyright, trade secret or other intellectual
property right is granted to or conferred upon you by disclosure or delivery of
the Materials, either expressly, by implication, inducement, estoppel or
otherwise. Any license under such intellectual property rights must be express
and approved by Intel in writing.
*******************************************************************************/

#ifndef _CVE_HW_H_
#define _CVE_HW_H_

/* defines the interface between the driver and the HW */

/*#ifndef __KERNEL__
#include <stdint.h>
#ifndef u32
#define U32_DEFINED_IN_CVE_HW
#define u32 uint32_t
#endif
#ifndef u16
#define U16_DEFINED_IN_CVE_HW
#define u16 uint16_t
#endif

#endif*/

#ifndef __KERNEL__
#include <stdint.h>
typedef uint16_t u16;
typedef uint32_t u32;
#endif

#include "cve_hw_values_forSw.h"

/* CVE virtual address type */
typedef u32 cve_virtual_address_t;

/*
 * number of dwords in a descriptor
 * make a descriptor occupy a complete cache line to avoid
 * issues when the driver and the TLC write to different descriptors
 * at the same time. (writing to the same descriptor at the same time
 * should not happen).
 */
#define CACHE_LINE_SIZE_BYTES 64
#define IS_CACHE_LINE_ALIGNED(ADDRESS) \
	((ADDRESS) & (CACHE_LINE_SIZE_BYTES - 1) == 0)
#define CVE_COMMAND_BUFFER_DESCRIPTOR_DWORDS \
	(CACHE_LINE_SIZE_BYTES / sizeof(u32))

#define NUM_CBD_REGISTERS (2)

/*
 * number of entries/CMDs in each Command Buffer
 * POR is 256, for HW integration purposes may keep it smaller
 */
#define CVE_COMMAND_BUFFER_MAX_ENTRIES 256

union cve_shared_cb_descriptor_flags {
	struct {
		/* Is the TLC allowed to preload the pointed CB before previous ones completed execution? */
		u32 isPreloadable:1;
		/* May the pointed CB be loaded more than once? (e.g., due to inter-CB loop) */
		u32 isReloadable:1;
		/* Suppress generation of CB_COMPLETED interrupt at end of CB execution */
		u32 disable_CB_COMPLETED_int:1;
		u32 reserved:29;
	};
	u32 fixed_size;
};

/* an entry in the command buffer descriptors list */
union cve_shared_cb_descriptor {
	struct {
		/* driver : for driver use */
		u32 driver_reserved0;
		/* driver : for driver use */
		u32 driver_reserved1;
		/* driver : address of the command buffer */
		cve_virtual_address_t address;
		/* driver : number of commands in the command buffer */
		u32 commands_nr;
		/* TLC : tick count when execution started */
		u32 start_time;
		/* TLC : tick count when execution completed */
		u32 completion_time;
		/* driver/TLC : command buffer status
		 * (of type CveCommandBufferStatus)
		 */
		u32 status;
		/* driver: various flags - see declaration of the structure
		 * above
		 */
		union cve_shared_cb_descriptor_flags flags;
		/* driver : for driver use */
		u32 host_haddress;
		u32	host_haddress_reserved;
		/* general-purpose values passed from the driver to the TLC */
		u32 cbd_reg[NUM_CBD_REGISTERS];
		/* command-buffer descriptor ID */
		u32 cbdId;
		/* tlc : for tlc use */
		u16 tlcStartCmdWinIp;
		/* tlc : for tlc use */
		u16 tlcEndCmdWinIp;
		u32 tlc_reserved0;
		u32 tlc_reserved1;
	};
	/* set the size of the structure regardless of its actual contents.
	 * this size of this struct should be larger than the other one for
	 * it to be effective
	 */
	struct {
		u32 fixed_size[CVE_COMMAND_BUFFER_DESCRIPTOR_DWORDS];
	};
};

/* an entry in the page table */
typedef u32 pt_entry_t;
union cve_page_table_entry {
	struct {
		u32 page_physical_address:24;
		u32 pasid:4;
		u32 reserved1:1;
		u32 is_executable:1;
		u32 is_writable:1;
		u32 is_readable:1;
	};
	u32 raw;
};

/* an entry in the page directory */
typedef u32 pd_entry_t;
union cve_page_dir_entry {
	struct {
		u32 page_physical_address:27;
		u32 pasid:1;
		u32 reserved1:1;
		u32 is_executable:1;
		u32 is_writable:1;
		u32 is_readable:1;
	};
	u32 raw;
};
#ifdef U32_DEFINED_IN_CVE_HW
#undef u32
#endif

#endif /* _CVE_HW_H_ */
