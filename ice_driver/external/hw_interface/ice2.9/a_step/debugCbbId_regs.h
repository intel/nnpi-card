/*******************************************************************************
INTEL CORPORATION CONFIDENTIAL Copyright(c) 2017-2021 Intel Corporation. All Rights Reserved.

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

#ifndef _DEBUGCBBID_REGS_H_
#define _DEBUGCBBID_REGS_H_
#define CVE_DEBUGCBBID_BASE 0x0F000
#define CVE_DEBUGCBBID_DEBUG_CBBID_CFG_REG_MMOFFSET 0x0
#ifndef DEBUGCBBID_MEM_DEBUG_CBBID_CFG_REG_FLAG
#define DEBUGCBBID_MEM_DEBUG_CBBID_CFG_REG_FLAG

/*  DEBUG_CBBID_CFG_REG desc:  Dummy configuration register; To be */
/* used to write to the debug CBBID */
union DEBUGCBBID_MEM_DEBUG_CBBID_CFG_REG_t {
	struct {
uint32_t  CFG_PAYLOAD          :  32;
/*   General Purpose Configuration */
	}                                field;
uint32_t                         val;
};
#endif
#define DEBUGCBBID_MEM_DEBUG_CBBID_CFG_REG_OFFSET 0x00
#define DEBUGCBBID_MEM_DEBUG_CBBID_CFG_REG_SCOPE 0x01
#define DEBUGCBBID_MEM_DEBUG_CBBID_CFG_REG_SIZE 32
#define DEBUGCBBID_MEM_DEBUG_CBBID_CFG_REG_BITFIELD_COUNT 0x01
#define DEBUGCBBID_MEM_DEBUG_CBBID_CFG_REG_RESET 0x00000000
#define DEBUGCBBID_MEM_DEBUG_CBBID_CFG_REG_CFG_PAYLOAD_LSB 0x0000
#define DEBUGCBBID_MEM_DEBUG_CBBID_CFG_REG_CFG_PAYLOAD_MSB 0x001f
#define DEBUGCBBID_MEM_DEBUG_CBBID_CFG_REG_CFG_PAYLOAD_RANGE 0x0020
#define DEBUGCBBID_MEM_DEBUG_CBBID_CFG_REG_CFG_PAYLOAD_MASK 0xffffffff
#define DEBUGCBBID_MEM_DEBUG_CBBID_CFG_REG_CFG_PAYLOAD_RESET_VALUE 0x00000000

/*  ------------------------------------------------------------------ */
/* */
/* starting the array instantiation section*/
struct debugCbbId_t {
union DEBUGCBBID_MEM_DEBUG_CBBID_CFG_REG_t DEBUG_CBBID_CFG_REG[64];
/*  offset 4'h0, width 32 */
};

#define CVE_DEBUGCBBID_DEBUG_CBBID_CFG_REG                     0

#endif // _DEBUGCBBID_REGS_H_
