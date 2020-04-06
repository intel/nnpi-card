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

#ifndef _CVE_DSE_REGS_H_
#define _CVE_DSE_REGS_H_
#define CVE_DSE_BASE 0x0C000
#define CVE_DSE_SELF_CONFIG_MMOFFSET 0x0
#define CVE_DSE_SELF_CONFIG_AXI_READ_CONFIG_MMOFFSET 0x4
#define CVE_DSE_SELF_CONFIG_AXI_AUSER_EXTEND_MMOFFSET 0x8
#define CVE_DSE_SURFACE_START_ADDR_MMOFFSET 0x0C
#define CVE_DSE_SURFACE_START_ADDR_MSB_MMOFFSET 0x4C
#define CVE_DSE_SURFACE_1D_LENGTH_MMOFFSET 0x8C
#define CVE_DSE_SURFACE_2D_LENGTH_MMOFFSET 0x0CC
#define CVE_DSE_SURFACE_3D_LENGTH_MMOFFSET 0x10C
#define CVE_DSE_SURFACE_4D_LENGTH_MMOFFSET 0x14C
#define CVE_DSE_SURFACE_1D_PITCH_MMOFFSET 0x18C
#define CVE_DSE_SURFACE_2D_PITCH_MMOFFSET 0x1CC
#define CVE_DSE_SURFACE_3D_PITCH_MMOFFSET 0x20C
#define CVE_DSE_TILE_1D_LENGTH_MMOFFSET 0x24C
#define CVE_DSE_TILE_2D_LENGTH_MMOFFSET 0x28C
#define CVE_DSE_TILE_3D_LENGTH_MMOFFSET 0x2CC
#define CVE_DSE_TILE_4D_LENGTH_MMOFFSET 0x30C
#define CVE_DSE_TILE_1D_STEP_MMOFFSET 0x34C
#define CVE_DSE_TILE_2D_STEP_MMOFFSET 0x38C
#define CVE_DSE_TILE_3D_STEP_MMOFFSET 0x3CC
#define CVE_DSE_TILE_4D_STEP_MMOFFSET 0x40C
#define CVE_DSE_TILE_1D_OFFSET_MMOFFSET 0x44C
#define CVE_DSE_TILE_2D_OFFSET_MMOFFSET 0x48C
#define CVE_DSE_TILE_3D_OFFSET_MMOFFSET 0x4CC
#define CVE_DSE_TILE_4D_OFFSET_MMOFFSET 0x50C
#define CVE_DSE_TILE_FETCH_REORDER_Q_NUM_MMOFFSET 0x54C
#define CVE_DSE_TILE_PADDING_CONFIG_MMOFFSET 0x58C
#define CVE_DSE_TILE_PADDING_DATA_MMOFFSET 0x5CC
#define CVE_DSE_AXI_READ_CONFIG_MMOFFSET 0x60C
#define CVE_DSE_AXI_WRITE_CONFIG_MMOFFSET 0x64C
#define CVE_DSE_AXI_AUSER_EXTEND_MMOFFSET 0x68C
#define CVE_DSE_AXI_MAX_INFLIGHT_MMOFFSET 0x6CC
#define CVE_DSE_NEAR_ZERO_TH_SETTING_MMOFFSET 0x6D0
#define CVE_DSE_WEIGHT_LUT_SETTING_MMOFFSET 0x710
#define CVE_DSE_WEIGHT_LUT_BASE_ADDR_MMOFFSET 0x750
#define CVE_DSE_SP_BUFFER_START_ADDR_MMOFFSET 0x754
#define CVE_DSE_SP_BUFFER_END_ADDR_MMOFFSET 0x7A4
#define CVE_DSE_SP_TILE_BOX_1D_LENGTH_MMOFFSET 0x7F4
#define CVE_DSE_SP_TILE_BOX_2D_LENGTH_MMOFFSET 0x844
#define CVE_DSE_SP_TILE_BOX_3D_LENGTH_MMOFFSET 0x894
#define CVE_DSE_SP_TILE_BOX_4D_LENGTH_MMOFFSET 0x8E4
#define CVE_DSE_SP_TILE_BOX_2D_PITCH_MMOFFSET 0x934
#define CVE_DSE_SP_TILE_BOX_3D_PITCH_MMOFFSET 0x984
#define CVE_DSE_SP_TILE_BOX_PITCH_MMOFFSET 0x9D4
#define CVE_DSE_TILE_1D_OFFSET_ON_SP_MMOFFSET 0x0A24
#define CVE_DSE_TILE_2D_OFFSET_ON_SP_MMOFFSET 0x0A74
#define CVE_DSE_SP_TILE_BOX_SCALE_MMOFFSET 0x0AC4
#define CVE_DSE_TOTAL_CREDITS_MMOFFSET 0x0B14
#define CVE_DSE_CREDIT_GRANULARITY_MMOFFSET 0x0B64
#define CVE_DSE_WACM_CONFIG_MMOFFSET 0x0BB4
#define CVE_DSE_X_E0_MMOFFSET 0x0BF4
#define CVE_DSE_X_R0_MMOFFSET 0x0C34
#define CVE_DSE_X_E1_MMOFFSET 0x0C74
#define CVE_DSE_X_R1_MMOFFSET 0x0CB4
#define CVE_DSE_X_E2_MMOFFSET 0x0CF4
#define CVE_DSE_X_R2_MMOFFSET 0x0D34
#define CVE_DSE_Y_E0_MMOFFSET 0x0D74
#define CVE_DSE_Y_R0_MMOFFSET 0x0DB4
#define CVE_DSE_Y_E1_MMOFFSET 0x0DF4
#define CVE_DSE_Y_R1_MMOFFSET 0x0E34
#define CVE_DSE_Y_E2_MMOFFSET 0x0E74
#define CVE_DSE_Y_R2_MMOFFSET 0x0EB4
#define CVE_DSE_Z_E0_MMOFFSET 0x0EF4
#define CVE_DSE_Z_R0_MMOFFSET 0x0F34
#define CVE_DSE_Z_E1_MMOFFSET 0x0F74
#define CVE_DSE_Z_R1_MMOFFSET 0x0FB4
#define CVE_DSE_Z_E2_MMOFFSET 0x0FF4
#define CVE_DSE_Z_R2_MMOFFSET 0x1034
#define CVE_DSE_W_E0_MMOFFSET 0x1074
#define CVE_DSE_W_R0_MMOFFSET 0x10B4
#define CVE_DSE_W_E1_MMOFFSET 0x10F4
#define CVE_DSE_W_R1_MMOFFSET 0x1134
#define CVE_DSE_W_E2_MMOFFSET 0x1174
#define CVE_DSE_W_R2_MMOFFSET 0x11B4
#define CVE_DSE_PMON_COUNTER_CONFIG_MMOFFSET 0x11F4
#define CVE_DSE_PMON_COUNTER_MMOFFSET 0x1234
#ifndef CVE_DSE_MEM_SELF_CONFIG_FLAG
#define CVE_DSE_MEM_SELF_CONFIG_FLAG
/* SELF_CONFIG desc:  Self Config*/
union CVE_DSE_MEM_SELF_CONFIG_t {
	struct {
uint32_t  NUM_OF_REGS          :   8;
/*   Self Configuration number of */
/* register to load., the*/
/* resolution is 4 register Units*/
/* 4 Registers Min 0 Max 2^16-1*/
uint32_t  BASE_ADDR            :  24;
/*   The Write to that register */
/* will trigger A self*/
/* Configuration Event. Flowing*/
/* DSE activates will be halt*/
/* until the self Configuration*/
/* is done. Self Configuration*/
/* Loading AXI Address MSB, the*/
/* minimum address resolution is*/
/* 0x100. Each register*/
/* Configuration takes 64 bit at*/
/* the external memory: [31: 0] -*/
/* Register Wrier data [47:32] -*/
/* Register Wrier Address in 4*/
/* byte resolution(each address*/
/* points on 32 bit register)*/
/* [63:48] - Reserved Units 256*/
/* Byte (0x100) Min 0 Max 2^32-1*/
	}                                field;
uint32_t                         val;
};
#endif
#define CVE_DSE_MEM_SELF_CONFIG_OFFSET 0x00
#define CVE_DSE_MEM_SELF_CONFIG_SCOPE 0x01
#define CVE_DSE_MEM_SELF_CONFIG_SIZE 32
#define CVE_DSE_MEM_SELF_CONFIG_BITFIELD_COUNT 0x02
#define CVE_DSE_MEM_SELF_CONFIG_RESET 0x00000000
#define CVE_DSE_MEM_SELF_CONFIG_NUM_OF_REGS_LSB 0x0000
#define CVE_DSE_MEM_SELF_CONFIG_NUM_OF_REGS_MSB 0x0007
#define CVE_DSE_MEM_SELF_CONFIG_NUM_OF_REGS_RANGE 0x0008
#define CVE_DSE_MEM_SELF_CONFIG_NUM_OF_REGS_MASK 0x000000ff
#define CVE_DSE_MEM_SELF_CONFIG_NUM_OF_REGS_RESET_VALUE 0x00000000
#define CVE_DSE_MEM_SELF_CONFIG_BASE_ADDR_LSB 0x0008
#define CVE_DSE_MEM_SELF_CONFIG_BASE_ADDR_MSB 0x001f
#define CVE_DSE_MEM_SELF_CONFIG_BASE_ADDR_RANGE 0x0018
#define CVE_DSE_MEM_SELF_CONFIG_BASE_ADDR_MASK 0xffffff00
#define CVE_DSE_MEM_SELF_CONFIG_BASE_ADDR_RESET_VALUE 0x00000000

/*  ------------------------------------------------------------------ */
/* */
#ifndef CVE_DSE_MEM_SELF_CONFIG_AXI_READ_CONFIG_FLAG
#define CVE_DSE_MEM_SELF_CONFIG_AXI_READ_CONFIG_FLAG

/*  SELF_CONFIG_AXI_READ_CONFIG desc:  Self Config Axi Read Config */
union CVE_DSE_MEM_SELF_CONFIG_AXI_READ_CONFIG_t {
	struct {
uint32_t  AXI_ARUSER           :  12;
/*   AXI_ARUSER[ 0] - Reserved */
/* AXI_ARUSER[ 1] - Flush*/
/* AXI_ARUSER[ 2] - Bypass*/
/* AXI_ARUSER[ 3] - Reserved*/
/* AXI_ARUSER[ 8:4] - Stream ID*/
/* (ATU_ID) AXI_ARUSER[11:9] -*/
/* Reserved Units Num Min 0 Max*/
/* 2^12-1*/
uint32_t  RSVD_0               :   4;
/*  Nebulon auto filled RSVD [15:12] */
uint32_t  AXI_ARCACHE          :   4;
/*   AXI Read cache attributes */
/* Units Num Min 0 Max 2^4-1*/
uint32_t  AXI_RD_MAX_BURST_LOG2 :   3;
/*   Log2(AXI Read max burst */
/* length) == Log2(1,2,4,8,16)*/
/* Units 2**() Min 0 Max 4*/
uint32_t  RSVD_1               :   9;
/*  Nebulon auto filled RSVD [31:23] */
	}                                field;
uint32_t                         val;
};
#endif
#define CVE_DSE_MEM_SELF_CONFIG_AXI_READ_CONFIG_OFFSET 0x04
#define CVE_DSE_MEM_SELF_CONFIG_AXI_READ_CONFIG_SCOPE 0x01
#define CVE_DSE_MEM_SELF_CONFIG_AXI_READ_CONFIG_SIZE 32
#define CVE_DSE_MEM_SELF_CONFIG_AXI_READ_CONFIG_BITFIELD_COUNT 0x03
#define CVE_DSE_MEM_SELF_CONFIG_AXI_READ_CONFIG_RESET 0x00200000
#define CVE_DSE_MEM_SELF_CONFIG_AXI_READ_CONFIG_AXI_ARUSER_LSB 0x0000
#define CVE_DSE_MEM_SELF_CONFIG_AXI_READ_CONFIG_AXI_ARUSER_MSB 0x000b
#define CVE_DSE_MEM_SELF_CONFIG_AXI_READ_CONFIG_AXI_ARUSER_RANGE 0x000c
#define CVE_DSE_MEM_SELF_CONFIG_AXI_READ_CONFIG_AXI_ARUSER_MASK 0x00000fff
#define CVE_DSE_MEM_SELF_CONFIG_AXI_READ_CONFIG_AXI_ARUSER_RESET_VALUE 0x00000000
#define CVE_DSE_MEM_SELF_CONFIG_AXI_READ_CONFIG_AXI_ARCACHE_LSB 0x0010
#define CVE_DSE_MEM_SELF_CONFIG_AXI_READ_CONFIG_AXI_ARCACHE_MSB 0x0013
#define CVE_DSE_MEM_SELF_CONFIG_AXI_READ_CONFIG_AXI_ARCACHE_RANGE 0x0004
#define CVE_DSE_MEM_SELF_CONFIG_AXI_READ_CONFIG_AXI_ARCACHE_MASK 0x000f0000
#define CVE_DSE_MEM_SELF_CONFIG_AXI_READ_CONFIG_AXI_ARCACHE_RESET_VALUE 0x00000000
#define CVE_DSE_MEM_SELF_CONFIG_AXI_READ_CONFIG_AXI_RD_MAX_BURST_LOG2_LSB 0x0014
#define CVE_DSE_MEM_SELF_CONFIG_AXI_READ_CONFIG_AXI_RD_MAX_BURST_LOG2_MSB 0x0016
#define CVE_DSE_MEM_SELF_CONFIG_AXI_READ_CONFIG_AXI_RD_MAX_BURST_LOG2_RANGE 0x0003
#define CVE_DSE_MEM_SELF_CONFIG_AXI_READ_CONFIG_AXI_RD_MAX_BURST_LOG2_MASK 0x00700000
#define CVE_DSE_MEM_SELF_CONFIG_AXI_READ_CONFIG_AXI_RD_MAX_BURST_LOG2_RESET_VALUE 0x00000002

/*  ------------------------------------------------------------------ */
/* */
#ifndef CVE_DSE_MEM_SELF_CONFIG_AXI_AUSER_EXTEND_FLAG
#define CVE_DSE_MEM_SELF_CONFIG_AXI_AUSER_EXTEND_FLAG

/*  SELF_CONFIG_AXI_AUSER_EXTEND desc:  Self Config Axi Auser Extend */
/* */
union CVE_DSE_MEM_SELF_CONFIG_AXI_AUSER_EXTEND_t {
	struct {
uint32_t  AXI_AUSER_EXTEND     :  16;
/*   AXI_AUSER_EXTEND[ 1: 0] - */
/* CLOS - LLC Class Service*/
/* AXI_AUSER_EXTEND[ 2] -*/
/* Reserved CLOS*/
/* AXI_AUSER_EXTEND[ 3] -*/
/* Bridge_Priority - Transaction*/
/* priority in the AXI2IDI bridge*/
/* AXI_AUSER_EXTEND[ 5: 4] -*/
/* Reserved Bridge_Priority*/
/* AXI_AUSER_EXTEND[ 7: 6] - NT -*/
/* LLC NT AXI_AUSER_EXTEND[ 8] -*/
/* Prefetch_LLC - LLC prefetch -*/
/* Set by DSE HW*/
/* AXI_AUSER_EXTEND[ 9] -*/
/* Prefetch_LLC_Fake_Data - If*/
/* LLC prefetch then return fake*/
/* data (all zeros)*/
/* AXI_AUSER_EXTEND[11:10] -*/
/* Reserved_Prefetch*/
/* AXI_AUSER_EXTEND[12:12] -*/
/* Shared read by both ICEs in*/
/* the ICEBO. Ignored by ICEBO if*/
/* Prefetch_LLC is set for this*/
/* transaction. Unset by GeCoe*/
/* for meta-data*/
/* AXI_AUSER_EXTEND[13:13] -*/
/* Forces caching in a*/
/* ICEBO-local bank of the LLC*/
/* AXI_AUSER_EXTEND[15:14] -*/
/* Reserved Units Num Min 0 Max*/
/* 2^16-1*/
uint32_t  RSVD_0               :  16;
/*  Nebulon auto filled RSVD [31:16] */
	}                                field;
uint32_t                         val;
};
#endif
#define CVE_DSE_MEM_SELF_CONFIG_AXI_AUSER_EXTEND_OFFSET 0x08
#define CVE_DSE_MEM_SELF_CONFIG_AXI_AUSER_EXTEND_SCOPE 0x01
#define CVE_DSE_MEM_SELF_CONFIG_AXI_AUSER_EXTEND_SIZE 32
#define CVE_DSE_MEM_SELF_CONFIG_AXI_AUSER_EXTEND_BITFIELD_COUNT 0x01
#define CVE_DSE_MEM_SELF_CONFIG_AXI_AUSER_EXTEND_RESET 0x00000000
#define CVE_DSE_MEM_SELF_CONFIG_AXI_AUSER_EXTEND_AXI_AUSER_EXTEND_LSB 0x0000
#define CVE_DSE_MEM_SELF_CONFIG_AXI_AUSER_EXTEND_AXI_AUSER_EXTEND_MSB 0x000f
#define CVE_DSE_MEM_SELF_CONFIG_AXI_AUSER_EXTEND_AXI_AUSER_EXTEND_RANGE 0x0010
#define CVE_DSE_MEM_SELF_CONFIG_AXI_AUSER_EXTEND_AXI_AUSER_EXTEND_MASK 0x0000ffff
#define CVE_DSE_MEM_SELF_CONFIG_AXI_AUSER_EXTEND_AXI_AUSER_EXTEND_RESET_VALUE 0x00000000

/*  ------------------------------------------------------------------ */
/* */
#ifndef CVE_DSE_MEM_SURFACE_START_ADDR_FLAG
#define CVE_DSE_MEM_SURFACE_START_ADDR_FLAG
/* SURFACE_START_ADDR desc:  Surface Start Addr*/
union CVE_DSE_MEM_SURFACE_START_ADDR_t {
	struct {
uint32_t  SURFACE_START_ADDR   :  32;
/*   surface Start point at memory */
/* Units Byte Min 0 Max 2^32-1*/
	}                                field;
uint32_t                         val;
};
#endif
#define CVE_DSE_MEM_SURFACE_START_ADDR_OFFSET 0x0c
#define CVE_DSE_MEM_SURFACE_START_ADDR_SCOPE 0x01
#define CVE_DSE_MEM_SURFACE_START_ADDR_SIZE 32
#define CVE_DSE_MEM_SURFACE_START_ADDR_BITFIELD_COUNT 0x01
#define CVE_DSE_MEM_SURFACE_START_ADDR_RESET 0x00000000
#define CVE_DSE_MEM_SURFACE_START_ADDR_SURFACE_START_ADDR_LSB 0x0000
#define CVE_DSE_MEM_SURFACE_START_ADDR_SURFACE_START_ADDR_MSB 0x001f
#define CVE_DSE_MEM_SURFACE_START_ADDR_SURFACE_START_ADDR_RANGE 0x0020
#define CVE_DSE_MEM_SURFACE_START_ADDR_SURFACE_START_ADDR_MASK 0xffffffff
#define CVE_DSE_MEM_SURFACE_START_ADDR_SURFACE_START_ADDR_RESET_VALUE 0x00000000

/*  ------------------------------------------------------------------ */
/* */
#ifndef CVE_DSE_MEM_SURFACE_START_ADDR_MSB_FLAG
#define CVE_DSE_MEM_SURFACE_START_ADDR_MSB_FLAG
/* SURFACE_START_ADDR_MSB desc:  Surface Start Addr Msb*/
union CVE_DSE_MEM_SURFACE_START_ADDR_MSB_t {
	struct {
uint32_t  SURFACE_START_ADDR_MSB :   3;
/*   surface Start point at memory */
/* 3 Msb's (32-34) Units Byte Min*/
/* 0 Max 2^3-1*/
uint32_t  RSVD_0               :  29;
/*  Nebulon auto filled RSVD [31:3] */
	}                                field;
uint32_t                         val;
};
#endif
#define CVE_DSE_MEM_SURFACE_START_ADDR_MSB_OFFSET 0x4c
#define CVE_DSE_MEM_SURFACE_START_ADDR_MSB_SCOPE 0x01
#define CVE_DSE_MEM_SURFACE_START_ADDR_MSB_SIZE 32
#define CVE_DSE_MEM_SURFACE_START_ADDR_MSB_BITFIELD_COUNT 0x01
#define CVE_DSE_MEM_SURFACE_START_ADDR_MSB_RESET 0x00000000
#define CVE_DSE_MEM_SURFACE_START_ADDR_MSB_SURFACE_START_ADDR_MSB_LSB 0x0000
#define CVE_DSE_MEM_SURFACE_START_ADDR_MSB_SURFACE_START_ADDR_MSB_MSB 0x0002
#define CVE_DSE_MEM_SURFACE_START_ADDR_MSB_SURFACE_START_ADDR_MSB_RANGE 0x0003
#define CVE_DSE_MEM_SURFACE_START_ADDR_MSB_SURFACE_START_ADDR_MSB_MASK 0x00000007
#define CVE_DSE_MEM_SURFACE_START_ADDR_MSB_SURFACE_START_ADDR_MSB_RESET_VALUE 0x00000000

/*  ------------------------------------------------------------------ */
/* */
#ifndef CVE_DSE_MEM_SURFACE_1D_LENGTH_FLAG
#define CVE_DSE_MEM_SURFACE_1D_LENGTH_FLAG
/* SURFACE_1D_LENGTH desc:  Surface 1D Length*/
union CVE_DSE_MEM_SURFACE_1D_LENGTH_t {
	struct {
uint32_t  SURFACE_1D_LENGTH    :  32;
/*   Surface First Dimension */
/* Length (Width/X) Units Byte*/
/* Min 1 Max 2^32-1*/
	}                                field;
uint32_t                         val;
};
#endif
#define CVE_DSE_MEM_SURFACE_1D_LENGTH_OFFSET 0x8c
#define CVE_DSE_MEM_SURFACE_1D_LENGTH_SCOPE 0x01
#define CVE_DSE_MEM_SURFACE_1D_LENGTH_SIZE 32
#define CVE_DSE_MEM_SURFACE_1D_LENGTH_BITFIELD_COUNT 0x01
#define CVE_DSE_MEM_SURFACE_1D_LENGTH_RESET 0x00000001
#define CVE_DSE_MEM_SURFACE_1D_LENGTH_SURFACE_1D_LENGTH_LSB 0x0000
#define CVE_DSE_MEM_SURFACE_1D_LENGTH_SURFACE_1D_LENGTH_MSB 0x001f
#define CVE_DSE_MEM_SURFACE_1D_LENGTH_SURFACE_1D_LENGTH_RANGE 0x0020
#define CVE_DSE_MEM_SURFACE_1D_LENGTH_SURFACE_1D_LENGTH_MASK 0xffffffff
#define CVE_DSE_MEM_SURFACE_1D_LENGTH_SURFACE_1D_LENGTH_RESET_VALUE 0x00000001

/*  ------------------------------------------------------------------ */
/* */
#ifndef CVE_DSE_MEM_SURFACE_2D_LENGTH_FLAG
#define CVE_DSE_MEM_SURFACE_2D_LENGTH_FLAG
/* SURFACE_2D_LENGTH desc:  Surface 2D Length*/
union CVE_DSE_MEM_SURFACE_2D_LENGTH_t {
	struct {
uint32_t  SURFACE_2D_LENGTH    :  32;
/*   Surface Second Dimension */
/* Length (Height/Y) Units*/
/* SURFACE_1D_PITCH Min 1 Max*/
/* 2^32-1*/
	}                                field;
uint32_t                         val;
};
#endif
#define CVE_DSE_MEM_SURFACE_2D_LENGTH_OFFSET 0xcc
#define CVE_DSE_MEM_SURFACE_2D_LENGTH_SCOPE 0x01
#define CVE_DSE_MEM_SURFACE_2D_LENGTH_SIZE 32
#define CVE_DSE_MEM_SURFACE_2D_LENGTH_BITFIELD_COUNT 0x01
#define CVE_DSE_MEM_SURFACE_2D_LENGTH_RESET 0x00000001
#define CVE_DSE_MEM_SURFACE_2D_LENGTH_SURFACE_2D_LENGTH_LSB 0x0000
#define CVE_DSE_MEM_SURFACE_2D_LENGTH_SURFACE_2D_LENGTH_MSB 0x001f
#define CVE_DSE_MEM_SURFACE_2D_LENGTH_SURFACE_2D_LENGTH_RANGE 0x0020
#define CVE_DSE_MEM_SURFACE_2D_LENGTH_SURFACE_2D_LENGTH_MASK 0xffffffff
#define CVE_DSE_MEM_SURFACE_2D_LENGTH_SURFACE_2D_LENGTH_RESET_VALUE 0x00000001

/*  ------------------------------------------------------------------ */
/* */
#ifndef CVE_DSE_MEM_SURFACE_3D_LENGTH_FLAG
#define CVE_DSE_MEM_SURFACE_3D_LENGTH_FLAG
/* SURFACE_3D_LENGTH desc:  Surface 3D Length*/
union CVE_DSE_MEM_SURFACE_3D_LENGTH_t {
	struct {
uint32_t  SURFACE_3D_LENGTH    :  16;
/*   Surface Third Dimension */
/* Length (Depth/Z) Units*/
/* SURFACE_2D_PITCH Min 1 Max*/
/* 2^16-1*/
uint32_t  RSVD_0               :  16;
/*  Nebulon auto filled RSVD [31:16] */
	}                                field;
uint32_t                         val;
};
#endif
#define CVE_DSE_MEM_SURFACE_3D_LENGTH_OFFSET 0x0c
#define CVE_DSE_MEM_SURFACE_3D_LENGTH_SCOPE 0x01
#define CVE_DSE_MEM_SURFACE_3D_LENGTH_SIZE 32
#define CVE_DSE_MEM_SURFACE_3D_LENGTH_BITFIELD_COUNT 0x01
#define CVE_DSE_MEM_SURFACE_3D_LENGTH_RESET 0x00000001
#define CVE_DSE_MEM_SURFACE_3D_LENGTH_SURFACE_3D_LENGTH_LSB 0x0000
#define CVE_DSE_MEM_SURFACE_3D_LENGTH_SURFACE_3D_LENGTH_MSB 0x000f
#define CVE_DSE_MEM_SURFACE_3D_LENGTH_SURFACE_3D_LENGTH_RANGE 0x0010
#define CVE_DSE_MEM_SURFACE_3D_LENGTH_SURFACE_3D_LENGTH_MASK 0x0000ffff
#define CVE_DSE_MEM_SURFACE_3D_LENGTH_SURFACE_3D_LENGTH_RESET_VALUE 0x00000001

/*  ------------------------------------------------------------------ */
/* */
#ifndef CVE_DSE_MEM_SURFACE_4D_LENGTH_FLAG
#define CVE_DSE_MEM_SURFACE_4D_LENGTH_FLAG
/* SURFACE_4D_LENGTH desc:  Surface 4D Length*/
union CVE_DSE_MEM_SURFACE_4D_LENGTH_t {
	struct {
uint32_t  SURFACE_4D_LENGTH    :  16;
/*   Surface Fourth Dimension */
/* Length Units SURFACE_3D_PITCH*/
/* Min 1 Max 2^16-1*/
uint32_t  RSVD_0               :  16;
/*  Nebulon auto filled RSVD [31:16] */
	}                                field;
uint32_t                         val;
};
#endif
#define CVE_DSE_MEM_SURFACE_4D_LENGTH_OFFSET 0x4c
#define CVE_DSE_MEM_SURFACE_4D_LENGTH_SCOPE 0x01
#define CVE_DSE_MEM_SURFACE_4D_LENGTH_SIZE 32
#define CVE_DSE_MEM_SURFACE_4D_LENGTH_BITFIELD_COUNT 0x01
#define CVE_DSE_MEM_SURFACE_4D_LENGTH_RESET 0x00000001
#define CVE_DSE_MEM_SURFACE_4D_LENGTH_SURFACE_4D_LENGTH_LSB 0x0000
#define CVE_DSE_MEM_SURFACE_4D_LENGTH_SURFACE_4D_LENGTH_MSB 0x000f
#define CVE_DSE_MEM_SURFACE_4D_LENGTH_SURFACE_4D_LENGTH_RANGE 0x0010
#define CVE_DSE_MEM_SURFACE_4D_LENGTH_SURFACE_4D_LENGTH_MASK 0x0000ffff
#define CVE_DSE_MEM_SURFACE_4D_LENGTH_SURFACE_4D_LENGTH_RESET_VALUE 0x00000001

/*  ------------------------------------------------------------------ */
/* */
#ifndef CVE_DSE_MEM_SURFACE_1D_PITCH_FLAG
#define CVE_DSE_MEM_SURFACE_1D_PITCH_FLAG
/* SURFACE_1D_PITCH desc:  Surface 1D Pitch*/
union CVE_DSE_MEM_SURFACE_1D_PITCH_t {
	struct {
uint32_t  SURFACE_1D_PITCH     :  32;
/*   Surface 1D Pitch - Distance */
/* in byte between two*/
/* consecutive line start point*/
/* Units Byte Min*/
/* SURFACE_1D_LENGTH Max 2^32-1*/
	}                                field;
uint32_t                         val;
};
#endif
#define CVE_DSE_MEM_SURFACE_1D_PITCH_OFFSET 0x8c
#define CVE_DSE_MEM_SURFACE_1D_PITCH_SCOPE 0x01
#define CVE_DSE_MEM_SURFACE_1D_PITCH_SIZE 32
#define CVE_DSE_MEM_SURFACE_1D_PITCH_BITFIELD_COUNT 0x01
#define CVE_DSE_MEM_SURFACE_1D_PITCH_RESET 0x00000001
#define CVE_DSE_MEM_SURFACE_1D_PITCH_SURFACE_1D_PITCH_LSB 0x0000
#define CVE_DSE_MEM_SURFACE_1D_PITCH_SURFACE_1D_PITCH_MSB 0x001f
#define CVE_DSE_MEM_SURFACE_1D_PITCH_SURFACE_1D_PITCH_RANGE 0x0020
#define CVE_DSE_MEM_SURFACE_1D_PITCH_SURFACE_1D_PITCH_MASK 0xffffffff
#define CVE_DSE_MEM_SURFACE_1D_PITCH_SURFACE_1D_PITCH_RESET_VALUE 0x00000001

/*  ------------------------------------------------------------------ */
/* */
#ifndef CVE_DSE_MEM_SURFACE_2D_PITCH_FLAG
#define CVE_DSE_MEM_SURFACE_2D_PITCH_FLAG
/* SURFACE_2D_PITCH desc:  Surface 2D Pitch*/
union CVE_DSE_MEM_SURFACE_2D_PITCH_t {
	struct {
uint32_t  SURFACE_2D_PITCH     :  32;
/*   Surface 2D Pitch - Distance */
/* in byte between two*/
/* consecutive 2D surface start*/
/* point Units Byte Min*/
/* SURFACE_2D_LENGTH **/
/* SURFACE_1D_PITCH Max 2^32-1*/
	}                                field;
uint32_t                         val;
};
#endif
#define CVE_DSE_MEM_SURFACE_2D_PITCH_OFFSET 0xcc
#define CVE_DSE_MEM_SURFACE_2D_PITCH_SCOPE 0x01
#define CVE_DSE_MEM_SURFACE_2D_PITCH_SIZE 32
#define CVE_DSE_MEM_SURFACE_2D_PITCH_BITFIELD_COUNT 0x01
#define CVE_DSE_MEM_SURFACE_2D_PITCH_RESET 0x00000001
#define CVE_DSE_MEM_SURFACE_2D_PITCH_SURFACE_2D_PITCH_LSB 0x0000
#define CVE_DSE_MEM_SURFACE_2D_PITCH_SURFACE_2D_PITCH_MSB 0x001f
#define CVE_DSE_MEM_SURFACE_2D_PITCH_SURFACE_2D_PITCH_RANGE 0x0020
#define CVE_DSE_MEM_SURFACE_2D_PITCH_SURFACE_2D_PITCH_MASK 0xffffffff
#define CVE_DSE_MEM_SURFACE_2D_PITCH_SURFACE_2D_PITCH_RESET_VALUE 0x00000001

/*  ------------------------------------------------------------------ */
/* */
#ifndef CVE_DSE_MEM_SURFACE_3D_PITCH_FLAG
#define CVE_DSE_MEM_SURFACE_3D_PITCH_FLAG
/* SURFACE_3D_PITCH desc:  Surface 3D Pitch*/
union CVE_DSE_MEM_SURFACE_3D_PITCH_t {
	struct {
uint32_t  SURFACE_3D_PITCH     :  32;
/*   Surface 3D Pitch - Distance */
/* in byte between two*/
/* consecutive 3D surface start*/
/* point Units Byte Min*/
/* SURFACE_3D_LENGTH **/
/* SURFACE_2D_PITCH Max 2^32-1*/
	}                                field;
uint32_t                         val;
};
#endif
#define CVE_DSE_MEM_SURFACE_3D_PITCH_OFFSET 0x0c
#define CVE_DSE_MEM_SURFACE_3D_PITCH_SCOPE 0x01
#define CVE_DSE_MEM_SURFACE_3D_PITCH_SIZE 32
#define CVE_DSE_MEM_SURFACE_3D_PITCH_BITFIELD_COUNT 0x01
#define CVE_DSE_MEM_SURFACE_3D_PITCH_RESET 0x00000001
#define CVE_DSE_MEM_SURFACE_3D_PITCH_SURFACE_3D_PITCH_LSB 0x0000
#define CVE_DSE_MEM_SURFACE_3D_PITCH_SURFACE_3D_PITCH_MSB 0x001f
#define CVE_DSE_MEM_SURFACE_3D_PITCH_SURFACE_3D_PITCH_RANGE 0x0020
#define CVE_DSE_MEM_SURFACE_3D_PITCH_SURFACE_3D_PITCH_MASK 0xffffffff
#define CVE_DSE_MEM_SURFACE_3D_PITCH_SURFACE_3D_PITCH_RESET_VALUE 0x00000001

/*  ------------------------------------------------------------------ */
/* */
#ifndef CVE_DSE_MEM_TILE_1D_LENGTH_FLAG
#define CVE_DSE_MEM_TILE_1D_LENGTH_FLAG
/* TILE_1D_LENGTH desc:  Tile 1D Length*/
union CVE_DSE_MEM_TILE_1D_LENGTH_t {
	struct {
uint32_t  TILE_1D_LENGTH       :  18;
/*   Tile First Dimension Length */
/* (Width) Units Byte Min 1 Max*/
/* 2^18-1*/
uint32_t  RSVD_0               :  14;
/*  Nebulon auto filled RSVD [31:18] */
	}                                field;
uint32_t                         val;
};
#endif
#define CVE_DSE_MEM_TILE_1D_LENGTH_OFFSET 0x4c
#define CVE_DSE_MEM_TILE_1D_LENGTH_SCOPE 0x01
#define CVE_DSE_MEM_TILE_1D_LENGTH_SIZE 32
#define CVE_DSE_MEM_TILE_1D_LENGTH_BITFIELD_COUNT 0x01
#define CVE_DSE_MEM_TILE_1D_LENGTH_RESET 0x0003ffff
#define CVE_DSE_MEM_TILE_1D_LENGTH_TILE_1D_LENGTH_LSB 0x0000
#define CVE_DSE_MEM_TILE_1D_LENGTH_TILE_1D_LENGTH_MSB 0x0011
#define CVE_DSE_MEM_TILE_1D_LENGTH_TILE_1D_LENGTH_RANGE 0x0012
#define CVE_DSE_MEM_TILE_1D_LENGTH_TILE_1D_LENGTH_MASK 0x0003ffff
#define CVE_DSE_MEM_TILE_1D_LENGTH_TILE_1D_LENGTH_RESET_VALUE 0x0003ffff

/*  ------------------------------------------------------------------ */
/* */
#ifndef CVE_DSE_MEM_TILE_2D_LENGTH_FLAG
#define CVE_DSE_MEM_TILE_2D_LENGTH_FLAG
/* TILE_2D_LENGTH desc:  Tile 2D Length*/
union CVE_DSE_MEM_TILE_2D_LENGTH_t {
	struct {
uint32_t  TILE_2D_LENGTH       :  18;
/*   Tile Second dimension length */
/* (Height) Units*/
/* SURFACE_1D_PITCH Min 1 Max*/
/* 2^18-1*/
uint32_t  RSVD_0               :  14;
/*  Nebulon auto filled RSVD [31:18] */
	}                                field;
uint32_t                         val;
};
#endif
#define CVE_DSE_MEM_TILE_2D_LENGTH_OFFSET 0x8c
#define CVE_DSE_MEM_TILE_2D_LENGTH_SCOPE 0x01
#define CVE_DSE_MEM_TILE_2D_LENGTH_SIZE 32
#define CVE_DSE_MEM_TILE_2D_LENGTH_BITFIELD_COUNT 0x01
#define CVE_DSE_MEM_TILE_2D_LENGTH_RESET 0x0003ffff
#define CVE_DSE_MEM_TILE_2D_LENGTH_TILE_2D_LENGTH_LSB 0x0000
#define CVE_DSE_MEM_TILE_2D_LENGTH_TILE_2D_LENGTH_MSB 0x0011
#define CVE_DSE_MEM_TILE_2D_LENGTH_TILE_2D_LENGTH_RANGE 0x0012
#define CVE_DSE_MEM_TILE_2D_LENGTH_TILE_2D_LENGTH_MASK 0x0003ffff
#define CVE_DSE_MEM_TILE_2D_LENGTH_TILE_2D_LENGTH_RESET_VALUE 0x0003ffff

/*  ------------------------------------------------------------------ */
/* */
#ifndef CVE_DSE_MEM_TILE_3D_LENGTH_FLAG
#define CVE_DSE_MEM_TILE_3D_LENGTH_FLAG
/* TILE_3D_LENGTH desc:  Tile 3D Length*/
union CVE_DSE_MEM_TILE_3D_LENGTH_t {
	struct {
uint32_t  TILE_3D_LENGTH       :  16;
/*   Tile Third Dimension Length */
/* (Depth) Units SURFACE_2D_PITCH*/
/* Min 1 Max 2^16-1*/
uint32_t  RSVD_0               :  16;
/*  Nebulon auto filled RSVD [31:16] */
	}                                field;
uint32_t                         val;
};
#endif
#define CVE_DSE_MEM_TILE_3D_LENGTH_OFFSET 0xcc
#define CVE_DSE_MEM_TILE_3D_LENGTH_SCOPE 0x01
#define CVE_DSE_MEM_TILE_3D_LENGTH_SIZE 32
#define CVE_DSE_MEM_TILE_3D_LENGTH_BITFIELD_COUNT 0x01
#define CVE_DSE_MEM_TILE_3D_LENGTH_RESET 0x00000001
#define CVE_DSE_MEM_TILE_3D_LENGTH_TILE_3D_LENGTH_LSB 0x0000
#define CVE_DSE_MEM_TILE_3D_LENGTH_TILE_3D_LENGTH_MSB 0x000f
#define CVE_DSE_MEM_TILE_3D_LENGTH_TILE_3D_LENGTH_RANGE 0x0010
#define CVE_DSE_MEM_TILE_3D_LENGTH_TILE_3D_LENGTH_MASK 0x0000ffff
#define CVE_DSE_MEM_TILE_3D_LENGTH_TILE_3D_LENGTH_RESET_VALUE 0x00000001

/*  ------------------------------------------------------------------ */
/* */
#ifndef CVE_DSE_MEM_TILE_4D_LENGTH_FLAG
#define CVE_DSE_MEM_TILE_4D_LENGTH_FLAG
/* TILE_4D_LENGTH desc:  Tile 4D Length*/
union CVE_DSE_MEM_TILE_4D_LENGTH_t {
	struct {
uint32_t  TILE_4D_LENGTH       :  16;
/*   Tile Fourth Dimension Length */
/* Units SURFACE_3D_PITCH Min 1*/
/* Max 2^16-1*/
uint32_t  RSVD_0               :  16;
/*  Nebulon auto filled RSVD [31:16] */
	}                                field;
uint32_t                         val;
};
#endif
#define CVE_DSE_MEM_TILE_4D_LENGTH_OFFSET 0x0c
#define CVE_DSE_MEM_TILE_4D_LENGTH_SCOPE 0x01
#define CVE_DSE_MEM_TILE_4D_LENGTH_SIZE 32
#define CVE_DSE_MEM_TILE_4D_LENGTH_BITFIELD_COUNT 0x01
#define CVE_DSE_MEM_TILE_4D_LENGTH_RESET 0x00000001
#define CVE_DSE_MEM_TILE_4D_LENGTH_TILE_4D_LENGTH_LSB 0x0000
#define CVE_DSE_MEM_TILE_4D_LENGTH_TILE_4D_LENGTH_MSB 0x000f
#define CVE_DSE_MEM_TILE_4D_LENGTH_TILE_4D_LENGTH_RANGE 0x0010
#define CVE_DSE_MEM_TILE_4D_LENGTH_TILE_4D_LENGTH_MASK 0x0000ffff
#define CVE_DSE_MEM_TILE_4D_LENGTH_TILE_4D_LENGTH_RESET_VALUE 0x00000001

/*  ------------------------------------------------------------------ */
/* */
#ifndef CVE_DSE_MEM_TILE_1D_STEP_FLAG
#define CVE_DSE_MEM_TILE_1D_STEP_FLAG
/* TILE_1D_STEP desc:  Tile 1D Step*/
union CVE_DSE_MEM_TILE_1D_STEP_t {
	struct {
uint32_t  TILE_1D_STEP         :  20;
/*   WalkX Step Length (Should be */
/* rename to STEP_1D_INDEX) Units*/
/* Byte Min 1 Max 2^20-1*/
uint32_t  RSVD_0               :  12;
/*  Nebulon auto filled RSVD [31:20] */
	}                                field;
uint32_t                         val;
};
#endif
#define CVE_DSE_MEM_TILE_1D_STEP_OFFSET 0x4c
#define CVE_DSE_MEM_TILE_1D_STEP_SCOPE 0x01
#define CVE_DSE_MEM_TILE_1D_STEP_SIZE 32
#define CVE_DSE_MEM_TILE_1D_STEP_BITFIELD_COUNT 0x01
#define CVE_DSE_MEM_TILE_1D_STEP_RESET 0x00000001
#define CVE_DSE_MEM_TILE_1D_STEP_TILE_1D_STEP_LSB 0x0000
#define CVE_DSE_MEM_TILE_1D_STEP_TILE_1D_STEP_MSB 0x0013
#define CVE_DSE_MEM_TILE_1D_STEP_TILE_1D_STEP_RANGE 0x0014
#define CVE_DSE_MEM_TILE_1D_STEP_TILE_1D_STEP_MASK 0x000fffff
#define CVE_DSE_MEM_TILE_1D_STEP_TILE_1D_STEP_RESET_VALUE 0x00000001

/*  ------------------------------------------------------------------ */
/* */
#ifndef CVE_DSE_MEM_TILE_2D_STEP_FLAG
#define CVE_DSE_MEM_TILE_2D_STEP_FLAG
/* TILE_2D_STEP desc:  Tile 2D Step*/
union CVE_DSE_MEM_TILE_2D_STEP_t {
	struct {
uint32_t  TILE_2D_STEP         :  20;
/*   WalkY Step Length (Should be */
/* rename to STEP_2D_INDEX) Units*/
/* SURFACE_1D_PITCH Min 1 Max*/
/* 2^20-1*/
uint32_t  RSVD_0               :  12;
/*  Nebulon auto filled RSVD [31:20] */
	}                                field;
uint32_t                         val;
};
#endif
#define CVE_DSE_MEM_TILE_2D_STEP_OFFSET 0x8c
#define CVE_DSE_MEM_TILE_2D_STEP_SCOPE 0x01
#define CVE_DSE_MEM_TILE_2D_STEP_SIZE 32
#define CVE_DSE_MEM_TILE_2D_STEP_BITFIELD_COUNT 0x01
#define CVE_DSE_MEM_TILE_2D_STEP_RESET 0x00000001
#define CVE_DSE_MEM_TILE_2D_STEP_TILE_2D_STEP_LSB 0x0000
#define CVE_DSE_MEM_TILE_2D_STEP_TILE_2D_STEP_MSB 0x0013
#define CVE_DSE_MEM_TILE_2D_STEP_TILE_2D_STEP_RANGE 0x0014
#define CVE_DSE_MEM_TILE_2D_STEP_TILE_2D_STEP_MASK 0x000fffff
#define CVE_DSE_MEM_TILE_2D_STEP_TILE_2D_STEP_RESET_VALUE 0x00000001

/*  ------------------------------------------------------------------ */
/* */
#ifndef CVE_DSE_MEM_TILE_3D_STEP_FLAG
#define CVE_DSE_MEM_TILE_3D_STEP_FLAG
/* TILE_3D_STEP desc:  Tile 3D Step*/
union CVE_DSE_MEM_TILE_3D_STEP_t {
	struct {
uint32_t  TILE_3D_STEP         :  16;
/*   WalkZ Step Length (Should be */
/* rename to STEP_3D_INDEX) Units*/
/* SURFACE_2D_PITCH Min 1 Max*/
/* 2^16-1*/
uint32_t  RSVD_0               :  16;
/*  Nebulon auto filled RSVD [31:16] */
	}                                field;
uint32_t                         val;
};
#endif
#define CVE_DSE_MEM_TILE_3D_STEP_OFFSET 0xcc
#define CVE_DSE_MEM_TILE_3D_STEP_SCOPE 0x01
#define CVE_DSE_MEM_TILE_3D_STEP_SIZE 32
#define CVE_DSE_MEM_TILE_3D_STEP_BITFIELD_COUNT 0x01
#define CVE_DSE_MEM_TILE_3D_STEP_RESET 0x00000001
#define CVE_DSE_MEM_TILE_3D_STEP_TILE_3D_STEP_LSB 0x0000
#define CVE_DSE_MEM_TILE_3D_STEP_TILE_3D_STEP_MSB 0x000f
#define CVE_DSE_MEM_TILE_3D_STEP_TILE_3D_STEP_RANGE 0x0010
#define CVE_DSE_MEM_TILE_3D_STEP_TILE_3D_STEP_MASK 0x0000ffff
#define CVE_DSE_MEM_TILE_3D_STEP_TILE_3D_STEP_RESET_VALUE 0x00000001

/*  ------------------------------------------------------------------ */
/* */
#ifndef CVE_DSE_MEM_TILE_4D_STEP_FLAG
#define CVE_DSE_MEM_TILE_4D_STEP_FLAG
/* TILE_4D_STEP desc:  Tile 4D Step*/
union CVE_DSE_MEM_TILE_4D_STEP_t {
	struct {
uint32_t  TILE_4D_STEP         :  16;
/*   Walk4D Step Length (Should be */
/* rename to STEP_4D_INDEX) Units*/
/* SURFACE_3D_PITCH Min 1 Max*/
/* 2^16-1*/
uint32_t  RSVD_0               :  16;
/*  Nebulon auto filled RSVD [31:16] */
	}                                field;
uint32_t                         val;
};
#endif
#define CVE_DSE_MEM_TILE_4D_STEP_OFFSET 0x0c
#define CVE_DSE_MEM_TILE_4D_STEP_SCOPE 0x01
#define CVE_DSE_MEM_TILE_4D_STEP_SIZE 32
#define CVE_DSE_MEM_TILE_4D_STEP_BITFIELD_COUNT 0x01
#define CVE_DSE_MEM_TILE_4D_STEP_RESET 0x00000001
#define CVE_DSE_MEM_TILE_4D_STEP_TILE_4D_STEP_LSB 0x0000
#define CVE_DSE_MEM_TILE_4D_STEP_TILE_4D_STEP_MSB 0x000f
#define CVE_DSE_MEM_TILE_4D_STEP_TILE_4D_STEP_RANGE 0x0010
#define CVE_DSE_MEM_TILE_4D_STEP_TILE_4D_STEP_MASK 0x0000ffff
#define CVE_DSE_MEM_TILE_4D_STEP_TILE_4D_STEP_RESET_VALUE 0x00000001

/*  ------------------------------------------------------------------ */
/* */
#ifndef CVE_DSE_MEM_TILE_1D_OFFSET_FLAG
#define CVE_DSE_MEM_TILE_1D_OFFSET_FLAG
/* TILE_1D_OFFSET desc:  Tile 1D Offset*/
union CVE_DSE_MEM_TILE_1D_OFFSET_t {
	struct {
uint32_t  TILE_1D_OFFSET       :  32;
/*   Tile Offset on First */
/* Dimension Units Byte Min -2^31*/
/* (Can Be Negative) Max 2^31-1*/
	}                                field;
uint32_t                         val;
};
#endif
#define CVE_DSE_MEM_TILE_1D_OFFSET_OFFSET 0x4c
#define CVE_DSE_MEM_TILE_1D_OFFSET_SCOPE 0x01
#define CVE_DSE_MEM_TILE_1D_OFFSET_SIZE 32
#define CVE_DSE_MEM_TILE_1D_OFFSET_BITFIELD_COUNT 0x01
#define CVE_DSE_MEM_TILE_1D_OFFSET_RESET 0x00000000
#define CVE_DSE_MEM_TILE_1D_OFFSET_TILE_1D_OFFSET_LSB 0x0000
#define CVE_DSE_MEM_TILE_1D_OFFSET_TILE_1D_OFFSET_MSB 0x001f
#define CVE_DSE_MEM_TILE_1D_OFFSET_TILE_1D_OFFSET_RANGE 0x0020
#define CVE_DSE_MEM_TILE_1D_OFFSET_TILE_1D_OFFSET_MASK 0xffffffff
#define CVE_DSE_MEM_TILE_1D_OFFSET_TILE_1D_OFFSET_RESET_VALUE 0x00000000

/*  ------------------------------------------------------------------ */
/* */
#ifndef CVE_DSE_MEM_TILE_2D_OFFSET_FLAG
#define CVE_DSE_MEM_TILE_2D_OFFSET_FLAG
/* TILE_2D_OFFSET desc:  Tile 2D Offset*/
union CVE_DSE_MEM_TILE_2D_OFFSET_t {
	struct {
uint32_t  TILE_2D_OFFSET       :  32;
/*   Tile Offset on Second */
/* Dimension Units*/
/* SURFACE_1D_PITCH Min -2^31*/
/* (Can Be Negative) Max 2^31-1*/
	}                                field;
uint32_t                         val;
};
#endif
#define CVE_DSE_MEM_TILE_2D_OFFSET_OFFSET 0x8c
#define CVE_DSE_MEM_TILE_2D_OFFSET_SCOPE 0x01
#define CVE_DSE_MEM_TILE_2D_OFFSET_SIZE 32
#define CVE_DSE_MEM_TILE_2D_OFFSET_BITFIELD_COUNT 0x01
#define CVE_DSE_MEM_TILE_2D_OFFSET_RESET 0x00000000
#define CVE_DSE_MEM_TILE_2D_OFFSET_TILE_2D_OFFSET_LSB 0x0000
#define CVE_DSE_MEM_TILE_2D_OFFSET_TILE_2D_OFFSET_MSB 0x001f
#define CVE_DSE_MEM_TILE_2D_OFFSET_TILE_2D_OFFSET_RANGE 0x0020
#define CVE_DSE_MEM_TILE_2D_OFFSET_TILE_2D_OFFSET_MASK 0xffffffff
#define CVE_DSE_MEM_TILE_2D_OFFSET_TILE_2D_OFFSET_RESET_VALUE 0x00000000

/*  ------------------------------------------------------------------ */
/* */
#ifndef CVE_DSE_MEM_TILE_3D_OFFSET_FLAG
#define CVE_DSE_MEM_TILE_3D_OFFSET_FLAG
/* TILE_3D_OFFSET desc:  Tile 3D Offset*/
union CVE_DSE_MEM_TILE_3D_OFFSET_t {
	struct {
uint32_t  TILE_3D_OFFSET       :  16;
/*   Tile Offset on Third */
/* Dimension Units*/
/* SURFACE_2D_PITCH Min -2^15*/
/* (Can Be Negative) Max 2^15-1*/
uint32_t  RSVD_0               :  16;
/*  Nebulon auto filled RSVD [31:16] */
	}                                field;
uint32_t                         val;
};
#endif
#define CVE_DSE_MEM_TILE_3D_OFFSET_OFFSET 0xcc
#define CVE_DSE_MEM_TILE_3D_OFFSET_SCOPE 0x01
#define CVE_DSE_MEM_TILE_3D_OFFSET_SIZE 32
#define CVE_DSE_MEM_TILE_3D_OFFSET_BITFIELD_COUNT 0x01
#define CVE_DSE_MEM_TILE_3D_OFFSET_RESET 0x00000000
#define CVE_DSE_MEM_TILE_3D_OFFSET_TILE_3D_OFFSET_LSB 0x0000
#define CVE_DSE_MEM_TILE_3D_OFFSET_TILE_3D_OFFSET_MSB 0x000f
#define CVE_DSE_MEM_TILE_3D_OFFSET_TILE_3D_OFFSET_RANGE 0x0010
#define CVE_DSE_MEM_TILE_3D_OFFSET_TILE_3D_OFFSET_MASK 0x0000ffff
#define CVE_DSE_MEM_TILE_3D_OFFSET_TILE_3D_OFFSET_RESET_VALUE 0x00000000

/*  ------------------------------------------------------------------ */
/* */
#ifndef CVE_DSE_MEM_TILE_4D_OFFSET_FLAG
#define CVE_DSE_MEM_TILE_4D_OFFSET_FLAG
/* TILE_4D_OFFSET desc:  Tile 4D Offset*/
union CVE_DSE_MEM_TILE_4D_OFFSET_t {
	struct {
uint32_t  TILE_4D_OFFSET       :  16;
/*   Tile Offset on Fourth */
/* Dimension Units*/
/* SURFACE_3D_PITCH Min -2^15*/
/* (Can Be Negative) Max 2^15-1*/
uint32_t  RSVD_0               :  16;
/*  Nebulon auto filled RSVD [31:16] */
	}                                field;
uint32_t                         val;
};
#endif
#define CVE_DSE_MEM_TILE_4D_OFFSET_OFFSET 0x0c
#define CVE_DSE_MEM_TILE_4D_OFFSET_SCOPE 0x01
#define CVE_DSE_MEM_TILE_4D_OFFSET_SIZE 32
#define CVE_DSE_MEM_TILE_4D_OFFSET_BITFIELD_COUNT 0x01
#define CVE_DSE_MEM_TILE_4D_OFFSET_RESET 0x00000000
#define CVE_DSE_MEM_TILE_4D_OFFSET_TILE_4D_OFFSET_LSB 0x0000
#define CVE_DSE_MEM_TILE_4D_OFFSET_TILE_4D_OFFSET_MSB 0x000f
#define CVE_DSE_MEM_TILE_4D_OFFSET_TILE_4D_OFFSET_RANGE 0x0010
#define CVE_DSE_MEM_TILE_4D_OFFSET_TILE_4D_OFFSET_MASK 0x0000ffff
#define CVE_DSE_MEM_TILE_4D_OFFSET_TILE_4D_OFFSET_RESET_VALUE 0x00000000

/*  ------------------------------------------------------------------ */
/* */
#ifndef CVE_DSE_MEM_TILE_FETCH_REORDER_Q_NUM_FLAG
#define CVE_DSE_MEM_TILE_FETCH_REORDER_Q_NUM_FLAG
/* TILE_FETCH_REORDER_Q_NUM desc:  Tile Fetch Reorder Q Num*/
union CVE_DSE_MEM_TILE_FETCH_REORDER_Q_NUM_t {
	struct {
uint32_t  TILE_FETCH_REORDER_Q_NUM :   4;
/*   Tile Fetch (AXI 2 SP) reorder */
/* Queue Number Units Num Min 0*/
/* Max 3*/
uint32_t  RSVD_0               :  28;
/*  Nebulon auto filled RSVD [31:4] */
	}                                field;
uint32_t                         val;
};
#endif
#define CVE_DSE_MEM_TILE_FETCH_REORDER_Q_NUM_OFFSET 0x4c
#define CVE_DSE_MEM_TILE_FETCH_REORDER_Q_NUM_SCOPE 0x01
#define CVE_DSE_MEM_TILE_FETCH_REORDER_Q_NUM_SIZE 32
#define CVE_DSE_MEM_TILE_FETCH_REORDER_Q_NUM_BITFIELD_COUNT 0x01
#define CVE_DSE_MEM_TILE_FETCH_REORDER_Q_NUM_RESET 0x00000000
#define CVE_DSE_MEM_TILE_FETCH_REORDER_Q_NUM_TILE_FETCH_REORDER_Q_NUM_LSB 0x0000
#define CVE_DSE_MEM_TILE_FETCH_REORDER_Q_NUM_TILE_FETCH_REORDER_Q_NUM_MSB 0x0003
#define CVE_DSE_MEM_TILE_FETCH_REORDER_Q_NUM_TILE_FETCH_REORDER_Q_NUM_RANGE 0x0004
#define CVE_DSE_MEM_TILE_FETCH_REORDER_Q_NUM_TILE_FETCH_REORDER_Q_NUM_MASK 0x0000000f
#define CVE_DSE_MEM_TILE_FETCH_REORDER_Q_NUM_TILE_FETCH_REORDER_Q_NUM_RESET_VALUE 0x00000000

/*  ------------------------------------------------------------------ */
/* */
#ifndef CVE_DSE_MEM_TILE_PADDING_CONFIG_FLAG
#define CVE_DSE_MEM_TILE_PADDING_CONFIG_FLAG
/* TILE_PADDING_CONFIG desc:  Tile Padding Config*/
union CVE_DSE_MEM_TILE_PADDING_CONFIG_t {
	struct {
uint32_t  TILE_1D_PADDING_LSB_EN :   1;
/*   Enable padding partial out of */
/* surface tiles on the 1D LSB*/
/* side Units Boolean Min 0 Max 1*/
uint32_t  TILE_1D_PADDING_MSB_EN :   1;
/*   Enable padding partial out of */
/* surface tiles on the 1D MSB*/
/* side Units Boolean Min 0 Max 1*/
uint32_t  TILE_2D_PADDING_LSB_EN :   1;
/*   Enable padding partial out of */
/* surface tiles on the 2D LSB*/
/* side Units Boolean Min 0 Max 1*/
uint32_t  TILE_2D_PADDING_MSB_EN :   1;
/*   Enable padding partial out of */
/* surface tiles on the 2D MSB*/
/* side Units Boolean Min 0 Max 1*/
uint32_t  TILE_3D_PADDING_LSB_EN :   1;
/*   Enable padding partial out of */
/* surface tiles on the 3D LSB*/
/* side Units Boolean Min 0 Max 1*/
uint32_t  TILE_3D_PADDING_MSB_EN :   1;
/*   Enable padding partial out of */
/* surface tiles on the 3D MSB*/
/* side Units Boolean Min 0 Max 1*/
uint32_t  RSVD_0               :   2;
/*  Nebulon auto filled RSVD [7:6] */
uint32_t  GLOBAL_PADDING_WRITE_DISABLE :   1;
/*   Avoide writing the padding */
/* data to SP. Units Boolean Min*/
/* 0 Max 1*/
uint32_t  RSVD_1               :  23;
/*  Nebulon auto filled RSVD [31:9] */
	}                                field;
uint32_t                         val;
};
#endif
#define CVE_DSE_MEM_TILE_PADDING_CONFIG_OFFSET 0x8c
#define CVE_DSE_MEM_TILE_PADDING_CONFIG_SCOPE 0x01
#define CVE_DSE_MEM_TILE_PADDING_CONFIG_SIZE 32
#define CVE_DSE_MEM_TILE_PADDING_CONFIG_BITFIELD_COUNT 0x07
#define CVE_DSE_MEM_TILE_PADDING_CONFIG_RESET 0x00000000
#define CVE_DSE_MEM_TILE_PADDING_CONFIG_TILE_1D_PADDING_LSB_EN_LSB 0x0000
#define CVE_DSE_MEM_TILE_PADDING_CONFIG_TILE_1D_PADDING_LSB_EN_MSB 0x0000
#define CVE_DSE_MEM_TILE_PADDING_CONFIG_TILE_1D_PADDING_LSB_EN_RANGE 0x0001
#define CVE_DSE_MEM_TILE_PADDING_CONFIG_TILE_1D_PADDING_LSB_EN_MASK 0x00000001
#define CVE_DSE_MEM_TILE_PADDING_CONFIG_TILE_1D_PADDING_LSB_EN_RESET_VALUE 0x00000000
#define CVE_DSE_MEM_TILE_PADDING_CONFIG_TILE_1D_PADDING_MSB_EN_LSB 0x0001
#define CVE_DSE_MEM_TILE_PADDING_CONFIG_TILE_1D_PADDING_MSB_EN_MSB 0x0001
#define CVE_DSE_MEM_TILE_PADDING_CONFIG_TILE_1D_PADDING_MSB_EN_RANGE 0x0001
#define CVE_DSE_MEM_TILE_PADDING_CONFIG_TILE_1D_PADDING_MSB_EN_MASK 0x00000002
#define CVE_DSE_MEM_TILE_PADDING_CONFIG_TILE_1D_PADDING_MSB_EN_RESET_VALUE 0x00000000
#define CVE_DSE_MEM_TILE_PADDING_CONFIG_TILE_2D_PADDING_LSB_EN_LSB 0x0002
#define CVE_DSE_MEM_TILE_PADDING_CONFIG_TILE_2D_PADDING_LSB_EN_MSB 0x0002
#define CVE_DSE_MEM_TILE_PADDING_CONFIG_TILE_2D_PADDING_LSB_EN_RANGE 0x0001
#define CVE_DSE_MEM_TILE_PADDING_CONFIG_TILE_2D_PADDING_LSB_EN_MASK 0x00000004
#define CVE_DSE_MEM_TILE_PADDING_CONFIG_TILE_2D_PADDING_LSB_EN_RESET_VALUE 0x00000000
#define CVE_DSE_MEM_TILE_PADDING_CONFIG_TILE_2D_PADDING_MSB_EN_LSB 0x0003
#define CVE_DSE_MEM_TILE_PADDING_CONFIG_TILE_2D_PADDING_MSB_EN_MSB 0x0003
#define CVE_DSE_MEM_TILE_PADDING_CONFIG_TILE_2D_PADDING_MSB_EN_RANGE 0x0001
#define CVE_DSE_MEM_TILE_PADDING_CONFIG_TILE_2D_PADDING_MSB_EN_MASK 0x00000008
#define CVE_DSE_MEM_TILE_PADDING_CONFIG_TILE_2D_PADDING_MSB_EN_RESET_VALUE 0x00000000
#define CVE_DSE_MEM_TILE_PADDING_CONFIG_TILE_3D_PADDING_LSB_EN_LSB 0x0004
#define CVE_DSE_MEM_TILE_PADDING_CONFIG_TILE_3D_PADDING_LSB_EN_MSB 0x0004
#define CVE_DSE_MEM_TILE_PADDING_CONFIG_TILE_3D_PADDING_LSB_EN_RANGE 0x0001
#define CVE_DSE_MEM_TILE_PADDING_CONFIG_TILE_3D_PADDING_LSB_EN_MASK 0x00000010
#define CVE_DSE_MEM_TILE_PADDING_CONFIG_TILE_3D_PADDING_LSB_EN_RESET_VALUE 0x00000000
#define CVE_DSE_MEM_TILE_PADDING_CONFIG_TILE_3D_PADDING_MSB_EN_LSB 0x0005
#define CVE_DSE_MEM_TILE_PADDING_CONFIG_TILE_3D_PADDING_MSB_EN_MSB 0x0005
#define CVE_DSE_MEM_TILE_PADDING_CONFIG_TILE_3D_PADDING_MSB_EN_RANGE 0x0001
#define CVE_DSE_MEM_TILE_PADDING_CONFIG_TILE_3D_PADDING_MSB_EN_MASK 0x00000020
#define CVE_DSE_MEM_TILE_PADDING_CONFIG_TILE_3D_PADDING_MSB_EN_RESET_VALUE 0x00000000
#define CVE_DSE_MEM_TILE_PADDING_CONFIG_GLOBAL_PADDING_WRITE_DISABLE_LSB 0x0008
#define CVE_DSE_MEM_TILE_PADDING_CONFIG_GLOBAL_PADDING_WRITE_DISABLE_MSB 0x0008
#define CVE_DSE_MEM_TILE_PADDING_CONFIG_GLOBAL_PADDING_WRITE_DISABLE_RANGE 0x0001
#define CVE_DSE_MEM_TILE_PADDING_CONFIG_GLOBAL_PADDING_WRITE_DISABLE_MASK 0x00000100
#define CVE_DSE_MEM_TILE_PADDING_CONFIG_GLOBAL_PADDING_WRITE_DISABLE_RESET_VALUE 0x00000000

/*  ------------------------------------------------------------------ */
/* */
#ifndef CVE_DSE_MEM_TILE_PADDING_DATA_FLAG
#define CVE_DSE_MEM_TILE_PADDING_DATA_FLAG
/* TILE_PADDING_DATA desc:  Tile Padding Data*/
union CVE_DSE_MEM_TILE_PADDING_DATA_t {
	struct {
uint32_t  TILE_PADDING_DATA    :  16;
/*   Tile Padding Values Units */
/* Data Min 0 Max 2^16-1*/
uint32_t  RSVD_0               :  16;
/*  Nebulon auto filled RSVD [31:16] */
	}                                field;
uint32_t                         val;
};
#endif
#define CVE_DSE_MEM_TILE_PADDING_DATA_OFFSET 0xcc
#define CVE_DSE_MEM_TILE_PADDING_DATA_SCOPE 0x01
#define CVE_DSE_MEM_TILE_PADDING_DATA_SIZE 32
#define CVE_DSE_MEM_TILE_PADDING_DATA_BITFIELD_COUNT 0x01
#define CVE_DSE_MEM_TILE_PADDING_DATA_RESET 0x00000000
#define CVE_DSE_MEM_TILE_PADDING_DATA_TILE_PADDING_DATA_LSB 0x0000
#define CVE_DSE_MEM_TILE_PADDING_DATA_TILE_PADDING_DATA_MSB 0x000f
#define CVE_DSE_MEM_TILE_PADDING_DATA_TILE_PADDING_DATA_RANGE 0x0010
#define CVE_DSE_MEM_TILE_PADDING_DATA_TILE_PADDING_DATA_MASK 0x0000ffff
#define CVE_DSE_MEM_TILE_PADDING_DATA_TILE_PADDING_DATA_RESET_VALUE 0x00000000

/*  ------------------------------------------------------------------ */
/* */
#ifndef CVE_DSE_MEM_AXI_READ_CONFIG_FLAG
#define CVE_DSE_MEM_AXI_READ_CONFIG_FLAG
/* AXI_READ_CONFIG desc:  Axi Read Config*/
union CVE_DSE_MEM_AXI_READ_CONFIG_t {
	struct {
uint32_t  AXI_ARUSER           :  12;
/*   AXI_ARUSER[ 0] - Reserved */
/* AXI_ARUSER[ 1] - Flush*/
/* AXI_ARUSER[ 2] - Bypass*/
/* AXI_ARUSER[ 3] - Reserved*/
/* AXI_ARUSER[ 8:4] - Stream ID*/
/* (ATU_ID) AXI_ARUSER[11:9] -*/
/* Reserved Units Num Min 0 Max*/
/* 2^12-1*/
uint32_t  RSVD_0               :   4;
/*  Nebulon auto filled RSVD [15:12] */
uint32_t  AXI_ARCACHE          :   4;
/*   AXI Read cache attributes */
/* Units Num Min 0 Max 2^4-1*/
uint32_t  AXI_RD_MAX_BURST_LOG2 :   3;
/*   Log2(AXI Read max burst */
/* length) == Log2(1,2,4,8,16)*/
/* Units 2**() Min 0 Max 4*/
uint32_t  RSVD_1               :   1;
/*  Nebulon auto filled RSVD [23:23] */
uint32_t  AXI_PREFETCH_ARCACHE :   4;
/*   AXI prefetch Read cache */
/* attributes Units Num Min 0 Max*/
/* 2^4-1*/
uint32_t  AXI_PREFETCH_MAX_BURST_LOG2 :   3;
/*   Log2(AXI prefetch Read max */
/* burst length) ==*/
/* Log2(1,2,4,8,16) Units 2**()*/
/* Min 0 Max 4*/
uint32_t  RSVD_2               :   1;
/*  Nebulon auto filled RSVD [31:31] */
	}                                field;
uint32_t                         val;
};
#endif
#define CVE_DSE_MEM_AXI_READ_CONFIG_OFFSET 0x0c
#define CVE_DSE_MEM_AXI_READ_CONFIG_SCOPE 0x01
#define CVE_DSE_MEM_AXI_READ_CONFIG_SIZE 32
#define CVE_DSE_MEM_AXI_READ_CONFIG_BITFIELD_COUNT 0x05
#define CVE_DSE_MEM_AXI_READ_CONFIG_RESET 0x20200000
#define CVE_DSE_MEM_AXI_READ_CONFIG_AXI_ARUSER_LSB 0x0000
#define CVE_DSE_MEM_AXI_READ_CONFIG_AXI_ARUSER_MSB 0x000b
#define CVE_DSE_MEM_AXI_READ_CONFIG_AXI_ARUSER_RANGE 0x000c
#define CVE_DSE_MEM_AXI_READ_CONFIG_AXI_ARUSER_MASK 0x00000fff
#define CVE_DSE_MEM_AXI_READ_CONFIG_AXI_ARUSER_RESET_VALUE 0x00000000
#define CVE_DSE_MEM_AXI_READ_CONFIG_AXI_ARCACHE_LSB 0x0010
#define CVE_DSE_MEM_AXI_READ_CONFIG_AXI_ARCACHE_MSB 0x0013
#define CVE_DSE_MEM_AXI_READ_CONFIG_AXI_ARCACHE_RANGE 0x0004
#define CVE_DSE_MEM_AXI_READ_CONFIG_AXI_ARCACHE_MASK 0x000f0000
#define CVE_DSE_MEM_AXI_READ_CONFIG_AXI_ARCACHE_RESET_VALUE 0x00000000
#define CVE_DSE_MEM_AXI_READ_CONFIG_AXI_RD_MAX_BURST_LOG2_LSB 0x0014
#define CVE_DSE_MEM_AXI_READ_CONFIG_AXI_RD_MAX_BURST_LOG2_MSB 0x0016
#define CVE_DSE_MEM_AXI_READ_CONFIG_AXI_RD_MAX_BURST_LOG2_RANGE 0x0003
#define CVE_DSE_MEM_AXI_READ_CONFIG_AXI_RD_MAX_BURST_LOG2_MASK 0x00700000
#define CVE_DSE_MEM_AXI_READ_CONFIG_AXI_RD_MAX_BURST_LOG2_RESET_VALUE 0x00000002
#define CVE_DSE_MEM_AXI_READ_CONFIG_AXI_PREFETCH_ARCACHE_LSB 0x0018
#define CVE_DSE_MEM_AXI_READ_CONFIG_AXI_PREFETCH_ARCACHE_MSB 0x001b
#define CVE_DSE_MEM_AXI_READ_CONFIG_AXI_PREFETCH_ARCACHE_RANGE 0x0004
#define CVE_DSE_MEM_AXI_READ_CONFIG_AXI_PREFETCH_ARCACHE_MASK 0x0f000000
#define CVE_DSE_MEM_AXI_READ_CONFIG_AXI_PREFETCH_ARCACHE_RESET_VALUE 0x00000000
#define CVE_DSE_MEM_AXI_READ_CONFIG_AXI_PREFETCH_MAX_BURST_LOG2_LSB 0x001c
#define CVE_DSE_MEM_AXI_READ_CONFIG_AXI_PREFETCH_MAX_BURST_LOG2_MSB 0x001e
#define CVE_DSE_MEM_AXI_READ_CONFIG_AXI_PREFETCH_MAX_BURST_LOG2_RANGE 0x0003
#define CVE_DSE_MEM_AXI_READ_CONFIG_AXI_PREFETCH_MAX_BURST_LOG2_MASK 0x70000000
#define CVE_DSE_MEM_AXI_READ_CONFIG_AXI_PREFETCH_MAX_BURST_LOG2_RESET_VALUE 0x00000002

/*  ------------------------------------------------------------------ */
/* */
#ifndef CVE_DSE_MEM_AXI_WRITE_CONFIG_FLAG
#define CVE_DSE_MEM_AXI_WRITE_CONFIG_FLAG
/* AXI_WRITE_CONFIG desc:  Axi Write Config*/
union CVE_DSE_MEM_AXI_WRITE_CONFIG_t {
	struct {
uint32_t  AXI_AWUSER           :  12;
/*   AXI_AWUSER[ 0] - Reserved */
/* AXI_AWUSER[ 1] - Flush*/
/* AXI_AWUSER[ 2] - Bypass*/
/* AXI_AWUSER[ 3] - Reserved*/
/* AXI_AWUSER[ 8:4] - Stream ID*/
/* (ATU_ID) AXI_AWUSER[11:9] -*/
/* Reserved Units Num Min 0 Max*/
/* 2^12-1*/
uint32_t  RSVD_0               :   4;
/*  Nebulon auto filled RSVD [15:12] */
uint32_t  AXI_AWCACHE          :   4;
/*   AXI Write cache attributes */
/* Units Num Min 0 Max 2^4-1*/
uint32_t  AXI_WR_MAX_BURST_LOG2 :   3;
/*   Log2(AXI Write max burst */
/* length) == Log2(1,2,4,8,16)*/
/* Units 2**() Min 0 Max 4*/
uint32_t  RSVD_1               :   1;
/*  Nebulon auto filled RSVD [23:23] */
uint32_t  AXI_WR_MIXED_BURST_EN :   1;
/*   Enable Burst with variant */
/* Byte Mask during the burst*/
/* (can vary on start end end)*/
/* Units Boolean Min 0 Max 1*/
uint32_t  RSVD_2               :   7;
/*  Nebulon auto filled RSVD [31:25] */
	}                                field;
uint32_t                         val;
};
#endif
#define CVE_DSE_MEM_AXI_WRITE_CONFIG_OFFSET 0x4c
#define CVE_DSE_MEM_AXI_WRITE_CONFIG_SCOPE 0x01
#define CVE_DSE_MEM_AXI_WRITE_CONFIG_SIZE 32
#define CVE_DSE_MEM_AXI_WRITE_CONFIG_BITFIELD_COUNT 0x04
#define CVE_DSE_MEM_AXI_WRITE_CONFIG_RESET 0x00200000
#define CVE_DSE_MEM_AXI_WRITE_CONFIG_AXI_AWUSER_LSB 0x0000
#define CVE_DSE_MEM_AXI_WRITE_CONFIG_AXI_AWUSER_MSB 0x000b
#define CVE_DSE_MEM_AXI_WRITE_CONFIG_AXI_AWUSER_RANGE 0x000c
#define CVE_DSE_MEM_AXI_WRITE_CONFIG_AXI_AWUSER_MASK 0x00000fff
#define CVE_DSE_MEM_AXI_WRITE_CONFIG_AXI_AWUSER_RESET_VALUE 0x00000000
#define CVE_DSE_MEM_AXI_WRITE_CONFIG_AXI_AWCACHE_LSB 0x0010
#define CVE_DSE_MEM_AXI_WRITE_CONFIG_AXI_AWCACHE_MSB 0x0013
#define CVE_DSE_MEM_AXI_WRITE_CONFIG_AXI_AWCACHE_RANGE 0x0004
#define CVE_DSE_MEM_AXI_WRITE_CONFIG_AXI_AWCACHE_MASK 0x000f0000
#define CVE_DSE_MEM_AXI_WRITE_CONFIG_AXI_AWCACHE_RESET_VALUE 0x00000000
#define CVE_DSE_MEM_AXI_WRITE_CONFIG_AXI_WR_MAX_BURST_LOG2_LSB 0x0014
#define CVE_DSE_MEM_AXI_WRITE_CONFIG_AXI_WR_MAX_BURST_LOG2_MSB 0x0016
#define CVE_DSE_MEM_AXI_WRITE_CONFIG_AXI_WR_MAX_BURST_LOG2_RANGE 0x0003
#define CVE_DSE_MEM_AXI_WRITE_CONFIG_AXI_WR_MAX_BURST_LOG2_MASK 0x00700000
#define CVE_DSE_MEM_AXI_WRITE_CONFIG_AXI_WR_MAX_BURST_LOG2_RESET_VALUE 0x00000002
#define CVE_DSE_MEM_AXI_WRITE_CONFIG_AXI_WR_MIXED_BURST_EN_LSB 0x0018
#define CVE_DSE_MEM_AXI_WRITE_CONFIG_AXI_WR_MIXED_BURST_EN_MSB 0x0018
#define CVE_DSE_MEM_AXI_WRITE_CONFIG_AXI_WR_MIXED_BURST_EN_RANGE 0x0001
#define CVE_DSE_MEM_AXI_WRITE_CONFIG_AXI_WR_MIXED_BURST_EN_MASK 0x01000000
#define CVE_DSE_MEM_AXI_WRITE_CONFIG_AXI_WR_MIXED_BURST_EN_RESET_VALUE 0x00000000

/*  ------------------------------------------------------------------ */
/* */
#ifndef CVE_DSE_MEM_AXI_AUSER_EXTEND_FLAG
#define CVE_DSE_MEM_AXI_AUSER_EXTEND_FLAG
/* AXI_AUSER_EXTEND desc:  Axi Auser Extend*/
union CVE_DSE_MEM_AXI_AUSER_EXTEND_t {
	struct {
uint32_t  AXI_AUSER_EXTEND     :  16;
/*   AXI_AUSER_EXTEND[ 1: 0] - */
/* CLOS - LLC Class Service*/
/* AXI_AUSER_EXTEND[ 2] -*/
/* Reserved CLOS*/
/* AXI_AUSER_EXTEND[ 3] -*/
/* Bridge_Priority - Transaction*/
/* priority in the AXI2IDI bridge*/
/* AXI_AUSER_EXTEND[ 5: 4] -*/
/* Reserved Bridge_Priority*/
/* AXI_AUSER_EXTEND[ 7: 6] - NT -*/
/* LLC NT AXI_AUSER_EXTEND[ 8] -*/
/* Prefetch_LLC - LLC prefetch -*/
/* Set by DSE HW*/
/* AXI_AUSER_EXTEND[ 9] -*/
/* Prefetch_LLC_Fake_Data - If*/
/* LLC prefetch then return fake*/
/* data (all zeros)*/
/* AXI_AUSER_EXTEND[11:10] -*/
/* Reserved_Prefetch*/
/* AXI_AUSER_EXTEND[12:12] -*/
/* Shared read by both ICEs in*/
/* the ICEBO. Ignored by ICEBO if*/
/* Prefetch_LLC is set for this*/
/* transaction. Unset by GeCoe*/
/* for meta-data*/
/* AXI_AUSER_EXTEND[13:13] -*/
/* Forces caching in a*/
/* ICEBO-local bank of the LLC*/
/* AXI_AUSER_EXTEND[15:14] -*/
/* Reserved Units Num Min 0 Max*/
/* 2^16-1*/
uint32_t  RSVD_0               :  16;
/*  Nebulon auto filled RSVD [31:16] */
	}                                field;
uint32_t                         val;
};
#endif
#define CVE_DSE_MEM_AXI_AUSER_EXTEND_OFFSET 0x8c
#define CVE_DSE_MEM_AXI_AUSER_EXTEND_SCOPE 0x01
#define CVE_DSE_MEM_AXI_AUSER_EXTEND_SIZE 32
#define CVE_DSE_MEM_AXI_AUSER_EXTEND_BITFIELD_COUNT 0x01
#define CVE_DSE_MEM_AXI_AUSER_EXTEND_RESET 0x00000000
#define CVE_DSE_MEM_AXI_AUSER_EXTEND_AXI_AUSER_EXTEND_LSB 0x0000
#define CVE_DSE_MEM_AXI_AUSER_EXTEND_AXI_AUSER_EXTEND_MSB 0x000f
#define CVE_DSE_MEM_AXI_AUSER_EXTEND_AXI_AUSER_EXTEND_RANGE 0x0010
#define CVE_DSE_MEM_AXI_AUSER_EXTEND_AXI_AUSER_EXTEND_MASK 0x0000ffff
#define CVE_DSE_MEM_AXI_AUSER_EXTEND_AXI_AUSER_EXTEND_RESET_VALUE 0x00000000

/*  ------------------------------------------------------------------ */
/* */
#ifndef CVE_DSE_MEM_AXI_MAX_INFLIGHT_FLAG
#define CVE_DSE_MEM_AXI_MAX_INFLIGHT_FLAG
/* AXI_MAX_INFLIGHT desc:  Axi Max Inflight*/
union CVE_DSE_MEM_AXI_MAX_INFLIGHT_t {
	struct {
uint32_t  AXI_MAX_WRITE_INFLIGHT :   8;
/*   Set limit to the AXI Write */
/* Inflight the DSE can produce*/
/* Units Number Min 1 Max 64*/
uint32_t  AXI_MAX_READ_INFLIGHT :   8;
/*   Set limit to the AXI Read */
/* Inflight the DSE can produce*/
/* Units Number Min 1 Max 64*/
uint32_t  RSVD_0               :  16;
/*  Nebulon auto filled RSVD [31:16] */
	}                                field;
uint32_t                         val;
};
#endif
#define CVE_DSE_MEM_AXI_MAX_INFLIGHT_OFFSET 0xcc
#define CVE_DSE_MEM_AXI_MAX_INFLIGHT_SCOPE 0x01
#define CVE_DSE_MEM_AXI_MAX_INFLIGHT_SIZE 32
#define CVE_DSE_MEM_AXI_MAX_INFLIGHT_BITFIELD_COUNT 0x02
#define CVE_DSE_MEM_AXI_MAX_INFLIGHT_RESET 0x00004040
#define CVE_DSE_MEM_AXI_MAX_INFLIGHT_AXI_MAX_WRITE_INFLIGHT_LSB 0x0000
#define CVE_DSE_MEM_AXI_MAX_INFLIGHT_AXI_MAX_WRITE_INFLIGHT_MSB 0x0007
#define CVE_DSE_MEM_AXI_MAX_INFLIGHT_AXI_MAX_WRITE_INFLIGHT_RANGE 0x0008
#define CVE_DSE_MEM_AXI_MAX_INFLIGHT_AXI_MAX_WRITE_INFLIGHT_MASK 0x000000ff
#define CVE_DSE_MEM_AXI_MAX_INFLIGHT_AXI_MAX_WRITE_INFLIGHT_RESET_VALUE 0x00000040
#define CVE_DSE_MEM_AXI_MAX_INFLIGHT_AXI_MAX_READ_INFLIGHT_LSB 0x0008
#define CVE_DSE_MEM_AXI_MAX_INFLIGHT_AXI_MAX_READ_INFLIGHT_MSB 0x000f
#define CVE_DSE_MEM_AXI_MAX_INFLIGHT_AXI_MAX_READ_INFLIGHT_RANGE 0x0008
#define CVE_DSE_MEM_AXI_MAX_INFLIGHT_AXI_MAX_READ_INFLIGHT_MASK 0x0000ff00
#define CVE_DSE_MEM_AXI_MAX_INFLIGHT_AXI_MAX_READ_INFLIGHT_RESET_VALUE 0x00000040

/*  ------------------------------------------------------------------ */
/* */
#ifndef CVE_DSE_MEM_NEAR_ZERO_TH_SETTING_FLAG
#define CVE_DSE_MEM_NEAR_ZERO_TH_SETTING_FLAG
/* NEAR_ZERO_TH_SETTING desc:  Near Zero Th Setting*/
union CVE_DSE_MEM_NEAR_ZERO_TH_SETTING_t {
	struct {
uint32_t  NEAR_ZERO_TH_MODE    :   2;
/*   0 : No Near Zero Threshold 1 */
/* : Near Zero Threshold on HP FP*/
/* 16 bit 2 : Near Zero Threshold*/
/* on Signed 8 bit 3 : Near Zero*/
/* Threshold on Unsigned 8 bit*/
/* Units Num Min 0 Max 3*/
uint32_t  RSVD_0               :  14;
/*  Nebulon auto filled RSVD [15:2] */
uint32_t  NEAR_ZERO_THRESHOLD  :  16;
/*   When Zero Threshold, If */
/* activate all pixel transferred*/
/* from SP to external memory*/
/* will be set to zero if their*/
/* absolute value is below the*/
/* threshold, this parameter can*/
/* be FP HP or 8 bit integer,*/
/* depends on the pixel type and*/
/* it should be positive. Units*/
/* FP HP/Integer Min 0 Max 2^16-1*/
	}                                field;
uint32_t                         val;
};
#endif
#define CVE_DSE_MEM_NEAR_ZERO_TH_SETTING_OFFSET 0xd0
#define CVE_DSE_MEM_NEAR_ZERO_TH_SETTING_SCOPE 0x01
#define CVE_DSE_MEM_NEAR_ZERO_TH_SETTING_SIZE 32
#define CVE_DSE_MEM_NEAR_ZERO_TH_SETTING_BITFIELD_COUNT 0x02
#define CVE_DSE_MEM_NEAR_ZERO_TH_SETTING_RESET 0x00000000
#define CVE_DSE_MEM_NEAR_ZERO_TH_SETTING_NEAR_ZERO_TH_MODE_LSB 0x0000
#define CVE_DSE_MEM_NEAR_ZERO_TH_SETTING_NEAR_ZERO_TH_MODE_MSB 0x0001
#define CVE_DSE_MEM_NEAR_ZERO_TH_SETTING_NEAR_ZERO_TH_MODE_RANGE 0x0002
#define CVE_DSE_MEM_NEAR_ZERO_TH_SETTING_NEAR_ZERO_TH_MODE_MASK 0x00000003
#define CVE_DSE_MEM_NEAR_ZERO_TH_SETTING_NEAR_ZERO_TH_MODE_RESET_VALUE 0x00000000
#define CVE_DSE_MEM_NEAR_ZERO_TH_SETTING_NEAR_ZERO_THRESHOLD_LSB 0x0010
#define CVE_DSE_MEM_NEAR_ZERO_TH_SETTING_NEAR_ZERO_THRESHOLD_MSB 0x001f
#define CVE_DSE_MEM_NEAR_ZERO_TH_SETTING_NEAR_ZERO_THRESHOLD_RANGE 0x0010
#define CVE_DSE_MEM_NEAR_ZERO_TH_SETTING_NEAR_ZERO_THRESHOLD_MASK 0xffff0000
#define CVE_DSE_MEM_NEAR_ZERO_TH_SETTING_NEAR_ZERO_THRESHOLD_RESET_VALUE 0x00000000

/*  ------------------------------------------------------------------ */
/* */
#ifndef CVE_DSE_MEM_WEIGHT_LUT_SETTING_FLAG
#define CVE_DSE_MEM_WEIGHT_LUT_SETTING_FLAG
/* WEIGHT_LUT_SETTING desc:  Weight Lut Setting*/
union CVE_DSE_MEM_WEIGHT_LUT_SETTING_t {
	struct {
uint32_t  DECOMPRESSION_MODE   :   1;
/*   0 : No Decompression 1 : */
/* Weight Decompression. Only for*/
/* fetching data from AXI to the*/
/* SP Units Num Min 0 Max 1*/
uint32_t  RSVD_0               :   1;
/*  Nebulon auto filled RSVD [1:1] */
uint32_t  PIXEL_SIZE_IS_16     :   1;
/*   0 : 8 Bit 1: 16 Bit Units Num */
/* Min 0 Max 1*/
uint32_t  RSVD_1               :   1;
/*  Nebulon auto filled RSVD [3:3] */
uint32_t  WEIGHT_COM_DATA_SIZE :   2;
/*   Set The Input Data Size */
/* (Compression Ratio) 0 : 1 Bit;*/
/* LUT_ADDRESS =*/
/* (WEIGHT_LUT_MSB[6:0],InputData[*/
/* 0]) 1: 2 Bit; LUT_ADDRESS =*/
/* (WEIGHT_LUT_MSB[5:0],InputData[1:0])*/
/* 2: 4 Bit; LUT_ADDRESS =*/
/* (WEIGHT_LUT_MSB[3:0],InputData[3:0])*/
/* 3: 8 Bit; LUT_ADDRESS = (*/
/* InputData[7:0]) Units Num Min*/
/* 0 Max 3*/
uint32_t  RSVD_2               :   2;
/*  Nebulon auto filled RSVD [7:6] */
uint32_t  WEIGHT_LUT_MSB_BASE  :   7;
/*   Manual LUT Msb Register - Set */
/* the Base address of the*/
/* surface within the LUT. Units*/
/* Num Min 0 Max 2^7-1*/
uint32_t  RSVD_3               :   1;
/*  Nebulon auto filled RSVD [15:15] */
uint32_t  WEIGHT_LUT_MSB_OFFSET_SRC :   2;
/*   Select the source of LUT */
/* address MSB's offset part*/
/* (LSB's are takes from the*/
/* Input Data) 0: LUT Msb = 0 1:*/
/* LUT Msb = 2D Position/Index 2:*/
/* LUT Msb = 3D Position/Index*/
/* Units Num Min 0 Max 2*/
uint32_t  RSVD_4               :   2;
/*  Nebulon auto filled RSVD [19:18] */
uint32_t  WEIGHT_LUT_MSB_OFFSET_SHIFTR :   6;
/*   An Option to play with the */
/* MSB_OFFSET Resolution by*/
/* removing LSB's from it.*/
/* LUT_ADDR[WEIGHT_COM_DATA_SIZE-1:0]*/
/* = Input Date*/
/* LUT_ADDR[7:WEIGHT_COM_DATA_SIZE]*/
/* = WEIGHT_LUT_MSB_BASE +*/
/* (0/2D_Position/3D_Position >>*/
/* WEIGHT_LUT_MSB_OFFSET_SHIFTR)*/
/* Units Num Min 0 Max 17*/
uint32_t  RSVD_5               :   6;
/*  Nebulon auto filled RSVD [31:26] */
	}                                field;
uint32_t                         val;
};
#endif
#define CVE_DSE_MEM_WEIGHT_LUT_SETTING_OFFSET 0x10
#define CVE_DSE_MEM_WEIGHT_LUT_SETTING_SCOPE 0x01
#define CVE_DSE_MEM_WEIGHT_LUT_SETTING_SIZE 32
#define CVE_DSE_MEM_WEIGHT_LUT_SETTING_BITFIELD_COUNT 0x06
#define CVE_DSE_MEM_WEIGHT_LUT_SETTING_RESET 0x00000034
#define CVE_DSE_MEM_WEIGHT_LUT_SETTING_DECOMPRESSION_MODE_LSB 0x0000
#define CVE_DSE_MEM_WEIGHT_LUT_SETTING_DECOMPRESSION_MODE_MSB 0x0000
#define CVE_DSE_MEM_WEIGHT_LUT_SETTING_DECOMPRESSION_MODE_RANGE 0x0001
#define CVE_DSE_MEM_WEIGHT_LUT_SETTING_DECOMPRESSION_MODE_MASK 0x00000001
#define CVE_DSE_MEM_WEIGHT_LUT_SETTING_DECOMPRESSION_MODE_RESET_VALUE 0x00000000
#define CVE_DSE_MEM_WEIGHT_LUT_SETTING_PIXEL_SIZE_IS_16_LSB 0x0002
#define CVE_DSE_MEM_WEIGHT_LUT_SETTING_PIXEL_SIZE_IS_16_MSB 0x0002
#define CVE_DSE_MEM_WEIGHT_LUT_SETTING_PIXEL_SIZE_IS_16_RANGE 0x0001
#define CVE_DSE_MEM_WEIGHT_LUT_SETTING_PIXEL_SIZE_IS_16_MASK 0x00000004
#define CVE_DSE_MEM_WEIGHT_LUT_SETTING_PIXEL_SIZE_IS_16_RESET_VALUE 0x00000001
#define CVE_DSE_MEM_WEIGHT_LUT_SETTING_WEIGHT_COM_DATA_SIZE_LSB 0x0004
#define CVE_DSE_MEM_WEIGHT_LUT_SETTING_WEIGHT_COM_DATA_SIZE_MSB 0x0005
#define CVE_DSE_MEM_WEIGHT_LUT_SETTING_WEIGHT_COM_DATA_SIZE_RANGE 0x0002
#define CVE_DSE_MEM_WEIGHT_LUT_SETTING_WEIGHT_COM_DATA_SIZE_MASK 0x00000030
#define CVE_DSE_MEM_WEIGHT_LUT_SETTING_WEIGHT_COM_DATA_SIZE_RESET_VALUE 0x00000003
#define CVE_DSE_MEM_WEIGHT_LUT_SETTING_WEIGHT_LUT_MSB_BASE_LSB 0x0008
#define CVE_DSE_MEM_WEIGHT_LUT_SETTING_WEIGHT_LUT_MSB_BASE_MSB 0x000e
#define CVE_DSE_MEM_WEIGHT_LUT_SETTING_WEIGHT_LUT_MSB_BASE_RANGE 0x0007
#define CVE_DSE_MEM_WEIGHT_LUT_SETTING_WEIGHT_LUT_MSB_BASE_MASK 0x00007f00
#define CVE_DSE_MEM_WEIGHT_LUT_SETTING_WEIGHT_LUT_MSB_BASE_RESET_VALUE 0x00000000
#define CVE_DSE_MEM_WEIGHT_LUT_SETTING_WEIGHT_LUT_MSB_OFFSET_SRC_LSB 0x0010
#define CVE_DSE_MEM_WEIGHT_LUT_SETTING_WEIGHT_LUT_MSB_OFFSET_SRC_MSB 0x0011
#define CVE_DSE_MEM_WEIGHT_LUT_SETTING_WEIGHT_LUT_MSB_OFFSET_SRC_RANGE 0x0002
#define CVE_DSE_MEM_WEIGHT_LUT_SETTING_WEIGHT_LUT_MSB_OFFSET_SRC_MASK 0x00030000
#define CVE_DSE_MEM_WEIGHT_LUT_SETTING_WEIGHT_LUT_MSB_OFFSET_SRC_RESET_VALUE 0x00000000
#define CVE_DSE_MEM_WEIGHT_LUT_SETTING_WEIGHT_LUT_MSB_OFFSET_SHIFTR_LSB 0x0014
#define CVE_DSE_MEM_WEIGHT_LUT_SETTING_WEIGHT_LUT_MSB_OFFSET_SHIFTR_MSB 0x0019
#define CVE_DSE_MEM_WEIGHT_LUT_SETTING_WEIGHT_LUT_MSB_OFFSET_SHIFTR_RANGE 0x0006
#define CVE_DSE_MEM_WEIGHT_LUT_SETTING_WEIGHT_LUT_MSB_OFFSET_SHIFTR_MASK 0x03f00000
#define CVE_DSE_MEM_WEIGHT_LUT_SETTING_WEIGHT_LUT_MSB_OFFSET_SHIFTR_RESET_VALUE 0x00000000

/*  ------------------------------------------------------------------ */
/* */
#ifndef CVE_DSE_MEM_WEIGHT_LUT_BASE_ADDR_FLAG
#define CVE_DSE_MEM_WEIGHT_LUT_BASE_ADDR_FLAG
/* WEIGHT_LUT_BASE_ADDR desc:  Weight Lut Base Addr*/
union CVE_DSE_MEM_WEIGHT_LUT_BASE_ADDR_t {
	struct {
uint32_t  WEIGHT_LUT_BASE_ADDR :  32;
/*   WEIGHT LUT Base Address - */
/* Must be align to 2 Byte (16*/
/* bit) Units Byte Min 0 Max*/
/* 2^31-1*/
	}                                field;
uint32_t                         val;
};
#endif
#define CVE_DSE_MEM_WEIGHT_LUT_BASE_ADDR_OFFSET 0x50
#define CVE_DSE_MEM_WEIGHT_LUT_BASE_ADDR_SCOPE 0x01
#define CVE_DSE_MEM_WEIGHT_LUT_BASE_ADDR_SIZE 32
#define CVE_DSE_MEM_WEIGHT_LUT_BASE_ADDR_BITFIELD_COUNT 0x01
#define CVE_DSE_MEM_WEIGHT_LUT_BASE_ADDR_RESET 0x00000000
#define CVE_DSE_MEM_WEIGHT_LUT_BASE_ADDR_WEIGHT_LUT_BASE_ADDR_LSB 0x0000
#define CVE_DSE_MEM_WEIGHT_LUT_BASE_ADDR_WEIGHT_LUT_BASE_ADDR_MSB 0x001f
#define CVE_DSE_MEM_WEIGHT_LUT_BASE_ADDR_WEIGHT_LUT_BASE_ADDR_RANGE 0x0020
#define CVE_DSE_MEM_WEIGHT_LUT_BASE_ADDR_WEIGHT_LUT_BASE_ADDR_MASK 0xffffffff
#define CVE_DSE_MEM_WEIGHT_LUT_BASE_ADDR_WEIGHT_LUT_BASE_ADDR_RESET_VALUE 0x00000000

/*  ------------------------------------------------------------------ */
/* */
#ifndef CVE_DSE_MEM_SP_BUFFER_START_ADDR_FLAG
#define CVE_DSE_MEM_SP_BUFFER_START_ADDR_FLAG
/* SP_BUFFER_START_ADDR desc:  Sp Buffer Start Addr*/
union CVE_DSE_MEM_SP_BUFFER_START_ADDR_t {
	struct {
uint32_t  SP_BUFFER_START_ADDR :  18;
/*   SP Cyclic Buffer Start/First */
/* address - the first address of*/
/* the Buffer Units Byte Min 0*/
/* Max 2^18-1*/
uint32_t  RSVD_0               :  14;
/*  Nebulon auto filled RSVD [31:18] */
	}                                field;
uint32_t                         val;
};
#endif
#define CVE_DSE_MEM_SP_BUFFER_START_ADDR_OFFSET 0x54
#define CVE_DSE_MEM_SP_BUFFER_START_ADDR_SCOPE 0x01
#define CVE_DSE_MEM_SP_BUFFER_START_ADDR_SIZE 32
#define CVE_DSE_MEM_SP_BUFFER_START_ADDR_BITFIELD_COUNT 0x01
#define CVE_DSE_MEM_SP_BUFFER_START_ADDR_RESET 0x00000000
#define CVE_DSE_MEM_SP_BUFFER_START_ADDR_SP_BUFFER_START_ADDR_LSB 0x0000
#define CVE_DSE_MEM_SP_BUFFER_START_ADDR_SP_BUFFER_START_ADDR_MSB 0x0011
#define CVE_DSE_MEM_SP_BUFFER_START_ADDR_SP_BUFFER_START_ADDR_RANGE 0x0012
#define CVE_DSE_MEM_SP_BUFFER_START_ADDR_SP_BUFFER_START_ADDR_MASK 0x0003ffff
#define CVE_DSE_MEM_SP_BUFFER_START_ADDR_SP_BUFFER_START_ADDR_RESET_VALUE 0x00000000

/*  ------------------------------------------------------------------ */
/* */
#ifndef CVE_DSE_MEM_SP_BUFFER_END_ADDR_FLAG
#define CVE_DSE_MEM_SP_BUFFER_END_ADDR_FLAG
/* SP_BUFFER_END_ADDR desc:  Sp Buffer End Addr*/
union CVE_DSE_MEM_SP_BUFFER_END_ADDR_t {
	struct {
uint32_t  SP_BUFFER_END_ADDR   :  18;
/*   SP Cyclic Buffer End/Last */
/* address - the last address of*/
/* the buffer Units Byte Min 0*/
/* Max 2^18-1*/
uint32_t  RSVD_0               :  14;
/*  Nebulon auto filled RSVD [31:18] */
	}                                field;
uint32_t                         val;
};
#endif
#define CVE_DSE_MEM_SP_BUFFER_END_ADDR_OFFSET 0xa4
#define CVE_DSE_MEM_SP_BUFFER_END_ADDR_SCOPE 0x01
#define CVE_DSE_MEM_SP_BUFFER_END_ADDR_SIZE 32
#define CVE_DSE_MEM_SP_BUFFER_END_ADDR_BITFIELD_COUNT 0x01
#define CVE_DSE_MEM_SP_BUFFER_END_ADDR_RESET 0x0003ffff
#define CVE_DSE_MEM_SP_BUFFER_END_ADDR_SP_BUFFER_END_ADDR_LSB 0x0000
#define CVE_DSE_MEM_SP_BUFFER_END_ADDR_SP_BUFFER_END_ADDR_MSB 0x0011
#define CVE_DSE_MEM_SP_BUFFER_END_ADDR_SP_BUFFER_END_ADDR_RANGE 0x0012
#define CVE_DSE_MEM_SP_BUFFER_END_ADDR_SP_BUFFER_END_ADDR_MASK 0x0003ffff
#define CVE_DSE_MEM_SP_BUFFER_END_ADDR_SP_BUFFER_END_ADDR_RESET_VALUE 0x0003ffff

/*  ------------------------------------------------------------------ */
/* */
#ifndef CVE_DSE_MEM_SP_TILE_BOX_1D_LENGTH_FLAG
#define CVE_DSE_MEM_SP_TILE_BOX_1D_LENGTH_FLAG
/* SP_TILE_BOX_1D_LENGTH desc:  Sp Tile Box 1D Length*/
union CVE_DSE_MEM_SP_TILE_BOX_1D_LENGTH_t {
	struct {
uint32_t  SP_TILE_BOX_1D_LENGTH :  18;
/*   SP Tile Box First Dimension */
/* Length (width) Units Byte Min*/
/* 1 Max 2^18-1*/
uint32_t  RSVD_0               :  14;
/*  Nebulon auto filled RSVD [31:18] */
	}                                field;
uint32_t                         val;
};
#endif
#define CVE_DSE_MEM_SP_TILE_BOX_1D_LENGTH_OFFSET 0xf4
#define CVE_DSE_MEM_SP_TILE_BOX_1D_LENGTH_SCOPE 0x01
#define CVE_DSE_MEM_SP_TILE_BOX_1D_LENGTH_SIZE 32
#define CVE_DSE_MEM_SP_TILE_BOX_1D_LENGTH_BITFIELD_COUNT 0x01
#define CVE_DSE_MEM_SP_TILE_BOX_1D_LENGTH_RESET 0x00000040
#define CVE_DSE_MEM_SP_TILE_BOX_1D_LENGTH_SP_TILE_BOX_1D_LENGTH_LSB 0x0000
#define CVE_DSE_MEM_SP_TILE_BOX_1D_LENGTH_SP_TILE_BOX_1D_LENGTH_MSB 0x0011
#define CVE_DSE_MEM_SP_TILE_BOX_1D_LENGTH_SP_TILE_BOX_1D_LENGTH_RANGE 0x0012
#define CVE_DSE_MEM_SP_TILE_BOX_1D_LENGTH_SP_TILE_BOX_1D_LENGTH_MASK 0x0003ffff
#define CVE_DSE_MEM_SP_TILE_BOX_1D_LENGTH_SP_TILE_BOX_1D_LENGTH_RESET_VALUE 0x00000040

/*  ------------------------------------------------------------------ */
/* */
#ifndef CVE_DSE_MEM_SP_TILE_BOX_2D_LENGTH_FLAG
#define CVE_DSE_MEM_SP_TILE_BOX_2D_LENGTH_FLAG
/* SP_TILE_BOX_2D_LENGTH desc:  Sp Tile Box 2D Length*/
union CVE_DSE_MEM_SP_TILE_BOX_2D_LENGTH_t {
	struct {
uint32_t  SP_TILE_BOX_2D_LENGTH :  18;
/*   SP Tile Box Second Dimension */
/* Length (height) Units*/
/* SP_TILE_BOX_1D_PITCH Min 1 Max*/
/* 2^18-1*/
uint32_t  RSVD_0               :  14;
/*  Nebulon auto filled RSVD [31:18] */
	}                                field;
uint32_t                         val;
};
#endif
#define CVE_DSE_MEM_SP_TILE_BOX_2D_LENGTH_OFFSET 0x44
#define CVE_DSE_MEM_SP_TILE_BOX_2D_LENGTH_SCOPE 0x01
#define CVE_DSE_MEM_SP_TILE_BOX_2D_LENGTH_SIZE 32
#define CVE_DSE_MEM_SP_TILE_BOX_2D_LENGTH_BITFIELD_COUNT 0x01
#define CVE_DSE_MEM_SP_TILE_BOX_2D_LENGTH_RESET 0x00000001
#define CVE_DSE_MEM_SP_TILE_BOX_2D_LENGTH_SP_TILE_BOX_2D_LENGTH_LSB 0x0000
#define CVE_DSE_MEM_SP_TILE_BOX_2D_LENGTH_SP_TILE_BOX_2D_LENGTH_MSB 0x0011
#define CVE_DSE_MEM_SP_TILE_BOX_2D_LENGTH_SP_TILE_BOX_2D_LENGTH_RANGE 0x0012
#define CVE_DSE_MEM_SP_TILE_BOX_2D_LENGTH_SP_TILE_BOX_2D_LENGTH_MASK 0x0003ffff
#define CVE_DSE_MEM_SP_TILE_BOX_2D_LENGTH_SP_TILE_BOX_2D_LENGTH_RESET_VALUE 0x00000001

/*  ------------------------------------------------------------------ */
/* */
#ifndef CVE_DSE_MEM_SP_TILE_BOX_3D_LENGTH_FLAG
#define CVE_DSE_MEM_SP_TILE_BOX_3D_LENGTH_FLAG
/* SP_TILE_BOX_3D_LENGTH desc:  Sp Tile Box 3D Length*/
union CVE_DSE_MEM_SP_TILE_BOX_3D_LENGTH_t {
	struct {
uint32_t  SP_TILE_BOX_3D_LENGTH :  18;
/*   SP Tile Box Third Dimension */
/* Length (depth) Units*/
/* SP_TILE_BOX_2D_PITCH Min 1 Max*/
/* 2^18-1*/
uint32_t  RSVD_0               :  14;
/*  Nebulon auto filled RSVD [31:18] */
	}                                field;
uint32_t                         val;
};
#endif
#define CVE_DSE_MEM_SP_TILE_BOX_3D_LENGTH_OFFSET 0x94
#define CVE_DSE_MEM_SP_TILE_BOX_3D_LENGTH_SCOPE 0x01
#define CVE_DSE_MEM_SP_TILE_BOX_3D_LENGTH_SIZE 32
#define CVE_DSE_MEM_SP_TILE_BOX_3D_LENGTH_BITFIELD_COUNT 0x01
#define CVE_DSE_MEM_SP_TILE_BOX_3D_LENGTH_RESET 0x00000001
#define CVE_DSE_MEM_SP_TILE_BOX_3D_LENGTH_SP_TILE_BOX_3D_LENGTH_LSB 0x0000
#define CVE_DSE_MEM_SP_TILE_BOX_3D_LENGTH_SP_TILE_BOX_3D_LENGTH_MSB 0x0011
#define CVE_DSE_MEM_SP_TILE_BOX_3D_LENGTH_SP_TILE_BOX_3D_LENGTH_RANGE 0x0012
#define CVE_DSE_MEM_SP_TILE_BOX_3D_LENGTH_SP_TILE_BOX_3D_LENGTH_MASK 0x0003ffff
#define CVE_DSE_MEM_SP_TILE_BOX_3D_LENGTH_SP_TILE_BOX_3D_LENGTH_RESET_VALUE 0x00000001

/*  ------------------------------------------------------------------ */
/* */
#ifndef CVE_DSE_MEM_SP_TILE_BOX_4D_LENGTH_FLAG
#define CVE_DSE_MEM_SP_TILE_BOX_4D_LENGTH_FLAG
/* SP_TILE_BOX_4D_LENGTH desc:  Sp Tile Box 4D Length*/
union CVE_DSE_MEM_SP_TILE_BOX_4D_LENGTH_t {
	struct {
uint32_t  SP_TILE_BOX_4D_LENGTH :  18;
/*   SP Tile Box Fourth Dimension */
/* Length Units*/
/* SP_TILE_BOX_3D_PITCH Min 1 Max*/
/* 2^18-1*/
uint32_t  RSVD_0               :  14;
/*  Nebulon auto filled RSVD [31:18] */
	}                                field;
uint32_t                         val;
};
#endif
#define CVE_DSE_MEM_SP_TILE_BOX_4D_LENGTH_OFFSET 0xe4
#define CVE_DSE_MEM_SP_TILE_BOX_4D_LENGTH_SCOPE 0x01
#define CVE_DSE_MEM_SP_TILE_BOX_4D_LENGTH_SIZE 32
#define CVE_DSE_MEM_SP_TILE_BOX_4D_LENGTH_BITFIELD_COUNT 0x01
#define CVE_DSE_MEM_SP_TILE_BOX_4D_LENGTH_RESET 0x00000001
#define CVE_DSE_MEM_SP_TILE_BOX_4D_LENGTH_SP_TILE_BOX_4D_LENGTH_LSB 0x0000
#define CVE_DSE_MEM_SP_TILE_BOX_4D_LENGTH_SP_TILE_BOX_4D_LENGTH_MSB 0x0011
#define CVE_DSE_MEM_SP_TILE_BOX_4D_LENGTH_SP_TILE_BOX_4D_LENGTH_RANGE 0x0012
#define CVE_DSE_MEM_SP_TILE_BOX_4D_LENGTH_SP_TILE_BOX_4D_LENGTH_MASK 0x0003ffff
#define CVE_DSE_MEM_SP_TILE_BOX_4D_LENGTH_SP_TILE_BOX_4D_LENGTH_RESET_VALUE 0x00000001

/*  ------------------------------------------------------------------ */
/* */
#ifndef CVE_DSE_MEM_SP_TILE_BOX_2D_PITCH_FLAG
#define CVE_DSE_MEM_SP_TILE_BOX_2D_PITCH_FLAG
/* SP_TILE_BOX_2D_PITCH desc:  Sp Tile Box 2D Pitch*/
union CVE_DSE_MEM_SP_TILE_BOX_2D_PITCH_t {
	struct {
uint32_t  SP_TILE_BOX_2D_PITCH :  18;
/*   Distance Between Two */
/* Consecutive 2D SP Tile Box's*/
/* if (SP_TILE_BOX_2D_PITCH == 0)*/
/* ACTUAL_SP_TILE_BOX_2D_PITCH =*/
/* SP_TILE_BOX_2D_LENGTH **/
/* SP_TILE_BOX_1D_PITCH else*/
/* ACTUAL_SP_TILE_BOX_2D_PITCH =*/
/* SP_TILE_BOX_2D_PITCH Units*/
/* Byte Min 0/*/
/* SP_TILE_BOX_2D_LENGTH **/
/* SP_TILE_BOX_1D_PITCH Max*/
/* 2^18-1*/
uint32_t  RSVD_0               :  14;
/*  Nebulon auto filled RSVD [31:18] */
	}                                field;
uint32_t                         val;
};
#endif
#define CVE_DSE_MEM_SP_TILE_BOX_2D_PITCH_OFFSET 0x34
#define CVE_DSE_MEM_SP_TILE_BOX_2D_PITCH_SCOPE 0x01
#define CVE_DSE_MEM_SP_TILE_BOX_2D_PITCH_SIZE 32
#define CVE_DSE_MEM_SP_TILE_BOX_2D_PITCH_BITFIELD_COUNT 0x01
#define CVE_DSE_MEM_SP_TILE_BOX_2D_PITCH_RESET 0x00000000
#define CVE_DSE_MEM_SP_TILE_BOX_2D_PITCH_SP_TILE_BOX_2D_PITCH_LSB 0x0000
#define CVE_DSE_MEM_SP_TILE_BOX_2D_PITCH_SP_TILE_BOX_2D_PITCH_MSB 0x0011
#define CVE_DSE_MEM_SP_TILE_BOX_2D_PITCH_SP_TILE_BOX_2D_PITCH_RANGE 0x0012
#define CVE_DSE_MEM_SP_TILE_BOX_2D_PITCH_SP_TILE_BOX_2D_PITCH_MASK 0x0003ffff
#define CVE_DSE_MEM_SP_TILE_BOX_2D_PITCH_SP_TILE_BOX_2D_PITCH_RESET_VALUE 0x00000000

/*  ------------------------------------------------------------------ */
/* */
#ifndef CVE_DSE_MEM_SP_TILE_BOX_3D_PITCH_FLAG
#define CVE_DSE_MEM_SP_TILE_BOX_3D_PITCH_FLAG
/* SP_TILE_BOX_3D_PITCH desc:  Sp Tile Box 3D Pitch*/
union CVE_DSE_MEM_SP_TILE_BOX_3D_PITCH_t {
	struct {
uint32_t  SP_TILE_BOX_3D_PITCH :  18;
/*   Distance Between Two */
/* Consecutive 3D SP Tile Box's*/
/* if (SP_TILE_BOX_3D_PITCH == 0)*/
/* ACTUAL_SP_TILE_BOX_3D_PITCH =*/
/* SP_TILE_BOX_3D_LENGTH **/
/* SP_TILE_BOX_2D_PITCH else*/
/* ACTUAL_SP_TILE_BOX_3D_PITCH =*/
/* SP_TILE_BOX_3D_PITCH Units*/
/* Byte Min*/
/* 0/SP_TILE_BOX_3D_LENGTH **/
/* SP_TILE_BOX_2D_PITCH Max*/
/* 2^18-1*/
uint32_t  RSVD_0               :  14;
/*  Nebulon auto filled RSVD [31:18] */
	}                                field;
uint32_t                         val;
};
#endif
#define CVE_DSE_MEM_SP_TILE_BOX_3D_PITCH_OFFSET 0x84
#define CVE_DSE_MEM_SP_TILE_BOX_3D_PITCH_SCOPE 0x01
#define CVE_DSE_MEM_SP_TILE_BOX_3D_PITCH_SIZE 32
#define CVE_DSE_MEM_SP_TILE_BOX_3D_PITCH_BITFIELD_COUNT 0x01
#define CVE_DSE_MEM_SP_TILE_BOX_3D_PITCH_RESET 0x00000000
#define CVE_DSE_MEM_SP_TILE_BOX_3D_PITCH_SP_TILE_BOX_3D_PITCH_LSB 0x0000
#define CVE_DSE_MEM_SP_TILE_BOX_3D_PITCH_SP_TILE_BOX_3D_PITCH_MSB 0x0011
#define CVE_DSE_MEM_SP_TILE_BOX_3D_PITCH_SP_TILE_BOX_3D_PITCH_RANGE 0x0012
#define CVE_DSE_MEM_SP_TILE_BOX_3D_PITCH_SP_TILE_BOX_3D_PITCH_MASK 0x0003ffff
#define CVE_DSE_MEM_SP_TILE_BOX_3D_PITCH_SP_TILE_BOX_3D_PITCH_RESET_VALUE 0x00000000

/*  ------------------------------------------------------------------ */
/* */
#ifndef CVE_DSE_MEM_SP_TILE_BOX_PITCH_FLAG
#define CVE_DSE_MEM_SP_TILE_BOX_PITCH_FLAG
/* SP_TILE_BOX_PITCH desc:  Sp Tile Box Pitch*/
union CVE_DSE_MEM_SP_TILE_BOX_PITCH_t {
	struct {
uint32_t  SP_TILE_BOX_PITCH    :  18;
/*   The Distance between two */
/* Consecutive SP_TILE_BOX's on*/
/* the Cyclic Buffer : if*/
/* (SP_TILE_BOX_PITCH == 0)*/
/* ACTUAL_SP_TILE_BOX_PITCH =*/
/* SP_TILE_BOX_4D_PITCH else*/
/* ACTUAL_SP_TILE_BOX_PITCH =*/
/* SP_TILE_BOX_PITCH Units Byte*/
/* Min 0/SP_TILE_BOX_4D_PITCH Max*/
/* 2^18-1*/
uint32_t  RSVD_0               :  14;
/*  Nebulon auto filled RSVD [31:18] */
	}                                field;
uint32_t                         val;
};
#endif
#define CVE_DSE_MEM_SP_TILE_BOX_PITCH_OFFSET 0xd4
#define CVE_DSE_MEM_SP_TILE_BOX_PITCH_SCOPE 0x01
#define CVE_DSE_MEM_SP_TILE_BOX_PITCH_SIZE 32
#define CVE_DSE_MEM_SP_TILE_BOX_PITCH_BITFIELD_COUNT 0x01
#define CVE_DSE_MEM_SP_TILE_BOX_PITCH_RESET 0x00000000
#define CVE_DSE_MEM_SP_TILE_BOX_PITCH_SP_TILE_BOX_PITCH_LSB 0x0000
#define CVE_DSE_MEM_SP_TILE_BOX_PITCH_SP_TILE_BOX_PITCH_MSB 0x0011
#define CVE_DSE_MEM_SP_TILE_BOX_PITCH_SP_TILE_BOX_PITCH_RANGE 0x0012
#define CVE_DSE_MEM_SP_TILE_BOX_PITCH_SP_TILE_BOX_PITCH_MASK 0x0003ffff
#define CVE_DSE_MEM_SP_TILE_BOX_PITCH_SP_TILE_BOX_PITCH_RESET_VALUE 0x00000000

/*  ------------------------------------------------------------------ */
/* */
#ifndef CVE_DSE_MEM_TILE_1D_OFFSET_ON_SP_FLAG
#define CVE_DSE_MEM_TILE_1D_OFFSET_ON_SP_FLAG
/* TILE_1D_OFFSET_ON_SP desc:  Tile 1D Offset On Sp*/
union CVE_DSE_MEM_TILE_1D_OFFSET_ON_SP_t {
	struct {
uint32_t  TILE_1D_OFFSET_ON_SP :  18;
/*   Tile 1D offset on the SP Tile */
/* BOX Units Byte Min 0 Max*/
/* SP_TILE_BOX_1D_LENGTH -2*/
uint32_t  RSVD_0               :  14;
/*  Nebulon auto filled RSVD [31:18] */
	}                                field;
uint32_t                         val;
};
#endif
#define CVE_DSE_MEM_TILE_1D_OFFSET_ON_SP_OFFSET 0x24
#define CVE_DSE_MEM_TILE_1D_OFFSET_ON_SP_SCOPE 0x01
#define CVE_DSE_MEM_TILE_1D_OFFSET_ON_SP_SIZE 32
#define CVE_DSE_MEM_TILE_1D_OFFSET_ON_SP_BITFIELD_COUNT 0x01
#define CVE_DSE_MEM_TILE_1D_OFFSET_ON_SP_RESET 0x00000000
#define CVE_DSE_MEM_TILE_1D_OFFSET_ON_SP_TILE_1D_OFFSET_ON_SP_LSB 0x0000
#define CVE_DSE_MEM_TILE_1D_OFFSET_ON_SP_TILE_1D_OFFSET_ON_SP_MSB 0x0011
#define CVE_DSE_MEM_TILE_1D_OFFSET_ON_SP_TILE_1D_OFFSET_ON_SP_RANGE 0x0012
#define CVE_DSE_MEM_TILE_1D_OFFSET_ON_SP_TILE_1D_OFFSET_ON_SP_MASK 0x0003ffff
#define CVE_DSE_MEM_TILE_1D_OFFSET_ON_SP_TILE_1D_OFFSET_ON_SP_RESET_VALUE 0x00000000

/*  ------------------------------------------------------------------ */
/* */
#ifndef CVE_DSE_MEM_TILE_2D_OFFSET_ON_SP_FLAG
#define CVE_DSE_MEM_TILE_2D_OFFSET_ON_SP_FLAG
/* TILE_2D_OFFSET_ON_SP desc:  Tile 2D Offset On Sp*/
union CVE_DSE_MEM_TILE_2D_OFFSET_ON_SP_t {
	struct {
uint32_t  TILE_2D_OFFSET_ON_SP :  18;
/*   Tile 2D offset on the SP Tile */
/* BOX Units*/
/* SP_TILE_BOX_1D_LENGTH Min 0*/
/* Max SP_TILE_BOX_2D_LENGTH -2*/
uint32_t  RSVD_0               :  14;
/*  Nebulon auto filled RSVD [31:18] */
	}                                field;
uint32_t                         val;
};
#endif
#define CVE_DSE_MEM_TILE_2D_OFFSET_ON_SP_OFFSET 0x74
#define CVE_DSE_MEM_TILE_2D_OFFSET_ON_SP_SCOPE 0x01
#define CVE_DSE_MEM_TILE_2D_OFFSET_ON_SP_SIZE 32
#define CVE_DSE_MEM_TILE_2D_OFFSET_ON_SP_BITFIELD_COUNT 0x01
#define CVE_DSE_MEM_TILE_2D_OFFSET_ON_SP_RESET 0x00000000
#define CVE_DSE_MEM_TILE_2D_OFFSET_ON_SP_TILE_2D_OFFSET_ON_SP_LSB 0x0000
#define CVE_DSE_MEM_TILE_2D_OFFSET_ON_SP_TILE_2D_OFFSET_ON_SP_MSB 0x0011
#define CVE_DSE_MEM_TILE_2D_OFFSET_ON_SP_TILE_2D_OFFSET_ON_SP_RANGE 0x0012
#define CVE_DSE_MEM_TILE_2D_OFFSET_ON_SP_TILE_2D_OFFSET_ON_SP_MASK 0x0003ffff
#define CVE_DSE_MEM_TILE_2D_OFFSET_ON_SP_TILE_2D_OFFSET_ON_SP_RESET_VALUE 0x00000000

/*  ------------------------------------------------------------------ */
/* */
#ifndef CVE_DSE_MEM_SP_TILE_BOX_SCALE_FLAG
#define CVE_DSE_MEM_SP_TILE_BOX_SCALE_FLAG
/* SP_TILE_BOX_SCALE desc:  Sp Tile Box Scale*/
union CVE_DSE_MEM_SP_TILE_BOX_SCALE_t {
	struct {
uint32_t  SP_TILE_BOX_SCALE    :  18;
/*   Setting the SP_TILE_BOX_SCALE */
/* overrides the*/
/* SP_TILE_BOX_2/3/4D_LENGTH for*/
/* backward compatibility to*/
/* tiles with TLC credits*/
/* management LEN =*/
/* SP_TILE_BOX_SCALE * Credits;*/
/* SP_TILE_BOX_2D_LENGTH =*/
/* 2Dscale ? LEN :*/
/* SP_TILE_BOX_2D_LENGTH*/
/* SP_TILE_BOX_3D_LENGTH =*/
/* 2Dscale ? 1 : 3Dscale ? LEN :*/
/* SP_TILE_BOX_3D_LENGTH*/
/* SP_TILE_BOX_4D_LENGTH =*/
/* 2Dscale ? 1 : 3Dscale ? 1 :*/
/* 4Dscale ? LEN :*/
/* SP_TILE_BOX_4D_LENGTH Units*/
/* SP_TILE_BOX_2/3/4D_PITCH Min 0*/
/* Max 2^18-1*/
uint32_t  RSVD_0               :   6;
/*  Nebulon auto filled RSVD [23:18] */
uint32_t  SP_TILE_BOX_SCALE_DIM :   2;
/*   Set the SP_TILE_BOX_SCALE */
/* Dimension 2Dscale =*/
/* (SP_TILE_BOX_SCALE_DIM == 0)*/
/* && (SP_TILE_BOX_SCALE > 0)*/
/* 3Dscale =*/
/* (SP_TILE_BOX_SCALE_DIM == 1)*/
/* && (SP_TILE_BOX_SCALE > 0)*/
/* 4Dscale =*/
/* (SP_TILE_BOX_SCALE_DIM == 2)*/
/* && (SP_TILE_BOX_SCALE > 0)*/
/* Units Num Min 0 Max 2*/
uint32_t  RSVD_1               :   6;
/*  Nebulon auto filled RSVD [31:26] */
	}                                field;
uint32_t                         val;
};
#endif
#define CVE_DSE_MEM_SP_TILE_BOX_SCALE_OFFSET 0xc4
#define CVE_DSE_MEM_SP_TILE_BOX_SCALE_SCOPE 0x01
#define CVE_DSE_MEM_SP_TILE_BOX_SCALE_SIZE 32
#define CVE_DSE_MEM_SP_TILE_BOX_SCALE_BITFIELD_COUNT 0x02
#define CVE_DSE_MEM_SP_TILE_BOX_SCALE_RESET 0x00000001
#define CVE_DSE_MEM_SP_TILE_BOX_SCALE_SP_TILE_BOX_SCALE_LSB 0x0000
#define CVE_DSE_MEM_SP_TILE_BOX_SCALE_SP_TILE_BOX_SCALE_MSB 0x0011
#define CVE_DSE_MEM_SP_TILE_BOX_SCALE_SP_TILE_BOX_SCALE_RANGE 0x0012
#define CVE_DSE_MEM_SP_TILE_BOX_SCALE_SP_TILE_BOX_SCALE_MASK 0x0003ffff
#define CVE_DSE_MEM_SP_TILE_BOX_SCALE_SP_TILE_BOX_SCALE_RESET_VALUE 0x00000001
#define CVE_DSE_MEM_SP_TILE_BOX_SCALE_SP_TILE_BOX_SCALE_DIM_LSB 0x0018
#define CVE_DSE_MEM_SP_TILE_BOX_SCALE_SP_TILE_BOX_SCALE_DIM_MSB 0x0019
#define CVE_DSE_MEM_SP_TILE_BOX_SCALE_SP_TILE_BOX_SCALE_DIM_RANGE 0x0002
#define CVE_DSE_MEM_SP_TILE_BOX_SCALE_SP_TILE_BOX_SCALE_DIM_MASK 0x03000000
#define CVE_DSE_MEM_SP_TILE_BOX_SCALE_SP_TILE_BOX_SCALE_DIM_RESET_VALUE 0x00000000

/*  ------------------------------------------------------------------ */
/* */
#ifndef CVE_DSE_MEM_TOTAL_CREDITS_FLAG
#define CVE_DSE_MEM_TOTAL_CREDITS_FLAG
/* TOTAL_CREDITS desc:  Total Credits*/
union CVE_DSE_MEM_TOTAL_CREDITS_t {
	struct {
uint32_t  TOTAL_CREDITS        :  32;
/*   WACM - Total Credits for */
/* complete walk operation Units*/
/* Num Min 0 Max 2^32-1*/
	}                                field;
uint32_t                         val;
};
#endif
#define CVE_DSE_MEM_TOTAL_CREDITS_OFFSET 0x14
#define CVE_DSE_MEM_TOTAL_CREDITS_SCOPE 0x01
#define CVE_DSE_MEM_TOTAL_CREDITS_SIZE 32
#define CVE_DSE_MEM_TOTAL_CREDITS_BITFIELD_COUNT 0x01
#define CVE_DSE_MEM_TOTAL_CREDITS_RESET 0x00000000
#define CVE_DSE_MEM_TOTAL_CREDITS_TOTAL_CREDITS_LSB 0x0000
#define CVE_DSE_MEM_TOTAL_CREDITS_TOTAL_CREDITS_MSB 0x001f
#define CVE_DSE_MEM_TOTAL_CREDITS_TOTAL_CREDITS_RANGE 0x0020
#define CVE_DSE_MEM_TOTAL_CREDITS_TOTAL_CREDITS_MASK 0xffffffff
#define CVE_DSE_MEM_TOTAL_CREDITS_TOTAL_CREDITS_RESET_VALUE 0x00000000

/*  ------------------------------------------------------------------ */
/* */
#ifndef CVE_DSE_MEM_CREDIT_GRANULARITY_FLAG
#define CVE_DSE_MEM_CREDIT_GRANULARITY_FLAG
/* CREDIT_GRANULARITY desc:  Credit Granularity*/
union CVE_DSE_MEM_CREDIT_GRANULARITY_t {
	struct {
uint32_t  CREDIT_GRANULARITY   :  16;
/*   WACm - Credits for 1 tile */
/* Units Num Min 0 Max 2^20-1*/
uint32_t  RSVD_0               :  16;
/*  Nebulon auto filled RSVD [31:16] */
	}                                field;
uint32_t                         val;
};
#endif
#define CVE_DSE_MEM_CREDIT_GRANULARITY_OFFSET 0x64
#define CVE_DSE_MEM_CREDIT_GRANULARITY_SCOPE 0x01
#define CVE_DSE_MEM_CREDIT_GRANULARITY_SIZE 32
#define CVE_DSE_MEM_CREDIT_GRANULARITY_BITFIELD_COUNT 0x01
#define CVE_DSE_MEM_CREDIT_GRANULARITY_RESET 0x00000000
#define CVE_DSE_MEM_CREDIT_GRANULARITY_CREDIT_GRANULARITY_LSB 0x0000
#define CVE_DSE_MEM_CREDIT_GRANULARITY_CREDIT_GRANULARITY_MSB 0x000f
#define CVE_DSE_MEM_CREDIT_GRANULARITY_CREDIT_GRANULARITY_RANGE 0x0010
#define CVE_DSE_MEM_CREDIT_GRANULARITY_CREDIT_GRANULARITY_MASK 0x0000ffff
#define CVE_DSE_MEM_CREDIT_GRANULARITY_CREDIT_GRANULARITY_RESET_VALUE 0x00000000

/*  ------------------------------------------------------------------ */
/* */
#ifndef CVE_DSE_MEM_WACM_CONFIG_FLAG
#define CVE_DSE_MEM_WACM_CONFIG_FLAG
/* WACM_CONFIG desc:  Wacm Config*/
union CVE_DSE_MEM_WACM_CONFIG_t {
	struct {
uint32_t  OPERATION_MODE       :   2;
/*   0 - Normal Mode 1 - Gather 2 */
/* - Prefetch 3- Auto K ahead*/
/* Prefetch Units Num Min 0 Max 3*/
uint32_t  RSVD_0               :   6;
/*  Nebulon auto filled RSVD [7:2] */
uint32_t  PREFETCH_K_AHEAD     :   8;
/*   Prefetch K ahead Units Num */
/* Min 0 Max 2^8-1*/
uint32_t  FORCE_IS_POSTED_ON_LAST :   1;
/*   When Set to one. WACM will */
/* forse is_posted=1 on the last*/
/* Tile Units Boolean Min 0 Max 1*/
uint32_t  RSVD_1               :   3;
/*  Nebulon auto filled RSVD [19:17] */
uint32_t  DISABLE_CYCLIC_BUFFER_ENTRY_RESET :   1;
/*   When Set to one. Entry Reset */
/* will not reset the Cyclic*/
/* Buffer related to it. Units*/
/* Boolean Min 0 Max 1*/
uint32_t  RSVD_2               :  11;
/*  Nebulon auto filled RSVD [31:21] */
	}                                field;
uint32_t                         val;
};
#endif
#define CVE_DSE_MEM_WACM_CONFIG_OFFSET 0xb4
#define CVE_DSE_MEM_WACM_CONFIG_SCOPE 0x01
#define CVE_DSE_MEM_WACM_CONFIG_SIZE 32
#define CVE_DSE_MEM_WACM_CONFIG_BITFIELD_COUNT 0x04
#define CVE_DSE_MEM_WACM_CONFIG_RESET 0x00000000
#define CVE_DSE_MEM_WACM_CONFIG_OPERATION_MODE_LSB 0x0000
#define CVE_DSE_MEM_WACM_CONFIG_OPERATION_MODE_MSB 0x0001
#define CVE_DSE_MEM_WACM_CONFIG_OPERATION_MODE_RANGE 0x0002
#define CVE_DSE_MEM_WACM_CONFIG_OPERATION_MODE_MASK 0x00000003
#define CVE_DSE_MEM_WACM_CONFIG_OPERATION_MODE_RESET_VALUE 0x00000000
#define CVE_DSE_MEM_WACM_CONFIG_PREFETCH_K_AHEAD_LSB 0x0008
#define CVE_DSE_MEM_WACM_CONFIG_PREFETCH_K_AHEAD_MSB 0x000f
#define CVE_DSE_MEM_WACM_CONFIG_PREFETCH_K_AHEAD_RANGE 0x0008
#define CVE_DSE_MEM_WACM_CONFIG_PREFETCH_K_AHEAD_MASK 0x0000ff00
#define CVE_DSE_MEM_WACM_CONFIG_PREFETCH_K_AHEAD_RESET_VALUE 0x00000000
#define CVE_DSE_MEM_WACM_CONFIG_FORCE_IS_POSTED_ON_LAST_LSB 0x0010
#define CVE_DSE_MEM_WACM_CONFIG_FORCE_IS_POSTED_ON_LAST_MSB 0x0010
#define CVE_DSE_MEM_WACM_CONFIG_FORCE_IS_POSTED_ON_LAST_RANGE 0x0001
#define CVE_DSE_MEM_WACM_CONFIG_FORCE_IS_POSTED_ON_LAST_MASK 0x00010000
#define CVE_DSE_MEM_WACM_CONFIG_FORCE_IS_POSTED_ON_LAST_RESET_VALUE 0x00000000
#define CVE_DSE_MEM_WACM_CONFIG_DISABLE_CYCLIC_BUFFER_ENTRY_RESET_LSB 0x0014
#define CVE_DSE_MEM_WACM_CONFIG_DISABLE_CYCLIC_BUFFER_ENTRY_RESET_MSB 0x0014
#define CVE_DSE_MEM_WACM_CONFIG_DISABLE_CYCLIC_BUFFER_ENTRY_RESET_RANGE 0x0001
#define CVE_DSE_MEM_WACM_CONFIG_DISABLE_CYCLIC_BUFFER_ENTRY_RESET_MASK 0x00100000
#define CVE_DSE_MEM_WACM_CONFIG_DISABLE_CYCLIC_BUFFER_ENTRY_RESET_RESET_VALUE 0x00000000

/*  ------------------------------------------------------------------ */
/* */
#ifndef CVE_DSE_MEM_X_E0_FLAG
#define CVE_DSE_MEM_X_E0_FLAG
/* X_E0 desc:  X E0*/
union CVE_DSE_MEM_X_E0_t {
	struct {
uint32_t  X_E0                 :  20;
/*   (walk1D) STEP_1D_IDX = */
/* (counter/X_E0) % X_R0) +*/
/* ((counter/X_E1) % X_R1) * X_R0*/
/* + ((counter/X_E2) % X_R2) **/
/* X_R0 * X_R1 Units Num Min 0*/
/* Max 2^20-1*/
uint32_t  RSVD_0               :  12;
/*  Nebulon auto filled RSVD [31:20] */
	}                                field;
uint32_t                         val;
};
#endif
#define CVE_DSE_MEM_X_E0_OFFSET 0xf4
#define CVE_DSE_MEM_X_E0_SCOPE 0x01
#define CVE_DSE_MEM_X_E0_SIZE 32
#define CVE_DSE_MEM_X_E0_BITFIELD_COUNT 0x01
#define CVE_DSE_MEM_X_E0_RESET 0x00000001
#define CVE_DSE_MEM_X_E0_X_E0_LSB 0x0000
#define CVE_DSE_MEM_X_E0_X_E0_MSB 0x0013
#define CVE_DSE_MEM_X_E0_X_E0_RANGE 0x0014
#define CVE_DSE_MEM_X_E0_X_E0_MASK 0x000fffff
#define CVE_DSE_MEM_X_E0_X_E0_RESET_VALUE 0x00000001

/*  ------------------------------------------------------------------ */
/* */
#ifndef CVE_DSE_MEM_X_R0_FLAG
#define CVE_DSE_MEM_X_R0_FLAG
/* X_R0 desc:  X R0*/
union CVE_DSE_MEM_X_R0_t {
	struct {
uint32_t  X_R0                 :  20;
/*   Units Num Min 0 Max 2^20-1 */
uint32_t  RSVD_0               :  12;
/*  Nebulon auto filled RSVD [31:20] */
	}                                field;
uint32_t                         val;
};
#endif
#define CVE_DSE_MEM_X_R0_OFFSET 0x34
#define CVE_DSE_MEM_X_R0_SCOPE 0x01
#define CVE_DSE_MEM_X_R0_SIZE 32
#define CVE_DSE_MEM_X_R0_BITFIELD_COUNT 0x01
#define CVE_DSE_MEM_X_R0_RESET 0x00000001
#define CVE_DSE_MEM_X_R0_X_R0_LSB 0x0000
#define CVE_DSE_MEM_X_R0_X_R0_MSB 0x0013
#define CVE_DSE_MEM_X_R0_X_R0_RANGE 0x0014
#define CVE_DSE_MEM_X_R0_X_R0_MASK 0x000fffff
#define CVE_DSE_MEM_X_R0_X_R0_RESET_VALUE 0x00000001

/*  ------------------------------------------------------------------ */
/* */
#ifndef CVE_DSE_MEM_X_E1_FLAG
#define CVE_DSE_MEM_X_E1_FLAG
/* X_E1 desc:  X E1*/
union CVE_DSE_MEM_X_E1_t {
	struct {
uint32_t  X_E1                 :  20;
/*   Units Num Min 0 Max 2^20-1 */
uint32_t  RSVD_0               :  12;
/*  Nebulon auto filled RSVD [31:20] */
	}                                field;
uint32_t                         val;
};
#endif
#define CVE_DSE_MEM_X_E1_OFFSET 0x74
#define CVE_DSE_MEM_X_E1_SCOPE 0x01
#define CVE_DSE_MEM_X_E1_SIZE 32
#define CVE_DSE_MEM_X_E1_BITFIELD_COUNT 0x01
#define CVE_DSE_MEM_X_E1_RESET 0x00000001
#define CVE_DSE_MEM_X_E1_X_E1_LSB 0x0000
#define CVE_DSE_MEM_X_E1_X_E1_MSB 0x0013
#define CVE_DSE_MEM_X_E1_X_E1_RANGE 0x0014
#define CVE_DSE_MEM_X_E1_X_E1_MASK 0x000fffff
#define CVE_DSE_MEM_X_E1_X_E1_RESET_VALUE 0x00000001

/*  ------------------------------------------------------------------ */
/* */
#ifndef CVE_DSE_MEM_X_R1_FLAG
#define CVE_DSE_MEM_X_R1_FLAG
/* X_R1 desc:  X R1*/
union CVE_DSE_MEM_X_R1_t {
	struct {
uint32_t  X_R1                 :  20;
/*   Units Num Min 0 Max 2^20-1 */
uint32_t  RSVD_0               :  12;
/*  Nebulon auto filled RSVD [31:20] */
	}                                field;
uint32_t                         val;
};
#endif
#define CVE_DSE_MEM_X_R1_OFFSET 0xb4
#define CVE_DSE_MEM_X_R1_SCOPE 0x01
#define CVE_DSE_MEM_X_R1_SIZE 32
#define CVE_DSE_MEM_X_R1_BITFIELD_COUNT 0x01
#define CVE_DSE_MEM_X_R1_RESET 0x00000001
#define CVE_DSE_MEM_X_R1_X_R1_LSB 0x0000
#define CVE_DSE_MEM_X_R1_X_R1_MSB 0x0013
#define CVE_DSE_MEM_X_R1_X_R1_RANGE 0x0014
#define CVE_DSE_MEM_X_R1_X_R1_MASK 0x000fffff
#define CVE_DSE_MEM_X_R1_X_R1_RESET_VALUE 0x00000001

/*  ------------------------------------------------------------------ */
/* */
#ifndef CVE_DSE_MEM_X_E2_FLAG
#define CVE_DSE_MEM_X_E2_FLAG
/* X_E2 desc:  X E2*/
union CVE_DSE_MEM_X_E2_t {
	struct {
uint32_t  X_E2                 :  20;
/*   Units Num Min 0 Max 2^20-1 */
uint32_t  RSVD_0               :  12;
/*  Nebulon auto filled RSVD [31:20] */
	}                                field;
uint32_t                         val;
};
#endif
#define CVE_DSE_MEM_X_E2_OFFSET 0xf4
#define CVE_DSE_MEM_X_E2_SCOPE 0x01
#define CVE_DSE_MEM_X_E2_SIZE 32
#define CVE_DSE_MEM_X_E2_BITFIELD_COUNT 0x01
#define CVE_DSE_MEM_X_E2_RESET 0x00000001
#define CVE_DSE_MEM_X_E2_X_E2_LSB 0x0000
#define CVE_DSE_MEM_X_E2_X_E2_MSB 0x0013
#define CVE_DSE_MEM_X_E2_X_E2_RANGE 0x0014
#define CVE_DSE_MEM_X_E2_X_E2_MASK 0x000fffff
#define CVE_DSE_MEM_X_E2_X_E2_RESET_VALUE 0x00000001

/*  ------------------------------------------------------------------ */
/* */
#ifndef CVE_DSE_MEM_X_R2_FLAG
#define CVE_DSE_MEM_X_R2_FLAG
/* X_R2 desc:  X R2*/
union CVE_DSE_MEM_X_R2_t {
	struct {
uint32_t  X_R2                 :  20;
/*   Units Num Min 0 Max 2^20-1 */
uint32_t  RSVD_0               :  12;
/*  Nebulon auto filled RSVD [31:20] */
	}                                field;
uint32_t                         val;
};
#endif
#define CVE_DSE_MEM_X_R2_OFFSET 0x34
#define CVE_DSE_MEM_X_R2_SCOPE 0x01
#define CVE_DSE_MEM_X_R2_SIZE 32
#define CVE_DSE_MEM_X_R2_BITFIELD_COUNT 0x01
#define CVE_DSE_MEM_X_R2_RESET 0x00000001
#define CVE_DSE_MEM_X_R2_X_R2_LSB 0x0000
#define CVE_DSE_MEM_X_R2_X_R2_MSB 0x0013
#define CVE_DSE_MEM_X_R2_X_R2_RANGE 0x0014
#define CVE_DSE_MEM_X_R2_X_R2_MASK 0x000fffff
#define CVE_DSE_MEM_X_R2_X_R2_RESET_VALUE 0x00000001

/*  ------------------------------------------------------------------ */
/* */
#ifndef CVE_DSE_MEM_Y_E0_FLAG
#define CVE_DSE_MEM_Y_E0_FLAG
/* Y_E0 desc:  Y E0*/
union CVE_DSE_MEM_Y_E0_t {
	struct {
uint32_t  Y_E0                 :  20;
/*   (walk2D) STEP_2D_IDX = */
/* (counter/Y_E0) % Y_R0) +*/
/* ((counter/Y_E1) % Y_R1) * Y_R0*/
/* + ((counter/Y_E2) % Y_R2) **/
/* Y_R0 * Y_R1 Units Num Min 0*/
/* Max 2^20-1*/
uint32_t  RSVD_0               :  12;
/*  Nebulon auto filled RSVD [31:20] */
	}                                field;
uint32_t                         val;
};
#endif
#define CVE_DSE_MEM_Y_E0_OFFSET 0x74
#define CVE_DSE_MEM_Y_E0_SCOPE 0x01
#define CVE_DSE_MEM_Y_E0_SIZE 32
#define CVE_DSE_MEM_Y_E0_BITFIELD_COUNT 0x01
#define CVE_DSE_MEM_Y_E0_RESET 0x00000001
#define CVE_DSE_MEM_Y_E0_Y_E0_LSB 0x0000
#define CVE_DSE_MEM_Y_E0_Y_E0_MSB 0x0013
#define CVE_DSE_MEM_Y_E0_Y_E0_RANGE 0x0014
#define CVE_DSE_MEM_Y_E0_Y_E0_MASK 0x000fffff
#define CVE_DSE_MEM_Y_E0_Y_E0_RESET_VALUE 0x00000001

/*  ------------------------------------------------------------------ */
/* */
#ifndef CVE_DSE_MEM_Y_R0_FLAG
#define CVE_DSE_MEM_Y_R0_FLAG
/* Y_R0 desc:  Y R0*/
union CVE_DSE_MEM_Y_R0_t {
	struct {
uint32_t  Y_R0                 :  20;
/*   Units Num Min 0 Max 2^20-1 */
uint32_t  RSVD_0               :  12;
/*  Nebulon auto filled RSVD [31:20] */
	}                                field;
uint32_t                         val;
};
#endif
#define CVE_DSE_MEM_Y_R0_OFFSET 0xb4
#define CVE_DSE_MEM_Y_R0_SCOPE 0x01
#define CVE_DSE_MEM_Y_R0_SIZE 32
#define CVE_DSE_MEM_Y_R0_BITFIELD_COUNT 0x01
#define CVE_DSE_MEM_Y_R0_RESET 0x00000001
#define CVE_DSE_MEM_Y_R0_Y_R0_LSB 0x0000
#define CVE_DSE_MEM_Y_R0_Y_R0_MSB 0x0013
#define CVE_DSE_MEM_Y_R0_Y_R0_RANGE 0x0014
#define CVE_DSE_MEM_Y_R0_Y_R0_MASK 0x000fffff
#define CVE_DSE_MEM_Y_R0_Y_R0_RESET_VALUE 0x00000001

/*  ------------------------------------------------------------------ */
/* */
#ifndef CVE_DSE_MEM_Y_E1_FLAG
#define CVE_DSE_MEM_Y_E1_FLAG
/* Y_E1 desc:  Y E1*/
union CVE_DSE_MEM_Y_E1_t {
	struct {
uint32_t  Y_E1                 :  20;
/*   Units Num Min 0 Max 2^20-1 */
uint32_t  RSVD_0               :  12;
/*  Nebulon auto filled RSVD [31:20] */
	}                                field;
uint32_t                         val;
};
#endif
#define CVE_DSE_MEM_Y_E1_OFFSET 0xf4
#define CVE_DSE_MEM_Y_E1_SCOPE 0x01
#define CVE_DSE_MEM_Y_E1_SIZE 32
#define CVE_DSE_MEM_Y_E1_BITFIELD_COUNT 0x01
#define CVE_DSE_MEM_Y_E1_RESET 0x00000001
#define CVE_DSE_MEM_Y_E1_Y_E1_LSB 0x0000
#define CVE_DSE_MEM_Y_E1_Y_E1_MSB 0x0013
#define CVE_DSE_MEM_Y_E1_Y_E1_RANGE 0x0014
#define CVE_DSE_MEM_Y_E1_Y_E1_MASK 0x000fffff
#define CVE_DSE_MEM_Y_E1_Y_E1_RESET_VALUE 0x00000001

/*  ------------------------------------------------------------------ */
/* */
#ifndef CVE_DSE_MEM_Y_R1_FLAG
#define CVE_DSE_MEM_Y_R1_FLAG
/* Y_R1 desc:  Y R1*/
union CVE_DSE_MEM_Y_R1_t {
	struct {
uint32_t  Y_R1                 :  20;
/*   Units Num Min 0 Max 2^20-1 */
uint32_t  RSVD_0               :  12;
/*  Nebulon auto filled RSVD [31:20] */
	}                                field;
uint32_t                         val;
};
#endif
#define CVE_DSE_MEM_Y_R1_OFFSET 0x34
#define CVE_DSE_MEM_Y_R1_SCOPE 0x01
#define CVE_DSE_MEM_Y_R1_SIZE 32
#define CVE_DSE_MEM_Y_R1_BITFIELD_COUNT 0x01
#define CVE_DSE_MEM_Y_R1_RESET 0x00000001
#define CVE_DSE_MEM_Y_R1_Y_R1_LSB 0x0000
#define CVE_DSE_MEM_Y_R1_Y_R1_MSB 0x0013
#define CVE_DSE_MEM_Y_R1_Y_R1_RANGE 0x0014
#define CVE_DSE_MEM_Y_R1_Y_R1_MASK 0x000fffff
#define CVE_DSE_MEM_Y_R1_Y_R1_RESET_VALUE 0x00000001

/*  ------------------------------------------------------------------ */
/* */
#ifndef CVE_DSE_MEM_Y_E2_FLAG
#define CVE_DSE_MEM_Y_E2_FLAG
/* Y_E2 desc:  Y E2*/
union CVE_DSE_MEM_Y_E2_t {
	struct {
uint32_t  Y_E2                 :  20;
/*   Units Num Min 0 Max 2^20-1 */
uint32_t  RSVD_0               :  12;
/*  Nebulon auto filled RSVD [31:20] */
	}                                field;
uint32_t                         val;
};
#endif
#define CVE_DSE_MEM_Y_E2_OFFSET 0x74
#define CVE_DSE_MEM_Y_E2_SCOPE 0x01
#define CVE_DSE_MEM_Y_E2_SIZE 32
#define CVE_DSE_MEM_Y_E2_BITFIELD_COUNT 0x01
#define CVE_DSE_MEM_Y_E2_RESET 0x00000001
#define CVE_DSE_MEM_Y_E2_Y_E2_LSB 0x0000
#define CVE_DSE_MEM_Y_E2_Y_E2_MSB 0x0013
#define CVE_DSE_MEM_Y_E2_Y_E2_RANGE 0x0014
#define CVE_DSE_MEM_Y_E2_Y_E2_MASK 0x000fffff
#define CVE_DSE_MEM_Y_E2_Y_E2_RESET_VALUE 0x00000001

/*  ------------------------------------------------------------------ */
/* */
#ifndef CVE_DSE_MEM_Y_R2_FLAG
#define CVE_DSE_MEM_Y_R2_FLAG
/* Y_R2 desc:  Y R2*/
union CVE_DSE_MEM_Y_R2_t {
	struct {
uint32_t  Y_R2                 :  20;
/*   Units Num Min 0 Max 2^20-1 */
uint32_t  RSVD_0               :  12;
/*  Nebulon auto filled RSVD [31:20] */
	}                                field;
uint32_t                         val;
};
#endif
#define CVE_DSE_MEM_Y_R2_OFFSET 0xb4
#define CVE_DSE_MEM_Y_R2_SCOPE 0x01
#define CVE_DSE_MEM_Y_R2_SIZE 32
#define CVE_DSE_MEM_Y_R2_BITFIELD_COUNT 0x01
#define CVE_DSE_MEM_Y_R2_RESET 0x00000001
#define CVE_DSE_MEM_Y_R2_Y_R2_LSB 0x0000
#define CVE_DSE_MEM_Y_R2_Y_R2_MSB 0x0013
#define CVE_DSE_MEM_Y_R2_Y_R2_RANGE 0x0014
#define CVE_DSE_MEM_Y_R2_Y_R2_MASK 0x000fffff
#define CVE_DSE_MEM_Y_R2_Y_R2_RESET_VALUE 0x00000001

/*  ------------------------------------------------------------------ */
/* */
#ifndef CVE_DSE_MEM_Z_E0_FLAG
#define CVE_DSE_MEM_Z_E0_FLAG
/* Z_E0 desc:  Z E0*/
union CVE_DSE_MEM_Z_E0_t {
	struct {
uint32_t  Z_E0                 :  20;
/*   (walk3D) STEP_3D_IDX = */
/* (counter/Z_E0) % Z_R0) +*/
/* ((counter/Z_E1) % Z_R1) * Z_R0*/
/* + ((counter/Z_E2) % Z_R2) **/
/* Z_R0 * Z_R1 Units Num Min 0*/
/* Max 2^20-1*/
uint32_t  RSVD_0               :  12;
/*  Nebulon auto filled RSVD [31:20] */
	}                                field;
uint32_t                         val;
};
#endif
#define CVE_DSE_MEM_Z_E0_OFFSET 0xf4
#define CVE_DSE_MEM_Z_E0_SCOPE 0x01
#define CVE_DSE_MEM_Z_E0_SIZE 32
#define CVE_DSE_MEM_Z_E0_BITFIELD_COUNT 0x01
#define CVE_DSE_MEM_Z_E0_RESET 0x00000001
#define CVE_DSE_MEM_Z_E0_Z_E0_LSB 0x0000
#define CVE_DSE_MEM_Z_E0_Z_E0_MSB 0x0013
#define CVE_DSE_MEM_Z_E0_Z_E0_RANGE 0x0014
#define CVE_DSE_MEM_Z_E0_Z_E0_MASK 0x000fffff
#define CVE_DSE_MEM_Z_E0_Z_E0_RESET_VALUE 0x00000001

/*  ------------------------------------------------------------------ */
/* */
#ifndef CVE_DSE_MEM_Z_R0_FLAG
#define CVE_DSE_MEM_Z_R0_FLAG
/* Z_R0 desc:  Z R0*/
union CVE_DSE_MEM_Z_R0_t {
	struct {
uint32_t  Z_R0                 :  20;
/*   Units Num Min 0 Max 2^20-1 */
uint32_t  RSVD_0               :  12;
/*  Nebulon auto filled RSVD [31:20] */
	}                                field;
uint32_t                         val;
};
#endif
#define CVE_DSE_MEM_Z_R0_OFFSET 0x34
#define CVE_DSE_MEM_Z_R0_SCOPE 0x01
#define CVE_DSE_MEM_Z_R0_SIZE 32
#define CVE_DSE_MEM_Z_R0_BITFIELD_COUNT 0x01
#define CVE_DSE_MEM_Z_R0_RESET 0x00000001
#define CVE_DSE_MEM_Z_R0_Z_R0_LSB 0x0000
#define CVE_DSE_MEM_Z_R0_Z_R0_MSB 0x0013
#define CVE_DSE_MEM_Z_R0_Z_R0_RANGE 0x0014
#define CVE_DSE_MEM_Z_R0_Z_R0_MASK 0x000fffff
#define CVE_DSE_MEM_Z_R0_Z_R0_RESET_VALUE 0x00000001

/*  ------------------------------------------------------------------ */
/* */
#ifndef CVE_DSE_MEM_Z_E1_FLAG
#define CVE_DSE_MEM_Z_E1_FLAG
/* Z_E1 desc:  Z E1*/
union CVE_DSE_MEM_Z_E1_t {
	struct {
uint32_t  Z_E1                 :  20;
/*   Units Num Min 0 Max 2^20-1 */
uint32_t  RSVD_0               :  12;
/*  Nebulon auto filled RSVD [31:20] */
	}                                field;
uint32_t                         val;
};
#endif
#define CVE_DSE_MEM_Z_E1_OFFSET 0x74
#define CVE_DSE_MEM_Z_E1_SCOPE 0x01
#define CVE_DSE_MEM_Z_E1_SIZE 32
#define CVE_DSE_MEM_Z_E1_BITFIELD_COUNT 0x01
#define CVE_DSE_MEM_Z_E1_RESET 0x00000001
#define CVE_DSE_MEM_Z_E1_Z_E1_LSB 0x0000
#define CVE_DSE_MEM_Z_E1_Z_E1_MSB 0x0013
#define CVE_DSE_MEM_Z_E1_Z_E1_RANGE 0x0014
#define CVE_DSE_MEM_Z_E1_Z_E1_MASK 0x000fffff
#define CVE_DSE_MEM_Z_E1_Z_E1_RESET_VALUE 0x00000001

/*  ------------------------------------------------------------------ */
/* */
#ifndef CVE_DSE_MEM_Z_R1_FLAG
#define CVE_DSE_MEM_Z_R1_FLAG
/* Z_R1 desc:  Z R1*/
union CVE_DSE_MEM_Z_R1_t {
	struct {
uint32_t  Z_R1                 :  20;
/*   Units Num Min 0 Max 2^20-1 */
uint32_t  RSVD_0               :  12;
/*  Nebulon auto filled RSVD [31:20] */
	}                                field;
uint32_t                         val;
};
#endif
#define CVE_DSE_MEM_Z_R1_OFFSET 0xb4
#define CVE_DSE_MEM_Z_R1_SCOPE 0x01
#define CVE_DSE_MEM_Z_R1_SIZE 32
#define CVE_DSE_MEM_Z_R1_BITFIELD_COUNT 0x01
#define CVE_DSE_MEM_Z_R1_RESET 0x00000001
#define CVE_DSE_MEM_Z_R1_Z_R1_LSB 0x0000
#define CVE_DSE_MEM_Z_R1_Z_R1_MSB 0x0013
#define CVE_DSE_MEM_Z_R1_Z_R1_RANGE 0x0014
#define CVE_DSE_MEM_Z_R1_Z_R1_MASK 0x000fffff
#define CVE_DSE_MEM_Z_R1_Z_R1_RESET_VALUE 0x00000001

/*  ------------------------------------------------------------------ */
/* */
#ifndef CVE_DSE_MEM_Z_E2_FLAG
#define CVE_DSE_MEM_Z_E2_FLAG
/* Z_E2 desc:  Z E2*/
union CVE_DSE_MEM_Z_E2_t {
	struct {
uint32_t  Z_E2                 :  20;
/*   Units Num Min 0 Max 2^20-1 */
uint32_t  RSVD_0               :  12;
/*  Nebulon auto filled RSVD [31:20] */
	}                                field;
uint32_t                         val;
};
#endif
#define CVE_DSE_MEM_Z_E2_OFFSET 0xf4
#define CVE_DSE_MEM_Z_E2_SCOPE 0x01
#define CVE_DSE_MEM_Z_E2_SIZE 32
#define CVE_DSE_MEM_Z_E2_BITFIELD_COUNT 0x01
#define CVE_DSE_MEM_Z_E2_RESET 0x00000001
#define CVE_DSE_MEM_Z_E2_Z_E2_LSB 0x0000
#define CVE_DSE_MEM_Z_E2_Z_E2_MSB 0x0013
#define CVE_DSE_MEM_Z_E2_Z_E2_RANGE 0x0014
#define CVE_DSE_MEM_Z_E2_Z_E2_MASK 0x000fffff
#define CVE_DSE_MEM_Z_E2_Z_E2_RESET_VALUE 0x00000001

/*  ------------------------------------------------------------------ */
/* */
#ifndef CVE_DSE_MEM_Z_R2_FLAG
#define CVE_DSE_MEM_Z_R2_FLAG
/* Z_R2 desc:  Z R2*/
union CVE_DSE_MEM_Z_R2_t {
	struct {
uint32_t  Z_R2                 :  20;
/*   Units Num Min 0 Max 2^20-1 */
uint32_t  RSVD_0               :  12;
/*  Nebulon auto filled RSVD [31:20] */
	}                                field;
uint32_t                         val;
};
#endif
#define CVE_DSE_MEM_Z_R2_OFFSET 0x34
#define CVE_DSE_MEM_Z_R2_SCOPE 0x01
#define CVE_DSE_MEM_Z_R2_SIZE 32
#define CVE_DSE_MEM_Z_R2_BITFIELD_COUNT 0x01
#define CVE_DSE_MEM_Z_R2_RESET 0x00000001
#define CVE_DSE_MEM_Z_R2_Z_R2_LSB 0x0000
#define CVE_DSE_MEM_Z_R2_Z_R2_MSB 0x0013
#define CVE_DSE_MEM_Z_R2_Z_R2_RANGE 0x0014
#define CVE_DSE_MEM_Z_R2_Z_R2_MASK 0x000fffff
#define CVE_DSE_MEM_Z_R2_Z_R2_RESET_VALUE 0x00000001

/*  ------------------------------------------------------------------ */
/* */
#ifndef CVE_DSE_MEM_W_E0_FLAG
#define CVE_DSE_MEM_W_E0_FLAG
/* W_E0 desc:  W E0*/
union CVE_DSE_MEM_W_E0_t {
	struct {
uint32_t  W_E0                 :  20;
/*   (walk4D) STEP_4D_IDX = */
/* (counter/W_E0) % W_R0) +*/
/* ((counter/W_E1) % W_R1) * W_R0*/
/* + ((counter/W_E2) % W_R2) **/
/* W_R0 * W_R1 Units Num Min 0*/
/* Max 2^20-1*/
uint32_t  RSVD_0               :  12;
/*  Nebulon auto filled RSVD [31:20] */
	}                                field;
uint32_t                         val;
};
#endif
#define CVE_DSE_MEM_W_E0_OFFSET 0x74
#define CVE_DSE_MEM_W_E0_SCOPE 0x01
#define CVE_DSE_MEM_W_E0_SIZE 32
#define CVE_DSE_MEM_W_E0_BITFIELD_COUNT 0x01
#define CVE_DSE_MEM_W_E0_RESET 0x00000001
#define CVE_DSE_MEM_W_E0_W_E0_LSB 0x0000
#define CVE_DSE_MEM_W_E0_W_E0_MSB 0x0013
#define CVE_DSE_MEM_W_E0_W_E0_RANGE 0x0014
#define CVE_DSE_MEM_W_E0_W_E0_MASK 0x000fffff
#define CVE_DSE_MEM_W_E0_W_E0_RESET_VALUE 0x00000001

/*  ------------------------------------------------------------------ */
/* */
#ifndef CVE_DSE_MEM_W_R0_FLAG
#define CVE_DSE_MEM_W_R0_FLAG
/* W_R0 desc:  W R0*/
union CVE_DSE_MEM_W_R0_t {
	struct {
uint32_t  W_R0                 :  20;
/*   Units Num Min 0 Max 2^20-1 */
uint32_t  RSVD_0               :  12;
/*  Nebulon auto filled RSVD [31:20] */
	}                                field;
uint32_t                         val;
};
#endif
#define CVE_DSE_MEM_W_R0_OFFSET 0xb4
#define CVE_DSE_MEM_W_R0_SCOPE 0x01
#define CVE_DSE_MEM_W_R0_SIZE 32
#define CVE_DSE_MEM_W_R0_BITFIELD_COUNT 0x01
#define CVE_DSE_MEM_W_R0_RESET 0x00000001
#define CVE_DSE_MEM_W_R0_W_R0_LSB 0x0000
#define CVE_DSE_MEM_W_R0_W_R0_MSB 0x0013
#define CVE_DSE_MEM_W_R0_W_R0_RANGE 0x0014
#define CVE_DSE_MEM_W_R0_W_R0_MASK 0x000fffff
#define CVE_DSE_MEM_W_R0_W_R0_RESET_VALUE 0x00000001

/*  ------------------------------------------------------------------ */
/* */
#ifndef CVE_DSE_MEM_W_E1_FLAG
#define CVE_DSE_MEM_W_E1_FLAG
/* W_E1 desc:  W E1*/
union CVE_DSE_MEM_W_E1_t {
	struct {
uint32_t  W_E1                 :  20;
/*   Units Num Min 0 Max 2^20-1 */
uint32_t  RSVD_0               :  12;
/*  Nebulon auto filled RSVD [31:20] */
	}                                field;
uint32_t                         val;
};
#endif
#define CVE_DSE_MEM_W_E1_OFFSET 0xf4
#define CVE_DSE_MEM_W_E1_SCOPE 0x01
#define CVE_DSE_MEM_W_E1_SIZE 32
#define CVE_DSE_MEM_W_E1_BITFIELD_COUNT 0x01
#define CVE_DSE_MEM_W_E1_RESET 0x00000001
#define CVE_DSE_MEM_W_E1_W_E1_LSB 0x0000
#define CVE_DSE_MEM_W_E1_W_E1_MSB 0x0013
#define CVE_DSE_MEM_W_E1_W_E1_RANGE 0x0014
#define CVE_DSE_MEM_W_E1_W_E1_MASK 0x000fffff
#define CVE_DSE_MEM_W_E1_W_E1_RESET_VALUE 0x00000001

/*  ------------------------------------------------------------------ */
/* */
#ifndef CVE_DSE_MEM_W_R1_FLAG
#define CVE_DSE_MEM_W_R1_FLAG
/* W_R1 desc:  W R1*/
union CVE_DSE_MEM_W_R1_t {
	struct {
uint32_t  W_R1                 :  20;
/*   Units Num Min 0 Max 2^20-1 */
uint32_t  RSVD_0               :  12;
/*  Nebulon auto filled RSVD [31:20] */
	}                                field;
uint32_t                         val;
};
#endif
#define CVE_DSE_MEM_W_R1_OFFSET 0x34
#define CVE_DSE_MEM_W_R1_SCOPE 0x01
#define CVE_DSE_MEM_W_R1_SIZE 32
#define CVE_DSE_MEM_W_R1_BITFIELD_COUNT 0x01
#define CVE_DSE_MEM_W_R1_RESET 0x00000001
#define CVE_DSE_MEM_W_R1_W_R1_LSB 0x0000
#define CVE_DSE_MEM_W_R1_W_R1_MSB 0x0013
#define CVE_DSE_MEM_W_R1_W_R1_RANGE 0x0014
#define CVE_DSE_MEM_W_R1_W_R1_MASK 0x000fffff
#define CVE_DSE_MEM_W_R1_W_R1_RESET_VALUE 0x00000001

/*  ------------------------------------------------------------------ */
/* */
#ifndef CVE_DSE_MEM_W_E2_FLAG
#define CVE_DSE_MEM_W_E2_FLAG
/* W_E2 desc:  W E2*/
union CVE_DSE_MEM_W_E2_t {
	struct {
uint32_t  W_E2                 :  20;
/*   Units Num Min 0 Max 2^20-1 */
uint32_t  RSVD_0               :  12;
/*  Nebulon auto filled RSVD [31:20] */
	}                                field;
uint32_t                         val;
};
#endif
#define CVE_DSE_MEM_W_E2_OFFSET 0x74
#define CVE_DSE_MEM_W_E2_SCOPE 0x01
#define CVE_DSE_MEM_W_E2_SIZE 32
#define CVE_DSE_MEM_W_E2_BITFIELD_COUNT 0x01
#define CVE_DSE_MEM_W_E2_RESET 0x00000001
#define CVE_DSE_MEM_W_E2_W_E2_LSB 0x0000
#define CVE_DSE_MEM_W_E2_W_E2_MSB 0x0013
#define CVE_DSE_MEM_W_E2_W_E2_RANGE 0x0014
#define CVE_DSE_MEM_W_E2_W_E2_MASK 0x000fffff
#define CVE_DSE_MEM_W_E2_W_E2_RESET_VALUE 0x00000001

/*  ------------------------------------------------------------------ */
/* */
#ifndef CVE_DSE_MEM_W_R2_FLAG
#define CVE_DSE_MEM_W_R2_FLAG
/* W_R2 desc:  W R2*/
union CVE_DSE_MEM_W_R2_t {
	struct {
uint32_t  W_R2                 :  20;
/*   Units Num Min 0 Max 2^20-1 */
uint32_t  RSVD_0               :  12;
/*  Nebulon auto filled RSVD [31:20] */
	}                                field;
uint32_t                         val;
};
#endif
#define CVE_DSE_MEM_W_R2_OFFSET 0xb4
#define CVE_DSE_MEM_W_R2_SCOPE 0x01
#define CVE_DSE_MEM_W_R2_SIZE 32
#define CVE_DSE_MEM_W_R2_BITFIELD_COUNT 0x01
#define CVE_DSE_MEM_W_R2_RESET 0x00000001
#define CVE_DSE_MEM_W_R2_W_R2_LSB 0x0000
#define CVE_DSE_MEM_W_R2_W_R2_MSB 0x0013
#define CVE_DSE_MEM_W_R2_W_R2_RANGE 0x0014
#define CVE_DSE_MEM_W_R2_W_R2_MASK 0x000fffff
#define CVE_DSE_MEM_W_R2_W_R2_RESET_VALUE 0x00000001

/*  ------------------------------------------------------------------ */
/* */
#ifndef CVE_DSE_MEM_PMON_COUNTER_CONFIG_FLAG
#define CVE_DSE_MEM_PMON_COUNTER_CONFIG_FLAG
/* PMON_COUNTER_CONFIG desc:  Pmon Counter Config*/
union CVE_DSE_MEM_PMON_COUNTER_CONFIG_t {
	struct {
uint32_t  PMON_ENABLE          :   1;
/*   Preformenc Counter Enable */
/* Units Num Min 0 Max 1*/
uint32_t  PMON_COUNT_ALL       :   1;
/*   Count all Surfaces Units Num */
/* Min 0 Max 1*/
uint32_t  RSVD_0               :   2;
/*  Nebulon auto filled RSVD [3:2] */
uint32_t  PMON_COUNT_SELECT    :   5;
/*   Preformenc Counter Selector */
/* Units Num Min 0 Max 21*/
uint32_t  RSVD_1               :   7;
/*  Nebulon auto filled RSVD [15:9] */
uint32_t  PMON_SBID            :   5;
/*   Some of the Counter can be */
/* count per Surface/Buffer ID*/
/* Units Num Min 0 Max 15*/
uint32_t  RSVD_2               :  11;
/*  Nebulon auto filled RSVD [31:21] */
	}                                field;
uint32_t                         val;
};
#endif
#define CVE_DSE_MEM_PMON_COUNTER_CONFIG_OFFSET 0xf4
#define CVE_DSE_MEM_PMON_COUNTER_CONFIG_SCOPE 0x01
#define CVE_DSE_MEM_PMON_COUNTER_CONFIG_SIZE 32
#define CVE_DSE_MEM_PMON_COUNTER_CONFIG_BITFIELD_COUNT 0x04
#define CVE_DSE_MEM_PMON_COUNTER_CONFIG_RESET 0x00000000
#define CVE_DSE_MEM_PMON_COUNTER_CONFIG_PMON_ENABLE_LSB 0x0000
#define CVE_DSE_MEM_PMON_COUNTER_CONFIG_PMON_ENABLE_MSB 0x0000
#define CVE_DSE_MEM_PMON_COUNTER_CONFIG_PMON_ENABLE_RANGE 0x0001
#define CVE_DSE_MEM_PMON_COUNTER_CONFIG_PMON_ENABLE_MASK 0x00000001
#define CVE_DSE_MEM_PMON_COUNTER_CONFIG_PMON_ENABLE_RESET_VALUE 0x00000000
#define CVE_DSE_MEM_PMON_COUNTER_CONFIG_PMON_COUNT_ALL_LSB 0x0001
#define CVE_DSE_MEM_PMON_COUNTER_CONFIG_PMON_COUNT_ALL_MSB 0x0001
#define CVE_DSE_MEM_PMON_COUNTER_CONFIG_PMON_COUNT_ALL_RANGE 0x0001
#define CVE_DSE_MEM_PMON_COUNTER_CONFIG_PMON_COUNT_ALL_MASK 0x00000002
#define CVE_DSE_MEM_PMON_COUNTER_CONFIG_PMON_COUNT_ALL_RESET_VALUE 0x00000000
#define CVE_DSE_MEM_PMON_COUNTER_CONFIG_PMON_COUNT_SELECT_LSB 0x0004
#define CVE_DSE_MEM_PMON_COUNTER_CONFIG_PMON_COUNT_SELECT_MSB 0x0008
#define CVE_DSE_MEM_PMON_COUNTER_CONFIG_PMON_COUNT_SELECT_RANGE 0x0005
#define CVE_DSE_MEM_PMON_COUNTER_CONFIG_PMON_COUNT_SELECT_MASK 0x000001f0
#define CVE_DSE_MEM_PMON_COUNTER_CONFIG_PMON_COUNT_SELECT_RESET_VALUE 0x00000000
#define CVE_DSE_MEM_PMON_COUNTER_CONFIG_PMON_SBID_LSB 0x0010
#define CVE_DSE_MEM_PMON_COUNTER_CONFIG_PMON_SBID_MSB 0x0014
#define CVE_DSE_MEM_PMON_COUNTER_CONFIG_PMON_SBID_RANGE 0x0005
#define CVE_DSE_MEM_PMON_COUNTER_CONFIG_PMON_SBID_MASK 0x001f0000
#define CVE_DSE_MEM_PMON_COUNTER_CONFIG_PMON_SBID_RESET_VALUE 0x00000000

/*  ------------------------------------------------------------------ */
/* */
#ifndef CVE_DSE_MEM_PMON_COUNTER_FLAG
#define CVE_DSE_MEM_PMON_COUNTER_FLAG
/* PMON_COUNTER desc:  Pmon Counter*/
union CVE_DSE_MEM_PMON_COUNTER_t {
	struct {
uint32_t  PMON_COUNTER         :  32;
/*   Preformence Counter Units Num */
/* Min 0 Max 2^32-1*/
	}                                field;
uint32_t                         val;
};
#endif
#define CVE_DSE_MEM_PMON_COUNTER_OFFSET 0x34
#define CVE_DSE_MEM_PMON_COUNTER_SCOPE 0x01
#define CVE_DSE_MEM_PMON_COUNTER_SIZE 32
#define CVE_DSE_MEM_PMON_COUNTER_BITFIELD_COUNT 0x01
#define CVE_DSE_MEM_PMON_COUNTER_RESET 0x00000000
#define CVE_DSE_MEM_PMON_COUNTER_PMON_COUNTER_LSB 0x0000
#define CVE_DSE_MEM_PMON_COUNTER_PMON_COUNTER_MSB 0x001f
#define CVE_DSE_MEM_PMON_COUNTER_PMON_COUNTER_RANGE 0x0020
#define CVE_DSE_MEM_PMON_COUNTER_PMON_COUNTER_MASK 0xffffffff
#define CVE_DSE_MEM_PMON_COUNTER_PMON_COUNTER_RESET_VALUE 0x00000000

/*  ------------------------------------------------------------------ */
/* */
/* starting the array instantiation section*/
struct cve_dse_t {
union CVE_DSE_MEM_SELF_CONFIG_t  SELF_CONFIG;
/*  offset 4'h0, width 32 */
union CVE_DSE_MEM_SELF_CONFIG_AXI_READ_CONFIG_t SELF_CONFIG_AXI_READ_CONFIG;
/*  offset 4'h4, width 32 */
union CVE_DSE_MEM_SELF_CONFIG_AXI_AUSER_EXTEND_t SELF_CONFIG_AXI_AUSER_EXTEND;
/*  offset 4'h8, width 32 */
union CVE_DSE_MEM_SURFACE_START_ADDR_t SURFACE_START_ADDR[16];
/*  offset 8'h0C, width 32 */
union CVE_DSE_MEM_SURFACE_START_ADDR_MSB_t SURFACE_START_ADDR_MSB[16];
/*  offset 8'h4C, width 32 */
union CVE_DSE_MEM_SURFACE_1D_LENGTH_t SURFACE_1D_LENGTH[16];
/*  offset 8'h8C, width 32 */
union CVE_DSE_MEM_SURFACE_2D_LENGTH_t SURFACE_2D_LENGTH[16];
/*  offset 12'h0CC, width 32 */
union CVE_DSE_MEM_SURFACE_3D_LENGTH_t SURFACE_3D_LENGTH[16];
/*  offset 12'h10C, width 32 */
union CVE_DSE_MEM_SURFACE_4D_LENGTH_t SURFACE_4D_LENGTH[16];
/*  offset 12'h14C, width 32 */
union CVE_DSE_MEM_SURFACE_1D_PITCH_t SURFACE_1D_PITCH[16];
/*  offset 12'h18C, width 32 */
union CVE_DSE_MEM_SURFACE_2D_PITCH_t SURFACE_2D_PITCH[16];
/*  offset 12'h1CC, width 32 */
union CVE_DSE_MEM_SURFACE_3D_PITCH_t SURFACE_3D_PITCH[16];
/*  offset 12'h20C, width 32 */
union CVE_DSE_MEM_TILE_1D_LENGTH_t TILE_1D_LENGTH[16];
/*  offset 12'h24C, width 32 */
union CVE_DSE_MEM_TILE_2D_LENGTH_t TILE_2D_LENGTH[16];
/*  offset 12'h28C, width 32 */
union CVE_DSE_MEM_TILE_3D_LENGTH_t TILE_3D_LENGTH[16];
/*  offset 12'h2CC, width 32 */
union CVE_DSE_MEM_TILE_4D_LENGTH_t TILE_4D_LENGTH[16];
/*  offset 12'h30C, width 32 */
union CVE_DSE_MEM_TILE_1D_STEP_t TILE_1D_STEP[16];
/*  offset 12'h34C, width 32 */
union CVE_DSE_MEM_TILE_2D_STEP_t TILE_2D_STEP[16];
/*  offset 12'h38C, width 32 */
union CVE_DSE_MEM_TILE_3D_STEP_t TILE_3D_STEP[16];
/*  offset 12'h3CC, width 32 */
union CVE_DSE_MEM_TILE_4D_STEP_t TILE_4D_STEP[16];
/*  offset 12'h40C, width 32 */
union CVE_DSE_MEM_TILE_1D_OFFSET_t TILE_1D_OFFSET[16];
/*  offset 12'h44C, width 32 */
union CVE_DSE_MEM_TILE_2D_OFFSET_t TILE_2D_OFFSET[16];
/*  offset 12'h48C, width 32 */
union CVE_DSE_MEM_TILE_3D_OFFSET_t TILE_3D_OFFSET[16];
/*  offset 12'h4CC, width 32 */
union CVE_DSE_MEM_TILE_4D_OFFSET_t TILE_4D_OFFSET[16];
/*  offset 12'h50C, width 32 */
union CVE_DSE_MEM_TILE_FETCH_REORDER_Q_NUM_t TILE_FETCH_REORDER_Q_NUM[16];
/*  offset 12'h54C, width 32 */
union CVE_DSE_MEM_TILE_PADDING_CONFIG_t TILE_PADDING_CONFIG[16];
/*  offset 12'h58C, width 32 */
union CVE_DSE_MEM_TILE_PADDING_DATA_t TILE_PADDING_DATA[16];
/*  offset 12'h5CC, width 32 */
union CVE_DSE_MEM_AXI_READ_CONFIG_t AXI_READ_CONFIG[16];
/*  offset 12'h60C, width 32 */
union CVE_DSE_MEM_AXI_WRITE_CONFIG_t AXI_WRITE_CONFIG[16];
/*  offset 12'h64C, width 32 */
union CVE_DSE_MEM_AXI_AUSER_EXTEND_t AXI_AUSER_EXTEND[16];
/*  offset 12'h68C, width 32 */
union CVE_DSE_MEM_AXI_MAX_INFLIGHT_t AXI_MAX_INFLIGHT;
/*  offset 12'h6CC, width 32 */
union CVE_DSE_MEM_NEAR_ZERO_TH_SETTING_t NEAR_ZERO_TH_SETTING[16];
/*  offset 12'h6D0, width 32 */
union CVE_DSE_MEM_WEIGHT_LUT_SETTING_t WEIGHT_LUT_SETTING[16];
/*  offset 12'h710, width 32 */
union CVE_DSE_MEM_WEIGHT_LUT_BASE_ADDR_t WEIGHT_LUT_BASE_ADDR;
/*  offset 12'h750, width 32 */
union CVE_DSE_MEM_SP_BUFFER_START_ADDR_t SP_BUFFER_START_ADDR[20];
/*  offset 12'h754, width 32 */
union CVE_DSE_MEM_SP_BUFFER_END_ADDR_t SP_BUFFER_END_ADDR[20];
/*  offset 12'h7A4, width 32 */
union CVE_DSE_MEM_SP_TILE_BOX_1D_LENGTH_t SP_TILE_BOX_1D_LENGTH[20];
/*  offset 12'h7F4, width 32 */
union CVE_DSE_MEM_SP_TILE_BOX_2D_LENGTH_t SP_TILE_BOX_2D_LENGTH[20];
/*  offset 12'h844, width 32 */
union CVE_DSE_MEM_SP_TILE_BOX_3D_LENGTH_t SP_TILE_BOX_3D_LENGTH[20];
/*  offset 12'h894, width 32 */
union CVE_DSE_MEM_SP_TILE_BOX_4D_LENGTH_t SP_TILE_BOX_4D_LENGTH[20];
/*  offset 12'h8E4, width 32 */
union CVE_DSE_MEM_SP_TILE_BOX_2D_PITCH_t SP_TILE_BOX_2D_PITCH[20];
/*  offset 12'h934, width 32 */
union CVE_DSE_MEM_SP_TILE_BOX_3D_PITCH_t SP_TILE_BOX_3D_PITCH[20];
/*  offset 12'h984, width 32 */
union CVE_DSE_MEM_SP_TILE_BOX_PITCH_t SP_TILE_BOX_PITCH[20];
/*  offset 12'h9D4, width 32 */
union CVE_DSE_MEM_TILE_1D_OFFSET_ON_SP_t TILE_1D_OFFSET_ON_SP[20];
/*  offset 16'h0A24, width 32 */
union CVE_DSE_MEM_TILE_2D_OFFSET_ON_SP_t TILE_2D_OFFSET_ON_SP[20];
/*  offset 16'h0A74, width 32 */
union CVE_DSE_MEM_SP_TILE_BOX_SCALE_t SP_TILE_BOX_SCALE[20];
/*  offset 16'h0AC4, width 32 */
union CVE_DSE_MEM_TOTAL_CREDITS_t TOTAL_CREDITS[20];
/*  offset 16'h0B14, width 32 */
union CVE_DSE_MEM_CREDIT_GRANULARITY_t CREDIT_GRANULARITY[20];
/*  offset 16'h0B64, width 32 */
union CVE_DSE_MEM_WACM_CONFIG_t  WACM_CONFIG[16];
/*  offset 16'h0BB4, width 32 */
union CVE_DSE_MEM_X_E0_t         X_E0[16];
/*  offset 16'h0BF4, width 32 */
union CVE_DSE_MEM_X_R0_t         X_R0[16];
/*  offset 16'h0C34, width 32 */
union CVE_DSE_MEM_X_E1_t         X_E1[16];
/*  offset 16'h0C74, width 32 */
union CVE_DSE_MEM_X_R1_t         X_R1[16];
/*  offset 16'h0CB4, width 32 */
union CVE_DSE_MEM_X_E2_t         X_E2[16];
/*  offset 16'h0CF4, width 32 */
union CVE_DSE_MEM_X_R2_t         X_R2[16];
/*  offset 16'h0D34, width 32 */
union CVE_DSE_MEM_Y_E0_t         Y_E0[16];
/*  offset 16'h0D74, width 32 */
union CVE_DSE_MEM_Y_R0_t         Y_R0[16];
/*  offset 16'h0DB4, width 32 */
union CVE_DSE_MEM_Y_E1_t         Y_E1[16];
/*  offset 16'h0DF4, width 32 */
union CVE_DSE_MEM_Y_R1_t         Y_R1[16];
/*  offset 16'h0E34, width 32 */
union CVE_DSE_MEM_Y_E2_t         Y_E2[16];
/*  offset 16'h0E74, width 32 */
union CVE_DSE_MEM_Y_R2_t         Y_R2[16];
/*  offset 16'h0EB4, width 32 */
union CVE_DSE_MEM_Z_E0_t         Z_E0[16];
/*  offset 16'h0EF4, width 32 */
union CVE_DSE_MEM_Z_R0_t         Z_R0[16];
/*  offset 16'h0F34, width 32 */
union CVE_DSE_MEM_Z_E1_t         Z_E1[16];
/*  offset 16'h0F74, width 32 */
union CVE_DSE_MEM_Z_R1_t         Z_R1[16];
/*  offset 16'h0FB4, width 32 */
union CVE_DSE_MEM_Z_E2_t         Z_E2[16];
/*  offset 16'h0FF4, width 32 */
union CVE_DSE_MEM_Z_R2_t         Z_R2[16];
/*  offset 16'h1034, width 32 */
union CVE_DSE_MEM_W_E0_t         W_E0[16];
/*  offset 16'h1074, width 32 */
union CVE_DSE_MEM_W_R0_t         W_R0[16];
/*  offset 16'h10B4, width 32 */
union CVE_DSE_MEM_W_E1_t         W_E1[16];
/*  offset 16'h10F4, width 32 */
union CVE_DSE_MEM_W_R1_t         W_R1[16];
/*  offset 16'h1134, width 32 */
union CVE_DSE_MEM_W_E2_t         W_E2[16];
/*  offset 16'h1174, width 32 */
union CVE_DSE_MEM_W_R2_t         W_R2[16];
/*  offset 16'h11B4, width 32 */
union CVE_DSE_MEM_PMON_COUNTER_CONFIG_t PMON_COUNTER_CONFIG[16];
/*  offset 16'h11F4, width 32 */
union CVE_DSE_MEM_PMON_COUNTER_t PMON_COUNTER[16];
/*  offset 16'h1234, width 32 */
};

#define CVE_DSE_SELF_CONFIG                                    0
#define CVE_DSE_SELF_CONFIG_AXI_READ_CONFIG                    1
#define CVE_DSE_SELF_CONFIG_AXI_AUSER_EXTEND                   2
#define CVE_DSE_SURFACE_START_ADDR                             3
#define CVE_DSE_SURFACE_START_ADDR_MSB                        19
#define CVE_DSE_SURFACE_1D_LENGTH                             35
#define CVE_DSE_SURFACE_2D_LENGTH                             51
#define CVE_DSE_SURFACE_3D_LENGTH                             67
#define CVE_DSE_SURFACE_4D_LENGTH                             83
#define CVE_DSE_SURFACE_1D_PITCH                              99
#define CVE_DSE_SURFACE_2D_PITCH                             115
#define CVE_DSE_SURFACE_3D_PITCH                             131
#define CVE_DSE_TILE_1D_LENGTH                               147
#define CVE_DSE_TILE_2D_LENGTH                               163
#define CVE_DSE_TILE_3D_LENGTH                               179
#define CVE_DSE_TILE_4D_LENGTH                               195
#define CVE_DSE_TILE_1D_STEP                                 211
#define CVE_DSE_TILE_2D_STEP                                 227
#define CVE_DSE_TILE_3D_STEP                                 243
#define CVE_DSE_TILE_4D_STEP                                 259
#define CVE_DSE_TILE_1D_OFFSET                               275
#define CVE_DSE_TILE_2D_OFFSET                               291
#define CVE_DSE_TILE_3D_OFFSET                               307
#define CVE_DSE_TILE_4D_OFFSET                               323
#define CVE_DSE_TILE_FETCH_REORDER_Q_NUM                     339
#define CVE_DSE_TILE_PADDING_CONFIG                          355
#define CVE_DSE_TILE_PADDING_DATA                            371
#define CVE_DSE_AXI_READ_CONFIG                              387
#define CVE_DSE_AXI_WRITE_CONFIG                             403
#define CVE_DSE_AXI_AUSER_EXTEND                             419
#define CVE_DSE_AXI_MAX_INFLIGHT                             435
#define CVE_DSE_NEAR_ZERO_TH_SETTING                         436
#define CVE_DSE_WEIGHT_LUT_SETTING                           452
#define CVE_DSE_WEIGHT_LUT_BASE_ADDR                         468
#define CVE_DSE_SP_BUFFER_START_ADDR                         469
#define CVE_DSE_SP_BUFFER_END_ADDR                           489
#define CVE_DSE_SP_TILE_BOX_1D_LENGTH                        509
#define CVE_DSE_SP_TILE_BOX_2D_LENGTH                        529
#define CVE_DSE_SP_TILE_BOX_3D_LENGTH                        549
#define CVE_DSE_SP_TILE_BOX_4D_LENGTH                        569
#define CVE_DSE_SP_TILE_BOX_2D_PITCH                         589
#define CVE_DSE_SP_TILE_BOX_3D_PITCH                         609
#define CVE_DSE_SP_TILE_BOX_PITCH                            629
#define CVE_DSE_TILE_1D_OFFSET_ON_SP                         649
#define CVE_DSE_TILE_2D_OFFSET_ON_SP                         669
#define CVE_DSE_SP_TILE_BOX_SCALE                            689
#define CVE_DSE_TOTAL_CREDITS                                709
#define CVE_DSE_CREDIT_GRANULARITY                           729
#define CVE_DSE_WACM_CONFIG                                  749
#define CVE_DSE_X_E0                                         765
#define CVE_DSE_X_R0                                         781
#define CVE_DSE_X_E1                                         797
#define CVE_DSE_X_R1                                         813
#define CVE_DSE_X_E2                                         829
#define CVE_DSE_X_R2                                         845
#define CVE_DSE_Y_E0                                         861
#define CVE_DSE_Y_R0                                         877
#define CVE_DSE_Y_E1                                         893
#define CVE_DSE_Y_R1                                         909
#define CVE_DSE_Y_E2                                         925
#define CVE_DSE_Y_R2                                         941
#define CVE_DSE_Z_E0                                         957
#define CVE_DSE_Z_R0                                         973
#define CVE_DSE_Z_E1                                         989
#define CVE_DSE_Z_R1                                        1005
#define CVE_DSE_Z_E2                                        1021
#define CVE_DSE_Z_R2                                        1037
#define CVE_DSE_W_E0                                        1053
#define CVE_DSE_W_R0                                        1069
#define CVE_DSE_W_E1                                        1085
#define CVE_DSE_W_R1                                        1101
#define CVE_DSE_W_E2                                        1117
#define CVE_DSE_W_R2                                        1133
#define CVE_DSE_PMON_COUNTER_CONFIG                         1149
#define CVE_DSE_PMON_COUNTER                                1165

#endif // _CVE_DSE_REGS_H_
