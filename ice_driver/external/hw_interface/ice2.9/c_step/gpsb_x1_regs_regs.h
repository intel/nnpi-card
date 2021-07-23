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

//                                                                             
// File:            gpsb_x1_regs_regs.h                                        
// Creator:         vchakki                                                    
// Time:            Friday Jan 25, 2019 [7:02:13 am]                           
//                                                                             
// Path:            /tmp/vchakki/nebulon_run/2882928829_2019-01-25.07:01:55    
// Arguments:       -input gpsb_x1_regs.rdl -chdr -out_dir .                   
//                                                                             
// MRE:             5.2018.2                                                   
// Machine:         icsl1890                                                   
// OS:              Linux 3.0.101-108.13.1.14249.0.PTF-default                 
// Nebulon version: d18ww24.4                                                  
// Description:                                                                
//                                                                             
// No Description Provided                                                     
//                                                                             
                                                                        


#ifndef _GPSB_X1_REGS_REGS_H_
#define _GPSB_X1_REGS_REGS_H_

#define GPSB_X1_REGS_BASE 0x0
#define GPSB_X1_REGS_PMA_ICE_OVERRIDES_MMOFFSET 0x0
#define GPSB_X1_REGS_LATEST_POWER_REQUEST_MMOFFSET 0x4
#define GPSB_X1_REGS_OVERRIDE_SLICE_STATE_MMOFFSET 0x8
#define GPSB_X1_REGS_ICEBO_POWER_STATUS_MMOFFSET 0x0C
#define GPSB_X1_REGS_ICEBO_FSM_STALL_MMOFFSET 0x10
#define GPSB_X1_REGS_CLK_GATE_CTL_MMOFFSET 0x14
#define GPSB_X1_REGS_DCF_CTL_MMOFFSET 0x18
#define GPSB_X1_REGS_ICCP_CONFIG1_MMOFFSET 0x1C
#define GPSB_X1_REGS_ICCP_CONFIG2_MMOFFSET 0x20
#define GPSB_X1_REGS_ICCP_CONFIG3_MMOFFSET 0x24
#define GPSB_X1_REGS_ICCP_MAX_CDYN_LEVEL_0_MMOFFSET 0x28
#define GPSB_X1_REGS_ICCP_MAX_CDYN_LEVEL_1_MMOFFSET 0x2C
#define GPSB_X1_REGS_ICCP_MAX_CDYN_LEVEL_2_MMOFFSET 0x30
#define GPSB_X1_REGS_ICCP_MAX_CDYN_LEVEL_3_MMOFFSET 0x34
#define GPSB_X1_REGS_ICCP_MAX_CDYN_LEVEL_4_MMOFFSET 0x38
#define GPSB_X1_REGS_ICCP_MAX_CDYN_LEVEL_5_MMOFFSET 0x3C
#define GPSB_X1_REGS_ICCP_MAX_CDYN_LEVEL_6_MMOFFSET 0x40
#define GPSB_X1_REGS_ICCP_MAX_CDYN_LEVEL_7_MMOFFSET 0x44
#define GPSB_X1_REGS_ICCP_MAX_CDYN_LEVEL_8_MMOFFSET 0x48
#define GPSB_X1_REGS_ICCP_MAX_CDYN_LEVEL_9_MMOFFSET 0x4C
#define GPSB_X1_REGS_ICCP_MAX_CDYN_LEVEL_10_MMOFFSET 0x50
#define GPSB_X1_REGS_ICCP_MAX_CDYN_LEVEL_11_MMOFFSET 0x54
#define GPSB_X1_REGS_ICCP_MAX_CDYN_LEVEL_12_MMOFFSET 0x58
#define GPSB_X1_REGS_ICCP_MAX_CDYN_LEVEL_13_MMOFFSET 0x5C
#define GPSB_X1_REGS_ICCP_MAX_CDYN_LEVEL_14_MMOFFSET 0x60
#define GPSB_X1_REGS_ICCP_DEBUG1_MMOFFSET 0x64
#define GPSB_X1_REGS_ICCP_DEBUG2_MMOFFSET 0x68

#ifndef MEM_PMA_ICE_OVERRIDES_FLAG
#define MEM_PMA_ICE_OVERRIDES_FLAG
// PMA_ICE_OVERRIDES desc:  PMA ICE OVERRIDES
typedef union {
    struct {
        uint32_t  POST_PLL_DIV2        :   1;    //  When '0 - iceclk is divided
                                                 // by 4 post glbdrv (default),
                                                 // when '1 - divided by 2
        uint32_t  RESERVED_5_1         :   5;    //  reserved
        uint32_t  PLL_RATIO_OVR_EN     :   1;    //  When '1, override the PLL
                                                 // ratio and post_pll_div2
                                                 // according to next 2 fields
        uint32_t  PLL_RATIO_OVR_VAL    :   6;    //  PLL ratio when
                                                 // PLL_RATIO_OVR_EN is set
        uint32_t  RESERVED_18_13       :   6;    //  reserved
        uint32_t  SKIP_OCP_DRAIN_ON_RESET :   1;    //  Skip the stage of OCP drain
                                                 // when doing ICE reset
        uint32_t  SKIP_AXI_DRAIN_ON_RESET :   1;    //  Skip the stage of AXI drain
                                                 // when doing ICE reset
        uint32_t  SKIP_OBSERVERS_ACK   :   1;    //  Skip BlockAck from ICE
                                                 // Observers and IDI Observer
        uint32_t  PRE_RESET_STALL      :   1;    //  Stall global ICSM before ICE
                                                 // reset de-assertion
        uint32_t  POST_RESET_STALL     :   1;    //  Stall global ICSM before
                                                 // final stage
        uint32_t  CVE_RESET_DURATION   :   7;    //  Minimum assertion time of
                                                 // cve_hw_reset (given in X1
                                                 // clocks)
        uint32_t  RESERVED_31_31       :   1;    //  RESERVED

    }                                field;
    uint32_t                         val;
} MEM_PMA_ICE_OVERRIDES_t;
#endif
#define MEM_PMA_ICE_OVERRIDES_OFFSET 0x00
#define MEM_PMA_ICE_OVERRIDES_SCOPE 0x01
#define MEM_PMA_ICE_OVERRIDES_SIZE 32
#define MEM_PMA_ICE_OVERRIDES_BITFIELD_COUNT 0x0c
#define MEM_PMA_ICE_OVERRIDES_RESET 0x10000000

#define MEM_PMA_ICE_OVERRIDES_POST_PLL_DIV2_LSB 0x0000
#define MEM_PMA_ICE_OVERRIDES_POST_PLL_DIV2_MSB 0x0000
#define MEM_PMA_ICE_OVERRIDES_POST_PLL_DIV2_RANGE 0x0001
#define MEM_PMA_ICE_OVERRIDES_POST_PLL_DIV2_MASK 0x00000001
#define MEM_PMA_ICE_OVERRIDES_POST_PLL_DIV2_RESET_VALUE 0x00000000

#define MEM_PMA_ICE_OVERRIDES_RESERVED_5_1_LSB 0x0001
#define MEM_PMA_ICE_OVERRIDES_RESERVED_5_1_MSB 0x0005
#define MEM_PMA_ICE_OVERRIDES_RESERVED_5_1_RANGE 0x0005
#define MEM_PMA_ICE_OVERRIDES_RESERVED_5_1_MASK 0x0000003e
#define MEM_PMA_ICE_OVERRIDES_RESERVED_5_1_RESET_VALUE 0x00000000

#define MEM_PMA_ICE_OVERRIDES_PLL_RATIO_OVR_EN_LSB 0x0006
#define MEM_PMA_ICE_OVERRIDES_PLL_RATIO_OVR_EN_MSB 0x0006
#define MEM_PMA_ICE_OVERRIDES_PLL_RATIO_OVR_EN_RANGE 0x0001
#define MEM_PMA_ICE_OVERRIDES_PLL_RATIO_OVR_EN_MASK 0x00000040
#define MEM_PMA_ICE_OVERRIDES_PLL_RATIO_OVR_EN_RESET_VALUE 0x00000000

#define MEM_PMA_ICE_OVERRIDES_PLL_RATIO_OVR_VAL_LSB 0x0007
#define MEM_PMA_ICE_OVERRIDES_PLL_RATIO_OVR_VAL_MSB 0x000c
#define MEM_PMA_ICE_OVERRIDES_PLL_RATIO_OVR_VAL_RANGE 0x0006
#define MEM_PMA_ICE_OVERRIDES_PLL_RATIO_OVR_VAL_MASK 0x00001f80
#define MEM_PMA_ICE_OVERRIDES_PLL_RATIO_OVR_VAL_RESET_VALUE 0x00000000

#define MEM_PMA_ICE_OVERRIDES_RESERVED_18_13_LSB 0x000d
#define MEM_PMA_ICE_OVERRIDES_RESERVED_18_13_MSB 0x0012
#define MEM_PMA_ICE_OVERRIDES_RESERVED_18_13_RANGE 0x0006
#define MEM_PMA_ICE_OVERRIDES_RESERVED_18_13_MASK 0x0007e000
#define MEM_PMA_ICE_OVERRIDES_RESERVED_18_13_RESET_VALUE 0x00000000

#define MEM_PMA_ICE_OVERRIDES_SKIP_OCP_DRAIN_ON_RESET_LSB 0x0013
#define MEM_PMA_ICE_OVERRIDES_SKIP_OCP_DRAIN_ON_RESET_MSB 0x0013
#define MEM_PMA_ICE_OVERRIDES_SKIP_OCP_DRAIN_ON_RESET_RANGE 0x0001
#define MEM_PMA_ICE_OVERRIDES_SKIP_OCP_DRAIN_ON_RESET_MASK 0x00080000
#define MEM_PMA_ICE_OVERRIDES_SKIP_OCP_DRAIN_ON_RESET_RESET_VALUE 0x00000000

#define MEM_PMA_ICE_OVERRIDES_SKIP_AXI_DRAIN_ON_RESET_LSB 0x0014
#define MEM_PMA_ICE_OVERRIDES_SKIP_AXI_DRAIN_ON_RESET_MSB 0x0014
#define MEM_PMA_ICE_OVERRIDES_SKIP_AXI_DRAIN_ON_RESET_RANGE 0x0001
#define MEM_PMA_ICE_OVERRIDES_SKIP_AXI_DRAIN_ON_RESET_MASK 0x00100000
#define MEM_PMA_ICE_OVERRIDES_SKIP_AXI_DRAIN_ON_RESET_RESET_VALUE 0x00000000

#define MEM_PMA_ICE_OVERRIDES_SKIP_OBSERVERS_ACK_LSB 0x0015
#define MEM_PMA_ICE_OVERRIDES_SKIP_OBSERVERS_ACK_MSB 0x0015
#define MEM_PMA_ICE_OVERRIDES_SKIP_OBSERVERS_ACK_RANGE 0x0001
#define MEM_PMA_ICE_OVERRIDES_SKIP_OBSERVERS_ACK_MASK 0x00200000
#define MEM_PMA_ICE_OVERRIDES_SKIP_OBSERVERS_ACK_RESET_VALUE 0x00000000

#define MEM_PMA_ICE_OVERRIDES_PRE_RESET_STALL_LSB 0x0016
#define MEM_PMA_ICE_OVERRIDES_PRE_RESET_STALL_MSB 0x0016
#define MEM_PMA_ICE_OVERRIDES_PRE_RESET_STALL_RANGE 0x0001
#define MEM_PMA_ICE_OVERRIDES_PRE_RESET_STALL_MASK 0x00400000
#define MEM_PMA_ICE_OVERRIDES_PRE_RESET_STALL_RESET_VALUE 0x00000000

#define MEM_PMA_ICE_OVERRIDES_POST_RESET_STALL_LSB 0x0017
#define MEM_PMA_ICE_OVERRIDES_POST_RESET_STALL_MSB 0x0017
#define MEM_PMA_ICE_OVERRIDES_POST_RESET_STALL_RANGE 0x0001
#define MEM_PMA_ICE_OVERRIDES_POST_RESET_STALL_MASK 0x00800000
#define MEM_PMA_ICE_OVERRIDES_POST_RESET_STALL_RESET_VALUE 0x00000000

#define MEM_PMA_ICE_OVERRIDES_CVE_RESET_DURATION_LSB 0x0018
#define MEM_PMA_ICE_OVERRIDES_CVE_RESET_DURATION_MSB 0x001e
#define MEM_PMA_ICE_OVERRIDES_CVE_RESET_DURATION_RANGE 0x0007
#define MEM_PMA_ICE_OVERRIDES_CVE_RESET_DURATION_MASK 0x7f000000
#define MEM_PMA_ICE_OVERRIDES_CVE_RESET_DURATION_RESET_VALUE 0x00000010

#define MEM_PMA_ICE_OVERRIDES_RESERVED_31_31_LSB 0x001f
#define MEM_PMA_ICE_OVERRIDES_RESERVED_31_31_MSB 0x001f
#define MEM_PMA_ICE_OVERRIDES_RESERVED_31_31_RANGE 0x0001
#define MEM_PMA_ICE_OVERRIDES_RESERVED_31_31_MASK 0x80000000
#define MEM_PMA_ICE_OVERRIDES_RESERVED_31_31_RESET_VALUE 0x00000000


// --------------------------------------------------------------------------------------------------------------------------------

#ifndef MEM_LATEST_POWER_REQUEST_FLAG
#define MEM_LATEST_POWER_REQUEST_FLAG
// LATEST_POWER_REQUEST desc:  Register to keep IceDC_to_IceBo message (per ICE turn on/off command)
typedef union {
    struct {
        uint32_t  ICE0_COMMAND         :   2;    //  Sampled when receiving
                                                 // power_request via
                                                 // IceDC_to_IceBo_Msg
        uint32_t  ICE1_COMMAND         :   2;    //  Sampled when receiving
                                                 // power_request via
                                                 // IceDC_to_IceBo_Msg
        uint32_t  RESERVED_7_4         :   4;    //  reserved
        uint32_t  IN_PROGRESS          :   1;    //  Set when receiving
                                                 // power_request via
                                                 // IceDC_to_IceBo_Msg, cleared
                                                 // when command is done
        uint32_t  COMMAND_ERROR        :   1;    //  Asserted if getting a command
                                                 // while previous command is in
                                                 // progress. Cleared on write
        uint32_t  RESERVED_31_10       :  22;    //  reserved

    }                                field;
    uint32_t                         val;
} MEM_LATEST_POWER_REQUEST_t;
#endif
#define MEM_LATEST_POWER_REQUEST_OFFSET 0x04
#define MEM_LATEST_POWER_REQUEST_SCOPE 0x01
#define MEM_LATEST_POWER_REQUEST_SIZE 32
#define MEM_LATEST_POWER_REQUEST_BITFIELD_COUNT 0x06
#define MEM_LATEST_POWER_REQUEST_RESET 0x00000000

#define MEM_LATEST_POWER_REQUEST_ICE0_COMMAND_LSB 0x0000
#define MEM_LATEST_POWER_REQUEST_ICE0_COMMAND_MSB 0x0001
#define MEM_LATEST_POWER_REQUEST_ICE0_COMMAND_RANGE 0x0002
#define MEM_LATEST_POWER_REQUEST_ICE0_COMMAND_MASK 0x00000003
#define MEM_LATEST_POWER_REQUEST_ICE0_COMMAND_RESET_VALUE 0x00000000

#define MEM_LATEST_POWER_REQUEST_ICE1_COMMAND_LSB 0x0002
#define MEM_LATEST_POWER_REQUEST_ICE1_COMMAND_MSB 0x0003
#define MEM_LATEST_POWER_REQUEST_ICE1_COMMAND_RANGE 0x0002
#define MEM_LATEST_POWER_REQUEST_ICE1_COMMAND_MASK 0x0000000c
#define MEM_LATEST_POWER_REQUEST_ICE1_COMMAND_RESET_VALUE 0x00000000

#define MEM_LATEST_POWER_REQUEST_RESERVED_7_4_LSB 0x0004
#define MEM_LATEST_POWER_REQUEST_RESERVED_7_4_MSB 0x0007
#define MEM_LATEST_POWER_REQUEST_RESERVED_7_4_RANGE 0x0004
#define MEM_LATEST_POWER_REQUEST_RESERVED_7_4_MASK 0x000000f0
#define MEM_LATEST_POWER_REQUEST_RESERVED_7_4_RESET_VALUE 0x00000000

#define MEM_LATEST_POWER_REQUEST_IN_PROGRESS_LSB 0x0008
#define MEM_LATEST_POWER_REQUEST_IN_PROGRESS_MSB 0x0008
#define MEM_LATEST_POWER_REQUEST_IN_PROGRESS_RANGE 0x0001
#define MEM_LATEST_POWER_REQUEST_IN_PROGRESS_MASK 0x00000100
#define MEM_LATEST_POWER_REQUEST_IN_PROGRESS_RESET_VALUE 0x00000000

#define MEM_LATEST_POWER_REQUEST_COMMAND_ERROR_LSB 0x0009
#define MEM_LATEST_POWER_REQUEST_COMMAND_ERROR_MSB 0x0009
#define MEM_LATEST_POWER_REQUEST_COMMAND_ERROR_RANGE 0x0001
#define MEM_LATEST_POWER_REQUEST_COMMAND_ERROR_MASK 0x00000200
#define MEM_LATEST_POWER_REQUEST_COMMAND_ERROR_RESET_VALUE 0x00000000

#define MEM_LATEST_POWER_REQUEST_RESERVED_31_10_LSB 0x000a
#define MEM_LATEST_POWER_REQUEST_RESERVED_31_10_MSB 0x001f
#define MEM_LATEST_POWER_REQUEST_RESERVED_31_10_RANGE 0x0016
#define MEM_LATEST_POWER_REQUEST_RESERVED_31_10_MASK 0xfffffc00
#define MEM_LATEST_POWER_REQUEST_RESERVED_31_10_RESET_VALUE 0x00000000


// --------------------------------------------------------------------------------------------------------------------------------

#ifndef MEM_OVERRIDE_SLICE_STATE_FLAG
#define MEM_OVERRIDE_SLICE_STATE_FLAG
// OVERRIDE_SLICE_STATE desc:  Manual slice and ICE handling
typedef union {
    struct {
        uint32_t  CHANGE_SLICE_STATE   :   1;    //  Command bit, write 1 to
                                                 // enable command
        uint32_t  SLICE_COMMAND        :   1;    //  Required slice state. 0 -
                                                 // turn off. 1 - turn on
        uint32_t  KEEP_SLICE_ON        :   1;    //  when '1, don't turn slice off
                                                 // on IceBoMsg, even when both
                                                 // ICEs are turned off (this bit
                                                 // is not related to
                                                 // CHANGE_SLICE_STATE)
        uint32_t  RESERVED_7_3         :   5;    //  reserved
        uint32_t  IN_PROGRESS          :   1;    //  Set when receiving a new
                                                 // command (write with
                                                 // change_slice_state=1), cleared
                                                 // when command is done
        uint32_t  COMMAND_ERROR        :   1;    //  Asserted if getting a turn
                                                 // off command while any ICE is
                                                 // ON, or if getting a new
                                                 // command while previous command
                                                 // is still in progress. Cleared
                                                 // on write
        uint32_t  RESERVED_10_10       :   1;    //  reserved
        uint32_t  ICE0_HW_RESET_OVR_EN :   1;    //  Enable override to
                                                 // ICE0/cve_hw_reset
        uint32_t  ICE0_HW_RESET_OVR_VAL :   1;    //  Value to override to
                                                 // ICE0/cve_hw_reset
        uint32_t  ICE0_SW_RESET_OVR_EN :   1;    //  Enable override to
                                                 // ICE0/cve_sw_reset
        uint32_t  ICE0_SW_RESET_OVR_VAL :   1;    //  Value to override to
                                                 // ICE0/cve_sw_reset
        uint32_t  ICE1_HW_RESET_OVR_EN :   1;    //  Enable override to
                                                 // ICE1/cve_hw_reset
        uint32_t  ICE1_HW_RESET_OVR_VAL :   1;    //  Value to override to
                                                 // ICE1/cve_hw_reset
        uint32_t  ICE1_SW_RESET_OVR_EN :   1;    //  Enable override to
                                                 // ICE1/cve_sw_reset
        uint32_t  ICE1_SW_RESET_OVR_VAL :   1;    //  Value to override to
                                                 // ICE1/cve_sw_reset
        uint32_t  RESERVED_31_19       :  13;    //  reserved

    }                                field;
    uint32_t                         val;
} MEM_OVERRIDE_SLICE_STATE_t;
#endif
#define MEM_OVERRIDE_SLICE_STATE_OFFSET 0x08
#define MEM_OVERRIDE_SLICE_STATE_SCOPE 0x01
#define MEM_OVERRIDE_SLICE_STATE_SIZE 32
#define MEM_OVERRIDE_SLICE_STATE_BITFIELD_COUNT 0x10
#define MEM_OVERRIDE_SLICE_STATE_RESET 0x00000000

#define MEM_OVERRIDE_SLICE_STATE_CHANGE_SLICE_STATE_LSB 0x0000
#define MEM_OVERRIDE_SLICE_STATE_CHANGE_SLICE_STATE_MSB 0x0000
#define MEM_OVERRIDE_SLICE_STATE_CHANGE_SLICE_STATE_RANGE 0x0001
#define MEM_OVERRIDE_SLICE_STATE_CHANGE_SLICE_STATE_MASK 0x00000001
#define MEM_OVERRIDE_SLICE_STATE_CHANGE_SLICE_STATE_RESET_VALUE 0x00000000

#define MEM_OVERRIDE_SLICE_STATE_SLICE_COMMAND_LSB 0x0001
#define MEM_OVERRIDE_SLICE_STATE_SLICE_COMMAND_MSB 0x0001
#define MEM_OVERRIDE_SLICE_STATE_SLICE_COMMAND_RANGE 0x0001
#define MEM_OVERRIDE_SLICE_STATE_SLICE_COMMAND_MASK 0x00000002
#define MEM_OVERRIDE_SLICE_STATE_SLICE_COMMAND_RESET_VALUE 0x00000000

#define MEM_OVERRIDE_SLICE_STATE_KEEP_SLICE_ON_LSB 0x0002
#define MEM_OVERRIDE_SLICE_STATE_KEEP_SLICE_ON_MSB 0x0002
#define MEM_OVERRIDE_SLICE_STATE_KEEP_SLICE_ON_RANGE 0x0001
#define MEM_OVERRIDE_SLICE_STATE_KEEP_SLICE_ON_MASK 0x00000004
#define MEM_OVERRIDE_SLICE_STATE_KEEP_SLICE_ON_RESET_VALUE 0x00000000

#define MEM_OVERRIDE_SLICE_STATE_RESERVED_7_3_LSB 0x0003
#define MEM_OVERRIDE_SLICE_STATE_RESERVED_7_3_MSB 0x0007
#define MEM_OVERRIDE_SLICE_STATE_RESERVED_7_3_RANGE 0x0005
#define MEM_OVERRIDE_SLICE_STATE_RESERVED_7_3_MASK 0x000000f8
#define MEM_OVERRIDE_SLICE_STATE_RESERVED_7_3_RESET_VALUE 0x00000000

#define MEM_OVERRIDE_SLICE_STATE_IN_PROGRESS_LSB 0x0008
#define MEM_OVERRIDE_SLICE_STATE_IN_PROGRESS_MSB 0x0008
#define MEM_OVERRIDE_SLICE_STATE_IN_PROGRESS_RANGE 0x0001
#define MEM_OVERRIDE_SLICE_STATE_IN_PROGRESS_MASK 0x00000100
#define MEM_OVERRIDE_SLICE_STATE_IN_PROGRESS_RESET_VALUE 0x00000000

#define MEM_OVERRIDE_SLICE_STATE_COMMAND_ERROR_LSB 0x0009
#define MEM_OVERRIDE_SLICE_STATE_COMMAND_ERROR_MSB 0x0009
#define MEM_OVERRIDE_SLICE_STATE_COMMAND_ERROR_RANGE 0x0001
#define MEM_OVERRIDE_SLICE_STATE_COMMAND_ERROR_MASK 0x00000200
#define MEM_OVERRIDE_SLICE_STATE_COMMAND_ERROR_RESET_VALUE 0x00000000

#define MEM_OVERRIDE_SLICE_STATE_RESERVED_10_10_LSB 0x000a
#define MEM_OVERRIDE_SLICE_STATE_RESERVED_10_10_MSB 0x000a
#define MEM_OVERRIDE_SLICE_STATE_RESERVED_10_10_RANGE 0x0001
#define MEM_OVERRIDE_SLICE_STATE_RESERVED_10_10_MASK 0x00000400
#define MEM_OVERRIDE_SLICE_STATE_RESERVED_10_10_RESET_VALUE 0x00000000

#define MEM_OVERRIDE_SLICE_STATE_ICE0_HW_RESET_OVR_EN_LSB 0x000b
#define MEM_OVERRIDE_SLICE_STATE_ICE0_HW_RESET_OVR_EN_MSB 0x000b
#define MEM_OVERRIDE_SLICE_STATE_ICE0_HW_RESET_OVR_EN_RANGE 0x0001
#define MEM_OVERRIDE_SLICE_STATE_ICE0_HW_RESET_OVR_EN_MASK 0x00000800
#define MEM_OVERRIDE_SLICE_STATE_ICE0_HW_RESET_OVR_EN_RESET_VALUE 0x00000000

#define MEM_OVERRIDE_SLICE_STATE_ICE0_HW_RESET_OVR_VAL_LSB 0x000c
#define MEM_OVERRIDE_SLICE_STATE_ICE0_HW_RESET_OVR_VAL_MSB 0x000c
#define MEM_OVERRIDE_SLICE_STATE_ICE0_HW_RESET_OVR_VAL_RANGE 0x0001
#define MEM_OVERRIDE_SLICE_STATE_ICE0_HW_RESET_OVR_VAL_MASK 0x00001000
#define MEM_OVERRIDE_SLICE_STATE_ICE0_HW_RESET_OVR_VAL_RESET_VALUE 0x00000000

#define MEM_OVERRIDE_SLICE_STATE_ICE0_SW_RESET_OVR_EN_LSB 0x000d
#define MEM_OVERRIDE_SLICE_STATE_ICE0_SW_RESET_OVR_EN_MSB 0x000d
#define MEM_OVERRIDE_SLICE_STATE_ICE0_SW_RESET_OVR_EN_RANGE 0x0001
#define MEM_OVERRIDE_SLICE_STATE_ICE0_SW_RESET_OVR_EN_MASK 0x00002000
#define MEM_OVERRIDE_SLICE_STATE_ICE0_SW_RESET_OVR_EN_RESET_VALUE 0x00000000

#define MEM_OVERRIDE_SLICE_STATE_ICE0_SW_RESET_OVR_VAL_LSB 0x000e
#define MEM_OVERRIDE_SLICE_STATE_ICE0_SW_RESET_OVR_VAL_MSB 0x000e
#define MEM_OVERRIDE_SLICE_STATE_ICE0_SW_RESET_OVR_VAL_RANGE 0x0001
#define MEM_OVERRIDE_SLICE_STATE_ICE0_SW_RESET_OVR_VAL_MASK 0x00004000
#define MEM_OVERRIDE_SLICE_STATE_ICE0_SW_RESET_OVR_VAL_RESET_VALUE 0x00000000

#define MEM_OVERRIDE_SLICE_STATE_ICE1_HW_RESET_OVR_EN_LSB 0x000f
#define MEM_OVERRIDE_SLICE_STATE_ICE1_HW_RESET_OVR_EN_MSB 0x000f
#define MEM_OVERRIDE_SLICE_STATE_ICE1_HW_RESET_OVR_EN_RANGE 0x0001
#define MEM_OVERRIDE_SLICE_STATE_ICE1_HW_RESET_OVR_EN_MASK 0x00008000
#define MEM_OVERRIDE_SLICE_STATE_ICE1_HW_RESET_OVR_EN_RESET_VALUE 0x00000000

#define MEM_OVERRIDE_SLICE_STATE_ICE1_HW_RESET_OVR_VAL_LSB 0x0010
#define MEM_OVERRIDE_SLICE_STATE_ICE1_HW_RESET_OVR_VAL_MSB 0x0010
#define MEM_OVERRIDE_SLICE_STATE_ICE1_HW_RESET_OVR_VAL_RANGE 0x0001
#define MEM_OVERRIDE_SLICE_STATE_ICE1_HW_RESET_OVR_VAL_MASK 0x00010000
#define MEM_OVERRIDE_SLICE_STATE_ICE1_HW_RESET_OVR_VAL_RESET_VALUE 0x00000000

#define MEM_OVERRIDE_SLICE_STATE_ICE1_SW_RESET_OVR_EN_LSB 0x0011
#define MEM_OVERRIDE_SLICE_STATE_ICE1_SW_RESET_OVR_EN_MSB 0x0011
#define MEM_OVERRIDE_SLICE_STATE_ICE1_SW_RESET_OVR_EN_RANGE 0x0001
#define MEM_OVERRIDE_SLICE_STATE_ICE1_SW_RESET_OVR_EN_MASK 0x00020000
#define MEM_OVERRIDE_SLICE_STATE_ICE1_SW_RESET_OVR_EN_RESET_VALUE 0x00000000

#define MEM_OVERRIDE_SLICE_STATE_ICE1_SW_RESET_OVR_VAL_LSB 0x0012
#define MEM_OVERRIDE_SLICE_STATE_ICE1_SW_RESET_OVR_VAL_MSB 0x0012
#define MEM_OVERRIDE_SLICE_STATE_ICE1_SW_RESET_OVR_VAL_RANGE 0x0001
#define MEM_OVERRIDE_SLICE_STATE_ICE1_SW_RESET_OVR_VAL_MASK 0x00040000
#define MEM_OVERRIDE_SLICE_STATE_ICE1_SW_RESET_OVR_VAL_RESET_VALUE 0x00000000

#define MEM_OVERRIDE_SLICE_STATE_RESERVED_31_19_LSB 0x0013
#define MEM_OVERRIDE_SLICE_STATE_RESERVED_31_19_MSB 0x001f
#define MEM_OVERRIDE_SLICE_STATE_RESERVED_31_19_RANGE 0x000d
#define MEM_OVERRIDE_SLICE_STATE_RESERVED_31_19_MASK 0xfff80000
#define MEM_OVERRIDE_SLICE_STATE_RESERVED_31_19_RESET_VALUE 0x00000000


// --------------------------------------------------------------------------------------------------------------------------------

#ifndef MEM_ICEBO_POWER_STATUS_FLAG
#define MEM_ICEBO_POWER_STATUS_FLAG
// ICEBO_POWER_STATUS desc:  Register to keep the slice and ICEs status
typedef union {
    struct {
        uint32_t  ICE0_STATUS          :   1;    //  ICE0 Status. 0-off, 1-on.
                                                 // Updated when
                                                 // IceDC_to_IceBo_Msg/Ovrd
                                                 // command is done
        uint32_t  ICE1_STATUS          :   1;    //  ICE1 Status. 0-off, 1-on.
                                                 // Updated when
                                                 // IceDC_to_IceBo_Msg/Ovrd
                                                 // command is done
        uint32_t  RESERVED_3_2         :   2;    //  reserved
        uint32_t  SLICE_STATUS         :   1;    //  Slice electrical Status.
                                                 // 0-off, 1-on. Updated when
                                                 // IceDC_to_IceBo_Msg/Ovrd
                                                 // command is done
        uint32_t  RESERVED_7_5         :   3;    //  reserved
        uint32_t  ICE0_CSM_STATE       :   4;    //  ICE0 CSM state
        uint32_t  ICE1_CSM_STATE       :   4;    //  ICE1 CSM state
        uint32_t  ICE_GLOBAL_CSM_STATE :   5;    //  ICE global CSM state
        uint32_t  RESERVED_31_21       :  11;    //  reserved

    }                                field;
    uint32_t                         val;
} MEM_ICEBO_POWER_STATUS_t;
#endif
#define MEM_ICEBO_POWER_STATUS_OFFSET 0x0c
#define MEM_ICEBO_POWER_STATUS_SCOPE 0x01
#define MEM_ICEBO_POWER_STATUS_SIZE 32
#define MEM_ICEBO_POWER_STATUS_BITFIELD_COUNT 0x09
#define MEM_ICEBO_POWER_STATUS_RESET 0x00000000

#define MEM_ICEBO_POWER_STATUS_ICE0_STATUS_LSB 0x0000
#define MEM_ICEBO_POWER_STATUS_ICE0_STATUS_MSB 0x0000
#define MEM_ICEBO_POWER_STATUS_ICE0_STATUS_RANGE 0x0001
#define MEM_ICEBO_POWER_STATUS_ICE0_STATUS_MASK 0x00000001
#define MEM_ICEBO_POWER_STATUS_ICE0_STATUS_RESET_VALUE 0x00000000

#define MEM_ICEBO_POWER_STATUS_ICE1_STATUS_LSB 0x0001
#define MEM_ICEBO_POWER_STATUS_ICE1_STATUS_MSB 0x0001
#define MEM_ICEBO_POWER_STATUS_ICE1_STATUS_RANGE 0x0001
#define MEM_ICEBO_POWER_STATUS_ICE1_STATUS_MASK 0x00000002
#define MEM_ICEBO_POWER_STATUS_ICE1_STATUS_RESET_VALUE 0x00000000

#define MEM_ICEBO_POWER_STATUS_RESERVED_3_2_LSB 0x0002
#define MEM_ICEBO_POWER_STATUS_RESERVED_3_2_MSB 0x0003
#define MEM_ICEBO_POWER_STATUS_RESERVED_3_2_RANGE 0x0002
#define MEM_ICEBO_POWER_STATUS_RESERVED_3_2_MASK 0x0000000c
#define MEM_ICEBO_POWER_STATUS_RESERVED_3_2_RESET_VALUE 0x00000000

#define MEM_ICEBO_POWER_STATUS_SLICE_STATUS_LSB 0x0004
#define MEM_ICEBO_POWER_STATUS_SLICE_STATUS_MSB 0x0004
#define MEM_ICEBO_POWER_STATUS_SLICE_STATUS_RANGE 0x0001
#define MEM_ICEBO_POWER_STATUS_SLICE_STATUS_MASK 0x00000010
#define MEM_ICEBO_POWER_STATUS_SLICE_STATUS_RESET_VALUE 0x00000000

#define MEM_ICEBO_POWER_STATUS_RESERVED_7_5_LSB 0x0005
#define MEM_ICEBO_POWER_STATUS_RESERVED_7_5_MSB 0x0007
#define MEM_ICEBO_POWER_STATUS_RESERVED_7_5_RANGE 0x0003
#define MEM_ICEBO_POWER_STATUS_RESERVED_7_5_MASK 0x000000e0
#define MEM_ICEBO_POWER_STATUS_RESERVED_7_5_RESET_VALUE 0x00000000

#define MEM_ICEBO_POWER_STATUS_ICE0_CSM_STATE_LSB 0x0008
#define MEM_ICEBO_POWER_STATUS_ICE0_CSM_STATE_MSB 0x000b
#define MEM_ICEBO_POWER_STATUS_ICE0_CSM_STATE_RANGE 0x0004
#define MEM_ICEBO_POWER_STATUS_ICE0_CSM_STATE_MASK 0x00000f00
#define MEM_ICEBO_POWER_STATUS_ICE0_CSM_STATE_RESET_VALUE 0x00000000

#define MEM_ICEBO_POWER_STATUS_ICE1_CSM_STATE_LSB 0x000c
#define MEM_ICEBO_POWER_STATUS_ICE1_CSM_STATE_MSB 0x000f
#define MEM_ICEBO_POWER_STATUS_ICE1_CSM_STATE_RANGE 0x0004
#define MEM_ICEBO_POWER_STATUS_ICE1_CSM_STATE_MASK 0x0000f000
#define MEM_ICEBO_POWER_STATUS_ICE1_CSM_STATE_RESET_VALUE 0x00000000

#define MEM_ICEBO_POWER_STATUS_ICE_GLOBAL_CSM_STATE_LSB 0x0010
#define MEM_ICEBO_POWER_STATUS_ICE_GLOBAL_CSM_STATE_MSB 0x0014
#define MEM_ICEBO_POWER_STATUS_ICE_GLOBAL_CSM_STATE_RANGE 0x0005
#define MEM_ICEBO_POWER_STATUS_ICE_GLOBAL_CSM_STATE_MASK 0x001f0000
#define MEM_ICEBO_POWER_STATUS_ICE_GLOBAL_CSM_STATE_RESET_VALUE 0x00000000

#define MEM_ICEBO_POWER_STATUS_RESERVED_31_21_LSB 0x0015
#define MEM_ICEBO_POWER_STATUS_RESERVED_31_21_MSB 0x001f
#define MEM_ICEBO_POWER_STATUS_RESERVED_31_21_RANGE 0x000b
#define MEM_ICEBO_POWER_STATUS_RESERVED_31_21_MASK 0xffe00000
#define MEM_ICEBO_POWER_STATUS_RESERVED_31_21_RESET_VALUE 0x00000000


// --------------------------------------------------------------------------------------------------------------------------------

#ifndef MEM_ICEBO_FSM_STALL_FLAG
#define MEM_ICEBO_FSM_STALL_FLAG
// ICEBO_FSM_STALL desc:  Stall ICEBO global and per-ICE FSMs for debug
typedef union {
    struct {
        uint32_t  ICE0_CSM_STATE_STALL_EN :   1;    //  When EN=1, stall ICE0 FSM on
                                                 // its STALL_STATE
        uint32_t  ICE0_CSM_STATE_STALL_STATE :   4;    //  Hold ICE0 FSM state at this
                                                 // state
        uint32_t  RESERVED_5_5         :   1;    //  reserved
        uint32_t  ICE1_CSM_STATE_STALL_EN :   1;    //  When EN=1, stall ICE1 FSM on
                                                 // its STALL_STATE
        uint32_t  ICE1_CSM_STATE_STALL_STATE :   4;    //  Hold ICE1 FSM state at this
                                                 // state
        uint32_t  RESERVED_11_11       :   1;    //  reserved
        uint32_t  ICE_GLOBAL_CSM_STALL_EN :   1;    //  When EN=1, stall ICEBO GLOBAL
                                                 // FSM on its STALL_STATE
        uint32_t  ICE_GLOBAL_CSM_STALL_STATE :   5;    //  Hold ICE1 FSM state at this
                                                 // state
        uint32_t  RESERVED_31_18       :  14;    //  reserved

    }                                field;
    uint32_t                         val;
} MEM_ICEBO_FSM_STALL_t;
#endif
#define MEM_ICEBO_FSM_STALL_OFFSET 0x10
#define MEM_ICEBO_FSM_STALL_SCOPE 0x01
#define MEM_ICEBO_FSM_STALL_SIZE 32
#define MEM_ICEBO_FSM_STALL_BITFIELD_COUNT 0x09
#define MEM_ICEBO_FSM_STALL_RESET 0x00000000

#define MEM_ICEBO_FSM_STALL_ICE0_CSM_STATE_STALL_EN_LSB 0x0000
#define MEM_ICEBO_FSM_STALL_ICE0_CSM_STATE_STALL_EN_MSB 0x0000
#define MEM_ICEBO_FSM_STALL_ICE0_CSM_STATE_STALL_EN_RANGE 0x0001
#define MEM_ICEBO_FSM_STALL_ICE0_CSM_STATE_STALL_EN_MASK 0x00000001
#define MEM_ICEBO_FSM_STALL_ICE0_CSM_STATE_STALL_EN_RESET_VALUE 0x00000000

#define MEM_ICEBO_FSM_STALL_ICE0_CSM_STATE_STALL_STATE_LSB 0x0001
#define MEM_ICEBO_FSM_STALL_ICE0_CSM_STATE_STALL_STATE_MSB 0x0004
#define MEM_ICEBO_FSM_STALL_ICE0_CSM_STATE_STALL_STATE_RANGE 0x0004
#define MEM_ICEBO_FSM_STALL_ICE0_CSM_STATE_STALL_STATE_MASK 0x0000001e
#define MEM_ICEBO_FSM_STALL_ICE0_CSM_STATE_STALL_STATE_RESET_VALUE 0x00000000

#define MEM_ICEBO_FSM_STALL_RESERVED_5_5_LSB 0x0005
#define MEM_ICEBO_FSM_STALL_RESERVED_5_5_MSB 0x0005
#define MEM_ICEBO_FSM_STALL_RESERVED_5_5_RANGE 0x0001
#define MEM_ICEBO_FSM_STALL_RESERVED_5_5_MASK 0x00000020
#define MEM_ICEBO_FSM_STALL_RESERVED_5_5_RESET_VALUE 0x00000000

#define MEM_ICEBO_FSM_STALL_ICE1_CSM_STATE_STALL_EN_LSB 0x0006
#define MEM_ICEBO_FSM_STALL_ICE1_CSM_STATE_STALL_EN_MSB 0x0006
#define MEM_ICEBO_FSM_STALL_ICE1_CSM_STATE_STALL_EN_RANGE 0x0001
#define MEM_ICEBO_FSM_STALL_ICE1_CSM_STATE_STALL_EN_MASK 0x00000040
#define MEM_ICEBO_FSM_STALL_ICE1_CSM_STATE_STALL_EN_RESET_VALUE 0x00000000

#define MEM_ICEBO_FSM_STALL_ICE1_CSM_STATE_STALL_STATE_LSB 0x0007
#define MEM_ICEBO_FSM_STALL_ICE1_CSM_STATE_STALL_STATE_MSB 0x000a
#define MEM_ICEBO_FSM_STALL_ICE1_CSM_STATE_STALL_STATE_RANGE 0x0004
#define MEM_ICEBO_FSM_STALL_ICE1_CSM_STATE_STALL_STATE_MASK 0x00000780
#define MEM_ICEBO_FSM_STALL_ICE1_CSM_STATE_STALL_STATE_RESET_VALUE 0x00000000

#define MEM_ICEBO_FSM_STALL_RESERVED_11_11_LSB 0x000b
#define MEM_ICEBO_FSM_STALL_RESERVED_11_11_MSB 0x000b
#define MEM_ICEBO_FSM_STALL_RESERVED_11_11_RANGE 0x0001
#define MEM_ICEBO_FSM_STALL_RESERVED_11_11_MASK 0x00000800
#define MEM_ICEBO_FSM_STALL_RESERVED_11_11_RESET_VALUE 0x00000000

#define MEM_ICEBO_FSM_STALL_ICE_GLOBAL_CSM_STALL_EN_LSB 0x000c
#define MEM_ICEBO_FSM_STALL_ICE_GLOBAL_CSM_STALL_EN_MSB 0x000c
#define MEM_ICEBO_FSM_STALL_ICE_GLOBAL_CSM_STALL_EN_RANGE 0x0001
#define MEM_ICEBO_FSM_STALL_ICE_GLOBAL_CSM_STALL_EN_MASK 0x00001000
#define MEM_ICEBO_FSM_STALL_ICE_GLOBAL_CSM_STALL_EN_RESET_VALUE 0x00000000

#define MEM_ICEBO_FSM_STALL_ICE_GLOBAL_CSM_STALL_STATE_LSB 0x000d
#define MEM_ICEBO_FSM_STALL_ICE_GLOBAL_CSM_STALL_STATE_MSB 0x0011
#define MEM_ICEBO_FSM_STALL_ICE_GLOBAL_CSM_STALL_STATE_RANGE 0x0005
#define MEM_ICEBO_FSM_STALL_ICE_GLOBAL_CSM_STALL_STATE_MASK 0x0003e000
#define MEM_ICEBO_FSM_STALL_ICE_GLOBAL_CSM_STALL_STATE_RESET_VALUE 0x00000000

#define MEM_ICEBO_FSM_STALL_RESERVED_31_18_LSB 0x0012
#define MEM_ICEBO_FSM_STALL_RESERVED_31_18_MSB 0x001f
#define MEM_ICEBO_FSM_STALL_RESERVED_31_18_RANGE 0x000e
#define MEM_ICEBO_FSM_STALL_RESERVED_31_18_MASK 0xfffc0000
#define MEM_ICEBO_FSM_STALL_RESERVED_31_18_RESET_VALUE 0x00000000


// --------------------------------------------------------------------------------------------------------------------------------

#ifndef MEM_CLK_GATE_CTL_FLAG
#define MEM_CLK_GATE_CTL_FLAG
// CLK_GATE_CTL desc:  Clk gate enables chicken bits, all fields are used in ICEclk, so
// there is a CDC One should make sure these are changed only while
// ICEclk is off, so can treat as stable for CDC
typedef union {
    struct {
        uint32_t  IGNORE_ICE_CLK_REQ   :   1;    //  ignore clk_en from ICE (treat
                                                 // as '1)
        uint32_t  DONT_GATE_ICE_OFF    :   1;    //  don't gate the clock when ICE
                                                 // is ON
        uint32_t  DONT_SQUASH_ICECLK   :   1;    //  don't squash iceclk
        uint32_t  RESERVED             :  29;    //  RESERVED

    }                                field;
    uint32_t                         val;
} MEM_CLK_GATE_CTL_t;
#endif
#define MEM_CLK_GATE_CTL_OFFSET 0x14
#define MEM_CLK_GATE_CTL_SCOPE 0x01
#define MEM_CLK_GATE_CTL_SIZE 32
#define MEM_CLK_GATE_CTL_BITFIELD_COUNT 0x04
#define MEM_CLK_GATE_CTL_RESET 0x00000000

#define MEM_CLK_GATE_CTL_IGNORE_ICE_CLK_REQ_LSB 0x0000
#define MEM_CLK_GATE_CTL_IGNORE_ICE_CLK_REQ_MSB 0x0000
#define MEM_CLK_GATE_CTL_IGNORE_ICE_CLK_REQ_RANGE 0x0001
#define MEM_CLK_GATE_CTL_IGNORE_ICE_CLK_REQ_MASK 0x00000001
#define MEM_CLK_GATE_CTL_IGNORE_ICE_CLK_REQ_RESET_VALUE 0x00000000

#define MEM_CLK_GATE_CTL_DONT_GATE_ICE_OFF_LSB 0x0001
#define MEM_CLK_GATE_CTL_DONT_GATE_ICE_OFF_MSB 0x0001
#define MEM_CLK_GATE_CTL_DONT_GATE_ICE_OFF_RANGE 0x0001
#define MEM_CLK_GATE_CTL_DONT_GATE_ICE_OFF_MASK 0x00000002
#define MEM_CLK_GATE_CTL_DONT_GATE_ICE_OFF_RESET_VALUE 0x00000000

#define MEM_CLK_GATE_CTL_DONT_SQUASH_ICECLK_LSB 0x0002
#define MEM_CLK_GATE_CTL_DONT_SQUASH_ICECLK_MSB 0x0002
#define MEM_CLK_GATE_CTL_DONT_SQUASH_ICECLK_RANGE 0x0001
#define MEM_CLK_GATE_CTL_DONT_SQUASH_ICECLK_MASK 0x00000004
#define MEM_CLK_GATE_CTL_DONT_SQUASH_ICECLK_RESET_VALUE 0x00000000

#define MEM_CLK_GATE_CTL_RESERVED_LSB 0x0003
#define MEM_CLK_GATE_CTL_RESERVED_MSB 0x001f
#define MEM_CLK_GATE_CTL_RESERVED_RANGE 0x001d
#define MEM_CLK_GATE_CTL_RESERVED_MASK 0xfffffff8
#define MEM_CLK_GATE_CTL_RESERVED_RESET_VALUE 0x00000000


// --------------------------------------------------------------------------------------------------------------------------------

#ifndef MEM_DCF_CTL_FLAG
#define MEM_DCF_CTL_FLAG
// DCF_CTL desc:  DCF control and chicken bits, all fields are used in ICEclk, so there
// is a CDC One should make sure these are changed only while ICEclk is
// off, so can treat as stable for CDC
typedef union {
    struct {
        uint32_t  DCF_COOL_OFF_DELAY   :   5;    //  cycles to wait between dcf
                                                 // exit and re-enter. Value '0'
                                                 // is not allowed
        uint32_t  DCF_X4_MIN_RATIO     :   1;    //  Minimum DCF ratio is 4x bus
                                                 // ratio (default is 2x bus
                                                 // ratio)
        uint32_t  DISABLE_DCF          :   1;    //  Disable DCF
        uint32_t  TAP_DCF_EN           :   1;    //  TAP DCF enable
        uint32_t  DEBUG_DCF_EN         :   1;    //  When set - values from this
                                                 // CR override DCF msg
        uint32_t  DBG_DCF_MASTER       :   1;    //  The master of the DCF is this
                                                 // register (when debug dcf en is
                                                 // set)
        uint32_t  DBG_DCF_RATIO        :   4;    //  DCF value override when
                                                 // DEBUG_DCF_EN and
                                                 // DBG_DCF_MASTER are set
                                                 // Allowed values: 4'b0000 : 1:1
                                                 // ratio 4'b1000 : 1:2 ratio
                                                 // 4'b0100 : 1:4 ratio 4'b0010 :
                                                 // 1:8 ratio 4'b0001 : 1:16
                                                 // ratio
        uint32_t  CYC_CNTR_CLK_EN_OVRD :   1;    //  CB to override the clk en
        uint32_t  RESERVED             :  17;    //  RESERVED

    }                                field;
    uint32_t                         val;
} MEM_DCF_CTL_t;
#endif
#define MEM_DCF_CTL_OFFSET 0x18
#define MEM_DCF_CTL_SCOPE 0x01
#define MEM_DCF_CTL_SIZE 32
#define MEM_DCF_CTL_BITFIELD_COUNT 0x09
#define MEM_DCF_CTL_RESET 0x0000000f

#define MEM_DCF_CTL_DCF_COOL_OFF_DELAY_LSB 0x0000
#define MEM_DCF_CTL_DCF_COOL_OFF_DELAY_MSB 0x0004
#define MEM_DCF_CTL_DCF_COOL_OFF_DELAY_RANGE 0x0005
#define MEM_DCF_CTL_DCF_COOL_OFF_DELAY_MASK 0x0000001f
#define MEM_DCF_CTL_DCF_COOL_OFF_DELAY_RESET_VALUE 0x0000000f

#define MEM_DCF_CTL_DCF_X4_MIN_RATIO_LSB 0x0005
#define MEM_DCF_CTL_DCF_X4_MIN_RATIO_MSB 0x0005
#define MEM_DCF_CTL_DCF_X4_MIN_RATIO_RANGE 0x0001
#define MEM_DCF_CTL_DCF_X4_MIN_RATIO_MASK 0x00000020
#define MEM_DCF_CTL_DCF_X4_MIN_RATIO_RESET_VALUE 0x00000000

#define MEM_DCF_CTL_DISABLE_DCF_LSB 0x0006
#define MEM_DCF_CTL_DISABLE_DCF_MSB 0x0006
#define MEM_DCF_CTL_DISABLE_DCF_RANGE 0x0001
#define MEM_DCF_CTL_DISABLE_DCF_MASK 0x00000040
#define MEM_DCF_CTL_DISABLE_DCF_RESET_VALUE 0x00000000

#define MEM_DCF_CTL_TAP_DCF_EN_LSB 0x0007
#define MEM_DCF_CTL_TAP_DCF_EN_MSB 0x0007
#define MEM_DCF_CTL_TAP_DCF_EN_RANGE 0x0001
#define MEM_DCF_CTL_TAP_DCF_EN_MASK 0x00000080
#define MEM_DCF_CTL_TAP_DCF_EN_RESET_VALUE 0x00000000

#define MEM_DCF_CTL_DEBUG_DCF_EN_LSB 0x0008
#define MEM_DCF_CTL_DEBUG_DCF_EN_MSB 0x0008
#define MEM_DCF_CTL_DEBUG_DCF_EN_RANGE 0x0001
#define MEM_DCF_CTL_DEBUG_DCF_EN_MASK 0x00000100
#define MEM_DCF_CTL_DEBUG_DCF_EN_RESET_VALUE 0x00000000

#define MEM_DCF_CTL_DBG_DCF_MASTER_LSB 0x0009
#define MEM_DCF_CTL_DBG_DCF_MASTER_MSB 0x0009
#define MEM_DCF_CTL_DBG_DCF_MASTER_RANGE 0x0001
#define MEM_DCF_CTL_DBG_DCF_MASTER_MASK 0x00000200
#define MEM_DCF_CTL_DBG_DCF_MASTER_RESET_VALUE 0x00000000

#define MEM_DCF_CTL_DBG_DCF_RATIO_LSB 0x000a
#define MEM_DCF_CTL_DBG_DCF_RATIO_MSB 0x000d
#define MEM_DCF_CTL_DBG_DCF_RATIO_RANGE 0x0004
#define MEM_DCF_CTL_DBG_DCF_RATIO_MASK 0x00003c00
#define MEM_DCF_CTL_DBG_DCF_RATIO_RESET_VALUE 0x00000000

#define MEM_DCF_CTL_CYC_CNTR_CLK_EN_OVRD_LSB 0x000e
#define MEM_DCF_CTL_CYC_CNTR_CLK_EN_OVRD_MSB 0x000e
#define MEM_DCF_CTL_CYC_CNTR_CLK_EN_OVRD_RANGE 0x0001
#define MEM_DCF_CTL_CYC_CNTR_CLK_EN_OVRD_MASK 0x00004000
#define MEM_DCF_CTL_CYC_CNTR_CLK_EN_OVRD_RESET_VALUE 0x00000000

#define MEM_DCF_CTL_RESERVED_LSB 0x000f
#define MEM_DCF_CTL_RESERVED_MSB 0x001f
#define MEM_DCF_CTL_RESERVED_RANGE 0x0011
#define MEM_DCF_CTL_RESERVED_MASK 0xffff8000
#define MEM_DCF_CTL_RESERVED_RESET_VALUE 0x00000000


// --------------------------------------------------------------------------------------------------------------------------------

#ifndef MEM_ICCP_CONFIG1_FLAG
#define MEM_ICCP_CONFIG1_FLAG
// ICCP_CONFIG1 desc:  ICCP configuration
typedef union {
    struct {
        uint32_t  EN_SQUASH            :   1;    //  Enable clock squashing due to
                                                 // ICCP
        uint32_t  ALLOW_THTL_OVR_EN    :   1;    //  Enable override of
                                                 // allow_throttle attribute
        uint32_t  ALLOW_THTL_OVR_VAL   :   1;    //  Value to override for
                                                 // allow_throttle attribute
        uint32_t  EN_DN_HYSTERISIS     :   1;    //  When enabled, wait some time
                                                 // before sending a lower ICCP
                                                 // request to PUNIT
        uint32_t  EN_UP_HYSTERISIS     :   1;    //  When enabled, wait some time
                                                 // before sending a higher ICCP
                                                 // request to PUNIT
        uint32_t  RESERVED             :  12;    //  RESERVED
        uint32_t  DOWN_HYST_COUNT      :   8;    //  X1clk (10ns) cycles to count
                                                 // for down hysterisis, multiply
                                                 // by 1024. The hysterisis
                                                 // counter has 18 bits, upper 8
                                                 // bits are loaded with this
                                                 // field value, lower 10 bits are
                                                 // loaded to 0. This allows
                                                 // counting of up to 2.5 ms
        uint32_t  RESERVED2            :   7;    //  RESERVED

    }                                field;
    uint32_t                         val;
} MEM_ICCP_CONFIG1_t;
#endif
#define MEM_ICCP_CONFIG1_OFFSET 0x1c
#define MEM_ICCP_CONFIG1_SCOPE 0x01
#define MEM_ICCP_CONFIG1_SIZE 32
#define MEM_ICCP_CONFIG1_BITFIELD_COUNT 0x08
#define MEM_ICCP_CONFIG1_RESET 0x00960001

#define MEM_ICCP_CONFIG1_EN_SQUASH_LSB 0x0000
#define MEM_ICCP_CONFIG1_EN_SQUASH_MSB 0x0000
#define MEM_ICCP_CONFIG1_EN_SQUASH_RANGE 0x0001
#define MEM_ICCP_CONFIG1_EN_SQUASH_MASK 0x00000001
#define MEM_ICCP_CONFIG1_EN_SQUASH_RESET_VALUE 0x00000001

#define MEM_ICCP_CONFIG1_ALLOW_THTL_OVR_EN_LSB 0x0001
#define MEM_ICCP_CONFIG1_ALLOW_THTL_OVR_EN_MSB 0x0001
#define MEM_ICCP_CONFIG1_ALLOW_THTL_OVR_EN_RANGE 0x0001
#define MEM_ICCP_CONFIG1_ALLOW_THTL_OVR_EN_MASK 0x00000002
#define MEM_ICCP_CONFIG1_ALLOW_THTL_OVR_EN_RESET_VALUE 0x00000000

#define MEM_ICCP_CONFIG1_ALLOW_THTL_OVR_VAL_LSB 0x0002
#define MEM_ICCP_CONFIG1_ALLOW_THTL_OVR_VAL_MSB 0x0002
#define MEM_ICCP_CONFIG1_ALLOW_THTL_OVR_VAL_RANGE 0x0001
#define MEM_ICCP_CONFIG1_ALLOW_THTL_OVR_VAL_MASK 0x00000004
#define MEM_ICCP_CONFIG1_ALLOW_THTL_OVR_VAL_RESET_VALUE 0x00000000

#define MEM_ICCP_CONFIG1_EN_DN_HYSTERISIS_LSB 0x0003
#define MEM_ICCP_CONFIG1_EN_DN_HYSTERISIS_MSB 0x0003
#define MEM_ICCP_CONFIG1_EN_DN_HYSTERISIS_RANGE 0x0001
#define MEM_ICCP_CONFIG1_EN_DN_HYSTERISIS_MASK 0x00000008
#define MEM_ICCP_CONFIG1_EN_DN_HYSTERISIS_RESET_VALUE 0x00000000

#define MEM_ICCP_CONFIG1_EN_UP_HYSTERISIS_LSB 0x0004
#define MEM_ICCP_CONFIG1_EN_UP_HYSTERISIS_MSB 0x0004
#define MEM_ICCP_CONFIG1_EN_UP_HYSTERISIS_RANGE 0x0001
#define MEM_ICCP_CONFIG1_EN_UP_HYSTERISIS_MASK 0x00000010
#define MEM_ICCP_CONFIG1_EN_UP_HYSTERISIS_RESET_VALUE 0x00000000

#define MEM_ICCP_CONFIG1_RESERVED_LSB 0x0005
#define MEM_ICCP_CONFIG1_RESERVED_MSB 0x0010
#define MEM_ICCP_CONFIG1_RESERVED_RANGE 0x000c
#define MEM_ICCP_CONFIG1_RESERVED_MASK 0x0001ffe0
#define MEM_ICCP_CONFIG1_RESERVED_RESET_VALUE 0x00000000

#define MEM_ICCP_CONFIG1_DOWN_HYST_COUNT_LSB 0x0011
#define MEM_ICCP_CONFIG1_DOWN_HYST_COUNT_MSB 0x0018
#define MEM_ICCP_CONFIG1_DOWN_HYST_COUNT_RANGE 0x0008
#define MEM_ICCP_CONFIG1_DOWN_HYST_COUNT_MASK 0x01fe0000
#define MEM_ICCP_CONFIG1_DOWN_HYST_COUNT_RESET_VALUE 0x0000004b

#define MEM_ICCP_CONFIG1_RESERVED2_LSB 0x0019
#define MEM_ICCP_CONFIG1_RESERVED2_MSB 0x001f
#define MEM_ICCP_CONFIG1_RESERVED2_RANGE 0x0007
#define MEM_ICCP_CONFIG1_RESERVED2_MASK 0xfe000000
#define MEM_ICCP_CONFIG1_RESERVED2_RESET_VALUE 0x00000000


// --------------------------------------------------------------------------------------------------------------------------------

#ifndef MEM_ICCP_CONFIG2_FLAG
#define MEM_ICCP_CONFIG2_FLAG
// ICCP_CONFIG2 desc:  ICCP configuration
typedef union {
    struct {
        uint32_t  RESET_CDYN           :  15;    //  Cdyn of single ICE, when ICE
                                                 // reset is active
        uint32_t  RESERVED             :   1;    //  RESERVED
        uint32_t  INITIAL_CDYN         :  15;    //  Cdyn of single ICE, after ICE
                                                 // reset de-assertion, before
                                                 // first request was sent
        uint32_t  RESERVED2            :   1;    //  RESERVED

    }                                field;
    uint32_t                         val;
} MEM_ICCP_CONFIG2_t;
#endif
#define MEM_ICCP_CONFIG2_OFFSET 0x20
#define MEM_ICCP_CONFIG2_SCOPE 0x01
#define MEM_ICCP_CONFIG2_SIZE 32
#define MEM_ICCP_CONFIG2_BITFIELD_COUNT 0x04
#define MEM_ICCP_CONFIG2_RESET 0x00000000

#define MEM_ICCP_CONFIG2_RESET_CDYN_LSB 0x0000
#define MEM_ICCP_CONFIG2_RESET_CDYN_MSB 0x000e
#define MEM_ICCP_CONFIG2_RESET_CDYN_RANGE 0x000f
#define MEM_ICCP_CONFIG2_RESET_CDYN_MASK 0x00007fff
#define MEM_ICCP_CONFIG2_RESET_CDYN_RESET_VALUE 0x00000000

#define MEM_ICCP_CONFIG2_RESERVED_LSB 0x000f
#define MEM_ICCP_CONFIG2_RESERVED_MSB 0x000f
#define MEM_ICCP_CONFIG2_RESERVED_RANGE 0x0001
#define MEM_ICCP_CONFIG2_RESERVED_MASK 0x00008000
#define MEM_ICCP_CONFIG2_RESERVED_RESET_VALUE 0x00000000

#define MEM_ICCP_CONFIG2_INITIAL_CDYN_LSB 0x0010
#define MEM_ICCP_CONFIG2_INITIAL_CDYN_MSB 0x001e
#define MEM_ICCP_CONFIG2_INITIAL_CDYN_RANGE 0x000f
#define MEM_ICCP_CONFIG2_INITIAL_CDYN_MASK 0x7fff0000
#define MEM_ICCP_CONFIG2_INITIAL_CDYN_RESET_VALUE 0x00000000

#define MEM_ICCP_CONFIG2_RESERVED2_LSB 0x001f
#define MEM_ICCP_CONFIG2_RESERVED2_MSB 0x001f
#define MEM_ICCP_CONFIG2_RESERVED2_RANGE 0x0001
#define MEM_ICCP_CONFIG2_RESERVED2_MASK 0x80000000
#define MEM_ICCP_CONFIG2_RESERVED2_RESET_VALUE 0x00000000


// --------------------------------------------------------------------------------------------------------------------------------

#ifndef MEM_ICCP_CONFIG3_FLAG
#define MEM_ICCP_CONFIG3_FLAG
// ICCP_CONFIG3 desc:  ICCP configuration
typedef union {
    struct {
        uint32_t  BLOCKED_CDYN         :  15;    //  Cdyn of single ICE, when
                                                 // there's a pending ICCP request
                                                 // in no throttling mode
        uint32_t  RESERVED             :   1;    //  RESERVED
        uint32_t  DEFAULT_CDYN         :  15;    //  Assumed Cdyn of a single ICE,
                                                 // when USE_DEFAULT_CDYN is set.
        uint32_t  USE_DEFAULT_CDYN     :   1;    //  Chicken bit to disable ICE
                                                 // ICCP request. Overrides
                                                 // reset/init/requested/blocked
                                                 // Cdyn, but use only
                                                 // DEFAULT_CDYN

    }                                field;
    uint32_t                         val;
} MEM_ICCP_CONFIG3_t;
#endif
#define MEM_ICCP_CONFIG3_OFFSET 0x24
#define MEM_ICCP_CONFIG3_SCOPE 0x01
#define MEM_ICCP_CONFIG3_SIZE 32
#define MEM_ICCP_CONFIG3_BITFIELD_COUNT 0x04
#define MEM_ICCP_CONFIG3_RESET 0x00000000

#define MEM_ICCP_CONFIG3_BLOCKED_CDYN_LSB 0x0000
#define MEM_ICCP_CONFIG3_BLOCKED_CDYN_MSB 0x000e
#define MEM_ICCP_CONFIG3_BLOCKED_CDYN_RANGE 0x000f
#define MEM_ICCP_CONFIG3_BLOCKED_CDYN_MASK 0x00007fff
#define MEM_ICCP_CONFIG3_BLOCKED_CDYN_RESET_VALUE 0x00000000

#define MEM_ICCP_CONFIG3_RESERVED_LSB 0x000f
#define MEM_ICCP_CONFIG3_RESERVED_MSB 0x000f
#define MEM_ICCP_CONFIG3_RESERVED_RANGE 0x0001
#define MEM_ICCP_CONFIG3_RESERVED_MASK 0x00008000
#define MEM_ICCP_CONFIG3_RESERVED_RESET_VALUE 0x00000000

#define MEM_ICCP_CONFIG3_DEFAULT_CDYN_LSB 0x0010
#define MEM_ICCP_CONFIG3_DEFAULT_CDYN_MSB 0x001e
#define MEM_ICCP_CONFIG3_DEFAULT_CDYN_RANGE 0x000f
#define MEM_ICCP_CONFIG3_DEFAULT_CDYN_MASK 0x7fff0000
#define MEM_ICCP_CONFIG3_DEFAULT_CDYN_RESET_VALUE 0x00000000

#define MEM_ICCP_CONFIG3_USE_DEFAULT_CDYN_LSB 0x001f
#define MEM_ICCP_CONFIG3_USE_DEFAULT_CDYN_MSB 0x001f
#define MEM_ICCP_CONFIG3_USE_DEFAULT_CDYN_RANGE 0x0001
#define MEM_ICCP_CONFIG3_USE_DEFAULT_CDYN_MASK 0x80000000
#define MEM_ICCP_CONFIG3_USE_DEFAULT_CDYN_RESET_VALUE 0x00000000


// --------------------------------------------------------------------------------------------------------------------------------

#ifndef MEM_ICCP_MAX_CDYN_LEVEL_0_FLAG
#define MEM_ICCP_MAX_CDYN_LEVEL_0_FLAG
// ICCP_MAX_CDYN_LEVEL_0 desc:  15 registers, Max Cdyn of each level. Level 15 doesn't have max Cdyn
// - if Cdyn is above level 14, it's considerred level 15
typedef union {
    struct {
        uint32_t  MAX_CDYN             :  16;    //  Max Cdyn of that level
        uint32_t  RESERVED             :  16;    //  RESERVED

    }                                field;
    uint32_t                         val;
} MEM_ICCP_MAX_CDYN_LEVEL_0_t;
#endif
#define MEM_ICCP_MAX_CDYN_LEVEL_0_OFFSET 0x28
#define MEM_ICCP_MAX_CDYN_LEVEL_0_SCOPE 0x01
#define MEM_ICCP_MAX_CDYN_LEVEL_0_SIZE 32
#define MEM_ICCP_MAX_CDYN_LEVEL_0_BITFIELD_COUNT 0x02
#define MEM_ICCP_MAX_CDYN_LEVEL_0_RESET 0x00000000

#define MEM_ICCP_MAX_CDYN_LEVEL_0_MAX_CDYN_LSB 0x0000
#define MEM_ICCP_MAX_CDYN_LEVEL_0_MAX_CDYN_MSB 0x000f
#define MEM_ICCP_MAX_CDYN_LEVEL_0_MAX_CDYN_RANGE 0x0010
#define MEM_ICCP_MAX_CDYN_LEVEL_0_MAX_CDYN_MASK 0x0000ffff
#define MEM_ICCP_MAX_CDYN_LEVEL_0_MAX_CDYN_RESET_VALUE 0x00000000

#define MEM_ICCP_MAX_CDYN_LEVEL_0_RESERVED_LSB 0x0010
#define MEM_ICCP_MAX_CDYN_LEVEL_0_RESERVED_MSB 0x001f
#define MEM_ICCP_MAX_CDYN_LEVEL_0_RESERVED_RANGE 0x0010
#define MEM_ICCP_MAX_CDYN_LEVEL_0_RESERVED_MASK 0xffff0000
#define MEM_ICCP_MAX_CDYN_LEVEL_0_RESERVED_RESET_VALUE 0x00000000


// --------------------------------------------------------------------------------------------------------------------------------

#ifndef MEM_ICCP_MAX_CDYN_LEVEL_1_FLAG
#define MEM_ICCP_MAX_CDYN_LEVEL_1_FLAG
// ICCP_MAX_CDYN_LEVEL_1 desc:  15 registers, Max Cdyn of each level. Level 15 doesn't have max Cdyn
// - if Cdyn is above level 14, it's considerred level 15
typedef union {
    struct {
        uint32_t  MAX_CDYN             :  16;    //  Max Cdyn of that level
        uint32_t  RESERVED             :  16;    //  RESERVED

    }                                field;
    uint32_t                         val;
} MEM_ICCP_MAX_CDYN_LEVEL_1_t;
#endif
#define MEM_ICCP_MAX_CDYN_LEVEL_1_OFFSET 0x2c
#define MEM_ICCP_MAX_CDYN_LEVEL_1_SCOPE 0x01
#define MEM_ICCP_MAX_CDYN_LEVEL_1_SIZE 32
#define MEM_ICCP_MAX_CDYN_LEVEL_1_BITFIELD_COUNT 0x02
#define MEM_ICCP_MAX_CDYN_LEVEL_1_RESET 0x00000100

#define MEM_ICCP_MAX_CDYN_LEVEL_1_MAX_CDYN_LSB 0x0000
#define MEM_ICCP_MAX_CDYN_LEVEL_1_MAX_CDYN_MSB 0x000f
#define MEM_ICCP_MAX_CDYN_LEVEL_1_MAX_CDYN_RANGE 0x0010
#define MEM_ICCP_MAX_CDYN_LEVEL_1_MAX_CDYN_MASK 0x0000ffff
#define MEM_ICCP_MAX_CDYN_LEVEL_1_MAX_CDYN_RESET_VALUE 0x00000100

#define MEM_ICCP_MAX_CDYN_LEVEL_1_RESERVED_LSB 0x0010
#define MEM_ICCP_MAX_CDYN_LEVEL_1_RESERVED_MSB 0x001f
#define MEM_ICCP_MAX_CDYN_LEVEL_1_RESERVED_RANGE 0x0010
#define MEM_ICCP_MAX_CDYN_LEVEL_1_RESERVED_MASK 0xffff0000
#define MEM_ICCP_MAX_CDYN_LEVEL_1_RESERVED_RESET_VALUE 0x00000000


// --------------------------------------------------------------------------------------------------------------------------------

#ifndef MEM_ICCP_MAX_CDYN_LEVEL_2_FLAG
#define MEM_ICCP_MAX_CDYN_LEVEL_2_FLAG
// ICCP_MAX_CDYN_LEVEL_2 desc:  15 registers, Max Cdyn of each level. Level 15 doesn't have max Cdyn
// - if Cdyn is above level 14, it's considerred level 15
typedef union {
    struct {
        uint32_t  MAX_CDYN             :  16;    //  Max Cdyn of that level
        uint32_t  RESERVED             :  16;    //  RESERVED

    }                                field;
    uint32_t                         val;
} MEM_ICCP_MAX_CDYN_LEVEL_2_t;
#endif
#define MEM_ICCP_MAX_CDYN_LEVEL_2_OFFSET 0x30
#define MEM_ICCP_MAX_CDYN_LEVEL_2_SCOPE 0x01
#define MEM_ICCP_MAX_CDYN_LEVEL_2_SIZE 32
#define MEM_ICCP_MAX_CDYN_LEVEL_2_BITFIELD_COUNT 0x02
#define MEM_ICCP_MAX_CDYN_LEVEL_2_RESET 0x00000200

#define MEM_ICCP_MAX_CDYN_LEVEL_2_MAX_CDYN_LSB 0x0000
#define MEM_ICCP_MAX_CDYN_LEVEL_2_MAX_CDYN_MSB 0x000f
#define MEM_ICCP_MAX_CDYN_LEVEL_2_MAX_CDYN_RANGE 0x0010
#define MEM_ICCP_MAX_CDYN_LEVEL_2_MAX_CDYN_MASK 0x0000ffff
#define MEM_ICCP_MAX_CDYN_LEVEL_2_MAX_CDYN_RESET_VALUE 0x00000200

#define MEM_ICCP_MAX_CDYN_LEVEL_2_RESERVED_LSB 0x0010
#define MEM_ICCP_MAX_CDYN_LEVEL_2_RESERVED_MSB 0x001f
#define MEM_ICCP_MAX_CDYN_LEVEL_2_RESERVED_RANGE 0x0010
#define MEM_ICCP_MAX_CDYN_LEVEL_2_RESERVED_MASK 0xffff0000
#define MEM_ICCP_MAX_CDYN_LEVEL_2_RESERVED_RESET_VALUE 0x00000000


// --------------------------------------------------------------------------------------------------------------------------------

#ifndef MEM_ICCP_MAX_CDYN_LEVEL_3_FLAG
#define MEM_ICCP_MAX_CDYN_LEVEL_3_FLAG
// ICCP_MAX_CDYN_LEVEL_3 desc:  15 registers, Max Cdyn of each level. Level 15 doesn't have max Cdyn
// - if Cdyn is above level 14, it's considerred level 15
typedef union {
    struct {
        uint32_t  MAX_CDYN             :  16;    //  Max Cdyn of that level
        uint32_t  RESERVED             :  16;    //  RESERVED

    }                                field;
    uint32_t                         val;
} MEM_ICCP_MAX_CDYN_LEVEL_3_t;
#endif
#define MEM_ICCP_MAX_CDYN_LEVEL_3_OFFSET 0x34
#define MEM_ICCP_MAX_CDYN_LEVEL_3_SCOPE 0x01
#define MEM_ICCP_MAX_CDYN_LEVEL_3_SIZE 32
#define MEM_ICCP_MAX_CDYN_LEVEL_3_BITFIELD_COUNT 0x02
#define MEM_ICCP_MAX_CDYN_LEVEL_3_RESET 0x00000300

#define MEM_ICCP_MAX_CDYN_LEVEL_3_MAX_CDYN_LSB 0x0000
#define MEM_ICCP_MAX_CDYN_LEVEL_3_MAX_CDYN_MSB 0x000f
#define MEM_ICCP_MAX_CDYN_LEVEL_3_MAX_CDYN_RANGE 0x0010
#define MEM_ICCP_MAX_CDYN_LEVEL_3_MAX_CDYN_MASK 0x0000ffff
#define MEM_ICCP_MAX_CDYN_LEVEL_3_MAX_CDYN_RESET_VALUE 0x00000300

#define MEM_ICCP_MAX_CDYN_LEVEL_3_RESERVED_LSB 0x0010
#define MEM_ICCP_MAX_CDYN_LEVEL_3_RESERVED_MSB 0x001f
#define MEM_ICCP_MAX_CDYN_LEVEL_3_RESERVED_RANGE 0x0010
#define MEM_ICCP_MAX_CDYN_LEVEL_3_RESERVED_MASK 0xffff0000
#define MEM_ICCP_MAX_CDYN_LEVEL_3_RESERVED_RESET_VALUE 0x00000000


// --------------------------------------------------------------------------------------------------------------------------------

#ifndef MEM_ICCP_MAX_CDYN_LEVEL_4_FLAG
#define MEM_ICCP_MAX_CDYN_LEVEL_4_FLAG
// ICCP_MAX_CDYN_LEVEL_4 desc:  15 registers, Max Cdyn of each level. Level 15 doesn't have max Cdyn
// - if Cdyn is above level 14, it's considerred level 15
typedef union {
    struct {
        uint32_t  MAX_CDYN             :  16;    //  Max Cdyn of that level
        uint32_t  RESERVED             :  16;    //  RESERVED

    }                                field;
    uint32_t                         val;
} MEM_ICCP_MAX_CDYN_LEVEL_4_t;
#endif
#define MEM_ICCP_MAX_CDYN_LEVEL_4_OFFSET 0x38
#define MEM_ICCP_MAX_CDYN_LEVEL_4_SCOPE 0x01
#define MEM_ICCP_MAX_CDYN_LEVEL_4_SIZE 32
#define MEM_ICCP_MAX_CDYN_LEVEL_4_BITFIELD_COUNT 0x02
#define MEM_ICCP_MAX_CDYN_LEVEL_4_RESET 0x00000400

#define MEM_ICCP_MAX_CDYN_LEVEL_4_MAX_CDYN_LSB 0x0000
#define MEM_ICCP_MAX_CDYN_LEVEL_4_MAX_CDYN_MSB 0x000f
#define MEM_ICCP_MAX_CDYN_LEVEL_4_MAX_CDYN_RANGE 0x0010
#define MEM_ICCP_MAX_CDYN_LEVEL_4_MAX_CDYN_MASK 0x0000ffff
#define MEM_ICCP_MAX_CDYN_LEVEL_4_MAX_CDYN_RESET_VALUE 0x00000400

#define MEM_ICCP_MAX_CDYN_LEVEL_4_RESERVED_LSB 0x0010
#define MEM_ICCP_MAX_CDYN_LEVEL_4_RESERVED_MSB 0x001f
#define MEM_ICCP_MAX_CDYN_LEVEL_4_RESERVED_RANGE 0x0010
#define MEM_ICCP_MAX_CDYN_LEVEL_4_RESERVED_MASK 0xffff0000
#define MEM_ICCP_MAX_CDYN_LEVEL_4_RESERVED_RESET_VALUE 0x00000000


// --------------------------------------------------------------------------------------------------------------------------------

#ifndef MEM_ICCP_MAX_CDYN_LEVEL_5_FLAG
#define MEM_ICCP_MAX_CDYN_LEVEL_5_FLAG
// ICCP_MAX_CDYN_LEVEL_5 desc:  15 registers, Max Cdyn of each level. Level 15 doesn't have max Cdyn
// - if Cdyn is above level 14, it's considerred level 15
typedef union {
    struct {
        uint32_t  MAX_CDYN             :  16;    //  Max Cdyn of that level
        uint32_t  RESERVED             :  16;    //  RESERVED

    }                                field;
    uint32_t                         val;
} MEM_ICCP_MAX_CDYN_LEVEL_5_t;
#endif
#define MEM_ICCP_MAX_CDYN_LEVEL_5_OFFSET 0x3c
#define MEM_ICCP_MAX_CDYN_LEVEL_5_SCOPE 0x01
#define MEM_ICCP_MAX_CDYN_LEVEL_5_SIZE 32
#define MEM_ICCP_MAX_CDYN_LEVEL_5_BITFIELD_COUNT 0x02
#define MEM_ICCP_MAX_CDYN_LEVEL_5_RESET 0x00000500

#define MEM_ICCP_MAX_CDYN_LEVEL_5_MAX_CDYN_LSB 0x0000
#define MEM_ICCP_MAX_CDYN_LEVEL_5_MAX_CDYN_MSB 0x000f
#define MEM_ICCP_MAX_CDYN_LEVEL_5_MAX_CDYN_RANGE 0x0010
#define MEM_ICCP_MAX_CDYN_LEVEL_5_MAX_CDYN_MASK 0x0000ffff
#define MEM_ICCP_MAX_CDYN_LEVEL_5_MAX_CDYN_RESET_VALUE 0x00000500

#define MEM_ICCP_MAX_CDYN_LEVEL_5_RESERVED_LSB 0x0010
#define MEM_ICCP_MAX_CDYN_LEVEL_5_RESERVED_MSB 0x001f
#define MEM_ICCP_MAX_CDYN_LEVEL_5_RESERVED_RANGE 0x0010
#define MEM_ICCP_MAX_CDYN_LEVEL_5_RESERVED_MASK 0xffff0000
#define MEM_ICCP_MAX_CDYN_LEVEL_5_RESERVED_RESET_VALUE 0x00000000


// --------------------------------------------------------------------------------------------------------------------------------

#ifndef MEM_ICCP_MAX_CDYN_LEVEL_6_FLAG
#define MEM_ICCP_MAX_CDYN_LEVEL_6_FLAG
// ICCP_MAX_CDYN_LEVEL_6 desc:  15 registers, Max Cdyn of each level. Level 15 doesn't have max Cdyn
// - if Cdyn is above level 14, it's considerred level 15
typedef union {
    struct {
        uint32_t  MAX_CDYN             :  16;    //  Max Cdyn of that level
        uint32_t  RESERVED             :  16;    //  RESERVED

    }                                field;
    uint32_t                         val;
} MEM_ICCP_MAX_CDYN_LEVEL_6_t;
#endif
#define MEM_ICCP_MAX_CDYN_LEVEL_6_OFFSET 0x40
#define MEM_ICCP_MAX_CDYN_LEVEL_6_SCOPE 0x01
#define MEM_ICCP_MAX_CDYN_LEVEL_6_SIZE 32
#define MEM_ICCP_MAX_CDYN_LEVEL_6_BITFIELD_COUNT 0x02
#define MEM_ICCP_MAX_CDYN_LEVEL_6_RESET 0x00000600

#define MEM_ICCP_MAX_CDYN_LEVEL_6_MAX_CDYN_LSB 0x0000
#define MEM_ICCP_MAX_CDYN_LEVEL_6_MAX_CDYN_MSB 0x000f
#define MEM_ICCP_MAX_CDYN_LEVEL_6_MAX_CDYN_RANGE 0x0010
#define MEM_ICCP_MAX_CDYN_LEVEL_6_MAX_CDYN_MASK 0x0000ffff
#define MEM_ICCP_MAX_CDYN_LEVEL_6_MAX_CDYN_RESET_VALUE 0x00000600

#define MEM_ICCP_MAX_CDYN_LEVEL_6_RESERVED_LSB 0x0010
#define MEM_ICCP_MAX_CDYN_LEVEL_6_RESERVED_MSB 0x001f
#define MEM_ICCP_MAX_CDYN_LEVEL_6_RESERVED_RANGE 0x0010
#define MEM_ICCP_MAX_CDYN_LEVEL_6_RESERVED_MASK 0xffff0000
#define MEM_ICCP_MAX_CDYN_LEVEL_6_RESERVED_RESET_VALUE 0x00000000


// --------------------------------------------------------------------------------------------------------------------------------

#ifndef MEM_ICCP_MAX_CDYN_LEVEL_7_FLAG
#define MEM_ICCP_MAX_CDYN_LEVEL_7_FLAG
// ICCP_MAX_CDYN_LEVEL_7 desc:  15 registers, Max Cdyn of each level. Level 15 doesn't have max Cdyn
// - if Cdyn is above level 14, it's considerred level 15
typedef union {
    struct {
        uint32_t  MAX_CDYN             :  16;    //  Max Cdyn of that level
        uint32_t  RESERVED             :  16;    //  RESERVED

    }                                field;
    uint32_t                         val;
} MEM_ICCP_MAX_CDYN_LEVEL_7_t;
#endif
#define MEM_ICCP_MAX_CDYN_LEVEL_7_OFFSET 0x44
#define MEM_ICCP_MAX_CDYN_LEVEL_7_SCOPE 0x01
#define MEM_ICCP_MAX_CDYN_LEVEL_7_SIZE 32
#define MEM_ICCP_MAX_CDYN_LEVEL_7_BITFIELD_COUNT 0x02
#define MEM_ICCP_MAX_CDYN_LEVEL_7_RESET 0x00000700

#define MEM_ICCP_MAX_CDYN_LEVEL_7_MAX_CDYN_LSB 0x0000
#define MEM_ICCP_MAX_CDYN_LEVEL_7_MAX_CDYN_MSB 0x000f
#define MEM_ICCP_MAX_CDYN_LEVEL_7_MAX_CDYN_RANGE 0x0010
#define MEM_ICCP_MAX_CDYN_LEVEL_7_MAX_CDYN_MASK 0x0000ffff
#define MEM_ICCP_MAX_CDYN_LEVEL_7_MAX_CDYN_RESET_VALUE 0x00000700

#define MEM_ICCP_MAX_CDYN_LEVEL_7_RESERVED_LSB 0x0010
#define MEM_ICCP_MAX_CDYN_LEVEL_7_RESERVED_MSB 0x001f
#define MEM_ICCP_MAX_CDYN_LEVEL_7_RESERVED_RANGE 0x0010
#define MEM_ICCP_MAX_CDYN_LEVEL_7_RESERVED_MASK 0xffff0000
#define MEM_ICCP_MAX_CDYN_LEVEL_7_RESERVED_RESET_VALUE 0x00000000


// --------------------------------------------------------------------------------------------------------------------------------

#ifndef MEM_ICCP_MAX_CDYN_LEVEL_8_FLAG
#define MEM_ICCP_MAX_CDYN_LEVEL_8_FLAG
// ICCP_MAX_CDYN_LEVEL_8 desc:  15 registers, Max Cdyn of each level. Level 15 doesn't have max Cdyn
// - if Cdyn is above level 14, it's considerred level 15
typedef union {
    struct {
        uint32_t  MAX_CDYN             :  16;    //  Max Cdyn of that level
        uint32_t  RESERVED             :  16;    //  RESERVED

    }                                field;
    uint32_t                         val;
} MEM_ICCP_MAX_CDYN_LEVEL_8_t;
#endif
#define MEM_ICCP_MAX_CDYN_LEVEL_8_OFFSET 0x48
#define MEM_ICCP_MAX_CDYN_LEVEL_8_SCOPE 0x01
#define MEM_ICCP_MAX_CDYN_LEVEL_8_SIZE 32
#define MEM_ICCP_MAX_CDYN_LEVEL_8_BITFIELD_COUNT 0x02
#define MEM_ICCP_MAX_CDYN_LEVEL_8_RESET 0x00000800

#define MEM_ICCP_MAX_CDYN_LEVEL_8_MAX_CDYN_LSB 0x0000
#define MEM_ICCP_MAX_CDYN_LEVEL_8_MAX_CDYN_MSB 0x000f
#define MEM_ICCP_MAX_CDYN_LEVEL_8_MAX_CDYN_RANGE 0x0010
#define MEM_ICCP_MAX_CDYN_LEVEL_8_MAX_CDYN_MASK 0x0000ffff
#define MEM_ICCP_MAX_CDYN_LEVEL_8_MAX_CDYN_RESET_VALUE 0x00000800

#define MEM_ICCP_MAX_CDYN_LEVEL_8_RESERVED_LSB 0x0010
#define MEM_ICCP_MAX_CDYN_LEVEL_8_RESERVED_MSB 0x001f
#define MEM_ICCP_MAX_CDYN_LEVEL_8_RESERVED_RANGE 0x0010
#define MEM_ICCP_MAX_CDYN_LEVEL_8_RESERVED_MASK 0xffff0000
#define MEM_ICCP_MAX_CDYN_LEVEL_8_RESERVED_RESET_VALUE 0x00000000


// --------------------------------------------------------------------------------------------------------------------------------

#ifndef MEM_ICCP_MAX_CDYN_LEVEL_9_FLAG
#define MEM_ICCP_MAX_CDYN_LEVEL_9_FLAG
// ICCP_MAX_CDYN_LEVEL_9 desc:  15 registers, Max Cdyn of each level. Level 15 doesn't have max Cdyn
// - if Cdyn is above level 14, it's considerred level 15
typedef union {
    struct {
        uint32_t  MAX_CDYN             :  16;    //  Max Cdyn of that level
        uint32_t  RESERVED             :  16;    //  RESERVED

    }                                field;
    uint32_t                         val;
} MEM_ICCP_MAX_CDYN_LEVEL_9_t;
#endif
#define MEM_ICCP_MAX_CDYN_LEVEL_9_OFFSET 0x4c
#define MEM_ICCP_MAX_CDYN_LEVEL_9_SCOPE 0x01
#define MEM_ICCP_MAX_CDYN_LEVEL_9_SIZE 32
#define MEM_ICCP_MAX_CDYN_LEVEL_9_BITFIELD_COUNT 0x02
#define MEM_ICCP_MAX_CDYN_LEVEL_9_RESET 0x00000900

#define MEM_ICCP_MAX_CDYN_LEVEL_9_MAX_CDYN_LSB 0x0000
#define MEM_ICCP_MAX_CDYN_LEVEL_9_MAX_CDYN_MSB 0x000f
#define MEM_ICCP_MAX_CDYN_LEVEL_9_MAX_CDYN_RANGE 0x0010
#define MEM_ICCP_MAX_CDYN_LEVEL_9_MAX_CDYN_MASK 0x0000ffff
#define MEM_ICCP_MAX_CDYN_LEVEL_9_MAX_CDYN_RESET_VALUE 0x00000900

#define MEM_ICCP_MAX_CDYN_LEVEL_9_RESERVED_LSB 0x0010
#define MEM_ICCP_MAX_CDYN_LEVEL_9_RESERVED_MSB 0x001f
#define MEM_ICCP_MAX_CDYN_LEVEL_9_RESERVED_RANGE 0x0010
#define MEM_ICCP_MAX_CDYN_LEVEL_9_RESERVED_MASK 0xffff0000
#define MEM_ICCP_MAX_CDYN_LEVEL_9_RESERVED_RESET_VALUE 0x00000000


// --------------------------------------------------------------------------------------------------------------------------------

#ifndef MEM_ICCP_MAX_CDYN_LEVEL_10_FLAG
#define MEM_ICCP_MAX_CDYN_LEVEL_10_FLAG
// ICCP_MAX_CDYN_LEVEL_10 desc:  15 registers, Max Cdyn of each level. Level 15 doesn't have max Cdyn
// - if Cdyn is above level 14, it's considerred level 15
typedef union {
    struct {
        uint32_t  MAX_CDYN             :  16;    //  Max Cdyn of that level
        uint32_t  RESERVED             :  16;    //  RESERVED

    }                                field;
    uint32_t                         val;
} MEM_ICCP_MAX_CDYN_LEVEL_10_t;
#endif
#define MEM_ICCP_MAX_CDYN_LEVEL_10_OFFSET 0x50
#define MEM_ICCP_MAX_CDYN_LEVEL_10_SCOPE 0x01
#define MEM_ICCP_MAX_CDYN_LEVEL_10_SIZE 32
#define MEM_ICCP_MAX_CDYN_LEVEL_10_BITFIELD_COUNT 0x02
#define MEM_ICCP_MAX_CDYN_LEVEL_10_RESET 0x00001000

#define MEM_ICCP_MAX_CDYN_LEVEL_10_MAX_CDYN_LSB 0x0000
#define MEM_ICCP_MAX_CDYN_LEVEL_10_MAX_CDYN_MSB 0x000f
#define MEM_ICCP_MAX_CDYN_LEVEL_10_MAX_CDYN_RANGE 0x0010
#define MEM_ICCP_MAX_CDYN_LEVEL_10_MAX_CDYN_MASK 0x0000ffff
#define MEM_ICCP_MAX_CDYN_LEVEL_10_MAX_CDYN_RESET_VALUE 0x00001000

#define MEM_ICCP_MAX_CDYN_LEVEL_10_RESERVED_LSB 0x0010
#define MEM_ICCP_MAX_CDYN_LEVEL_10_RESERVED_MSB 0x001f
#define MEM_ICCP_MAX_CDYN_LEVEL_10_RESERVED_RANGE 0x0010
#define MEM_ICCP_MAX_CDYN_LEVEL_10_RESERVED_MASK 0xffff0000
#define MEM_ICCP_MAX_CDYN_LEVEL_10_RESERVED_RESET_VALUE 0x00000000


// --------------------------------------------------------------------------------------------------------------------------------

#ifndef MEM_ICCP_MAX_CDYN_LEVEL_11_FLAG
#define MEM_ICCP_MAX_CDYN_LEVEL_11_FLAG
// ICCP_MAX_CDYN_LEVEL_11 desc:  15 registers, Max Cdyn of each level. Level 15 doesn't have max Cdyn
// - if Cdyn is above level 14, it's considerred level 15
typedef union {
    struct {
        uint32_t  MAX_CDYN             :  16;    //  Max Cdyn of that level
        uint32_t  RESERVED             :  16;    //  RESERVED

    }                                field;
    uint32_t                         val;
} MEM_ICCP_MAX_CDYN_LEVEL_11_t;
#endif
#define MEM_ICCP_MAX_CDYN_LEVEL_11_OFFSET 0x54
#define MEM_ICCP_MAX_CDYN_LEVEL_11_SCOPE 0x01
#define MEM_ICCP_MAX_CDYN_LEVEL_11_SIZE 32
#define MEM_ICCP_MAX_CDYN_LEVEL_11_BITFIELD_COUNT 0x02
#define MEM_ICCP_MAX_CDYN_LEVEL_11_RESET 0x00001100

#define MEM_ICCP_MAX_CDYN_LEVEL_11_MAX_CDYN_LSB 0x0000
#define MEM_ICCP_MAX_CDYN_LEVEL_11_MAX_CDYN_MSB 0x000f
#define MEM_ICCP_MAX_CDYN_LEVEL_11_MAX_CDYN_RANGE 0x0010
#define MEM_ICCP_MAX_CDYN_LEVEL_11_MAX_CDYN_MASK 0x0000ffff
#define MEM_ICCP_MAX_CDYN_LEVEL_11_MAX_CDYN_RESET_VALUE 0x00001100

#define MEM_ICCP_MAX_CDYN_LEVEL_11_RESERVED_LSB 0x0010
#define MEM_ICCP_MAX_CDYN_LEVEL_11_RESERVED_MSB 0x001f
#define MEM_ICCP_MAX_CDYN_LEVEL_11_RESERVED_RANGE 0x0010
#define MEM_ICCP_MAX_CDYN_LEVEL_11_RESERVED_MASK 0xffff0000
#define MEM_ICCP_MAX_CDYN_LEVEL_11_RESERVED_RESET_VALUE 0x00000000


// --------------------------------------------------------------------------------------------------------------------------------

#ifndef MEM_ICCP_MAX_CDYN_LEVEL_12_FLAG
#define MEM_ICCP_MAX_CDYN_LEVEL_12_FLAG
// ICCP_MAX_CDYN_LEVEL_12 desc:  15 registers, Max Cdyn of each level. Level 15 doesn't have max Cdyn
// - if Cdyn is above level 14, it's considerred level 15
typedef union {
    struct {
        uint32_t  MAX_CDYN             :  16;    //  Max Cdyn of that level
        uint32_t  RESERVED             :  16;    //  RESERVED

    }                                field;
    uint32_t                         val;
} MEM_ICCP_MAX_CDYN_LEVEL_12_t;
#endif
#define MEM_ICCP_MAX_CDYN_LEVEL_12_OFFSET 0x58
#define MEM_ICCP_MAX_CDYN_LEVEL_12_SCOPE 0x01
#define MEM_ICCP_MAX_CDYN_LEVEL_12_SIZE 32
#define MEM_ICCP_MAX_CDYN_LEVEL_12_BITFIELD_COUNT 0x02
#define MEM_ICCP_MAX_CDYN_LEVEL_12_RESET 0x00001200

#define MEM_ICCP_MAX_CDYN_LEVEL_12_MAX_CDYN_LSB 0x0000
#define MEM_ICCP_MAX_CDYN_LEVEL_12_MAX_CDYN_MSB 0x000f
#define MEM_ICCP_MAX_CDYN_LEVEL_12_MAX_CDYN_RANGE 0x0010
#define MEM_ICCP_MAX_CDYN_LEVEL_12_MAX_CDYN_MASK 0x0000ffff
#define MEM_ICCP_MAX_CDYN_LEVEL_12_MAX_CDYN_RESET_VALUE 0x00001200

#define MEM_ICCP_MAX_CDYN_LEVEL_12_RESERVED_LSB 0x0010
#define MEM_ICCP_MAX_CDYN_LEVEL_12_RESERVED_MSB 0x001f
#define MEM_ICCP_MAX_CDYN_LEVEL_12_RESERVED_RANGE 0x0010
#define MEM_ICCP_MAX_CDYN_LEVEL_12_RESERVED_MASK 0xffff0000
#define MEM_ICCP_MAX_CDYN_LEVEL_12_RESERVED_RESET_VALUE 0x00000000


// --------------------------------------------------------------------------------------------------------------------------------

#ifndef MEM_ICCP_MAX_CDYN_LEVEL_13_FLAG
#define MEM_ICCP_MAX_CDYN_LEVEL_13_FLAG
// ICCP_MAX_CDYN_LEVEL_13 desc:  15 registers, Max Cdyn of each level. Level 15 doesn't have max Cdyn
// - if Cdyn is above level 14, it's considerred level 15
typedef union {
    struct {
        uint32_t  MAX_CDYN             :  16;    //  Max Cdyn of that level
        uint32_t  RESERVED             :  16;    //  RESERVED

    }                                field;
    uint32_t                         val;
} MEM_ICCP_MAX_CDYN_LEVEL_13_t;
#endif
#define MEM_ICCP_MAX_CDYN_LEVEL_13_OFFSET 0x5c
#define MEM_ICCP_MAX_CDYN_LEVEL_13_SCOPE 0x01
#define MEM_ICCP_MAX_CDYN_LEVEL_13_SIZE 32
#define MEM_ICCP_MAX_CDYN_LEVEL_13_BITFIELD_COUNT 0x02
#define MEM_ICCP_MAX_CDYN_LEVEL_13_RESET 0x00001300

#define MEM_ICCP_MAX_CDYN_LEVEL_13_MAX_CDYN_LSB 0x0000
#define MEM_ICCP_MAX_CDYN_LEVEL_13_MAX_CDYN_MSB 0x000f
#define MEM_ICCP_MAX_CDYN_LEVEL_13_MAX_CDYN_RANGE 0x0010
#define MEM_ICCP_MAX_CDYN_LEVEL_13_MAX_CDYN_MASK 0x0000ffff
#define MEM_ICCP_MAX_CDYN_LEVEL_13_MAX_CDYN_RESET_VALUE 0x00001300

#define MEM_ICCP_MAX_CDYN_LEVEL_13_RESERVED_LSB 0x0010
#define MEM_ICCP_MAX_CDYN_LEVEL_13_RESERVED_MSB 0x001f
#define MEM_ICCP_MAX_CDYN_LEVEL_13_RESERVED_RANGE 0x0010
#define MEM_ICCP_MAX_CDYN_LEVEL_13_RESERVED_MASK 0xffff0000
#define MEM_ICCP_MAX_CDYN_LEVEL_13_RESERVED_RESET_VALUE 0x00000000


// --------------------------------------------------------------------------------------------------------------------------------

#ifndef MEM_ICCP_MAX_CDYN_LEVEL_14_FLAG
#define MEM_ICCP_MAX_CDYN_LEVEL_14_FLAG
// ICCP_MAX_CDYN_LEVEL_14 desc:  15 registers, Max Cdyn of each level. Level 15 doesn't have max Cdyn
// - if Cdyn is above level 14, it's considerred level 15
typedef union {
    struct {
        uint32_t  MAX_CDYN             :  16;    //  Max Cdyn of that level
        uint32_t  RESERVED             :  16;    //  RESERVED

    }                                field;
    uint32_t                         val;
} MEM_ICCP_MAX_CDYN_LEVEL_14_t;
#endif
#define MEM_ICCP_MAX_CDYN_LEVEL_14_OFFSET 0x60
#define MEM_ICCP_MAX_CDYN_LEVEL_14_SCOPE 0x01
#define MEM_ICCP_MAX_CDYN_LEVEL_14_SIZE 32
#define MEM_ICCP_MAX_CDYN_LEVEL_14_BITFIELD_COUNT 0x02
#define MEM_ICCP_MAX_CDYN_LEVEL_14_RESET 0x00001400

#define MEM_ICCP_MAX_CDYN_LEVEL_14_MAX_CDYN_LSB 0x0000
#define MEM_ICCP_MAX_CDYN_LEVEL_14_MAX_CDYN_MSB 0x000f
#define MEM_ICCP_MAX_CDYN_LEVEL_14_MAX_CDYN_RANGE 0x0010
#define MEM_ICCP_MAX_CDYN_LEVEL_14_MAX_CDYN_MASK 0x0000ffff
#define MEM_ICCP_MAX_CDYN_LEVEL_14_MAX_CDYN_RESET_VALUE 0x00001400

#define MEM_ICCP_MAX_CDYN_LEVEL_14_RESERVED_LSB 0x0010
#define MEM_ICCP_MAX_CDYN_LEVEL_14_RESERVED_MSB 0x001f
#define MEM_ICCP_MAX_CDYN_LEVEL_14_RESERVED_RANGE 0x0010
#define MEM_ICCP_MAX_CDYN_LEVEL_14_RESERVED_MASK 0xffff0000
#define MEM_ICCP_MAX_CDYN_LEVEL_14_RESERVED_RESET_VALUE 0x00000000


// --------------------------------------------------------------------------------------------------------------------------------

#ifndef MEM_ICCP_DEBUG1_FLAG
#define MEM_ICCP_DEBUG1_FLAG
// ICCP_DEBUG1 desc:  Read only. Current Cdyn of each ICE
typedef union {
    struct {
        uint32_t  CDYN_ICE0            :  15;    //  Current Cdyn of ICE0
        uint32_t  RESERVED             :   1;    //  RESERVED
        uint32_t  CDYN_ICE1            :  15;    //  Current Cdyn of ICE1
        uint32_t  RESERVED2            :   1;    //  RESERVED

    }                                field;
    uint32_t                         val;
} MEM_ICCP_DEBUG1_t;
#endif
#define MEM_ICCP_DEBUG1_OFFSET 0x64
#define MEM_ICCP_DEBUG1_SCOPE 0x01
#define MEM_ICCP_DEBUG1_SIZE 32
#define MEM_ICCP_DEBUG1_BITFIELD_COUNT 0x04
#define MEM_ICCP_DEBUG1_RESET 0x00000000

#define MEM_ICCP_DEBUG1_CDYN_ICE0_LSB 0x0000
#define MEM_ICCP_DEBUG1_CDYN_ICE0_MSB 0x000e
#define MEM_ICCP_DEBUG1_CDYN_ICE0_RANGE 0x000f
#define MEM_ICCP_DEBUG1_CDYN_ICE0_MASK 0x00007fff
#define MEM_ICCP_DEBUG1_CDYN_ICE0_RESET_VALUE 0x00000000

#define MEM_ICCP_DEBUG1_RESERVED_LSB 0x000f
#define MEM_ICCP_DEBUG1_RESERVED_MSB 0x000f
#define MEM_ICCP_DEBUG1_RESERVED_RANGE 0x0001
#define MEM_ICCP_DEBUG1_RESERVED_MASK 0x00008000
#define MEM_ICCP_DEBUG1_RESERVED_RESET_VALUE 0x00000000

#define MEM_ICCP_DEBUG1_CDYN_ICE1_LSB 0x0010
#define MEM_ICCP_DEBUG1_CDYN_ICE1_MSB 0x001e
#define MEM_ICCP_DEBUG1_CDYN_ICE1_RANGE 0x000f
#define MEM_ICCP_DEBUG1_CDYN_ICE1_MASK 0x7fff0000
#define MEM_ICCP_DEBUG1_CDYN_ICE1_RESET_VALUE 0x00000000

#define MEM_ICCP_DEBUG1_RESERVED2_LSB 0x001f
#define MEM_ICCP_DEBUG1_RESERVED2_MSB 0x001f
#define MEM_ICCP_DEBUG1_RESERVED2_RANGE 0x0001
#define MEM_ICCP_DEBUG1_RESERVED2_MASK 0x80000000
#define MEM_ICCP_DEBUG1_RESERVED2_RESET_VALUE 0x00000000


// --------------------------------------------------------------------------------------------------------------------------------

#ifndef MEM_ICCP_DEBUG2_FLAG
#define MEM_ICCP_DEBUG2_FLAG
// ICCP_DEBUG2 desc: 
typedef union {
    struct {
        uint32_t  MAX_REACHED_TOTAL_CDYN :  16;    //  Current Cdyn of ICE0
        uint32_t  RESERVED             :  16;    //  RESERVED

    }                                field;
    uint32_t                         val;
} MEM_ICCP_DEBUG2_t;
#endif
#define MEM_ICCP_DEBUG2_OFFSET 0x68
#define MEM_ICCP_DEBUG2_SCOPE 0x01
#define MEM_ICCP_DEBUG2_SIZE 32
#define MEM_ICCP_DEBUG2_BITFIELD_COUNT 0x02
#define MEM_ICCP_DEBUG2_RESET 0x00000000

#define MEM_ICCP_DEBUG2_MAX_REACHED_TOTAL_CDYN_LSB 0x0000
#define MEM_ICCP_DEBUG2_MAX_REACHED_TOTAL_CDYN_MSB 0x000f
#define MEM_ICCP_DEBUG2_MAX_REACHED_TOTAL_CDYN_RANGE 0x0010
#define MEM_ICCP_DEBUG2_MAX_REACHED_TOTAL_CDYN_MASK 0x0000ffff
#define MEM_ICCP_DEBUG2_MAX_REACHED_TOTAL_CDYN_RESET_VALUE 0x00000000

#define MEM_ICCP_DEBUG2_RESERVED_LSB 0x0010
#define MEM_ICCP_DEBUG2_RESERVED_MSB 0x001f
#define MEM_ICCP_DEBUG2_RESERVED_RANGE 0x0010
#define MEM_ICCP_DEBUG2_RESERVED_MASK 0xffff0000
#define MEM_ICCP_DEBUG2_RESERVED_RESET_VALUE 0x00000000


// --------------------------------------------------------------------------------------------------------------------------------

// starting the array instantiation section
typedef struct {
    MEM_PMA_ICE_OVERRIDES_t    PMA_ICE_OVERRIDES; // offset 4'h0, width 32
    MEM_LATEST_POWER_REQUEST_t LATEST_POWER_REQUEST; // offset 4'h4, width 32
    MEM_OVERRIDE_SLICE_STATE_t OVERRIDE_SLICE_STATE; // offset 4'h8, width 32
    MEM_ICEBO_POWER_STATUS_t   ICEBO_POWER_STATUS; // offset 8'h0C, width 32
    MEM_ICEBO_FSM_STALL_t      ICEBO_FSM_STALL;  // offset 8'h10, width 32
    MEM_CLK_GATE_CTL_t         CLK_GATE_CTL;     // offset 8'h14, width 32
    MEM_DCF_CTL_t              DCF_CTL;          // offset 8'h18, width 32
    MEM_ICCP_CONFIG1_t         ICCP_CONFIG1;     // offset 8'h1C, width 32
    MEM_ICCP_CONFIG2_t         ICCP_CONFIG2;     // offset 8'h20, width 32
    MEM_ICCP_CONFIG3_t         ICCP_CONFIG3;     // offset 8'h24, width 32
    MEM_ICCP_MAX_CDYN_LEVEL_0_t ICCP_MAX_CDYN_LEVEL_0; // offset 8'h28, width 32
    MEM_ICCP_MAX_CDYN_LEVEL_1_t ICCP_MAX_CDYN_LEVEL_1; // offset 8'h2C, width 32
    MEM_ICCP_MAX_CDYN_LEVEL_2_t ICCP_MAX_CDYN_LEVEL_2; // offset 8'h30, width 32
    MEM_ICCP_MAX_CDYN_LEVEL_3_t ICCP_MAX_CDYN_LEVEL_3; // offset 8'h34, width 32
    MEM_ICCP_MAX_CDYN_LEVEL_4_t ICCP_MAX_CDYN_LEVEL_4; // offset 8'h38, width 32
    MEM_ICCP_MAX_CDYN_LEVEL_5_t ICCP_MAX_CDYN_LEVEL_5; // offset 8'h3C, width 32
    MEM_ICCP_MAX_CDYN_LEVEL_6_t ICCP_MAX_CDYN_LEVEL_6; // offset 8'h40, width 32
    MEM_ICCP_MAX_CDYN_LEVEL_7_t ICCP_MAX_CDYN_LEVEL_7; // offset 8'h44, width 32
    MEM_ICCP_MAX_CDYN_LEVEL_8_t ICCP_MAX_CDYN_LEVEL_8; // offset 8'h48, width 32
    MEM_ICCP_MAX_CDYN_LEVEL_9_t ICCP_MAX_CDYN_LEVEL_9; // offset 8'h4C, width 32
    MEM_ICCP_MAX_CDYN_LEVEL_10_t ICCP_MAX_CDYN_LEVEL_10; // offset 8'h50, width 32
    MEM_ICCP_MAX_CDYN_LEVEL_11_t ICCP_MAX_CDYN_LEVEL_11; // offset 8'h54, width 32
    MEM_ICCP_MAX_CDYN_LEVEL_12_t ICCP_MAX_CDYN_LEVEL_12; // offset 8'h58, width 32
    MEM_ICCP_MAX_CDYN_LEVEL_13_t ICCP_MAX_CDYN_LEVEL_13; // offset 8'h5C, width 32
    MEM_ICCP_MAX_CDYN_LEVEL_14_t ICCP_MAX_CDYN_LEVEL_14; // offset 8'h60, width 32
    MEM_ICCP_DEBUG1_t          ICCP_DEBUG1;      // offset 8'h64, width 32
    MEM_ICCP_DEBUG2_t          ICCP_DEBUG2;      // offset 8'h68, width 32
} gpsb_x1_regs_t;                                // size:  8'h6C


#endif // _GPSB_X1_REGS_REGS_H_

