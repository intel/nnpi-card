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
// File:            ice_obs_dtf_obs_enc_regs_regs.h                            
// Creator:         pvenkat3                                                   
// Time:            Thursday Jan 17, 2019 [2:24:44 pm]                         
//                                                                             
// Path:            /tmp/pvenkat3/nebulon_run/5180751807_2019-01-17.14:24:24   
// Arguments:       -input                                                     
//                  /nfs/site/disks/cdk_drop.7/icebo/icebo-18ww50-dropIt.1/source/icebo/rdl/ice_obs_regs.rdl
//                  -incdirs source/rdl//cve_cr_top_incdirs -chdr -out_dir ./  
//                                                                             
// MRE:             5.2018.2                                                   
// Machine:         icsl2875                                                   
// OS:              Linux 3.0.101-108.13.1.14249.0.PTF-default                 
// Nebulon version: d18ww24.4                                                  
// Description:                                                                
//                                                                             
// No Description Provided                                                     
//                                                                         


#ifndef _ICE_OBS_DTF_OBS_ENC_REGS_REGS_H_
#define _ICE_OBS_DTF_OBS_ENC_REGS_REGS_H_

#define ICE_OBS_ENC_REGS_ICE_OBS_DSO_DTF_OBS_MSG_REGS_MSGPORT     0x62
#define ICE_OBS_ENC_REGS_ICE_OBS_DSO_DTF_OBS_MSG_REGS_DSO_CFG_STATUS_REG_MSGREGADDR 0x10
#define ICE_OBS_ENC_REGS_ICE_OBS_DSO_DTF_OBS_MSG_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_MSGREGADDR 0x14
#define ICE_OBS_ENC_REGS_ICE_OBS_DSO_DTF_OBS_MSG_REGS_DSO_CFG_PTYPE_FILTER_CH0_REG_MSGREGADDR 0x18
#define ICE_OBS_ENC_REGS_ICE_OBS_DSO_DTF_OBS_MSG_REGS_DSO_FILTER_MATCH_LOW_CH0_REG_MSGREGADDR 0x1C
#define ICE_OBS_ENC_REGS_ICE_OBS_DSO_DTF_OBS_MSG_REGS_DSO_FILTER_MATCH_HIGH_CH0_REG_MSGREGADDR 0x20
#define ICE_OBS_ENC_REGS_ICE_OBS_DSO_DTF_OBS_MSG_REGS_DSO_FILTER_MASK_LOW_CH0_REG_MSGREGADDR 0x24
#define ICE_OBS_ENC_REGS_ICE_OBS_DSO_DTF_OBS_MSG_REGS_DSO_FILTER_MASK_HIGH_CH0_REG_MSGREGADDR 0x28
#define ICE_OBS_ENC_REGS_ICE_OBS_DSO_DTF_OBS_MSG_REGS_DSO_FILTER_INV_CH0_REG_MSGREGADDR 0x2C
#define ICE_OBS_ENC_REGS_ICE_OBS_DSO_DTF_OBS_MSG_REGS_DSO_CFG_PTYPE_FILTER_CH1_REG_MSGREGADDR 0x30
#define ICE_OBS_ENC_REGS_ICE_OBS_DSO_DTF_OBS_MSG_REGS_DSO_FILTER_MATCH_LOW_CH1_REG_MSGREGADDR 0x34
#define ICE_OBS_ENC_REGS_ICE_OBS_DSO_DTF_OBS_MSG_REGS_DSO_FILTER_MATCH_HIGH_CH1_REG_MSGREGADDR 0x38
#define ICE_OBS_ENC_REGS_ICE_OBS_DSO_DTF_OBS_MSG_REGS_DSO_FILTER_MASK_LOW_CH1_REG_MSGREGADDR 0x3C
#define ICE_OBS_ENC_REGS_ICE_OBS_DSO_DTF_OBS_MSG_REGS_DSO_FILTER_MASK_HIGH_CH1_REG_MSGREGADDR 0x40
#define ICE_OBS_ENC_REGS_ICE_OBS_DSO_DTF_OBS_MSG_REGS_DSO_FILTER_INV_CH1_REG_MSGREGADDR 0x44
#define ICE_OBS_ENC_REGS_ICE_OBS_PA_REGS_MSG_REGS_MSGPORT     0x62
#define ICE_OBS_ENC_REGS_ICE_OBS_PA_REGS_MSG_REGS_ICE_OBS_PA_CONFIG_REG_MSGREGADDR 0x0A0
#define ICE_OBS_ENC_REGS_ICE_OBS_PA_REGS_MSG_REGS_PSF_OBS_SAI_READ_POLICY_TYPE_MSGREGADDR 0x0E0
#define ICE_OBS_ENC_REGS_ICE_OBS_PA_REGS_MSG_REGS_PSF_OBS_SAI_WRITE_POLICY_TYPE_MSGREGADDR 0x0E8
#define ICE_OBS_ENC_REGS_ICE_OBS_PA_REGS_MSG_REGS_PSF_OBS_SAI_CONTROL_POLICY_TYPE_MSGREGADDR 0x0F0
#define ICE_OBS_ENC_REGS_ICE_OBS_DSO_DTF_OBS_MEM_REGS_BASE 0x0
#define ICE_OBS_ENC_REGS_ICE_OBS_DSO_DTF_OBS_MEM_REGS_DSO_CFG_STATUS_REG_MMOFFSET 0x10
#define ICE_OBS_ENC_REGS_ICE_OBS_DSO_DTF_OBS_MEM_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_MMOFFSET 0x14
#define ICE_OBS_ENC_REGS_ICE_OBS_DSO_DTF_OBS_MEM_REGS_DSO_CFG_PTYPE_FILTER_CH0_REG_MMOFFSET 0x18
#define ICE_OBS_ENC_REGS_ICE_OBS_DSO_DTF_OBS_MEM_REGS_DSO_FILTER_MATCH_LOW_CH0_REG_MMOFFSET 0x1C
#define ICE_OBS_ENC_REGS_ICE_OBS_DSO_DTF_OBS_MEM_REGS_DSO_FILTER_MATCH_HIGH_CH0_REG_MMOFFSET 0x20
#define ICE_OBS_ENC_REGS_ICE_OBS_DSO_DTF_OBS_MEM_REGS_DSO_FILTER_MASK_LOW_CH0_REG_MMOFFSET 0x24
#define ICE_OBS_ENC_REGS_ICE_OBS_DSO_DTF_OBS_MEM_REGS_DSO_FILTER_MASK_HIGH_CH0_REG_MMOFFSET 0x28
#define ICE_OBS_ENC_REGS_ICE_OBS_DSO_DTF_OBS_MEM_REGS_DSO_FILTER_INV_CH0_REG_MMOFFSET 0x2C
#define ICE_OBS_ENC_REGS_ICE_OBS_DSO_DTF_OBS_MEM_REGS_DSO_CFG_PTYPE_FILTER_CH1_REG_MMOFFSET 0x30
#define ICE_OBS_ENC_REGS_ICE_OBS_DSO_DTF_OBS_MEM_REGS_DSO_FILTER_MATCH_LOW_CH1_REG_MMOFFSET 0x34
#define ICE_OBS_ENC_REGS_ICE_OBS_DSO_DTF_OBS_MEM_REGS_DSO_FILTER_MATCH_HIGH_CH1_REG_MMOFFSET 0x38
#define ICE_OBS_ENC_REGS_ICE_OBS_DSO_DTF_OBS_MEM_REGS_DSO_FILTER_MASK_LOW_CH1_REG_MMOFFSET 0x3C
#define ICE_OBS_ENC_REGS_ICE_OBS_DSO_DTF_OBS_MEM_REGS_DSO_FILTER_MASK_HIGH_CH1_REG_MMOFFSET 0x40
#define ICE_OBS_ENC_REGS_ICE_OBS_DSO_DTF_OBS_MEM_REGS_DSO_FILTER_INV_CH1_REG_MMOFFSET 0x44
#define ICE_OBS_ENC_REGS_ICE_OBS_DSO_DTF_ENC_MSG_REGS_MSGPORT     0x62
#define ICE_OBS_ENC_REGS_ICE_OBS_DSO_DTF_ENC_MSG_REGS_DSO_DTF_ENCODER_CONFIG_REG_MSGREGADDR 0x4
#define ICE_OBS_ENC_REGS_ICE_OBS_DSO_DTF_ENC_MSG_REGS_DSO_DTF_ENCODER_STATUS_REG_MSGREGADDR 0x8
#define ICE_OBS_ENC_REGS_ICE_OBS_DSO_DTF_ENC_MEM_REGS_BASE 0x0
#define ICE_OBS_ENC_REGS_ICE_OBS_DSO_DTF_ENC_MEM_REGS_DSO_DTF_ENCODER_CONFIG_REG_MMOFFSET 0x4
#define ICE_OBS_ENC_REGS_ICE_OBS_DSO_DTF_ENC_MEM_REGS_DSO_DTF_ENCODER_STATUS_REG_MMOFFSET 0x8
#define ICE_OBS_ENC_REGS_ICE_OBS_PA_REGS_MEM_REGS_BASE 0x0
#define ICE_OBS_ENC_REGS_ICE_OBS_PA_REGS_MEM_REGS_ICE_OBS_PA_CONFIG_REG_MMOFFSET 0x0A0
#define ICE_OBS_ENC_REGS_ICE_OBS_PA_REGS_MEM_REGS_PSF_OBS_SAI_READ_POLICY_TYPE_MMOFFSET 0x0E0
#define ICE_OBS_ENC_REGS_ICE_OBS_PA_REGS_MEM_REGS_PSF_OBS_SAI_WRITE_POLICY_TYPE_MMOFFSET 0x0E8
#define ICE_OBS_ENC_REGS_ICE_OBS_PA_REGS_MEM_REGS_PSF_OBS_SAI_CONTROL_POLICY_TYPE_MMOFFSET 0x0F0

#ifndef ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_FLAG
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_FLAG
// DSO_CFG_STATUS_REG desc: 
typedef union {
    struct {
        uint32_t  MSTR_ID              :   8;    //  This bit specifies the Master
                                                 // ID sent to DTF encoder
        uint32_t  CH_ID                :   8;    //  This bit specifies the
                                                 // channel ID sent to DTF encoder
        uint32_t  QUAL_TRACE_ACTIVE    :   1;    //  Monitors QualTraceActive
                                                 // signal. QualTraceActive =
                                                 // ~BlockAndDrainReq &#38;
                                                 // DTFActive &#38; CfgTraceEnable
                                                 // &#38; TimeValidIndication
        uint32_t  BLOCK_AND_DRAIN_FSM  :   2;    //  Floped BlockAndDrainFsmNnnnH
                                                 // state. TRACE_STOPPED = 2'b00;
                                                 // TRACE_ACTIVE = 2'b01;
                                                 // STOP_TRACE = 2'b10;
                                                 // START_TRACE = 2'b11;
        uint32_t  GS_SOURCE_ACTIVE     :   1;    //  Monitors GSSourceActive
                                                 // signal. Indication that source
                                                 // and Observer Active
        uint32_t  GS_BLOCK_AND_DRAIN_ACK :   1;    //  Monitores GSBlockAndDrainAck
                                                 // signal. Acknowlege for power
                                                 // flows.
        uint32_t  GS_BLOCK_AND_DRAIN_REQ :   1;    //  Monitores GSBlockAndDrainReq
                                                 // signal. Request from Ip for
                                                 // power flows.
        uint32_t  EBLOCK_FROM_ANY_CH   :   1;    //  Monitors EBlockFromAnyCh
                                                 // signal from gs_flow_ctrl that
                                                 // indicates that at least one
                                                 // channel requested block
        uint32_t  DRAIN_DONE_FROM_ALL_CH :   1;    //  Monitors DrainDoneFromAllCh
                                                 // signal from gs_flow_ctrl that
                                                 // indicates that all channels
                                                 // drained their fifos
        uint32_t  CENTRAL_BLOCK_REQ    :   1;    //  Monitors CentralBlockReq
                                                 // signal from gs_flow_ctrl that
                                                 // indicates that flow_ctrl
                                                 // requested block from all
                                                 // channels
        uint32_t  TIME_VALID_INDICATION :   1;    //  Monitors TimeValidIndication,
                                                 // that means that Fast and Slow
                                                 // counters are valid or
                                                 // CfgTimeValidOvrd is set
        uint32_t  INORDER_ARB_BIDS_OUT :   2;    //  Monitors
                                                 // InOrderArbBidsOut[1:0] signal,
                                                 // which shows which channels
                                                 // sent bids to
                                                 // gs_logical_sniffer_rr_arb.
                                                 // InOrderArbBidsOut[0] - atomic
                                                 // channel , InOrderArbBidsOut[1]
                                                 // - data channel0
        uint32_t  INORDER_ARB_BIDS_OUT_VALID :   1;    //  Monitors
                                                 // InOrderArbBidsOutValid signal
                                                 // that indicates that there are
                                                 // valid bids in
                                                 // gs_logical_sniffer_rr_arb
        uint32_t  UPPER_LEVEL_ARB_FREEZ_REQ :   1;    //  Monitors
                                                 // UpperLevelArbFreezReqStg1,
                                                 // signal that connected to park
                                                 // port of
                                                 // gs_logical_sniffer_rr_arb
        uint32_t  LOGICAL_SNIFFER_RR_ARB_WIN :   2;    //  Monitors
                                                 // LogicalSnifferRRArbWin[1:0],
                                                 // LogicalSnifferRRArbWin[0] -
                                                 // atomic channel,
                                                 // LogicalSnifferRRArbWin[1] -
                                                 // data channel0

    }                                field;
    uint32_t                         val;
} ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_t;
#endif
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_OFFSET 0x10
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_SCOPE 0x01
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_SIZE 32
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_BITFIELD_COUNT 0x0f
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_RESET 0x00000000

#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_MSTR_ID_LSB 0x0000
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_MSTR_ID_MSB 0x0007
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_MSTR_ID_RANGE 0x0008
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_MSTR_ID_MASK 0x000000ff
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_MSTR_ID_RESET_VALUE 0x00000000

#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_CH_ID_LSB 0x0008
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_CH_ID_MSB 0x000f
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_CH_ID_RANGE 0x0008
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_CH_ID_MASK 0x0000ff00
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_CH_ID_RESET_VALUE 0x00000000

#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_QUAL_TRACE_ACTIVE_LSB 0x0010
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_QUAL_TRACE_ACTIVE_MSB 0x0010
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_QUAL_TRACE_ACTIVE_RANGE 0x0001
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_QUAL_TRACE_ACTIVE_MASK 0x00010000
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_QUAL_TRACE_ACTIVE_RESET_VALUE 0x00000000

#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_BLOCK_AND_DRAIN_FSM_LSB 0x0011
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_BLOCK_AND_DRAIN_FSM_MSB 0x0012
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_BLOCK_AND_DRAIN_FSM_RANGE 0x0002
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_BLOCK_AND_DRAIN_FSM_MASK 0x00060000
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_BLOCK_AND_DRAIN_FSM_RESET_VALUE 0x00000000

#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_GS_SOURCE_ACTIVE_LSB 0x0013
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_GS_SOURCE_ACTIVE_MSB 0x0013
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_GS_SOURCE_ACTIVE_RANGE 0x0001
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_GS_SOURCE_ACTIVE_MASK 0x00080000
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_GS_SOURCE_ACTIVE_RESET_VALUE 0x00000000

#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_GS_BLOCK_AND_DRAIN_ACK_LSB 0x0014
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_GS_BLOCK_AND_DRAIN_ACK_MSB 0x0014
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_GS_BLOCK_AND_DRAIN_ACK_RANGE 0x0001
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_GS_BLOCK_AND_DRAIN_ACK_MASK 0x00100000
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_GS_BLOCK_AND_DRAIN_ACK_RESET_VALUE 0x00000000

#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_GS_BLOCK_AND_DRAIN_REQ_LSB 0x0015
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_GS_BLOCK_AND_DRAIN_REQ_MSB 0x0015
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_GS_BLOCK_AND_DRAIN_REQ_RANGE 0x0001
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_GS_BLOCK_AND_DRAIN_REQ_MASK 0x00200000
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_GS_BLOCK_AND_DRAIN_REQ_RESET_VALUE 0x00000000

#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_EBLOCK_FROM_ANY_CH_LSB 0x0016
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_EBLOCK_FROM_ANY_CH_MSB 0x0016
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_EBLOCK_FROM_ANY_CH_RANGE 0x0001
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_EBLOCK_FROM_ANY_CH_MASK 0x00400000
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_EBLOCK_FROM_ANY_CH_RESET_VALUE 0x00000000

#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_DRAIN_DONE_FROM_ALL_CH_LSB 0x0017
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_DRAIN_DONE_FROM_ALL_CH_MSB 0x0017
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_DRAIN_DONE_FROM_ALL_CH_RANGE 0x0001
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_DRAIN_DONE_FROM_ALL_CH_MASK 0x00800000
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_DRAIN_DONE_FROM_ALL_CH_RESET_VALUE 0x00000000

#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_CENTRAL_BLOCK_REQ_LSB 0x0018
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_CENTRAL_BLOCK_REQ_MSB 0x0018
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_CENTRAL_BLOCK_REQ_RANGE 0x0001
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_CENTRAL_BLOCK_REQ_MASK 0x01000000
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_CENTRAL_BLOCK_REQ_RESET_VALUE 0x00000000

#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_TIME_VALID_INDICATION_LSB 0x0019
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_TIME_VALID_INDICATION_MSB 0x0019
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_TIME_VALID_INDICATION_RANGE 0x0001
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_TIME_VALID_INDICATION_MASK 0x02000000
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_TIME_VALID_INDICATION_RESET_VALUE 0x00000000

#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_INORDER_ARB_BIDS_OUT_LSB 0x001a
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_INORDER_ARB_BIDS_OUT_MSB 0x001b
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_INORDER_ARB_BIDS_OUT_RANGE 0x0002
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_INORDER_ARB_BIDS_OUT_MASK 0x0c000000
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_INORDER_ARB_BIDS_OUT_RESET_VALUE 0x00000000

#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_INORDER_ARB_BIDS_OUT_VALID_LSB 0x001c
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_INORDER_ARB_BIDS_OUT_VALID_MSB 0x001c
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_INORDER_ARB_BIDS_OUT_VALID_RANGE 0x0001
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_INORDER_ARB_BIDS_OUT_VALID_MASK 0x10000000
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_INORDER_ARB_BIDS_OUT_VALID_RESET_VALUE 0x00000000

#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_UPPER_LEVEL_ARB_FREEZ_REQ_LSB 0x001d
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_UPPER_LEVEL_ARB_FREEZ_REQ_MSB 0x001d
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_UPPER_LEVEL_ARB_FREEZ_REQ_RANGE 0x0001
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_UPPER_LEVEL_ARB_FREEZ_REQ_MASK 0x20000000
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_UPPER_LEVEL_ARB_FREEZ_REQ_RESET_VALUE 0x00000000

#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_LOGICAL_SNIFFER_RR_ARB_WIN_LSB 0x001e
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_LOGICAL_SNIFFER_RR_ARB_WIN_MSB 0x001f
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_LOGICAL_SNIFFER_RR_ARB_WIN_RANGE 0x0002
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_LOGICAL_SNIFFER_RR_ARB_WIN_MASK 0xc0000000
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_LOGICAL_SNIFFER_RR_ARB_WIN_RESET_VALUE 0x00000000


// --------------------------------------------------------------------------------------------------------------------------------

#ifndef ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_FLAG
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_FLAG
// DSO_CFG_DTF_SRC_CONFIG_REG desc: 
typedef union {
    struct {
        uint32_t  SRC_EN               :   1;    //  Enables the packetizer enable
        uint32_t  DST_ID               :   1;    //  This bit specifies which
                                                 // trace aggregator to use
        uint32_t  PWRDN_OVRD           :   1;    //  Power clock gating is ignored
                                                 // when 1, giving free-running
                                                 // clock.
        uint32_t  CROSS_CH_MATCH_EN    :   4;    //  Enabling cross channel match
                                                 // per channel. Lsb-ch0 MSB-ch3.
                                                 // Incase of cross channel match,
                                                 // CH0 should always be enabled
        uint32_t  CHANNEL_ENABLE       :   4;    //  Enbles the trace on specified
                                                 // channel. bit 8 - channel0. bit
                                                 // 9 - channel1. bit10 - channel
                                                 // 2. bit11 - channel 3
        uint32_t  PWR_FLOW_OVERIDE_CTRL :   1;    //  when set to 1'b1 disables,
                                                 // observer sends Ack to Ip
                                                 // imidiatly after reciving the
                                                 // Req
        uint32_t  TRIGGER_MARKER_PCKT_DISABLE :   1;    //  when set to 1'b1 disables
                                                 // insertion of trigger marker
                                                 // packet into trace
        uint32_t  TIME_VALID_OVRD      :   1;    //  when set to 1'b1 excludes
                                                 // TimeValid from SnifferActive
                                                 // equation
        uint32_t  DTFEncSyncIgnore     :   1;    //  when set to 1'b1 ignores
                                                 // DTFEncSync request
        uint32_t  DATA_CHUNK_DISABLE   :   4;    //  Disables some portions of
                                                 // data in parallel packetization
                                                 // and in serrial &#62; 64 bit
        uint32_t  STANDALONE_MODE_EN   :   1;    //  Enables storing with rotating
                                                 // buffer
        uint32_t  GVEvIgnore           :   1;    //  when set to 1'b1 ignores
                                                 // dtfso_gvev signal toggling
        uint32_t  RSVD_27_21           :   7;    //  RESERVED
        uint32_t  RSVD_28_28           :   1;    //  Bit 28 is used for
                                                 // enable/disable improved lta
                                                 // algo
        uint32_t  MIPI_CTRL            :   1;    //  Bit 29 when set to 1'b0
                                                 // forces D64 D64M types out of
                                                 // observer, regardless of
                                                 // dtfso_pa_data_size_chX
        uint32_t  DSO_VERSION          :   2;    //  0x0 = CNL A0 only; 0x1 = 10nm
                                                 // Server and client from CNL B0;
                                                 // 0x2 = for future use; 0x3 =
                                                 // for future use

    }                                field;
    uint32_t                         val;
} ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_t;
#endif
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_OFFSET 0x14
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_SCOPE 0x01
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_SIZE 32
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_BITFIELD_COUNT 0x10
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_RESET 0x40078780

#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_SRC_EN_LSB 0x0000
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_SRC_EN_MSB 0x0000
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_SRC_EN_RANGE 0x0001
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_SRC_EN_MASK 0x00000001
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_SRC_EN_RESET_VALUE 0x00000000

#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_DST_ID_LSB 0x0001
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_DST_ID_MSB 0x0001
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_DST_ID_RANGE 0x0001
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_DST_ID_MASK 0x00000002
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_DST_ID_RESET_VALUE 0x00000000

#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_PWRDN_OVRD_LSB 0x0002
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_PWRDN_OVRD_MSB 0x0002
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_PWRDN_OVRD_RANGE 0x0001
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_PWRDN_OVRD_MASK 0x00000004
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_PWRDN_OVRD_RESET_VALUE 0x00000000

#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_CROSS_CH_MATCH_EN_LSB 0x0003
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_CROSS_CH_MATCH_EN_MSB 0x0006
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_CROSS_CH_MATCH_EN_RANGE 0x0004
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_CROSS_CH_MATCH_EN_MASK 0x00000078
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_CROSS_CH_MATCH_EN_RESET_VALUE 0x00000000

#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_CHANNEL_ENABLE_LSB 0x0007
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_CHANNEL_ENABLE_MSB 0x000a
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_CHANNEL_ENABLE_RANGE 0x0004
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_CHANNEL_ENABLE_MASK 0x00000780
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_CHANNEL_ENABLE_RESET_VALUE 0x0000000f

#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_PWR_FLOW_OVERIDE_CTRL_LSB 0x000b
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_PWR_FLOW_OVERIDE_CTRL_MSB 0x000b
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_PWR_FLOW_OVERIDE_CTRL_RANGE 0x0001
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_PWR_FLOW_OVERIDE_CTRL_MASK 0x00000800
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_PWR_FLOW_OVERIDE_CTRL_RESET_VALUE 0x00000000

#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_TRIGGER_MARKER_PCKT_DISABLE_LSB 0x000c
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_TRIGGER_MARKER_PCKT_DISABLE_MSB 0x000c
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_TRIGGER_MARKER_PCKT_DISABLE_RANGE 0x0001
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_TRIGGER_MARKER_PCKT_DISABLE_MASK 0x00001000
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_TRIGGER_MARKER_PCKT_DISABLE_RESET_VALUE 0x00000000

#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_TIME_VALID_OVRD_LSB 0x000d
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_TIME_VALID_OVRD_MSB 0x000d
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_TIME_VALID_OVRD_RANGE 0x0001
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_TIME_VALID_OVRD_MASK 0x00002000
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_TIME_VALID_OVRD_RESET_VALUE 0x00000000

#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_DTFENCSYNCIGNORE_LSB 0x000e
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_DTFENCSYNCIGNORE_MSB 0x000e
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_DTFENCSYNCIGNORE_RANGE 0x0001
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_DTFENCSYNCIGNORE_MASK 0x00004000
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_DTFENCSYNCIGNORE_RESET_VALUE 0x00000000

#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_DATA_CHUNK_DISABLE_LSB 0x000f
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_DATA_CHUNK_DISABLE_MSB 0x0012
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_DATA_CHUNK_DISABLE_RANGE 0x0004
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_DATA_CHUNK_DISABLE_MASK 0x00078000
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_DATA_CHUNK_DISABLE_RESET_VALUE 0x0000000f

#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_STANDALONE_MODE_EN_LSB 0x0013
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_STANDALONE_MODE_EN_MSB 0x0013
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_STANDALONE_MODE_EN_RANGE 0x0001
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_STANDALONE_MODE_EN_MASK 0x00080000
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_STANDALONE_MODE_EN_RESET_VALUE 0x00000000

#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_GVEVIGNORE_LSB 0x0014
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_GVEVIGNORE_MSB 0x0014
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_GVEVIGNORE_RANGE 0x0001
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_GVEVIGNORE_MASK 0x00100000
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_GVEVIGNORE_RESET_VALUE 0x00000000

#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_RSVD_27_21_LSB 0x0015
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_RSVD_27_21_MSB 0x001b
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_RSVD_27_21_RANGE 0x0007
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_RSVD_27_21_MASK 0x0fe00000
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_RSVD_27_21_RESET_VALUE 0x00000000

#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_RSVD_28_28_LSB 0x001c
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_RSVD_28_28_MSB 0x001c
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_RSVD_28_28_RANGE 0x0001
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_RSVD_28_28_MASK 0x10000000
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_RSVD_28_28_RESET_VALUE 0x00000000

#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_MIPI_CTRL_LSB 0x001d
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_MIPI_CTRL_MSB 0x001d
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_MIPI_CTRL_RANGE 0x0001
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_MIPI_CTRL_MASK 0x20000000
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_MIPI_CTRL_RESET_VALUE 0x00000000

#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_DSO_VERSION_LSB 0x001e
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_DSO_VERSION_MSB 0x001f
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_DSO_VERSION_RANGE 0x0002
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_DSO_VERSION_MASK 0xc0000000
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_DSO_VERSION_RESET_VALUE 0x00000001


// --------------------------------------------------------------------------------------------------------------------------------

#ifndef ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_PTYPE_FILTER_CH0_REG_FLAG
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_PTYPE_FILTER_CH0_REG_FLAG
// DSO_CFG_PTYPE_FILTER_CH0_REG desc: 
typedef union {
    struct {
        uint32_t  DSO_CFG_PTYPE_FILTER_CH0 :  32;    //  Bit vector for all 32
                                                 // possible payload types. Bit 0
                                                 // corrsponds to ptype of 0, etc.
                                                 // Setting of 1'b0 will filter
                                                 // the particular ptype out of
                                                 // trace

    }                                field;
    uint32_t                         val;
} ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_PTYPE_FILTER_CH0_REG_t;
#endif
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_PTYPE_FILTER_CH0_REG_OFFSET 0x18
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_PTYPE_FILTER_CH0_REG_SCOPE 0x01
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_PTYPE_FILTER_CH0_REG_SIZE 32
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_PTYPE_FILTER_CH0_REG_BITFIELD_COUNT 0x01
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_PTYPE_FILTER_CH0_REG_RESET 0x00000000

#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_PTYPE_FILTER_CH0_REG_DSO_CFG_PTYPE_FILTER_CH0_LSB 0x0000
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_PTYPE_FILTER_CH0_REG_DSO_CFG_PTYPE_FILTER_CH0_MSB 0x001f
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_PTYPE_FILTER_CH0_REG_DSO_CFG_PTYPE_FILTER_CH0_RANGE 0x0020
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_PTYPE_FILTER_CH0_REG_DSO_CFG_PTYPE_FILTER_CH0_MASK 0xffffffff
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_PTYPE_FILTER_CH0_REG_DSO_CFG_PTYPE_FILTER_CH0_RESET_VALUE 0x00000000


// --------------------------------------------------------------------------------------------------------------------------------

#ifndef ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MATCH_LOW_CH0_REG_FLAG
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MATCH_LOW_CH0_REG_FLAG
// DSO_FILTER_MATCH_LOW_CH0_REG desc: 
typedef union {
    struct {
        uint32_t  DSO_FILTER_MATCH_LOW_CH0 :  32;    //  Configures GSniffer's bits to
                                                 // be matched

    }                                field;
    uint32_t                         val;
} ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MATCH_LOW_CH0_REG_t;
#endif
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MATCH_LOW_CH0_REG_OFFSET 0x1c
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MATCH_LOW_CH0_REG_SCOPE 0x01
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MATCH_LOW_CH0_REG_SIZE 32
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MATCH_LOW_CH0_REG_BITFIELD_COUNT 0x01
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MATCH_LOW_CH0_REG_RESET 0x00000000

#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MATCH_LOW_CH0_REG_DSO_FILTER_MATCH_LOW_CH0_LSB 0x0000
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MATCH_LOW_CH0_REG_DSO_FILTER_MATCH_LOW_CH0_MSB 0x001f
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MATCH_LOW_CH0_REG_DSO_FILTER_MATCH_LOW_CH0_RANGE 0x0020
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MATCH_LOW_CH0_REG_DSO_FILTER_MATCH_LOW_CH0_MASK 0xffffffff
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MATCH_LOW_CH0_REG_DSO_FILTER_MATCH_LOW_CH0_RESET_VALUE 0x00000000


// --------------------------------------------------------------------------------------------------------------------------------

#ifndef ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MATCH_HIGH_CH0_REG_FLAG
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MATCH_HIGH_CH0_REG_FLAG
// DSO_FILTER_MATCH_HIGH_CH0_REG desc: 
typedef union {
    struct {
        uint32_t  DSO_FILTER_MATCH_HIGH_CH0 :  32;    //  Configures GSniffer's bits to
                                                 // be matched

    }                                field;
    uint32_t                         val;
} ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MATCH_HIGH_CH0_REG_t;
#endif
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MATCH_HIGH_CH0_REG_OFFSET 0x20
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MATCH_HIGH_CH0_REG_SCOPE 0x01
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MATCH_HIGH_CH0_REG_SIZE 32
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MATCH_HIGH_CH0_REG_BITFIELD_COUNT 0x01
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MATCH_HIGH_CH0_REG_RESET 0x00000000

#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MATCH_HIGH_CH0_REG_DSO_FILTER_MATCH_HIGH_CH0_LSB 0x0000
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MATCH_HIGH_CH0_REG_DSO_FILTER_MATCH_HIGH_CH0_MSB 0x001f
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MATCH_HIGH_CH0_REG_DSO_FILTER_MATCH_HIGH_CH0_RANGE 0x0020
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MATCH_HIGH_CH0_REG_DSO_FILTER_MATCH_HIGH_CH0_MASK 0xffffffff
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MATCH_HIGH_CH0_REG_DSO_FILTER_MATCH_HIGH_CH0_RESET_VALUE 0x00000000


// --------------------------------------------------------------------------------------------------------------------------------

#ifndef ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MASK_LOW_CH0_REG_FLAG
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MASK_LOW_CH0_REG_FLAG
// DSO_FILTER_MASK_LOW_CH0_REG desc: 
typedef union {
    struct {
        uint32_t  DSO_FILTER_MASK_LOW_CH0 :  32;    //  Configures GSniffer's bits to
                                                 // be don't care

    }                                field;
    uint32_t                         val;
} ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MASK_LOW_CH0_REG_t;
#endif
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MASK_LOW_CH0_REG_OFFSET 0x24
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MASK_LOW_CH0_REG_SCOPE 0x01
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MASK_LOW_CH0_REG_SIZE 32
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MASK_LOW_CH0_REG_BITFIELD_COUNT 0x01
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MASK_LOW_CH0_REG_RESET 0x00000000

#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MASK_LOW_CH0_REG_DSO_FILTER_MASK_LOW_CH0_LSB 0x0000
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MASK_LOW_CH0_REG_DSO_FILTER_MASK_LOW_CH0_MSB 0x001f
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MASK_LOW_CH0_REG_DSO_FILTER_MASK_LOW_CH0_RANGE 0x0020
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MASK_LOW_CH0_REG_DSO_FILTER_MASK_LOW_CH0_MASK 0xffffffff
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MASK_LOW_CH0_REG_DSO_FILTER_MASK_LOW_CH0_RESET_VALUE 0x00000000


// --------------------------------------------------------------------------------------------------------------------------------

#ifndef ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MASK_HIGH_CH0_REG_FLAG
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MASK_HIGH_CH0_REG_FLAG
// DSO_FILTER_MASK_HIGH_CH0_REG desc: 
typedef union {
    struct {
        uint32_t  DSO_FILTER_MASK_HIGH_CH0 :  32;    //  Configures GSniffer's bits to
                                                 // be don't care

    }                                field;
    uint32_t                         val;
} ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MASK_HIGH_CH0_REG_t;
#endif
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MASK_HIGH_CH0_REG_OFFSET 0x28
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MASK_HIGH_CH0_REG_SCOPE 0x01
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MASK_HIGH_CH0_REG_SIZE 32
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MASK_HIGH_CH0_REG_BITFIELD_COUNT 0x01
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MASK_HIGH_CH0_REG_RESET 0x00000000

#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MASK_HIGH_CH0_REG_DSO_FILTER_MASK_HIGH_CH0_LSB 0x0000
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MASK_HIGH_CH0_REG_DSO_FILTER_MASK_HIGH_CH0_MSB 0x001f
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MASK_HIGH_CH0_REG_DSO_FILTER_MASK_HIGH_CH0_RANGE 0x0020
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MASK_HIGH_CH0_REG_DSO_FILTER_MASK_HIGH_CH0_MASK 0xffffffff
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MASK_HIGH_CH0_REG_DSO_FILTER_MASK_HIGH_CH0_RESET_VALUE 0x00000000


// --------------------------------------------------------------------------------------------------------------------------------

#ifndef ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_INV_CH0_REG_FLAG
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_INV_CH0_REG_FLAG
// DSO_FILTER_INV_CH0_REG desc: 
typedef union {
    struct {
        uint32_t  DSO_FILTER_INV_CH0   :  32;    //  Describes how to handled
                                                 // matched data, filter it out or
                                                 // pass it through

    }                                field;
    uint32_t                         val;
} ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_INV_CH0_REG_t;
#endif
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_INV_CH0_REG_OFFSET 0x2c
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_INV_CH0_REG_SCOPE 0x01
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_INV_CH0_REG_SIZE 32
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_INV_CH0_REG_BITFIELD_COUNT 0x01
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_INV_CH0_REG_RESET 0x00000000

#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_INV_CH0_REG_DSO_FILTER_INV_CH0_LSB 0x0000
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_INV_CH0_REG_DSO_FILTER_INV_CH0_MSB 0x001f
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_INV_CH0_REG_DSO_FILTER_INV_CH0_RANGE 0x0020
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_INV_CH0_REG_DSO_FILTER_INV_CH0_MASK 0xffffffff
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_INV_CH0_REG_DSO_FILTER_INV_CH0_RESET_VALUE 0x00000000


// --------------------------------------------------------------------------------------------------------------------------------

#ifndef ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_PTYPE_FILTER_CH1_REG_FLAG
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_PTYPE_FILTER_CH1_REG_FLAG
// DSO_CFG_PTYPE_FILTER_CH1_REG desc: 
typedef union {
    struct {
        uint32_t  DSO_CFG_PTYPE_FILTER_CH1 :  32;    //  Bit vector for all 32
                                                 // possible payload types. Bit 0
                                                 // corrsponds to ptype of 0, etc.
                                                 // Setting of 1'b0 will filter
                                                 // the particular ptype out of
                                                 // trace

    }                                field;
    uint32_t                         val;
} ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_PTYPE_FILTER_CH1_REG_t;
#endif
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_PTYPE_FILTER_CH1_REG_OFFSET 0x30
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_PTYPE_FILTER_CH1_REG_SCOPE 0x01
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_PTYPE_FILTER_CH1_REG_SIZE 32
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_PTYPE_FILTER_CH1_REG_BITFIELD_COUNT 0x01
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_PTYPE_FILTER_CH1_REG_RESET 0x00000000

#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_PTYPE_FILTER_CH1_REG_DSO_CFG_PTYPE_FILTER_CH1_LSB 0x0000
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_PTYPE_FILTER_CH1_REG_DSO_CFG_PTYPE_FILTER_CH1_MSB 0x001f
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_PTYPE_FILTER_CH1_REG_DSO_CFG_PTYPE_FILTER_CH1_RANGE 0x0020
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_PTYPE_FILTER_CH1_REG_DSO_CFG_PTYPE_FILTER_CH1_MASK 0xffffffff
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_PTYPE_FILTER_CH1_REG_DSO_CFG_PTYPE_FILTER_CH1_RESET_VALUE 0x00000000


// --------------------------------------------------------------------------------------------------------------------------------

#ifndef ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MATCH_LOW_CH1_REG_FLAG
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MATCH_LOW_CH1_REG_FLAG
// DSO_FILTER_MATCH_LOW_CH1_REG desc: 
typedef union {
    struct {
        uint32_t  DSO_FILTER_MATCH_LOW_CH1 :  32;    //  Configures GSniffer's bits to
                                                 // be matched

    }                                field;
    uint32_t                         val;
} ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MATCH_LOW_CH1_REG_t;
#endif
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MATCH_LOW_CH1_REG_OFFSET 0x34
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MATCH_LOW_CH1_REG_SCOPE 0x01
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MATCH_LOW_CH1_REG_SIZE 32
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MATCH_LOW_CH1_REG_BITFIELD_COUNT 0x01
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MATCH_LOW_CH1_REG_RESET 0x00000000

#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MATCH_LOW_CH1_REG_DSO_FILTER_MATCH_LOW_CH1_LSB 0x0000
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MATCH_LOW_CH1_REG_DSO_FILTER_MATCH_LOW_CH1_MSB 0x001f
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MATCH_LOW_CH1_REG_DSO_FILTER_MATCH_LOW_CH1_RANGE 0x0020
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MATCH_LOW_CH1_REG_DSO_FILTER_MATCH_LOW_CH1_MASK 0xffffffff
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MATCH_LOW_CH1_REG_DSO_FILTER_MATCH_LOW_CH1_RESET_VALUE 0x00000000


// --------------------------------------------------------------------------------------------------------------------------------

#ifndef ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MATCH_HIGH_CH1_REG_FLAG
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MATCH_HIGH_CH1_REG_FLAG
// DSO_FILTER_MATCH_HIGH_CH1_REG desc: 
typedef union {
    struct {
        uint32_t  DSO_FILTER_MATCH_HIGH_CH1 :  32;    //  Configures GSniffer's bits to
                                                 // be matched

    }                                field;
    uint32_t                         val;
} ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MATCH_HIGH_CH1_REG_t;
#endif
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MATCH_HIGH_CH1_REG_OFFSET 0x38
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MATCH_HIGH_CH1_REG_SCOPE 0x01
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MATCH_HIGH_CH1_REG_SIZE 32
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MATCH_HIGH_CH1_REG_BITFIELD_COUNT 0x01
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MATCH_HIGH_CH1_REG_RESET 0x00000000

#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MATCH_HIGH_CH1_REG_DSO_FILTER_MATCH_HIGH_CH1_LSB 0x0000
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MATCH_HIGH_CH1_REG_DSO_FILTER_MATCH_HIGH_CH1_MSB 0x001f
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MATCH_HIGH_CH1_REG_DSO_FILTER_MATCH_HIGH_CH1_RANGE 0x0020
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MATCH_HIGH_CH1_REG_DSO_FILTER_MATCH_HIGH_CH1_MASK 0xffffffff
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MATCH_HIGH_CH1_REG_DSO_FILTER_MATCH_HIGH_CH1_RESET_VALUE 0x00000000


// --------------------------------------------------------------------------------------------------------------------------------

#ifndef ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MASK_LOW_CH1_REG_FLAG
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MASK_LOW_CH1_REG_FLAG
// DSO_FILTER_MASK_LOW_CH1_REG desc: 
typedef union {
    struct {
        uint32_t  DSO_FILTER_MASK_LOW_CH1 :  32;    //  Configures GSniffer's bits to
                                                 // be don't care

    }                                field;
    uint32_t                         val;
} ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MASK_LOW_CH1_REG_t;
#endif
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MASK_LOW_CH1_REG_OFFSET 0x3c
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MASK_LOW_CH1_REG_SCOPE 0x01
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MASK_LOW_CH1_REG_SIZE 32
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MASK_LOW_CH1_REG_BITFIELD_COUNT 0x01
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MASK_LOW_CH1_REG_RESET 0x00000000

#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MASK_LOW_CH1_REG_DSO_FILTER_MASK_LOW_CH1_LSB 0x0000
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MASK_LOW_CH1_REG_DSO_FILTER_MASK_LOW_CH1_MSB 0x001f
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MASK_LOW_CH1_REG_DSO_FILTER_MASK_LOW_CH1_RANGE 0x0020
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MASK_LOW_CH1_REG_DSO_FILTER_MASK_LOW_CH1_MASK 0xffffffff
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MASK_LOW_CH1_REG_DSO_FILTER_MASK_LOW_CH1_RESET_VALUE 0x00000000


// --------------------------------------------------------------------------------------------------------------------------------

#ifndef ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MASK_HIGH_CH1_REG_FLAG
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MASK_HIGH_CH1_REG_FLAG
// DSO_FILTER_MASK_HIGH_CH1_REG desc: 
typedef union {
    struct {
        uint32_t  DSO_FILTER_MASK_HIGH_CH1 :  32;    //  Configures GSniffer's bits to
                                                 // be don't care

    }                                field;
    uint32_t                         val;
} ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MASK_HIGH_CH1_REG_t;
#endif
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MASK_HIGH_CH1_REG_OFFSET 0x40
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MASK_HIGH_CH1_REG_SCOPE 0x01
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MASK_HIGH_CH1_REG_SIZE 32
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MASK_HIGH_CH1_REG_BITFIELD_COUNT 0x01
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MASK_HIGH_CH1_REG_RESET 0x00000000

#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MASK_HIGH_CH1_REG_DSO_FILTER_MASK_HIGH_CH1_LSB 0x0000
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MASK_HIGH_CH1_REG_DSO_FILTER_MASK_HIGH_CH1_MSB 0x001f
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MASK_HIGH_CH1_REG_DSO_FILTER_MASK_HIGH_CH1_RANGE 0x0020
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MASK_HIGH_CH1_REG_DSO_FILTER_MASK_HIGH_CH1_MASK 0xffffffff
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MASK_HIGH_CH1_REG_DSO_FILTER_MASK_HIGH_CH1_RESET_VALUE 0x00000000


// --------------------------------------------------------------------------------------------------------------------------------

#ifndef ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_INV_CH1_REG_FLAG
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_INV_CH1_REG_FLAG
// DSO_FILTER_INV_CH1_REG desc: 
typedef union {
    struct {
        uint32_t  DSO_FILTER_INV_CH1   :  32;    //  Describes how to handled
                                                 // matched data, filter it out or
                                                 // pass it through

    }                                field;
    uint32_t                         val;
} ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_INV_CH1_REG_t;
#endif
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_INV_CH1_REG_OFFSET 0x44
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_INV_CH1_REG_SCOPE 0x01
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_INV_CH1_REG_SIZE 32
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_INV_CH1_REG_BITFIELD_COUNT 0x01
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_INV_CH1_REG_RESET 0x00000000

#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_INV_CH1_REG_DSO_FILTER_INV_CH1_LSB 0x0000
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_INV_CH1_REG_DSO_FILTER_INV_CH1_MSB 0x001f
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_INV_CH1_REG_DSO_FILTER_INV_CH1_RANGE 0x0020
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_INV_CH1_REG_DSO_FILTER_INV_CH1_MASK 0xffffffff
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_INV_CH1_REG_DSO_FILTER_INV_CH1_RESET_VALUE 0x00000000


// --------------------------------------------------------------------------------------------------------------------------------

#ifndef ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_CONFIG_REG_FLAG
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_CONFIG_REG_FLAG
// DSO_DTF_ENCODER_CONFIG_REG desc:  ENCODER CONFIG
typedef union {
    struct {
        uint32_t  CRDT_CTRL            :   1;    //  0 = normal run mode; 1 =
                                                 // ignore credits
        uint32_t  EOF_CTRL             :   1;    //  0 = normal run mode; 1 =
                                                 // always high
        uint32_t  PATGEN_CTRL          :   1;    //  0 = not enable; 1 = enabled
        uint32_t  PATGEN_MODE          :   3;    //  0: 0x0 1:
                                                 // 0xFFFFFFFFFFFFFFFF 2:
                                                 // 0xAAAAAAAAAAAAAAAA 3: 64b LTA
                                                 // (0x0 if LTA not present) 4:
                                                 // toggle 0x0 -
                                                 // 0xFFFFFFFFFFFFFFFF 5: toggle
                                                 // 0xAA55AA55AA55AA55 -
                                                 // 0x55AA55AA55AA55AA 6: counter
                                                 // (16b, wrapping, upper 48b set
                                                 // to zero) 7: Walking 1 (order
                                                 // low bit to high bit)
        uint32_t  PATGEN_DEST          :   1;    //  0 = normal destination; 1 =
                                                 // secondery destination
        uint32_t  RSVD_31_6            :  25;    //  RESERVED

    }                                field;
    uint32_t                         val;
} ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_CONFIG_REG_t;
#endif
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_CONFIG_REG_OFFSET 0x04
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_CONFIG_REG_SCOPE 0x01
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_CONFIG_REG_SIZE 32
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_CONFIG_REG_BITFIELD_COUNT 0x06
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_CONFIG_REG_RESET 0x00000000

#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_CONFIG_REG_CRDT_CTRL_LSB 0x0000
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_CONFIG_REG_CRDT_CTRL_MSB 0x0000
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_CONFIG_REG_CRDT_CTRL_RANGE 0x0001
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_CONFIG_REG_CRDT_CTRL_MASK 0x00000001
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_CONFIG_REG_CRDT_CTRL_RESET_VALUE 0x00000000

#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_CONFIG_REG_EOF_CTRL_LSB 0x0001
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_CONFIG_REG_EOF_CTRL_MSB 0x0001
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_CONFIG_REG_EOF_CTRL_RANGE 0x0001
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_CONFIG_REG_EOF_CTRL_MASK 0x00000002
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_CONFIG_REG_EOF_CTRL_RESET_VALUE 0x00000000

#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_CONFIG_REG_PATGEN_CTRL_LSB 0x0002
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_CONFIG_REG_PATGEN_CTRL_MSB 0x0002
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_CONFIG_REG_PATGEN_CTRL_RANGE 0x0001
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_CONFIG_REG_PATGEN_CTRL_MASK 0x00000004
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_CONFIG_REG_PATGEN_CTRL_RESET_VALUE 0x00000000

#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_CONFIG_REG_PATGEN_MODE_LSB 0x0003
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_CONFIG_REG_PATGEN_MODE_MSB 0x0005
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_CONFIG_REG_PATGEN_MODE_RANGE 0x0003
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_CONFIG_REG_PATGEN_MODE_MASK 0x00000038
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_CONFIG_REG_PATGEN_MODE_RESET_VALUE 0x00000000

#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_CONFIG_REG_PATGEN_DEST_LSB 0x0006
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_CONFIG_REG_PATGEN_DEST_MSB 0x0006
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_CONFIG_REG_PATGEN_DEST_RANGE 0x0001
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_CONFIG_REG_PATGEN_DEST_MASK 0x00000040
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_CONFIG_REG_PATGEN_DEST_RESET_VALUE 0x00000000

#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_CONFIG_REG_RSVD_31_6_LSB 0x0007
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_CONFIG_REG_RSVD_31_6_MSB 0x001f
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_CONFIG_REG_RSVD_31_6_RANGE 0x0019
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_CONFIG_REG_RSVD_31_6_MASK 0xffffff80
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_CONFIG_REG_RSVD_31_6_RESET_VALUE 0x00000000


// --------------------------------------------------------------------------------------------------------------------------------

#ifndef ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_STATUS_REG_FLAG
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_STATUS_REG_FLAG
// DSO_DTF_ENCODER_STATUS_REG desc:  ENCODER STATUS
typedef union {
    struct {
        uint32_t  credit_ok            :   1;    //  credit_ok signal can send ds
                                                 // data
        uint32_t  txid_uci             :   1;    //  txid signal
        uint32_t  eof                  :   1;    //  eof signal
        uint32_t  fifo_rd_int          :   1;    //  fifo_rd_int signal
        uint32_t  fifo_wr_int          :   1;    //  fifo_wr_int signal
        uint32_t  ts                   :   1;    //  ts signal
        uint32_t  fifo_valid           :   1;    //  fifo_valid signal
        uint32_t  drain                :   1;    //  drain signal
        uint32_t  dtfe_upstream_credit :   1;    //  dtfe_upstream_credit signal
        uint32_t  D_FIFO_s             :   1;    //  D_FIFO_s signal
        uint32_t  valid_cnt            :   3;    //  valid_cnt signal
        uint32_t  cnt_valid_out        :   3;    //  cnt_valid_out signal
                                                 // cnt_valid_out contain the
                                                 // number of transfers to send
                                                 // when it 4 or more there is
                                                 // enougth data to transmit.
        uint32_t  RSVD_31_16           :  16;    //  RESERVED

    }                                field;
    uint32_t                         val;
} ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_STATUS_REG_t;
#endif
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_STATUS_REG_OFFSET 0x08
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_STATUS_REG_SCOPE 0x01
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_STATUS_REG_SIZE 32
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_STATUS_REG_BITFIELD_COUNT 0x0d
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_STATUS_REG_RESET 0x00000000

#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_STATUS_REG_CREDIT_OK_LSB 0x0000
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_STATUS_REG_CREDIT_OK_MSB 0x0000
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_STATUS_REG_CREDIT_OK_RANGE 0x0001
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_STATUS_REG_CREDIT_OK_MASK 0x00000001
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_STATUS_REG_CREDIT_OK_RESET_VALUE 0x00000000

#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_STATUS_REG_TXID_UCI_LSB 0x0001
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_STATUS_REG_TXID_UCI_MSB 0x0001
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_STATUS_REG_TXID_UCI_RANGE 0x0001
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_STATUS_REG_TXID_UCI_MASK 0x00000002
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_STATUS_REG_TXID_UCI_RESET_VALUE 0x00000000

#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_STATUS_REG_EOF_LSB 0x0002
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_STATUS_REG_EOF_MSB 0x0002
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_STATUS_REG_EOF_RANGE 0x0001
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_STATUS_REG_EOF_MASK 0x00000004
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_STATUS_REG_EOF_RESET_VALUE 0x00000000

#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_STATUS_REG_FIFO_RD_INT_LSB 0x0003
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_STATUS_REG_FIFO_RD_INT_MSB 0x0003
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_STATUS_REG_FIFO_RD_INT_RANGE 0x0001
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_STATUS_REG_FIFO_RD_INT_MASK 0x00000008
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_STATUS_REG_FIFO_RD_INT_RESET_VALUE 0x00000000

#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_STATUS_REG_FIFO_WR_INT_LSB 0x0004
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_STATUS_REG_FIFO_WR_INT_MSB 0x0004
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_STATUS_REG_FIFO_WR_INT_RANGE 0x0001
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_STATUS_REG_FIFO_WR_INT_MASK 0x00000010
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_STATUS_REG_FIFO_WR_INT_RESET_VALUE 0x00000000

#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_STATUS_REG_TS_LSB 0x0005
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_STATUS_REG_TS_MSB 0x0005
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_STATUS_REG_TS_RANGE 0x0001
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_STATUS_REG_TS_MASK 0x00000020
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_STATUS_REG_TS_RESET_VALUE 0x00000000

#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_STATUS_REG_FIFO_VALID_LSB 0x0006
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_STATUS_REG_FIFO_VALID_MSB 0x0006
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_STATUS_REG_FIFO_VALID_RANGE 0x0001
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_STATUS_REG_FIFO_VALID_MASK 0x00000040
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_STATUS_REG_FIFO_VALID_RESET_VALUE 0x00000000

#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_STATUS_REG_DRAIN_LSB 0x0007
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_STATUS_REG_DRAIN_MSB 0x0007
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_STATUS_REG_DRAIN_RANGE 0x0001
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_STATUS_REG_DRAIN_MASK 0x00000080
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_STATUS_REG_DRAIN_RESET_VALUE 0x00000000

#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_STATUS_REG_DTFE_UPSTREAM_CREDIT_LSB 0x0008
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_STATUS_REG_DTFE_UPSTREAM_CREDIT_MSB 0x0008
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_STATUS_REG_DTFE_UPSTREAM_CREDIT_RANGE 0x0001
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_STATUS_REG_DTFE_UPSTREAM_CREDIT_MASK 0x00000100
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_STATUS_REG_DTFE_UPSTREAM_CREDIT_RESET_VALUE 0x00000000

#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_STATUS_REG_D_FIFO_S_LSB 0x0009
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_STATUS_REG_D_FIFO_S_MSB 0x0009
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_STATUS_REG_D_FIFO_S_RANGE 0x0001
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_STATUS_REG_D_FIFO_S_MASK 0x00000200
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_STATUS_REG_D_FIFO_S_RESET_VALUE 0x00000000

#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_STATUS_REG_VALID_CNT_LSB 0x000a
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_STATUS_REG_VALID_CNT_MSB 0x000c
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_STATUS_REG_VALID_CNT_RANGE 0x0003
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_STATUS_REG_VALID_CNT_MASK 0x00001c00
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_STATUS_REG_VALID_CNT_RESET_VALUE 0x00000000

#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_STATUS_REG_CNT_VALID_OUT_LSB 0x000d
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_STATUS_REG_CNT_VALID_OUT_MSB 0x000f
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_STATUS_REG_CNT_VALID_OUT_RANGE 0x0003
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_STATUS_REG_CNT_VALID_OUT_MASK 0x0000e000
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_STATUS_REG_CNT_VALID_OUT_RESET_VALUE 0x00000000

#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_STATUS_REG_RSVD_31_16_LSB 0x0010
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_STATUS_REG_RSVD_31_16_MSB 0x001f
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_STATUS_REG_RSVD_31_16_RANGE 0x0010
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_STATUS_REG_RSVD_31_16_MASK 0xffff0000
#define ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_STATUS_REG_RSVD_31_16_RESET_VALUE 0x00000000


// --------------------------------------------------------------------------------------------------------------------------------

#ifndef ICE_OBS_DTF_OBS_ENC_REGS_ICE_OBS_PA_CONFIG_REG_FLAG
#define ICE_OBS_DTF_OBS_ENC_REGS_ICE_OBS_PA_CONFIG_REG_FLAG
// ICE_OBS_PA_CONFIG_REG desc: 
typedef union {
    struct {
        uint32_t  RSVD_30_0            :  31;    // 
        uint32_t  SRC_EN               :   1;    //  Enables the protocol aware
                                                 // logic

    }                                field;
    uint32_t                         val;
} ICE_OBS_DTF_OBS_ENC_REGS_ICE_OBS_PA_CONFIG_REG_t;
#endif
#define ICE_OBS_DTF_OBS_ENC_REGS_ICE_OBS_PA_CONFIG_REG_OFFSET 0xa0
#define ICE_OBS_DTF_OBS_ENC_REGS_ICE_OBS_PA_CONFIG_REG_SCOPE 0x01
#define ICE_OBS_DTF_OBS_ENC_REGS_ICE_OBS_PA_CONFIG_REG_SIZE 32
#define ICE_OBS_DTF_OBS_ENC_REGS_ICE_OBS_PA_CONFIG_REG_BITFIELD_COUNT 0x02
#define ICE_OBS_DTF_OBS_ENC_REGS_ICE_OBS_PA_CONFIG_REG_RESET 0x00000000

#define ICE_OBS_DTF_OBS_ENC_REGS_ICE_OBS_PA_CONFIG_REG_RSVD_30_0_LSB 0x0000
#define ICE_OBS_DTF_OBS_ENC_REGS_ICE_OBS_PA_CONFIG_REG_RSVD_30_0_MSB 0x001e
#define ICE_OBS_DTF_OBS_ENC_REGS_ICE_OBS_PA_CONFIG_REG_RSVD_30_0_RANGE 0x001f
#define ICE_OBS_DTF_OBS_ENC_REGS_ICE_OBS_PA_CONFIG_REG_RSVD_30_0_MASK 0x7fffffff
#define ICE_OBS_DTF_OBS_ENC_REGS_ICE_OBS_PA_CONFIG_REG_RSVD_30_0_RESET_VALUE 0x00000000

#define ICE_OBS_DTF_OBS_ENC_REGS_ICE_OBS_PA_CONFIG_REG_SRC_EN_LSB 0x001f
#define ICE_OBS_DTF_OBS_ENC_REGS_ICE_OBS_PA_CONFIG_REG_SRC_EN_MSB 0x001f
#define ICE_OBS_DTF_OBS_ENC_REGS_ICE_OBS_PA_CONFIG_REG_SRC_EN_RANGE 0x0001
#define ICE_OBS_DTF_OBS_ENC_REGS_ICE_OBS_PA_CONFIG_REG_SRC_EN_MASK 0x80000000
#define ICE_OBS_DTF_OBS_ENC_REGS_ICE_OBS_PA_CONFIG_REG_SRC_EN_RESET_VALUE 0x00000000


// --------------------------------------------------------------------------------------------------------------------------------

#ifndef ICE_OBS_DTF_OBS_ENC_REGS_PSF_OBS_SAI_READ_POLICY_type_FLAG
#define ICE_OBS_DTF_OBS_ENC_REGS_PSF_OBS_SAI_READ_POLICY_type_FLAG
// PSF_OBS_SAI_READ_POLICY_type desc:  SAI RAC register for registers with restricted access
typedef union {
    struct {
        uint64_t  read_policy          :  64;    //  Read policy groups

    }                                field;
    uint64_t                         val;
} ICE_OBS_DTF_OBS_ENC_REGS_PSF_OBS_SAI_READ_POLICY_type_t;
#endif
#define ICE_OBS_DTF_OBS_ENC_REGS_PSF_OBS_SAI_READ_POLICY_TYPE_OFFSET 0xe0
#define ICE_OBS_DTF_OBS_ENC_REGS_PSF_OBS_SAI_READ_POLICY_TYPE_SCOPE 0x01
#define ICE_OBS_DTF_OBS_ENC_REGS_PSF_OBS_SAI_READ_POLICY_TYPE_SIZE 64
#define ICE_OBS_DTF_OBS_ENC_REGS_PSF_OBS_SAI_READ_POLICY_TYPE_BITFIELD_COUNT 0x01
#define ICE_OBS_DTF_OBS_ENC_REGS_PSF_OBS_SAI_READ_POLICY_TYPE_RESET 0x4000300021f

#define ICE_OBS_DTF_OBS_ENC_REGS_PSF_OBS_SAI_READ_POLICY_TYPE_READ_POLICY_LSB 0x0000
#define ICE_OBS_DTF_OBS_ENC_REGS_PSF_OBS_SAI_READ_POLICY_TYPE_READ_POLICY_MSB 0x003f
#define ICE_OBS_DTF_OBS_ENC_REGS_PSF_OBS_SAI_READ_POLICY_TYPE_READ_POLICY_RANGE 0x0040
#define ICE_OBS_DTF_OBS_ENC_REGS_PSF_OBS_SAI_READ_POLICY_TYPE_READ_POLICY_MASK 0xffffffffffffffff
#define ICE_OBS_DTF_OBS_ENC_REGS_PSF_OBS_SAI_READ_POLICY_TYPE_READ_POLICY_RESET_VALUE 0x4000300021f


// --------------------------------------------------------------------------------------------------------------------------------

#ifndef ICE_OBS_DTF_OBS_ENC_REGS_PSF_OBS_SAI_WRITE_POLICY_type_FLAG
#define ICE_OBS_DTF_OBS_ENC_REGS_PSF_OBS_SAI_WRITE_POLICY_type_FLAG
// PSF_OBS_SAI_WRITE_POLICY_type desc:  SAI WAC register for registers with restricted access
typedef union {
    struct {
        uint64_t  write_policy         :  64;    //  write policy groups

    }                                field;
    uint64_t                         val;
} ICE_OBS_DTF_OBS_ENC_REGS_PSF_OBS_SAI_WRITE_POLICY_type_t;
#endif
#define ICE_OBS_DTF_OBS_ENC_REGS_PSF_OBS_SAI_WRITE_POLICY_TYPE_OFFSET 0xe8
#define ICE_OBS_DTF_OBS_ENC_REGS_PSF_OBS_SAI_WRITE_POLICY_TYPE_SCOPE 0x01
#define ICE_OBS_DTF_OBS_ENC_REGS_PSF_OBS_SAI_WRITE_POLICY_TYPE_SIZE 64
#define ICE_OBS_DTF_OBS_ENC_REGS_PSF_OBS_SAI_WRITE_POLICY_TYPE_BITFIELD_COUNT 0x01
#define ICE_OBS_DTF_OBS_ENC_REGS_PSF_OBS_SAI_WRITE_POLICY_TYPE_RESET 0x4000300021f

#define ICE_OBS_DTF_OBS_ENC_REGS_PSF_OBS_SAI_WRITE_POLICY_TYPE_WRITE_POLICY_LSB 0x0000
#define ICE_OBS_DTF_OBS_ENC_REGS_PSF_OBS_SAI_WRITE_POLICY_TYPE_WRITE_POLICY_MSB 0x003f
#define ICE_OBS_DTF_OBS_ENC_REGS_PSF_OBS_SAI_WRITE_POLICY_TYPE_WRITE_POLICY_RANGE 0x0040
#define ICE_OBS_DTF_OBS_ENC_REGS_PSF_OBS_SAI_WRITE_POLICY_TYPE_WRITE_POLICY_MASK 0xffffffffffffffff
#define ICE_OBS_DTF_OBS_ENC_REGS_PSF_OBS_SAI_WRITE_POLICY_TYPE_WRITE_POLICY_RESET_VALUE 0x4000300021f


// --------------------------------------------------------------------------------------------------------------------------------

#ifndef ICE_OBS_DTF_OBS_ENC_REGS_PSF_OBS_SAI_CONTROL_POLICY_type_FLAG
#define ICE_OBS_DTF_OBS_ENC_REGS_PSF_OBS_SAI_CONTROL_POLICY_type_FLAG
// PSF_OBS_SAI_CONTROL_POLICY_type desc:  SAI CP register for registers with restricted access
typedef union {
    struct {
        uint64_t  cp_policy            :  64;    //  control policy groups

    }                                field;
    uint64_t                         val;
} ICE_OBS_DTF_OBS_ENC_REGS_PSF_OBS_SAI_CONTROL_POLICY_type_t;
#endif
#define ICE_OBS_DTF_OBS_ENC_REGS_PSF_OBS_SAI_CONTROL_POLICY_TYPE_OFFSET 0xf0
#define ICE_OBS_DTF_OBS_ENC_REGS_PSF_OBS_SAI_CONTROL_POLICY_TYPE_SCOPE 0x01
#define ICE_OBS_DTF_OBS_ENC_REGS_PSF_OBS_SAI_CONTROL_POLICY_TYPE_SIZE 64
#define ICE_OBS_DTF_OBS_ENC_REGS_PSF_OBS_SAI_CONTROL_POLICY_TYPE_BITFIELD_COUNT 0x01
#define ICE_OBS_DTF_OBS_ENC_REGS_PSF_OBS_SAI_CONTROL_POLICY_TYPE_RESET 0x4000300021f

#define ICE_OBS_DTF_OBS_ENC_REGS_PSF_OBS_SAI_CONTROL_POLICY_TYPE_CP_POLICY_LSB 0x0000
#define ICE_OBS_DTF_OBS_ENC_REGS_PSF_OBS_SAI_CONTROL_POLICY_TYPE_CP_POLICY_MSB 0x003f
#define ICE_OBS_DTF_OBS_ENC_REGS_PSF_OBS_SAI_CONTROL_POLICY_TYPE_CP_POLICY_RANGE 0x0040
#define ICE_OBS_DTF_OBS_ENC_REGS_PSF_OBS_SAI_CONTROL_POLICY_TYPE_CP_POLICY_MASK 0xffffffffffffffff
#define ICE_OBS_DTF_OBS_ENC_REGS_PSF_OBS_SAI_CONTROL_POLICY_TYPE_CP_POLICY_RESET_VALUE 0x4000300021f


// --------------------------------------------------------------------------------------------------------------------------------

// starting the array instantiation section
typedef struct {
    uint8_t                    rsvd0[16];
    ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_STATUS_REG_t DSO_CFG_STATUS_REG; // offset 8'h10, width 32
    uint8_t                    rsvd1[16];
    ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_DTF_SRC_CONFIG_REG_t DSO_CFG_DTF_SRC_CONFIG_REG; // offset 8'h14, width 32
    uint8_t                    rsvd2[16];
    ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_PTYPE_FILTER_CH0_REG_t DSO_CFG_PTYPE_FILTER_CH0_REG; // offset 8'h18, width 32
    uint8_t                    rsvd3[16];
    ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MATCH_LOW_CH0_REG_t DSO_FILTER_MATCH_LOW_CH0_REG; // offset 8'h1C, width 32
    uint8_t                    rsvd4[16];
    ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MATCH_HIGH_CH0_REG_t DSO_FILTER_MATCH_HIGH_CH0_REG; // offset 8'h20, width 32
    uint8_t                    rsvd5[16];
    ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MASK_LOW_CH0_REG_t DSO_FILTER_MASK_LOW_CH0_REG; // offset 8'h24, width 32
    uint8_t                    rsvd6[16];
    ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MASK_HIGH_CH0_REG_t DSO_FILTER_MASK_HIGH_CH0_REG; // offset 8'h28, width 32
    uint8_t                    rsvd7[16];
    ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_INV_CH0_REG_t DSO_FILTER_INV_CH0_REG; // offset 8'h2C, width 32
    uint8_t                    rsvd8[16];
    ICE_OBS_DTF_OBS_ENC_REGS_DSO_CFG_PTYPE_FILTER_CH1_REG_t DSO_CFG_PTYPE_FILTER_CH1_REG; // offset 8'h30, width 32
    uint8_t                    rsvd9[16];
    ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MATCH_LOW_CH1_REG_t DSO_FILTER_MATCH_LOW_CH1_REG; // offset 8'h34, width 32
    uint8_t                    rsvd10[16];
    ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MATCH_HIGH_CH1_REG_t DSO_FILTER_MATCH_HIGH_CH1_REG; // offset 8'h38, width 32
    uint8_t                    rsvd11[16];
    ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MASK_LOW_CH1_REG_t DSO_FILTER_MASK_LOW_CH1_REG; // offset 8'h3C, width 32
    uint8_t                    rsvd12[16];
    ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_MASK_HIGH_CH1_REG_t DSO_FILTER_MASK_HIGH_CH1_REG; // offset 8'h40, width 32
    uint8_t                    rsvd13[16];
    ICE_OBS_DTF_OBS_ENC_REGS_DSO_FILTER_INV_CH1_REG_t DSO_FILTER_INV_CH1_REG; // offset 8'h44, width 32
    ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_CONFIG_REG_t DSO_DTF_ENCODER_CONFIG_REG; // offset 4'h4, width 32
    uint8_t                    rsvd14[4];
    ICE_OBS_DTF_OBS_ENC_REGS_DSO_DTF_ENCODER_STATUS_REG_t DSO_DTF_ENCODER_STATUS_REG; // offset 4'h8, width 32
    uint8_t                    rsvd15[152];
    ICE_OBS_DTF_OBS_ENC_REGS_ICE_OBS_PA_CONFIG_REG_t ICE_OBS_PA_CONFIG_REG; // offset 12'h0A0, width 32
    uint8_t                    rsvd16[220];
    ICE_OBS_DTF_OBS_ENC_REGS_PSF_OBS_SAI_READ_POLICY_type_t PSF_OBS_SAI_READ_POLICY_type; // offset 12'h0E0, width 64
    uint8_t                    rsvd17[216];
    ICE_OBS_DTF_OBS_ENC_REGS_PSF_OBS_SAI_WRITE_POLICY_type_t PSF_OBS_SAI_WRITE_POLICY_type; // offset 12'h0E8, width 64
    uint8_t                    rsvd18[216];
    ICE_OBS_DTF_OBS_ENC_REGS_PSF_OBS_SAI_CONTROL_POLICY_type_t PSF_OBS_SAI_CONTROL_POLICY_type; // offset 12'h0F0, width 64
} ice_obs_dtf_obs_enc_regs_t;                    // size:  12'h464


#endif // _ICE_OBS_DTF_OBS_ENC_REGS_REGS_H_

