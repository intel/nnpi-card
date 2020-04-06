/*******************************************************************************
INTEL CORPORATION CONFIDENTIAL Copyright(c) 2017-2020 Intel Corporation. All Rights Reserved.

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
// File:            axi2idi_regs_regs.h                                        
// Creator:         vchakki                                                    
// Time:            Thursday Dec 13, 2018 [6:14:22 am]                         
//                                                                             
// Path:            /tmp/vchakki/nebulon_run/1993919939_2018-12-13.06:14:05    
// Arguments:       -input axi2idi.rdl -chdr -out_dir .                        
//                                                                             
// MRE:             5.2018.2                                                   
// Machine:         icsl1890                                                   
// OS:              Linux 3.0.101-108.13.1.14249.0.PTF-default                 
// Nebulon version: d18ww24.4                                                  
// Description:                                                                


#ifndef _AXI2IDI_REGS_REGS_H_
#define _AXI2IDI_REGS_REGS_H_

#define MSG_A2I_SECURITY_POLICY_MSGPORT     0x0
#define MSG_A2I_SECURITY_POLICY_A2I_PGI_NO_ICE_POLICY_CP_MSGREGADDR 0x100
#define MSG_A2I_SECURITY_POLICY_A2I_PGI_NO_ICE_POLICY_WAC_MSGREGADDR 0x108
#define MSG_A2I_SECURITY_POLICY_A2I_PGI_NO_ICE_POLICY_RAC_MSGREGADDR 0x110
#define MSG_A2I_SECURITY_POLICY_A2I_PGI_NO_IA_POLICY_CP_MSGREGADDR 0x118
#define MSG_A2I_SECURITY_POLICY_A2I_PGI_NO_IA_POLICY_WAC_MSGREGADDR 0x120
#define MSG_A2I_SECURITY_POLICY_A2I_PGI_NO_IA_POLICY_RAC_MSGREGADDR 0x128
#define MSG_A2I_ICEBAR_MSGPORT     0x0
#define MSG_A2I_ICEBAR_CONVERTOR_ENTRY_CONFIG_MSGREGADDR 0x0
#define MSG_A2I_ICEBAR_CONVERTOR_DISABLED_ENTRIES_MSGREGADDR 0x8
#define MSG_A2I_ICEBAR_IDI_CONFIG_MSGREGADDR 0x10
#define MSG_A2I_ICEBAR_AXI_USER_CONFIG_MSGREGADDR 0x14
#define MSG_A2I_ICEBAR_IDI_FLOW_CONFIG_MSGREGADDR 0x18
#define MSG_A2I_ICEBAR_AXI_ARB_CONFIG_MSGREGADDR 0x1C
#define MSG_A2I_ICEBAR_AXI_SHARED_READ_CFG_MSGREGADDR 0x20
#define MSG_A2I_ICEBAR_AXI_SHARED_READ_STATUS_MSGREGADDR 0x24
#define MSG_A2I_ICEBAR_DFX_STREAM_CTL_MSGREGADDR 0x28
#define MSG_A2I_ICEBAR_HVM_MODES_MSGREGADDR 0x2C
#define MSG_A2I_ICEBAR_ICEBO_PMON_GLOBAL_MSGREGADDR 0x30
#define MSG_A2I_ICEBAR_ICEBO_PMON_EVENT_0_MSGREGADDR 0x34
#define MSG_A2I_ICEBAR_ICEBO_PMON_EVENT_1_MSGREGADDR 0x38
#define MSG_A2I_ICEBAR_ICEBO_PMON_EVENT_2_MSGREGADDR 0x3C
#define MSG_A2I_ICEBAR_ICEBO_PMON_EVENT_3_MSGREGADDR 0x40
#define MSG_A2I_ICEBAR_ICEBO_PMON_STATUS_MSGREGADDR 0x44
#define MSG_A2I_ICEBAR_ICEBO_PMON_COUNTER_0_MSGREGADDR 0x48
#define MSG_A2I_ICEBAR_ICEBO_PMON_COUNTER_1_MSGREGADDR 0x50
#define MSG_A2I_ICEBAR_ICEBO_PMON_COUNTER_2_MSGREGADDR 0x58
#define MSG_A2I_ICEBAR_ICEBO_PMON_COUNTER_3_MSGREGADDR 0x60
#define MSG_A2I_ICEBAR_ICE_CONFIG_MSGREGADDR 0x68
#define MEM_A2I_ICEBAR_BASE 0x0
#define MEM_A2I_ICEBAR_CONVERTOR_ENTRY_CONFIG_MMOFFSET 0x0
#define MEM_A2I_ICEBAR_CONVERTOR_DISABLED_ENTRIES_MMOFFSET 0x8
#define MEM_A2I_ICEBAR_IDI_CONFIG_MMOFFSET 0x10
#define MEM_A2I_ICEBAR_AXI_USER_CONFIG_MMOFFSET 0x14
#define MEM_A2I_ICEBAR_IDI_FLOW_CONFIG_MMOFFSET 0x18
#define MEM_A2I_ICEBAR_AXI_ARB_CONFIG_MMOFFSET 0x1C
#define MEM_A2I_ICEBAR_AXI_SHARED_READ_CFG_MMOFFSET 0x20
#define MEM_A2I_ICEBAR_AXI_SHARED_READ_STATUS_MMOFFSET 0x24
#define MEM_A2I_ICEBAR_DFX_STREAM_CTL_MMOFFSET 0x28
#define MEM_A2I_ICEBAR_HVM_MODES_MMOFFSET 0x2C
#define MEM_A2I_ICEBAR_ICEBO_PMON_GLOBAL_MMOFFSET 0x30
#define MEM_A2I_ICEBAR_ICEBO_PMON_EVENT_0_MMOFFSET 0x34
#define MEM_A2I_ICEBAR_ICEBO_PMON_EVENT_1_MMOFFSET 0x38
#define MEM_A2I_ICEBAR_ICEBO_PMON_EVENT_2_MMOFFSET 0x3C
#define MEM_A2I_ICEBAR_ICEBO_PMON_EVENT_3_MMOFFSET 0x40
#define MEM_A2I_ICEBAR_ICEBO_PMON_STATUS_MMOFFSET 0x44
#define MEM_A2I_ICEBAR_ICEBO_PMON_COUNTER_0_MMOFFSET 0x48
#define MEM_A2I_ICEBAR_ICEBO_PMON_COUNTER_1_MMOFFSET 0x50
#define MEM_A2I_ICEBAR_ICEBO_PMON_COUNTER_2_MMOFFSET 0x58
#define MEM_A2I_ICEBAR_ICEBO_PMON_COUNTER_3_MMOFFSET 0x60
#define MEM_A2I_ICEBAR_ICE_CONFIG_MMOFFSET 0x68
#define MEM_A2I_SECURITY_POLICY_BASE 0x0
#define MEM_A2I_SECURITY_POLICY_A2I_PGI_NO_ICE_POLICY_CP_MMOFFSET 0x100
#define MEM_A2I_SECURITY_POLICY_A2I_PGI_NO_ICE_POLICY_WAC_MMOFFSET 0x108
#define MEM_A2I_SECURITY_POLICY_A2I_PGI_NO_ICE_POLICY_RAC_MMOFFSET 0x110
#define MEM_A2I_SECURITY_POLICY_A2I_PGI_NO_IA_POLICY_CP_MMOFFSET 0x118
#define MEM_A2I_SECURITY_POLICY_A2I_PGI_NO_IA_POLICY_WAC_MMOFFSET 0x120
#define MEM_A2I_SECURITY_POLICY_A2I_PGI_NO_IA_POLICY_RAC_MMOFFSET 0x128

#ifndef convertor_entry_config_FLAG
#define convertor_entry_config_FLAG
// convertor_entry_config desc:  convertor entry configuration
typedef union {
    struct {
        uint64_t  num_convertor_entries :   7;    //  Number of convertor entries
                                                 // to use. HW maintains a counter
                                                 // that is incremented on entry
                                                 // allocation and decremented on
                                                 // entry de-allocation.
                                                 // Allocation is block if exceeds
                                                 // that number
        uint64_t  reserved1            :   3;    //  reserved1
        uint64_t  max_pending_idi      :   7;    //  Max Number of IDI requests
                                                 // between C2U_REQ and U2C_GO. HW
                                                 // maintains a counter that is
                                                 // incremented on C2U request and
                                                 // decremented on GO. Allocation
                                                 // is blocked if exceeds that
                                                 // number
        uint64_t  reserved2            :   3;    //  reserved2
        uint64_t  max_pending_reads    :   7;    //  Max entries allocated for AXI
                                                 // read (including prefetch).
                                                 // Allocation of reads is blocked
                                                 // if exceeds that number (note:
                                                 // must be greater than
                                                 // max_shared_distance)
        uint64_t  reserved3            :   3;    //  reserved3
        uint64_t  max_pending_writes   :   7;    //  Max entries allocated for AXI
                                                 // write. Allocation of writes is
                                                 // blocked if exceeds that number
        uint64_t  reserved4            :   3;    //  reserved4
        uint64_t  max_pending_per_agent :   7;    //  Max entries allocated for
                                                 // requests from each AXI agent.
                                                 // Allocation from that agent is
                                                 // blocked is exceeds that number
        uint64_t  reserved5            :   3;    //  reserved5
        uint64_t  RSVD_0               :  14;    // Nebulon auto filled RSVD [63:50]

    }                                field;
    uint64_t                         val;
} convertor_entry_config_t;
#endif
#define CONVERTOR_ENTRY_CONFIG_OFFSET 0x00
#define CONVERTOR_ENTRY_CONFIG_SCOPE 0x01
#define CONVERTOR_ENTRY_CONFIG_SIZE 64
#define CONVERTOR_ENTRY_CONFIG_BITFIELD_COUNT 0x0a
#define CONVERTOR_ENTRY_CONFIG_RESET 0x401004010040

#define CONVERTOR_ENTRY_CONFIG_NUM_CONVERTOR_ENTRIES_LSB 0x0000
#define CONVERTOR_ENTRY_CONFIG_NUM_CONVERTOR_ENTRIES_MSB 0x0006
#define CONVERTOR_ENTRY_CONFIG_NUM_CONVERTOR_ENTRIES_RANGE 0x0007
#define CONVERTOR_ENTRY_CONFIG_NUM_CONVERTOR_ENTRIES_MASK 0x0000007f
#define CONVERTOR_ENTRY_CONFIG_NUM_CONVERTOR_ENTRIES_RESET_VALUE 0x00000040

#define CONVERTOR_ENTRY_CONFIG_RESERVED1_LSB 0x0007
#define CONVERTOR_ENTRY_CONFIG_RESERVED1_MSB 0x0009
#define CONVERTOR_ENTRY_CONFIG_RESERVED1_RANGE 0x0003
#define CONVERTOR_ENTRY_CONFIG_RESERVED1_MASK 0x00000380
#define CONVERTOR_ENTRY_CONFIG_RESERVED1_RESET_VALUE 0x00000000

#define CONVERTOR_ENTRY_CONFIG_MAX_PENDING_IDI_LSB 0x000a
#define CONVERTOR_ENTRY_CONFIG_MAX_PENDING_IDI_MSB 0x0010
#define CONVERTOR_ENTRY_CONFIG_MAX_PENDING_IDI_RANGE 0x0007
#define CONVERTOR_ENTRY_CONFIG_MAX_PENDING_IDI_MASK 0x0001fc00
#define CONVERTOR_ENTRY_CONFIG_MAX_PENDING_IDI_RESET_VALUE 0x00000040

#define CONVERTOR_ENTRY_CONFIG_RESERVED2_LSB 0x0011
#define CONVERTOR_ENTRY_CONFIG_RESERVED2_MSB 0x0013
#define CONVERTOR_ENTRY_CONFIG_RESERVED2_RANGE 0x0003
#define CONVERTOR_ENTRY_CONFIG_RESERVED2_MASK 0x000e0000
#define CONVERTOR_ENTRY_CONFIG_RESERVED2_RESET_VALUE 0x00000000

#define CONVERTOR_ENTRY_CONFIG_MAX_PENDING_READS_LSB 0x0014
#define CONVERTOR_ENTRY_CONFIG_MAX_PENDING_READS_MSB 0x001a
#define CONVERTOR_ENTRY_CONFIG_MAX_PENDING_READS_RANGE 0x0007
#define CONVERTOR_ENTRY_CONFIG_MAX_PENDING_READS_MASK 0x07f00000
#define CONVERTOR_ENTRY_CONFIG_MAX_PENDING_READS_RESET_VALUE 0x00000040

#define CONVERTOR_ENTRY_CONFIG_RESERVED3_LSB 0x001b
#define CONVERTOR_ENTRY_CONFIG_RESERVED3_MSB 0x001d
#define CONVERTOR_ENTRY_CONFIG_RESERVED3_RANGE 0x0003
#define CONVERTOR_ENTRY_CONFIG_RESERVED3_MASK 0x38000000
#define CONVERTOR_ENTRY_CONFIG_RESERVED3_RESET_VALUE 0x00000000

#define CONVERTOR_ENTRY_CONFIG_MAX_PENDING_WRITES_LSB 0x001e
#define CONVERTOR_ENTRY_CONFIG_MAX_PENDING_WRITES_MSB 0x0024
#define CONVERTOR_ENTRY_CONFIG_MAX_PENDING_WRITES_RANGE 0x0007
#define CONVERTOR_ENTRY_CONFIG_MAX_PENDING_WRITES_MASK 0x1fc0000000
#define CONVERTOR_ENTRY_CONFIG_MAX_PENDING_WRITES_RESET_VALUE 0x00000040

#define CONVERTOR_ENTRY_CONFIG_RESERVED4_LSB 0x0025
#define CONVERTOR_ENTRY_CONFIG_RESERVED4_MSB 0x0027
#define CONVERTOR_ENTRY_CONFIG_RESERVED4_RANGE 0x0003
#define CONVERTOR_ENTRY_CONFIG_RESERVED4_MASK 0xe000000000
#define CONVERTOR_ENTRY_CONFIG_RESERVED4_RESET_VALUE 0x00000000

#define CONVERTOR_ENTRY_CONFIG_MAX_PENDING_PER_AGENT_LSB 0x0028
#define CONVERTOR_ENTRY_CONFIG_MAX_PENDING_PER_AGENT_MSB 0x002e
#define CONVERTOR_ENTRY_CONFIG_MAX_PENDING_PER_AGENT_RANGE 0x0007
#define CONVERTOR_ENTRY_CONFIG_MAX_PENDING_PER_AGENT_MASK 0x7f0000000000
#define CONVERTOR_ENTRY_CONFIG_MAX_PENDING_PER_AGENT_RESET_VALUE 0x00000040

#define CONVERTOR_ENTRY_CONFIG_RESERVED5_LSB 0x002f
#define CONVERTOR_ENTRY_CONFIG_RESERVED5_MSB 0x0031
#define CONVERTOR_ENTRY_CONFIG_RESERVED5_RANGE 0x0003
#define CONVERTOR_ENTRY_CONFIG_RESERVED5_MASK 0x3800000000000
#define CONVERTOR_ENTRY_CONFIG_RESERVED5_RESET_VALUE 0x00000000


// --------------------------------------------------------------------------------------------------------------------------------

#ifndef convertor_disabled_entries_FLAG
#define convertor_disabled_entries_FLAG
// convertor_disabled_entries desc:  disable convertor entries
typedef union {
    struct {
        uint64_t  disabled_entries     :  64;    //  1 means that entry is
                                                 // disabled. Number of enabled
                                                 // entries must be equal or
                                                 // smaller than
                                                 // NUM_CONVERTOR_ENTRIES. A
                                                 // disabled entry cannot accept a
                                                 // new request (but existing
                                                 // request will be completed)

    }                                field;
    uint64_t                         val;
} convertor_disabled_entries_t;
#endif
#define CONVERTOR_DISABLED_ENTRIES_OFFSET 0x08
#define CONVERTOR_DISABLED_ENTRIES_SCOPE 0x01
#define CONVERTOR_DISABLED_ENTRIES_SIZE 64
#define CONVERTOR_DISABLED_ENTRIES_BITFIELD_COUNT 0x01
#define CONVERTOR_DISABLED_ENTRIES_RESET 0x00000000

#define CONVERTOR_DISABLED_ENTRIES_DISABLED_ENTRIES_LSB 0x0000
#define CONVERTOR_DISABLED_ENTRIES_DISABLED_ENTRIES_MSB 0x003f
#define CONVERTOR_DISABLED_ENTRIES_DISABLED_ENTRIES_RANGE 0x0040
#define CONVERTOR_DISABLED_ENTRIES_DISABLED_ENTRIES_MASK 0xffffffffffffffff
#define CONVERTOR_DISABLED_ENTRIES_DISABLED_ENTRIES_RESET_VALUE 0x00000000


// --------------------------------------------------------------------------------------------------------------------------------

#ifndef idi_config_FLAG
#define idi_config_FLAG
// idi_config desc:  IDI credits Configuration
typedef union {
    struct {
        uint32_t  max_u2c_req_credit   :   5;    //  max u2c req credit
        uint32_t  max_u2c_rsp_credit   :   5;    //  max u2c rsp credit
        uint32_t  max_u2c_data_credit  :   5;    //  max u2c data credit
        uint32_t  RSVD_0               :  17;    // Nebulon auto filled RSVD [31:15]

    }                                field;
    uint32_t                         val;
} idi_config_t;
#endif
#define IDI_CONFIG_OFFSET 0x10
#define IDI_CONFIG_SCOPE 0x01
#define IDI_CONFIG_SIZE 32
#define IDI_CONFIG_BITFIELD_COUNT 0x03
#define IDI_CONFIG_RESET 0x00004204

#define IDI_CONFIG_MAX_U2C_REQ_CREDIT_LSB 0x0000
#define IDI_CONFIG_MAX_U2C_REQ_CREDIT_MSB 0x0004
#define IDI_CONFIG_MAX_U2C_REQ_CREDIT_RANGE 0x0005
#define IDI_CONFIG_MAX_U2C_REQ_CREDIT_MASK 0x0000001f
#define IDI_CONFIG_MAX_U2C_REQ_CREDIT_RESET_VALUE 0x00000004

#define IDI_CONFIG_MAX_U2C_RSP_CREDIT_LSB 0x0005
#define IDI_CONFIG_MAX_U2C_RSP_CREDIT_MSB 0x0009
#define IDI_CONFIG_MAX_U2C_RSP_CREDIT_RANGE 0x0005
#define IDI_CONFIG_MAX_U2C_RSP_CREDIT_MASK 0x000003e0
#define IDI_CONFIG_MAX_U2C_RSP_CREDIT_RESET_VALUE 0x00000010

#define IDI_CONFIG_MAX_U2C_DATA_CREDIT_LSB 0x000a
#define IDI_CONFIG_MAX_U2C_DATA_CREDIT_MSB 0x000e
#define IDI_CONFIG_MAX_U2C_DATA_CREDIT_RANGE 0x0005
#define IDI_CONFIG_MAX_U2C_DATA_CREDIT_MASK 0x00007c00
#define IDI_CONFIG_MAX_U2C_DATA_CREDIT_RESET_VALUE 0x00000010


// --------------------------------------------------------------------------------------------------------------------------------

#ifndef axi_user_config_FLAG
#define axi_user_config_FLAG
// axi_user_config desc:  AXI user bits configuration
typedef union {
    struct {
        uint32_t  axuser_1_0_is_clos   :   1;    //  Use AxUSER[1:0] as CLOS
        uint32_t  axuser_3_is_priority :   1;    //  Use AxUSER[3] as Priority
        uint32_t  axuser_7_6_is_nt     :   1;    //  Use AxUSER[7:6] as NT
        uint32_t  axuser_8_is_prefetch :   1;    //  Use AxUSER[8] as Prefetch
        uint32_t  axuser_12_is_shared_read :   1;    //  Use AxUSER[12] as Shared_Read
        uint32_t  RSVD_0               :  27;    // Nebulon auto filled RSVD [31:5]

    }                                field;
    uint32_t                         val;
} axi_user_config_t;
#endif
#define AXI_USER_CONFIG_OFFSET 0x14
#define AXI_USER_CONFIG_SCOPE 0x01
#define AXI_USER_CONFIG_SIZE 32
#define AXI_USER_CONFIG_BITFIELD_COUNT 0x05
#define AXI_USER_CONFIG_RESET 0x0000001d

#define AXI_USER_CONFIG_AXUSER_1_0_IS_CLOS_LSB 0x0000
#define AXI_USER_CONFIG_AXUSER_1_0_IS_CLOS_MSB 0x0000
#define AXI_USER_CONFIG_AXUSER_1_0_IS_CLOS_RANGE 0x0001
#define AXI_USER_CONFIG_AXUSER_1_0_IS_CLOS_MASK 0x00000001
#define AXI_USER_CONFIG_AXUSER_1_0_IS_CLOS_RESET_VALUE 0x00000001

#define AXI_USER_CONFIG_AXUSER_3_IS_PRIORITY_LSB 0x0001
#define AXI_USER_CONFIG_AXUSER_3_IS_PRIORITY_MSB 0x0001
#define AXI_USER_CONFIG_AXUSER_3_IS_PRIORITY_RANGE 0x0001
#define AXI_USER_CONFIG_AXUSER_3_IS_PRIORITY_MASK 0x00000002
#define AXI_USER_CONFIG_AXUSER_3_IS_PRIORITY_RESET_VALUE 0x00000000

#define AXI_USER_CONFIG_AXUSER_7_6_IS_NT_LSB 0x0002
#define AXI_USER_CONFIG_AXUSER_7_6_IS_NT_MSB 0x0002
#define AXI_USER_CONFIG_AXUSER_7_6_IS_NT_RANGE 0x0001
#define AXI_USER_CONFIG_AXUSER_7_6_IS_NT_MASK 0x00000004
#define AXI_USER_CONFIG_AXUSER_7_6_IS_NT_RESET_VALUE 0x00000001

#define AXI_USER_CONFIG_AXUSER_8_IS_PREFETCH_LSB 0x0003
#define AXI_USER_CONFIG_AXUSER_8_IS_PREFETCH_MSB 0x0003
#define AXI_USER_CONFIG_AXUSER_8_IS_PREFETCH_RANGE 0x0001
#define AXI_USER_CONFIG_AXUSER_8_IS_PREFETCH_MASK 0x00000008
#define AXI_USER_CONFIG_AXUSER_8_IS_PREFETCH_RESET_VALUE 0x00000001

#define AXI_USER_CONFIG_AXUSER_12_IS_SHARED_READ_LSB 0x0004
#define AXI_USER_CONFIG_AXUSER_12_IS_SHARED_READ_MSB 0x0004
#define AXI_USER_CONFIG_AXUSER_12_IS_SHARED_READ_RANGE 0x0001
#define AXI_USER_CONFIG_AXUSER_12_IS_SHARED_READ_MASK 0x00000010
#define AXI_USER_CONFIG_AXUSER_12_IS_SHARED_READ_RESET_VALUE 0x00000001


// --------------------------------------------------------------------------------------------------------------------------------

#ifndef idi_flow_config_FLAG
#define idi_flow_config_FLAG
// idi_flow_config desc:  Control the behavior of various IDI flows
typedef union {
    struct {
        uint32_t  disable_cachable_pwr :   1;    //  Treat Cacheable Partial Write
                                                 // as Uncachable, i.e. don't use
                                                 // RfoWr but use WCiL
        uint32_t  disable_write_cacheable :   1;    //  Clear Cacheable indication
                                                 // for all AXI write commands
        uint32_t  disable_read_cacheable :   1;    //  Clear Cacheable indication
                                                 // for all AXI read commands
        uint32_t  wcil_2_wil           :   1;    //  Convert WCiL opcode to WIL
                                                 // (including RfoWr that was
                                                 // converted to WCiL, see bit
                                                 // [0])
        uint32_t  disable_fast_go      :   1;    //  Ignore FastGo part of a
                                                 // U2C_RSP (but don't ignore the
                                                 // Pull part), and treat ExtCmp
                                                 // as Go
        uint32_t  disable_prefetch_on_idi :   1;    //  On a preftch command, don't
                                                 // issue any IDI opcode, just
                                                 // return zeros to AXI
        uint32_t  RSVD_0               :  25;    // Nebulon auto filled RSVD [30:6]
        uint32_t  disable_gate_clk_axi2idi :   1;    //  disable clock gating in
                                                 // AXI2IDI bridge

    }                                field;
    uint32_t                         val;
} idi_flow_config_t;
#endif
#define IDI_FLOW_CONFIG_OFFSET 0x18
#define IDI_FLOW_CONFIG_SCOPE 0x01
#define IDI_FLOW_CONFIG_SIZE 32
#define IDI_FLOW_CONFIG_BITFIELD_COUNT 0x07
#define IDI_FLOW_CONFIG_RESET 0x00000000

#define IDI_FLOW_CONFIG_DISABLE_CACHABLE_PWR_LSB 0x0000
#define IDI_FLOW_CONFIG_DISABLE_CACHABLE_PWR_MSB 0x0000
#define IDI_FLOW_CONFIG_DISABLE_CACHABLE_PWR_RANGE 0x0001
#define IDI_FLOW_CONFIG_DISABLE_CACHABLE_PWR_MASK 0x00000001
#define IDI_FLOW_CONFIG_DISABLE_CACHABLE_PWR_RESET_VALUE 0x00000000

#define IDI_FLOW_CONFIG_DISABLE_WRITE_CACHEABLE_LSB 0x0001
#define IDI_FLOW_CONFIG_DISABLE_WRITE_CACHEABLE_MSB 0x0001
#define IDI_FLOW_CONFIG_DISABLE_WRITE_CACHEABLE_RANGE 0x0001
#define IDI_FLOW_CONFIG_DISABLE_WRITE_CACHEABLE_MASK 0x00000002
#define IDI_FLOW_CONFIG_DISABLE_WRITE_CACHEABLE_RESET_VALUE 0x00000000

#define IDI_FLOW_CONFIG_DISABLE_READ_CACHEABLE_LSB 0x0002
#define IDI_FLOW_CONFIG_DISABLE_READ_CACHEABLE_MSB 0x0002
#define IDI_FLOW_CONFIG_DISABLE_READ_CACHEABLE_RANGE 0x0001
#define IDI_FLOW_CONFIG_DISABLE_READ_CACHEABLE_MASK 0x00000004
#define IDI_FLOW_CONFIG_DISABLE_READ_CACHEABLE_RESET_VALUE 0x00000000

#define IDI_FLOW_CONFIG_WCIL_2_WIL_LSB 0x0003
#define IDI_FLOW_CONFIG_WCIL_2_WIL_MSB 0x0003
#define IDI_FLOW_CONFIG_WCIL_2_WIL_RANGE 0x0001
#define IDI_FLOW_CONFIG_WCIL_2_WIL_MASK 0x00000008
#define IDI_FLOW_CONFIG_WCIL_2_WIL_RESET_VALUE 0x00000000

#define IDI_FLOW_CONFIG_DISABLE_FAST_GO_LSB 0x0004
#define IDI_FLOW_CONFIG_DISABLE_FAST_GO_MSB 0x0004
#define IDI_FLOW_CONFIG_DISABLE_FAST_GO_RANGE 0x0001
#define IDI_FLOW_CONFIG_DISABLE_FAST_GO_MASK 0x00000010
#define IDI_FLOW_CONFIG_DISABLE_FAST_GO_RESET_VALUE 0x00000000

#define IDI_FLOW_CONFIG_DISABLE_PREFETCH_ON_IDI_LSB 0x0005
#define IDI_FLOW_CONFIG_DISABLE_PREFETCH_ON_IDI_MSB 0x0005
#define IDI_FLOW_CONFIG_DISABLE_PREFETCH_ON_IDI_RANGE 0x0001
#define IDI_FLOW_CONFIG_DISABLE_PREFETCH_ON_IDI_MASK 0x00000020
#define IDI_FLOW_CONFIG_DISABLE_PREFETCH_ON_IDI_RESET_VALUE 0x00000000

#define IDI_FLOW_CONFIG_DISABLE_GATE_CLK_AXI2IDI_LSB 0x001f
#define IDI_FLOW_CONFIG_DISABLE_GATE_CLK_AXI2IDI_MSB 0x001f
#define IDI_FLOW_CONFIG_DISABLE_GATE_CLK_AXI2IDI_RANGE 0x0001
#define IDI_FLOW_CONFIG_DISABLE_GATE_CLK_AXI2IDI_MASK 0x80000000
#define IDI_FLOW_CONFIG_DISABLE_GATE_CLK_AXI2IDI_RESET_VALUE 0x00000000


// --------------------------------------------------------------------------------------------------------------------------------

#ifndef axi_arb_config_FLAG
#define axi_arb_config_FLAG
// axi_arb_config desc:  ACI Arb configuration
typedef union {
    struct {
        uint32_t  park_on_read_burst   :   1;    //  park on a read burst that won
                                                 // the 1st CL request (note:
                                                 // don't park on a shared_read
                                                 // leader if it exceeds the max
                                                 // shared distance)
        uint32_t  park_on_write_burst  :   1;    //  park on a write burst that
                                                 // won the 1st CL request
        uint32_t  RSVD_0               :  30;    // Nebulon auto filled RSVD [31:2]

    }                                field;
    uint32_t                         val;
} axi_arb_config_t;
#endif
#define AXI_ARB_CONFIG_OFFSET 0x1c
#define AXI_ARB_CONFIG_SCOPE 0x01
#define AXI_ARB_CONFIG_SIZE 32
#define AXI_ARB_CONFIG_BITFIELD_COUNT 0x02
#define AXI_ARB_CONFIG_RESET 0x00000000

#define AXI_ARB_CONFIG_PARK_ON_READ_BURST_LSB 0x0000
#define AXI_ARB_CONFIG_PARK_ON_READ_BURST_MSB 0x0000
#define AXI_ARB_CONFIG_PARK_ON_READ_BURST_RANGE 0x0001
#define AXI_ARB_CONFIG_PARK_ON_READ_BURST_MASK 0x00000001
#define AXI_ARB_CONFIG_PARK_ON_READ_BURST_RESET_VALUE 0x00000000

#define AXI_ARB_CONFIG_PARK_ON_WRITE_BURST_LSB 0x0001
#define AXI_ARB_CONFIG_PARK_ON_WRITE_BURST_MSB 0x0001
#define AXI_ARB_CONFIG_PARK_ON_WRITE_BURST_RANGE 0x0001
#define AXI_ARB_CONFIG_PARK_ON_WRITE_BURST_MASK 0x00000002
#define AXI_ARB_CONFIG_PARK_ON_WRITE_BURST_RESET_VALUE 0x00000000


// --------------------------------------------------------------------------------------------------------------------------------

#ifndef axi_shared_read_cfg_FLAG
#define axi_shared_read_cfg_FLAG
// axi_shared_read_cfg desc:  Shared_Read configuration
typedef union {
    struct {
        uint32_t  shared_read_enable   :   1;    //  Enable Shared_Read feature.
                                                 // When cleared, ignore
                                                 // Shared_Read attribute
        uint32_t  max_shared_distance  :   6;    //  max number of Shared_Read
                                                 // requests from the leader, that
                                                 // were not yet matched by the
                                                 // follower. Number must be
                                                 // smaller than number of
                                                 // Convertor entries that can be
                                                 // used for reads
        uint32_t  RSVD_0               :   2;    // Nebulon auto filled RSVD [8:7]
        uint32_t  enable_timeout       :   1;    //  when cleared, Shared_Read
                                                 // timeout mechanism is disabled
        uint32_t  timeout_threshold    :  10;    //  timeout counter threshold
                                                 // bits [19:10] (bits [9:0] are
                                                 // 0). Counted in Uclks
        uint32_t  RSVD_1               :  12;    // Nebulon auto filled RSVD [31:20]

    }                                field;
    uint32_t                         val;
} axi_shared_read_cfg_t;
#endif
#define AXI_SHARED_READ_CFG_OFFSET 0x20
#define AXI_SHARED_READ_CFG_SCOPE 0x01
#define AXI_SHARED_READ_CFG_SIZE 32
#define AXI_SHARED_READ_CFG_BITFIELD_COUNT 0x04
#define AXI_SHARED_READ_CFG_RESET 0x00005221

#define AXI_SHARED_READ_CFG_SHARED_READ_ENABLE_LSB 0x0000
#define AXI_SHARED_READ_CFG_SHARED_READ_ENABLE_MSB 0x0000
#define AXI_SHARED_READ_CFG_SHARED_READ_ENABLE_RANGE 0x0001
#define AXI_SHARED_READ_CFG_SHARED_READ_ENABLE_MASK 0x00000001
#define AXI_SHARED_READ_CFG_SHARED_READ_ENABLE_RESET_VALUE 0x00000001

#define AXI_SHARED_READ_CFG_MAX_SHARED_DISTANCE_LSB 0x0001
#define AXI_SHARED_READ_CFG_MAX_SHARED_DISTANCE_MSB 0x0006
#define AXI_SHARED_READ_CFG_MAX_SHARED_DISTANCE_RANGE 0x0006
#define AXI_SHARED_READ_CFG_MAX_SHARED_DISTANCE_MASK 0x0000007e
#define AXI_SHARED_READ_CFG_MAX_SHARED_DISTANCE_RESET_VALUE 0x00000010

#define AXI_SHARED_READ_CFG_ENABLE_TIMEOUT_LSB 0x0009
#define AXI_SHARED_READ_CFG_ENABLE_TIMEOUT_MSB 0x0009
#define AXI_SHARED_READ_CFG_ENABLE_TIMEOUT_RANGE 0x0001
#define AXI_SHARED_READ_CFG_ENABLE_TIMEOUT_MASK 0x00000200
#define AXI_SHARED_READ_CFG_ENABLE_TIMEOUT_RESET_VALUE 0x00000001

#define AXI_SHARED_READ_CFG_TIMEOUT_THRESHOLD_LSB 0x000a
#define AXI_SHARED_READ_CFG_TIMEOUT_THRESHOLD_MSB 0x0013
#define AXI_SHARED_READ_CFG_TIMEOUT_THRESHOLD_RANGE 0x000a
#define AXI_SHARED_READ_CFG_TIMEOUT_THRESHOLD_MASK 0x000ffc00
#define AXI_SHARED_READ_CFG_TIMEOUT_THRESHOLD_RESET_VALUE 0x00000014


// --------------------------------------------------------------------------------------------------------------------------------

#ifndef axi_shared_read_status_FLAG
#define axi_shared_read_status_FLAG
// axi_shared_read_status desc:  A debug register for Shared_Read feature
typedef union {
    struct {
        uint32_t  error_flag           :   1;    //  Set on Shared_Read_Error
                                                 // event. When set, Shared_Read
                                                 // is disabled (regardless of
                                                 // enable bit). Write 0 clears
                                                 // this flag (and re-enabled
                                                 // Shared_Read)
        uint32_t  current_shared_distance :   6;    //  current value of shared_read
                                                 // distance
        uint32_t  RSVD_0               :   5;    // Nebulon auto filled RSVD [11:7]
        uint32_t  current_timeout      :  11;    //  current value of timeout
                                                 // counter
        uint32_t  RSVD_1               :   1;    // Nebulon auto filled RSVD [23:23]
        uint32_t  shared_leader_switch :   6;    //  incremented every time
                                                 // Shared_Leader is switched.
                                                 // Cleared on write
        uint32_t  RSVD_2               :   1;    // Nebulon auto filled RSVD [30:30]
        uint32_t  shared_leader        :   1;    //  current shared_leader. Has a
                                                 // meaning when
                                                 // current_shared_distance is not
                                                 // 0

    }                                field;
    uint32_t                         val;
} axi_shared_read_status_t;
#endif
#define AXI_SHARED_READ_STATUS_OFFSET 0x24
#define AXI_SHARED_READ_STATUS_SCOPE 0x01
#define AXI_SHARED_READ_STATUS_SIZE 32
#define AXI_SHARED_READ_STATUS_BITFIELD_COUNT 0x05
#define AXI_SHARED_READ_STATUS_RESET 0x00000000

#define AXI_SHARED_READ_STATUS_ERROR_FLAG_LSB 0x0000
#define AXI_SHARED_READ_STATUS_ERROR_FLAG_MSB 0x0000
#define AXI_SHARED_READ_STATUS_ERROR_FLAG_RANGE 0x0001
#define AXI_SHARED_READ_STATUS_ERROR_FLAG_MASK 0x00000001
#define AXI_SHARED_READ_STATUS_ERROR_FLAG_RESET_VALUE 0x00000000

#define AXI_SHARED_READ_STATUS_CURRENT_SHARED_DISTANCE_LSB 0x0001
#define AXI_SHARED_READ_STATUS_CURRENT_SHARED_DISTANCE_MSB 0x0006
#define AXI_SHARED_READ_STATUS_CURRENT_SHARED_DISTANCE_RANGE 0x0006
#define AXI_SHARED_READ_STATUS_CURRENT_SHARED_DISTANCE_MASK 0x0000007e
#define AXI_SHARED_READ_STATUS_CURRENT_SHARED_DISTANCE_RESET_VALUE 0x00000000

#define AXI_SHARED_READ_STATUS_CURRENT_TIMEOUT_LSB 0x000c
#define AXI_SHARED_READ_STATUS_CURRENT_TIMEOUT_MSB 0x0016
#define AXI_SHARED_READ_STATUS_CURRENT_TIMEOUT_RANGE 0x000b
#define AXI_SHARED_READ_STATUS_CURRENT_TIMEOUT_MASK 0x007ff000
#define AXI_SHARED_READ_STATUS_CURRENT_TIMEOUT_RESET_VALUE 0x00000000

#define AXI_SHARED_READ_STATUS_SHARED_LEADER_SWITCH_LSB 0x0018
#define AXI_SHARED_READ_STATUS_SHARED_LEADER_SWITCH_MSB 0x001d
#define AXI_SHARED_READ_STATUS_SHARED_LEADER_SWITCH_RANGE 0x0006
#define AXI_SHARED_READ_STATUS_SHARED_LEADER_SWITCH_MASK 0x3f000000
#define AXI_SHARED_READ_STATUS_SHARED_LEADER_SWITCH_RESET_VALUE 0x00000000

#define AXI_SHARED_READ_STATUS_SHARED_LEADER_LSB 0x001f
#define AXI_SHARED_READ_STATUS_SHARED_LEADER_MSB 0x001f
#define AXI_SHARED_READ_STATUS_SHARED_LEADER_RANGE 0x0001
#define AXI_SHARED_READ_STATUS_SHARED_LEADER_MASK 0x80000000
#define AXI_SHARED_READ_STATUS_SHARED_LEADER_RESET_VALUE 0x00000000


// --------------------------------------------------------------------------------------------------------------------------------

#ifndef dfx_stream_ctl_FLAG
#define dfx_stream_ctl_FLAG
// dfx_stream_ctl desc:  enable debug in tap (berez) method - constantly block streams, (by
// setting a bit) until released (by clearing the bit). Alos enables
// back-pressure
typedef union {
    struct {
        uint32_t  block_read_req_axi_0 :   1;    //  Block stream: AXI0 read
                                                 // request
        uint32_t  block_read_req_axi_1 :   1;    //  Block stream: AXI1 read
                                                 // request
        uint32_t  block_write_req_axi_0 :   1;    //  Block stream: AXI0 write
                                                 // request
        uint32_t  block_write_req_axi_1 :   1;    //  Block stream: AXI1 write
                                                 // request
        uint32_t  block_read_rsp_axi_0 :   1;    //  Block stream: AXI0 read
                                                 // response
        uint32_t  block_read_rsp_axi_1 :   1;    //  Block stream: AXI1 read
                                                 // response
        uint32_t  block_write_rsp_axi_0 :   1;    //  Block stream: AXI0 write
                                                 // response
        uint32_t  block_write_rsp_axi_1 :   1;    //  Block stream: AXI1 write
                                                 // response
        uint32_t  block_idi_c2u_req    :   1;    //  Block stream: IDI C2U request
        uint32_t  block_idi_c2u_rsp    :   1;    //  Block stream: IDI C2U
                                                 // response
        uint32_t  block_idi_c2u_data   :   1;    //  Block stream: IDI C2U data
        uint32_t  block_convertor_dealloc :   1;    //  Block de-allocation of
                                                 // Convertor entries
        uint32_t  RSVD_0               :  20;    // Nebulon auto filled RSVD [31:12]

    }                                field;
    uint32_t                         val;
} dfx_stream_ctl_t;
#endif
#define DFX_STREAM_CTL_OFFSET 0x28
#define DFX_STREAM_CTL_SCOPE 0x01
#define DFX_STREAM_CTL_SIZE 32
#define DFX_STREAM_CTL_BITFIELD_COUNT 0x0c
#define DFX_STREAM_CTL_RESET 0x00000000

#define DFX_STREAM_CTL_BLOCK_READ_REQ_AXI_0_LSB 0x0000
#define DFX_STREAM_CTL_BLOCK_READ_REQ_AXI_0_MSB 0x0000
#define DFX_STREAM_CTL_BLOCK_READ_REQ_AXI_0_RANGE 0x0001
#define DFX_STREAM_CTL_BLOCK_READ_REQ_AXI_0_MASK 0x00000001
#define DFX_STREAM_CTL_BLOCK_READ_REQ_AXI_0_RESET_VALUE 0x00000000

#define DFX_STREAM_CTL_BLOCK_READ_REQ_AXI_1_LSB 0x0001
#define DFX_STREAM_CTL_BLOCK_READ_REQ_AXI_1_MSB 0x0001
#define DFX_STREAM_CTL_BLOCK_READ_REQ_AXI_1_RANGE 0x0001
#define DFX_STREAM_CTL_BLOCK_READ_REQ_AXI_1_MASK 0x00000002
#define DFX_STREAM_CTL_BLOCK_READ_REQ_AXI_1_RESET_VALUE 0x00000000

#define DFX_STREAM_CTL_BLOCK_WRITE_REQ_AXI_0_LSB 0x0002
#define DFX_STREAM_CTL_BLOCK_WRITE_REQ_AXI_0_MSB 0x0002
#define DFX_STREAM_CTL_BLOCK_WRITE_REQ_AXI_0_RANGE 0x0001
#define DFX_STREAM_CTL_BLOCK_WRITE_REQ_AXI_0_MASK 0x00000004
#define DFX_STREAM_CTL_BLOCK_WRITE_REQ_AXI_0_RESET_VALUE 0x00000000

#define DFX_STREAM_CTL_BLOCK_WRITE_REQ_AXI_1_LSB 0x0003
#define DFX_STREAM_CTL_BLOCK_WRITE_REQ_AXI_1_MSB 0x0003
#define DFX_STREAM_CTL_BLOCK_WRITE_REQ_AXI_1_RANGE 0x0001
#define DFX_STREAM_CTL_BLOCK_WRITE_REQ_AXI_1_MASK 0x00000008
#define DFX_STREAM_CTL_BLOCK_WRITE_REQ_AXI_1_RESET_VALUE 0x00000000

#define DFX_STREAM_CTL_BLOCK_READ_RSP_AXI_0_LSB 0x0004
#define DFX_STREAM_CTL_BLOCK_READ_RSP_AXI_0_MSB 0x0004
#define DFX_STREAM_CTL_BLOCK_READ_RSP_AXI_0_RANGE 0x0001
#define DFX_STREAM_CTL_BLOCK_READ_RSP_AXI_0_MASK 0x00000010
#define DFX_STREAM_CTL_BLOCK_READ_RSP_AXI_0_RESET_VALUE 0x00000000

#define DFX_STREAM_CTL_BLOCK_READ_RSP_AXI_1_LSB 0x0005
#define DFX_STREAM_CTL_BLOCK_READ_RSP_AXI_1_MSB 0x0005
#define DFX_STREAM_CTL_BLOCK_READ_RSP_AXI_1_RANGE 0x0001
#define DFX_STREAM_CTL_BLOCK_READ_RSP_AXI_1_MASK 0x00000020
#define DFX_STREAM_CTL_BLOCK_READ_RSP_AXI_1_RESET_VALUE 0x00000000

#define DFX_STREAM_CTL_BLOCK_WRITE_RSP_AXI_0_LSB 0x0006
#define DFX_STREAM_CTL_BLOCK_WRITE_RSP_AXI_0_MSB 0x0006
#define DFX_STREAM_CTL_BLOCK_WRITE_RSP_AXI_0_RANGE 0x0001
#define DFX_STREAM_CTL_BLOCK_WRITE_RSP_AXI_0_MASK 0x00000040
#define DFX_STREAM_CTL_BLOCK_WRITE_RSP_AXI_0_RESET_VALUE 0x00000000

#define DFX_STREAM_CTL_BLOCK_WRITE_RSP_AXI_1_LSB 0x0007
#define DFX_STREAM_CTL_BLOCK_WRITE_RSP_AXI_1_MSB 0x0007
#define DFX_STREAM_CTL_BLOCK_WRITE_RSP_AXI_1_RANGE 0x0001
#define DFX_STREAM_CTL_BLOCK_WRITE_RSP_AXI_1_MASK 0x00000080
#define DFX_STREAM_CTL_BLOCK_WRITE_RSP_AXI_1_RESET_VALUE 0x00000000

#define DFX_STREAM_CTL_BLOCK_IDI_C2U_REQ_LSB 0x0008
#define DFX_STREAM_CTL_BLOCK_IDI_C2U_REQ_MSB 0x0008
#define DFX_STREAM_CTL_BLOCK_IDI_C2U_REQ_RANGE 0x0001
#define DFX_STREAM_CTL_BLOCK_IDI_C2U_REQ_MASK 0x00000100
#define DFX_STREAM_CTL_BLOCK_IDI_C2U_REQ_RESET_VALUE 0x00000000

#define DFX_STREAM_CTL_BLOCK_IDI_C2U_RSP_LSB 0x0009
#define DFX_STREAM_CTL_BLOCK_IDI_C2U_RSP_MSB 0x0009
#define DFX_STREAM_CTL_BLOCK_IDI_C2U_RSP_RANGE 0x0001
#define DFX_STREAM_CTL_BLOCK_IDI_C2U_RSP_MASK 0x00000200
#define DFX_STREAM_CTL_BLOCK_IDI_C2U_RSP_RESET_VALUE 0x00000000

#define DFX_STREAM_CTL_BLOCK_IDI_C2U_DATA_LSB 0x000a
#define DFX_STREAM_CTL_BLOCK_IDI_C2U_DATA_MSB 0x000a
#define DFX_STREAM_CTL_BLOCK_IDI_C2U_DATA_RANGE 0x0001
#define DFX_STREAM_CTL_BLOCK_IDI_C2U_DATA_MASK 0x00000400
#define DFX_STREAM_CTL_BLOCK_IDI_C2U_DATA_RESET_VALUE 0x00000000

#define DFX_STREAM_CTL_BLOCK_CONVERTOR_DEALLOC_LSB 0x000b
#define DFX_STREAM_CTL_BLOCK_CONVERTOR_DEALLOC_MSB 0x000b
#define DFX_STREAM_CTL_BLOCK_CONVERTOR_DEALLOC_RANGE 0x0001
#define DFX_STREAM_CTL_BLOCK_CONVERTOR_DEALLOC_MASK 0x00000800
#define DFX_STREAM_CTL_BLOCK_CONVERTOR_DEALLOC_RESET_VALUE 0x00000000


// --------------------------------------------------------------------------------------------------------------------------------

#ifndef hvm_modes_FLAG
#define hvm_modes_FLAG
// hvm_modes desc:  hvm_modes
typedef union {
    struct {
        uint32_t  force_colocated      :   1;    //  Send all IDI requests to
                                                 // co-located slice (for Slice
                                                 // SBFT)
        uint32_t  force_llc_opcode     :   1;    //  Use IDI request opcodes that,
                                                 // in case of LLC hit, do not go
                                                 // to external memory.(LLC hit
                                                 // should be ensured by test
                                                 // preload). All reads are mapped
                                                 // to RdCurr, CacheNear=0. Full
                                                 // line write mapped to ItomWr.
                                                 // Partial write mapped to RfoWr.
        uint32_t  addr_msb_is_ice_id   :   1;    //  Option to run 2 ICE in
                                                 // parallel. The test is expected
                                                 // to put zero(s) on upper AXI
                                                 // address bits. These bits are
                                                 // modified by the bridge
                                                 // according to USE_ADDR_BITS
        uint32_t  use_addr_bits        :   1;    //  0 - change upper address bit
                                                 // (addr[38]) to local ICE_ID. 1-
                                                 // change 4 upper address bits
                                                 // (addr[38:35]) to global ICE_ID
                                                 // (as defined in ICE_CONFIG)
        uint32_t  RSVD_0               :  28;    // Nebulon auto filled RSVD [31:4]

    }                                field;
    uint32_t                         val;
} hvm_modes_t;
#endif
#define HVM_MODES_OFFSET 0x2c
#define HVM_MODES_SCOPE 0x01
#define HVM_MODES_SIZE 32
#define HVM_MODES_BITFIELD_COUNT 0x04
#define HVM_MODES_RESET 0x00000000

#define HVM_MODES_FORCE_COLOCATED_LSB 0x0000
#define HVM_MODES_FORCE_COLOCATED_MSB 0x0000
#define HVM_MODES_FORCE_COLOCATED_RANGE 0x0001
#define HVM_MODES_FORCE_COLOCATED_MASK 0x00000001
#define HVM_MODES_FORCE_COLOCATED_RESET_VALUE 0x00000000

#define HVM_MODES_FORCE_LLC_OPCODE_LSB 0x0001
#define HVM_MODES_FORCE_LLC_OPCODE_MSB 0x0001
#define HVM_MODES_FORCE_LLC_OPCODE_RANGE 0x0001
#define HVM_MODES_FORCE_LLC_OPCODE_MASK 0x00000002
#define HVM_MODES_FORCE_LLC_OPCODE_RESET_VALUE 0x00000000

#define HVM_MODES_ADDR_MSB_IS_ICE_ID_LSB 0x0002
#define HVM_MODES_ADDR_MSB_IS_ICE_ID_MSB 0x0002
#define HVM_MODES_ADDR_MSB_IS_ICE_ID_RANGE 0x0001
#define HVM_MODES_ADDR_MSB_IS_ICE_ID_MASK 0x00000004
#define HVM_MODES_ADDR_MSB_IS_ICE_ID_RESET_VALUE 0x00000000

#define HVM_MODES_USE_ADDR_BITS_LSB 0x0003
#define HVM_MODES_USE_ADDR_BITS_MSB 0x0003
#define HVM_MODES_USE_ADDR_BITS_RANGE 0x0001
#define HVM_MODES_USE_ADDR_BITS_MASK 0x00000008
#define HVM_MODES_USE_ADDR_BITS_RESET_VALUE 0x00000000


// --------------------------------------------------------------------------------------------------------------------------------

#ifndef icebo_pmon_global_FLAG
#define icebo_pmon_global_FLAG
// icebo_pmon_global desc:  icebo pmon global control
typedef union {
    struct {
        uint32_t  enable_counter_0     :   1;    //  Enable counter 0
        uint32_t  enable_counter_1     :   1;    //  Enable counter 1
        uint32_t  enable_counter_2     :   1;    //  Enable counter 2
        uint32_t  enable_counter_3     :   1;    //  Enable counter 3
        uint32_t  RSVD_0               :   4;    // Nebulon auto filled RSVD [7:4]
        uint32_t  reset_pmon           :   1;    //  Reset all PMON counters and
                                                 // associated logic
        uint32_t  RSVD_1               :  23;    // Nebulon auto filled RSVD [31:9]

    }                                field;
    uint32_t                         val;
} icebo_pmon_global_t;
#endif
#define ICEBO_PMON_GLOBAL_OFFSET 0x30
#define ICEBO_PMON_GLOBAL_SCOPE 0x01
#define ICEBO_PMON_GLOBAL_SIZE 32
#define ICEBO_PMON_GLOBAL_BITFIELD_COUNT 0x05
#define ICEBO_PMON_GLOBAL_RESET 0x00000000

#define ICEBO_PMON_GLOBAL_ENABLE_COUNTER_0_LSB 0x0000
#define ICEBO_PMON_GLOBAL_ENABLE_COUNTER_0_MSB 0x0000
#define ICEBO_PMON_GLOBAL_ENABLE_COUNTER_0_RANGE 0x0001
#define ICEBO_PMON_GLOBAL_ENABLE_COUNTER_0_MASK 0x00000001
#define ICEBO_PMON_GLOBAL_ENABLE_COUNTER_0_RESET_VALUE 0x00000000

#define ICEBO_PMON_GLOBAL_ENABLE_COUNTER_1_LSB 0x0001
#define ICEBO_PMON_GLOBAL_ENABLE_COUNTER_1_MSB 0x0001
#define ICEBO_PMON_GLOBAL_ENABLE_COUNTER_1_RANGE 0x0001
#define ICEBO_PMON_GLOBAL_ENABLE_COUNTER_1_MASK 0x00000002
#define ICEBO_PMON_GLOBAL_ENABLE_COUNTER_1_RESET_VALUE 0x00000000

#define ICEBO_PMON_GLOBAL_ENABLE_COUNTER_2_LSB 0x0002
#define ICEBO_PMON_GLOBAL_ENABLE_COUNTER_2_MSB 0x0002
#define ICEBO_PMON_GLOBAL_ENABLE_COUNTER_2_RANGE 0x0001
#define ICEBO_PMON_GLOBAL_ENABLE_COUNTER_2_MASK 0x00000004
#define ICEBO_PMON_GLOBAL_ENABLE_COUNTER_2_RESET_VALUE 0x00000000

#define ICEBO_PMON_GLOBAL_ENABLE_COUNTER_3_LSB 0x0003
#define ICEBO_PMON_GLOBAL_ENABLE_COUNTER_3_MSB 0x0003
#define ICEBO_PMON_GLOBAL_ENABLE_COUNTER_3_RANGE 0x0001
#define ICEBO_PMON_GLOBAL_ENABLE_COUNTER_3_MASK 0x00000008
#define ICEBO_PMON_GLOBAL_ENABLE_COUNTER_3_RESET_VALUE 0x00000000

#define ICEBO_PMON_GLOBAL_RESET_PMON_LSB 0x0008
#define ICEBO_PMON_GLOBAL_RESET_PMON_MSB 0x0008
#define ICEBO_PMON_GLOBAL_RESET_PMON_RANGE 0x0001
#define ICEBO_PMON_GLOBAL_RESET_PMON_MASK 0x00000100
#define ICEBO_PMON_GLOBAL_RESET_PMON_RESET_VALUE 0x00000000


// --------------------------------------------------------------------------------------------------------------------------------

#ifndef icebo_pmon_event_0_FLAG
#define icebo_pmon_event_0_FLAG
// icebo_pmon_event_0 desc:  icebo pmon event 0 and 1
typedef union {
    struct {
        uint32_t  event_to_count       :   3;    //  0 CONVERTOR_ALLCOATIONS -
                                                 // number of transactions
                                                 // allocated to Convertor (number
                                                 // of IDI requests. AXI burst of
                                                 // N is counted N times) 1
                                                 // VALID_CONVERTOR_ENTRIES -
                                                 // number of entries that are
                                                 // valid in Convertor
                                                 // (incremented every cycle by
                                                 // number of valid Convertor
                                                 // entries). In order to count
                                                 // avarage Convertor occupancy,
                                                 // use 2 counters in parallel,
                                                 // one to count number of valid
                                                 // transations and the other to
                                                 // count allocations, and use the
                                                 // same mask in both. Then
                                                 // avarage occupancy is
                                                 // VALID_CONVERTOR_ENTRIES /
                                                 // CONVERTOR_ALLOCATIONS. Note:
                                                 // this event is applicable to
                                                 // Counter0 only other reserved
        uint32_t  axi_agent_mask       :   2;    //  bitmask one or more bits can
                                                 // be set 3 count transactions
                                                 // of AXI_0 4 count transactions
                                                 // of AXI_1
        uint32_t  RSVD_0               :   2;    // Nebulon auto filled RSVD [6:5]
        uint32_t  request_type_mask    :   3;    //  bitmask one or more bits can
                                                 // be set 7 count read 8 count
                                                 // write 9 count prefetch
        uint32_t  RSVD_1               :   1;    // Nebulon auto filled RSVD [10:10]
        uint32_t  read_type_mask       :   3;    //  bitmask which reads to count,
                                                 // when reads are counted (one or
                                                 // more bit can be set) 11 count
                                                 // non-shared read 12 count
                                                 // shared read of the shared
                                                 // leader (or when there is no
                                                 // leader) 13 count shared read
                                                 // of the non-leader
        uint32_t  RSVD_2               :   3;    // Nebulon auto filled RSVD [16:14]
        uint32_t  write_type_mask      :   2;    //  bitmask which writes to
                                                 // count, when writes are counted
                                                 // (one or more bit can be set)
                                                 // 17 count full line write 18
                                                 // count partial write
        uint32_t  RSVD_3               :   2;    // Nebulon auto filled RSVD [20:19]
        uint32_t  target_mask          :   2;    //  bitmask one or more bits can
                                                 // be set 21 count memory
                                                 // accesses (AxCACHE is not 0000)
                                                 // 22 count MMIO accesses
                                                 // (defined by AxCACHE=0000,
                                                 // although such access can also
                                                 // go to memory)
        uint32_t  RSVD_4               :   1;    // Nebulon auto filled RSVD [23:23]
        uint32_t  burst_mask           :   3;    //  bitmask one or more bits can
                                                 // be set 24 count if
                                                 // transaction is a not a part of
                                                 // burst 25 count if transaction
                                                 // is a part of burst, but not
                                                 // last 26 count if transaction
                                                 // is a burst-last (when burst
                                                 // size > 1)
        uint32_t  RSVD_5               :   1;    // Nebulon auto filled RSVD [27:27]
        uint32_t  llc_mask             :   2;    //  bitmask One or more bits can
                                                 // be set. Note: when counting
                                                 // VALID_CONVERTOR_ENTRY, this
                                                 // mask should be ALL_1,
                                                 // otherwise counter value is
                                                 // undefined 28 count LLC hit
                                                 // 29 count LLC miss
        uint32_t  RSVD_6               :   2;    // Nebulon auto filled RSVD [31:30]

    }                                field;
    uint32_t                         val;
} icebo_pmon_event_0_t;
#endif
#define ICEBO_PMON_EVENT_0_OFFSET 0x34
#define ICEBO_PMON_EVENT_0_SCOPE 0x01
#define ICEBO_PMON_EVENT_0_SIZE 32
#define ICEBO_PMON_EVENT_0_BITFIELD_COUNT 0x08
#define ICEBO_PMON_EVENT_0_RESET 0x00000000

#define ICEBO_PMON_EVENT_0_EVENT_TO_COUNT_LSB 0x0000
#define ICEBO_PMON_EVENT_0_EVENT_TO_COUNT_MSB 0x0002
#define ICEBO_PMON_EVENT_0_EVENT_TO_COUNT_RANGE 0x0003
#define ICEBO_PMON_EVENT_0_EVENT_TO_COUNT_MASK 0x00000007
#define ICEBO_PMON_EVENT_0_EVENT_TO_COUNT_RESET_VALUE 0x00000000

#define ICEBO_PMON_EVENT_0_AXI_AGENT_MASK_LSB 0x0003
#define ICEBO_PMON_EVENT_0_AXI_AGENT_MASK_MSB 0x0004
#define ICEBO_PMON_EVENT_0_AXI_AGENT_MASK_RANGE 0x0002
#define ICEBO_PMON_EVENT_0_AXI_AGENT_MASK_MASK 0x00000018
#define ICEBO_PMON_EVENT_0_AXI_AGENT_MASK_RESET_VALUE 0x00000000

#define ICEBO_PMON_EVENT_0_REQUEST_TYPE_MASK_LSB 0x0007
#define ICEBO_PMON_EVENT_0_REQUEST_TYPE_MASK_MSB 0x0009
#define ICEBO_PMON_EVENT_0_REQUEST_TYPE_MASK_RANGE 0x0003
#define ICEBO_PMON_EVENT_0_REQUEST_TYPE_MASK_MASK 0x00000380
#define ICEBO_PMON_EVENT_0_REQUEST_TYPE_MASK_RESET_VALUE 0x00000000

#define ICEBO_PMON_EVENT_0_READ_TYPE_MASK_LSB 0x000b
#define ICEBO_PMON_EVENT_0_READ_TYPE_MASK_MSB 0x000d
#define ICEBO_PMON_EVENT_0_READ_TYPE_MASK_RANGE 0x0003
#define ICEBO_PMON_EVENT_0_READ_TYPE_MASK_MASK 0x00003800
#define ICEBO_PMON_EVENT_0_READ_TYPE_MASK_RESET_VALUE 0x00000000

#define ICEBO_PMON_EVENT_0_WRITE_TYPE_MASK_LSB 0x0011
#define ICEBO_PMON_EVENT_0_WRITE_TYPE_MASK_MSB 0x0012
#define ICEBO_PMON_EVENT_0_WRITE_TYPE_MASK_RANGE 0x0002
#define ICEBO_PMON_EVENT_0_WRITE_TYPE_MASK_MASK 0x00060000
#define ICEBO_PMON_EVENT_0_WRITE_TYPE_MASK_RESET_VALUE 0x00000000

#define ICEBO_PMON_EVENT_0_TARGET_MASK_LSB 0x0015
#define ICEBO_PMON_EVENT_0_TARGET_MASK_MSB 0x0016
#define ICEBO_PMON_EVENT_0_TARGET_MASK_RANGE 0x0002
#define ICEBO_PMON_EVENT_0_TARGET_MASK_MASK 0x00600000
#define ICEBO_PMON_EVENT_0_TARGET_MASK_RESET_VALUE 0x00000000

#define ICEBO_PMON_EVENT_0_BURST_MASK_LSB 0x0018
#define ICEBO_PMON_EVENT_0_BURST_MASK_MSB 0x001a
#define ICEBO_PMON_EVENT_0_BURST_MASK_RANGE 0x0003
#define ICEBO_PMON_EVENT_0_BURST_MASK_MASK 0x07000000
#define ICEBO_PMON_EVENT_0_BURST_MASK_RESET_VALUE 0x00000000

#define ICEBO_PMON_EVENT_0_LLC_MASK_LSB 0x001c
#define ICEBO_PMON_EVENT_0_LLC_MASK_MSB 0x001d
#define ICEBO_PMON_EVENT_0_LLC_MASK_RANGE 0x0002
#define ICEBO_PMON_EVENT_0_LLC_MASK_MASK 0x30000000
#define ICEBO_PMON_EVENT_0_LLC_MASK_RESET_VALUE 0x00000000


// --------------------------------------------------------------------------------------------------------------------------------

#ifndef icebo_pmon_event_1_FLAG
#define icebo_pmon_event_1_FLAG
// icebo_pmon_event_1 desc:  icebo pmon event 0 and 1
typedef union {
    struct {
        uint32_t  event_to_count       :   3;    //  0 CONVERTOR_ALLCOATIONS -
                                                 // number of transactions
                                                 // allocated to Convertor (number
                                                 // of IDI requests. AXI burst of
                                                 // N is counted N times) 1
                                                 // VALID_CONVERTOR_ENTRIES -
                                                 // number of entries that are
                                                 // valid in Convertor
                                                 // (incremented every cycle by
                                                 // number of valid Convertor
                                                 // entries). In order to count
                                                 // avarage Convertor occupancy,
                                                 // use 2 counters in parallel,
                                                 // one to count number of valid
                                                 // transations and the other to
                                                 // count allocations, and use the
                                                 // same mask in both. Then
                                                 // avarage occupancy is
                                                 // VALID_CONVERTOR_ENTRIES /
                                                 // CONVERTOR_ALLOCATIONS. Note:
                                                 // this event is applicable to
                                                 // Counter0 only other reserved
        uint32_t  axi_agent_mask       :   2;    //  bitmask one or more bits can
                                                 // be set 3 count transactions
                                                 // of AXI_0 4 count transactions
                                                 // of AXI_1
        uint32_t  RSVD_0               :   2;    // Nebulon auto filled RSVD [6:5]
        uint32_t  request_type_mask    :   3;    //  bitmask one or more bits can
                                                 // be set 7 count read 8 count
                                                 // write 9 count prefetch
        uint32_t  RSVD_1               :   1;    // Nebulon auto filled RSVD [10:10]
        uint32_t  read_type_mask       :   3;    //  bitmask which reads to count,
                                                 // when reads are counted (one or
                                                 // more bit can be set) 11 count
                                                 // non-shared read 12 count
                                                 // shared read of the shared
                                                 // leader (or when there is no
                                                 // leader) 13 count shared read
                                                 // of the non-leader
        uint32_t  RSVD_2               :   3;    // Nebulon auto filled RSVD [16:14]
        uint32_t  write_type_mask      :   2;    //  bitmask which writes to
                                                 // count, when writes are counted
                                                 // (one or more bit can be set)
                                                 // 17 count full line write 18
                                                 // count partial write
        uint32_t  RSVD_3               :   2;    // Nebulon auto filled RSVD [20:19]
        uint32_t  target_mask          :   2;    //  bitmask one or more bits can
                                                 // be set 21 count memory
                                                 // accesses (AxCACHE is not 0000)
                                                 // 22 count MMIO accesses
                                                 // (defined by AxCACHE=0000,
                                                 // although such access can also
                                                 // go to memory)
        uint32_t  RSVD_4               :   1;    // Nebulon auto filled RSVD [23:23]
        uint32_t  burst_mask           :   3;    //  bitmask one or more bits can
                                                 // be set 24 count if
                                                 // transaction is a not a part of
                                                 // burst 25 count if transaction
                                                 // is a part of burst, but not
                                                 // last 26 count if transaction
                                                 // is a burst-last (when burst
                                                 // size > 1)
        uint32_t  RSVD_5               :   1;    // Nebulon auto filled RSVD [27:27]
        uint32_t  llc_mask             :   2;    //  bitmask One or more bits can
                                                 // be set. Note: when counting
                                                 // VALID_CONVERTOR_ENTRY, this
                                                 // mask should be ALL_1,
                                                 // otherwise counter value is
                                                 // undefined 28 count LLC hit
                                                 // 29 count LLC miss
        uint32_t  RSVD_6               :   2;    // Nebulon auto filled RSVD [31:30]

    }                                field;
    uint32_t                         val;
} icebo_pmon_event_1_t;
#endif
#define ICEBO_PMON_EVENT_1_OFFSET 0x38
#define ICEBO_PMON_EVENT_1_SCOPE 0x01
#define ICEBO_PMON_EVENT_1_SIZE 32
#define ICEBO_PMON_EVENT_1_BITFIELD_COUNT 0x08
#define ICEBO_PMON_EVENT_1_RESET 0x00000000

#define ICEBO_PMON_EVENT_1_EVENT_TO_COUNT_LSB 0x0000
#define ICEBO_PMON_EVENT_1_EVENT_TO_COUNT_MSB 0x0002
#define ICEBO_PMON_EVENT_1_EVENT_TO_COUNT_RANGE 0x0003
#define ICEBO_PMON_EVENT_1_EVENT_TO_COUNT_MASK 0x00000007
#define ICEBO_PMON_EVENT_1_EVENT_TO_COUNT_RESET_VALUE 0x00000000

#define ICEBO_PMON_EVENT_1_AXI_AGENT_MASK_LSB 0x0003
#define ICEBO_PMON_EVENT_1_AXI_AGENT_MASK_MSB 0x0004
#define ICEBO_PMON_EVENT_1_AXI_AGENT_MASK_RANGE 0x0002
#define ICEBO_PMON_EVENT_1_AXI_AGENT_MASK_MASK 0x00000018
#define ICEBO_PMON_EVENT_1_AXI_AGENT_MASK_RESET_VALUE 0x00000000

#define ICEBO_PMON_EVENT_1_REQUEST_TYPE_MASK_LSB 0x0007
#define ICEBO_PMON_EVENT_1_REQUEST_TYPE_MASK_MSB 0x0009
#define ICEBO_PMON_EVENT_1_REQUEST_TYPE_MASK_RANGE 0x0003
#define ICEBO_PMON_EVENT_1_REQUEST_TYPE_MASK_MASK 0x00000380
#define ICEBO_PMON_EVENT_1_REQUEST_TYPE_MASK_RESET_VALUE 0x00000000

#define ICEBO_PMON_EVENT_1_READ_TYPE_MASK_LSB 0x000b
#define ICEBO_PMON_EVENT_1_READ_TYPE_MASK_MSB 0x000d
#define ICEBO_PMON_EVENT_1_READ_TYPE_MASK_RANGE 0x0003
#define ICEBO_PMON_EVENT_1_READ_TYPE_MASK_MASK 0x00003800
#define ICEBO_PMON_EVENT_1_READ_TYPE_MASK_RESET_VALUE 0x00000000

#define ICEBO_PMON_EVENT_1_WRITE_TYPE_MASK_LSB 0x0011
#define ICEBO_PMON_EVENT_1_WRITE_TYPE_MASK_MSB 0x0012
#define ICEBO_PMON_EVENT_1_WRITE_TYPE_MASK_RANGE 0x0002
#define ICEBO_PMON_EVENT_1_WRITE_TYPE_MASK_MASK 0x00060000
#define ICEBO_PMON_EVENT_1_WRITE_TYPE_MASK_RESET_VALUE 0x00000000

#define ICEBO_PMON_EVENT_1_TARGET_MASK_LSB 0x0015
#define ICEBO_PMON_EVENT_1_TARGET_MASK_MSB 0x0016
#define ICEBO_PMON_EVENT_1_TARGET_MASK_RANGE 0x0002
#define ICEBO_PMON_EVENT_1_TARGET_MASK_MASK 0x00600000
#define ICEBO_PMON_EVENT_1_TARGET_MASK_RESET_VALUE 0x00000000

#define ICEBO_PMON_EVENT_1_BURST_MASK_LSB 0x0018
#define ICEBO_PMON_EVENT_1_BURST_MASK_MSB 0x001a
#define ICEBO_PMON_EVENT_1_BURST_MASK_RANGE 0x0003
#define ICEBO_PMON_EVENT_1_BURST_MASK_MASK 0x07000000
#define ICEBO_PMON_EVENT_1_BURST_MASK_RESET_VALUE 0x00000000

#define ICEBO_PMON_EVENT_1_LLC_MASK_LSB 0x001c
#define ICEBO_PMON_EVENT_1_LLC_MASK_MSB 0x001d
#define ICEBO_PMON_EVENT_1_LLC_MASK_RANGE 0x0002
#define ICEBO_PMON_EVENT_1_LLC_MASK_MASK 0x30000000
#define ICEBO_PMON_EVENT_1_LLC_MASK_RESET_VALUE 0x00000000


// --------------------------------------------------------------------------------------------------------------------------------

#ifndef icebo_pmon_event_2_FLAG
#define icebo_pmon_event_2_FLAG
// icebo_pmon_event_2 desc:  icebo pmon event 2 and 3
typedef union {
    struct {
        uint32_t  event_to_count       :   4;    //  0 Convertor occupancy is
                                                 // above/below threshold 1
                                                 // IDI_C2U_REQ credit is
                                                 // above/below threshold 2
                                                 // IDI_C2U_DATA credit is
                                                 // above/below threshold 3
                                                 // Current_Shared_Distance is
                                                 // above/below threshold 4
                                                 // Back-Pressure from AXI read
                                                 // data channel (FIFO full) 5
                                                 // Back-Pressure from AXI write
                                                 // response channel (FIFO full)
                                                 // 6 Shared_Leader is stalled
                                                 // other reserved
        uint32_t  above_below          :   1;    //  for events that count above
                                                 // or below threshold 0 below
                                                 // threshold 1 above threshold
        uint32_t  pmon_threshold       :   8;    //  for events that count above
                                                 // or below threshold
        uint32_t  RSVD_0               :   2;    // Nebulon auto filled RSVD [14:13]
        uint32_t  level_edge           :   1;    //  0 count rising edge of the
                                                 // event 1 count cycles in which
                                                 // the event is active
        uint32_t  axi_agent_mask       :   2;    //  for AXI related events
                                                 // (back-pressure and stall) 0
                                                 // event for all AXI agents at
                                                 // once (not relevant for
                                                 // shared_read stall) 1 event
                                                 // for AXI agent 0 only 2 event
                                                 // for AXI agent 1 only 3 event
                                                 // for any AXI agent
        uint32_t  RSVD_1               :  14;    // Nebulon auto filled RSVD [31:18]

    }                                field;
    uint32_t                         val;
} icebo_pmon_event_2_t;
#endif
#define ICEBO_PMON_EVENT_2_OFFSET 0x3c
#define ICEBO_PMON_EVENT_2_SCOPE 0x01
#define ICEBO_PMON_EVENT_2_SIZE 32
#define ICEBO_PMON_EVENT_2_BITFIELD_COUNT 0x05
#define ICEBO_PMON_EVENT_2_RESET 0x00000000

#define ICEBO_PMON_EVENT_2_EVENT_TO_COUNT_LSB 0x0000
#define ICEBO_PMON_EVENT_2_EVENT_TO_COUNT_MSB 0x0003
#define ICEBO_PMON_EVENT_2_EVENT_TO_COUNT_RANGE 0x0004
#define ICEBO_PMON_EVENT_2_EVENT_TO_COUNT_MASK 0x0000000f
#define ICEBO_PMON_EVENT_2_EVENT_TO_COUNT_RESET_VALUE 0x00000000

#define ICEBO_PMON_EVENT_2_ABOVE_BELOW_LSB 0x0004
#define ICEBO_PMON_EVENT_2_ABOVE_BELOW_MSB 0x0004
#define ICEBO_PMON_EVENT_2_ABOVE_BELOW_RANGE 0x0001
#define ICEBO_PMON_EVENT_2_ABOVE_BELOW_MASK 0x00000010
#define ICEBO_PMON_EVENT_2_ABOVE_BELOW_RESET_VALUE 0x00000000

#define ICEBO_PMON_EVENT_2_PMON_THRESHOLD_LSB 0x0005
#define ICEBO_PMON_EVENT_2_PMON_THRESHOLD_MSB 0x000c
#define ICEBO_PMON_EVENT_2_PMON_THRESHOLD_RANGE 0x0008
#define ICEBO_PMON_EVENT_2_PMON_THRESHOLD_MASK 0x00001fe0
#define ICEBO_PMON_EVENT_2_PMON_THRESHOLD_RESET_VALUE 0x00000000

#define ICEBO_PMON_EVENT_2_LEVEL_EDGE_LSB 0x000f
#define ICEBO_PMON_EVENT_2_LEVEL_EDGE_MSB 0x000f
#define ICEBO_PMON_EVENT_2_LEVEL_EDGE_RANGE 0x0001
#define ICEBO_PMON_EVENT_2_LEVEL_EDGE_MASK 0x00008000
#define ICEBO_PMON_EVENT_2_LEVEL_EDGE_RESET_VALUE 0x00000000

#define ICEBO_PMON_EVENT_2_AXI_AGENT_MASK_LSB 0x0010
#define ICEBO_PMON_EVENT_2_AXI_AGENT_MASK_MSB 0x0011
#define ICEBO_PMON_EVENT_2_AXI_AGENT_MASK_RANGE 0x0002
#define ICEBO_PMON_EVENT_2_AXI_AGENT_MASK_MASK 0x00030000
#define ICEBO_PMON_EVENT_2_AXI_AGENT_MASK_RESET_VALUE 0x00000000


// --------------------------------------------------------------------------------------------------------------------------------

#ifndef icebo_pmon_event_3_FLAG
#define icebo_pmon_event_3_FLAG
// icebo_pmon_event_3 desc:  icebo pmon event 2 and 3
typedef union {
    struct {
        uint32_t  event_to_count       :   4;    //  0 Convertor occupancy is
                                                 // above/below threshold 1
                                                 // IDI_C2U_REQ credit is
                                                 // above/below threshold 2
                                                 // IDI_C2U_DATA credit is
                                                 // above/below threshold 3
                                                 // Current_Shared_Distance is
                                                 // above/below threshold 4
                                                 // Back-Pressure from AXI read
                                                 // data channel (FIFO full) 5
                                                 // Back-Pressure from AXI write
                                                 // response channel (FIFO full)
                                                 // 6 Shared_Leader is stalled
                                                 // other reserved
        uint32_t  above_below          :   1;    //  for events that count above
                                                 // or below threshold 0 below
                                                 // threshold 1 above threshold
        uint32_t  pmon_threshold       :   8;    //  for events that count above
                                                 // or below threshold
        uint32_t  RSVD_0               :   2;    // Nebulon auto filled RSVD [14:13]
        uint32_t  level_edge           :   1;    //  0 count rising edge of the
                                                 // event 1 count cycles in which
                                                 // the event is active
        uint32_t  axi_agent_mask       :   2;    //  for AXI related events
                                                 // (back-pressure and stall) 0
                                                 // event for all AXI agents at
                                                 // once (not relevant for
                                                 // shared_read stall) 1 event
                                                 // for AXI agent 0 only 2 event
                                                 // for AXI agent 1 only 3 event
                                                 // for any AXI agent
        uint32_t  RSVD_1               :  14;    // Nebulon auto filled RSVD [31:18]

    }                                field;
    uint32_t                         val;
} icebo_pmon_event_3_t;
#endif
#define ICEBO_PMON_EVENT_3_OFFSET 0x40
#define ICEBO_PMON_EVENT_3_SCOPE 0x01
#define ICEBO_PMON_EVENT_3_SIZE 32
#define ICEBO_PMON_EVENT_3_BITFIELD_COUNT 0x05
#define ICEBO_PMON_EVENT_3_RESET 0x00000000

#define ICEBO_PMON_EVENT_3_EVENT_TO_COUNT_LSB 0x0000
#define ICEBO_PMON_EVENT_3_EVENT_TO_COUNT_MSB 0x0003
#define ICEBO_PMON_EVENT_3_EVENT_TO_COUNT_RANGE 0x0004
#define ICEBO_PMON_EVENT_3_EVENT_TO_COUNT_MASK 0x0000000f
#define ICEBO_PMON_EVENT_3_EVENT_TO_COUNT_RESET_VALUE 0x00000000

#define ICEBO_PMON_EVENT_3_ABOVE_BELOW_LSB 0x0004
#define ICEBO_PMON_EVENT_3_ABOVE_BELOW_MSB 0x0004
#define ICEBO_PMON_EVENT_3_ABOVE_BELOW_RANGE 0x0001
#define ICEBO_PMON_EVENT_3_ABOVE_BELOW_MASK 0x00000010
#define ICEBO_PMON_EVENT_3_ABOVE_BELOW_RESET_VALUE 0x00000000

#define ICEBO_PMON_EVENT_3_PMON_THRESHOLD_LSB 0x0005
#define ICEBO_PMON_EVENT_3_PMON_THRESHOLD_MSB 0x000c
#define ICEBO_PMON_EVENT_3_PMON_THRESHOLD_RANGE 0x0008
#define ICEBO_PMON_EVENT_3_PMON_THRESHOLD_MASK 0x00001fe0
#define ICEBO_PMON_EVENT_3_PMON_THRESHOLD_RESET_VALUE 0x00000000

#define ICEBO_PMON_EVENT_3_LEVEL_EDGE_LSB 0x000f
#define ICEBO_PMON_EVENT_3_LEVEL_EDGE_MSB 0x000f
#define ICEBO_PMON_EVENT_3_LEVEL_EDGE_RANGE 0x0001
#define ICEBO_PMON_EVENT_3_LEVEL_EDGE_MASK 0x00008000
#define ICEBO_PMON_EVENT_3_LEVEL_EDGE_RESET_VALUE 0x00000000

#define ICEBO_PMON_EVENT_3_AXI_AGENT_MASK_LSB 0x0010
#define ICEBO_PMON_EVENT_3_AXI_AGENT_MASK_MSB 0x0011
#define ICEBO_PMON_EVENT_3_AXI_AGENT_MASK_RANGE 0x0002
#define ICEBO_PMON_EVENT_3_AXI_AGENT_MASK_MASK 0x00030000
#define ICEBO_PMON_EVENT_3_AXI_AGENT_MASK_RESET_VALUE 0x00000000


// --------------------------------------------------------------------------------------------------------------------------------

#ifndef icebo_pmon_status_FLAG
#define icebo_pmon_status_FLAG
// icebo_pmon_status desc:  icebo pmon status
typedef union {
    struct {
        uint32_t  overflow_0           :   1;    //  Overflow of counter 0
                                                 // (sticky, can be written to 0)
        uint32_t  overflow_1           :   1;    //  Overflow of counter 1
                                                 // (sticky, can be written to 0)
        uint32_t  overflow_2           :   1;    //  Overflow of counter 2
                                                 // (sticky, can be written to 0)
        uint32_t  overflow_3           :   1;    //  Overflow of counter 3
                                                 // (sticky, can be written to 0)
        uint32_t  RSVD_0               :  28;    // Nebulon auto filled RSVD [31:4]

    }                                field;
    uint32_t                         val;
} icebo_pmon_status_t;
#endif
#define ICEBO_PMON_STATUS_OFFSET 0x44
#define ICEBO_PMON_STATUS_SCOPE 0x01
#define ICEBO_PMON_STATUS_SIZE 32
#define ICEBO_PMON_STATUS_BITFIELD_COUNT 0x04
#define ICEBO_PMON_STATUS_RESET 0x00000000

#define ICEBO_PMON_STATUS_OVERFLOW_0_LSB 0x0000
#define ICEBO_PMON_STATUS_OVERFLOW_0_MSB 0x0000
#define ICEBO_PMON_STATUS_OVERFLOW_0_RANGE 0x0001
#define ICEBO_PMON_STATUS_OVERFLOW_0_MASK 0x00000001
#define ICEBO_PMON_STATUS_OVERFLOW_0_RESET_VALUE 0x00000000

#define ICEBO_PMON_STATUS_OVERFLOW_1_LSB 0x0001
#define ICEBO_PMON_STATUS_OVERFLOW_1_MSB 0x0001
#define ICEBO_PMON_STATUS_OVERFLOW_1_RANGE 0x0001
#define ICEBO_PMON_STATUS_OVERFLOW_1_MASK 0x00000002
#define ICEBO_PMON_STATUS_OVERFLOW_1_RESET_VALUE 0x00000000

#define ICEBO_PMON_STATUS_OVERFLOW_2_LSB 0x0002
#define ICEBO_PMON_STATUS_OVERFLOW_2_MSB 0x0002
#define ICEBO_PMON_STATUS_OVERFLOW_2_RANGE 0x0001
#define ICEBO_PMON_STATUS_OVERFLOW_2_MASK 0x00000004
#define ICEBO_PMON_STATUS_OVERFLOW_2_RESET_VALUE 0x00000000

#define ICEBO_PMON_STATUS_OVERFLOW_3_LSB 0x0003
#define ICEBO_PMON_STATUS_OVERFLOW_3_MSB 0x0003
#define ICEBO_PMON_STATUS_OVERFLOW_3_RANGE 0x0001
#define ICEBO_PMON_STATUS_OVERFLOW_3_MASK 0x00000008
#define ICEBO_PMON_STATUS_OVERFLOW_3_RESET_VALUE 0x00000000


// --------------------------------------------------------------------------------------------------------------------------------

#ifndef icebo_pmon_counter_0_FLAG
#define icebo_pmon_counter_0_FLAG
// icebo_pmon_counter_0 desc:  icebo pmon counter
typedef union {
    struct {
        uint64_t  pmon_counter         :  64;    // 

    }                                field;
    uint64_t                         val;
} icebo_pmon_counter_0_t;
#endif
#define ICEBO_PMON_COUNTER_0_OFFSET 0x48
#define ICEBO_PMON_COUNTER_0_SCOPE 0x01
#define ICEBO_PMON_COUNTER_0_SIZE 64
#define ICEBO_PMON_COUNTER_0_BITFIELD_COUNT 0x01
#define ICEBO_PMON_COUNTER_0_RESET 0x00000000

#define ICEBO_PMON_COUNTER_0_PMON_COUNTER_LSB 0x0000
#define ICEBO_PMON_COUNTER_0_PMON_COUNTER_MSB 0x003f
#define ICEBO_PMON_COUNTER_0_PMON_COUNTER_RANGE 0x0040
#define ICEBO_PMON_COUNTER_0_PMON_COUNTER_MASK 0xffffffffffffffff
#define ICEBO_PMON_COUNTER_0_PMON_COUNTER_RESET_VALUE 0x00000000


// --------------------------------------------------------------------------------------------------------------------------------

#ifndef icebo_pmon_counter_1_FLAG
#define icebo_pmon_counter_1_FLAG
// icebo_pmon_counter_1 desc:  icebo pmon counter
typedef union {
    struct {
        uint64_t  pmon_counter         :  64;    // 

    }                                field;
    uint64_t                         val;
} icebo_pmon_counter_1_t;
#endif
#define ICEBO_PMON_COUNTER_1_OFFSET 0x50
#define ICEBO_PMON_COUNTER_1_SCOPE 0x01
#define ICEBO_PMON_COUNTER_1_SIZE 64
#define ICEBO_PMON_COUNTER_1_BITFIELD_COUNT 0x01
#define ICEBO_PMON_COUNTER_1_RESET 0x00000000

#define ICEBO_PMON_COUNTER_1_PMON_COUNTER_LSB 0x0000
#define ICEBO_PMON_COUNTER_1_PMON_COUNTER_MSB 0x003f
#define ICEBO_PMON_COUNTER_1_PMON_COUNTER_RANGE 0x0040
#define ICEBO_PMON_COUNTER_1_PMON_COUNTER_MASK 0xffffffffffffffff
#define ICEBO_PMON_COUNTER_1_PMON_COUNTER_RESET_VALUE 0x00000000


// --------------------------------------------------------------------------------------------------------------------------------

#ifndef icebo_pmon_counter_2_FLAG
#define icebo_pmon_counter_2_FLAG
// icebo_pmon_counter_2 desc:  icebo pmon counter
typedef union {
    struct {
        uint64_t  pmon_counter         :  64;    // 

    }                                field;
    uint64_t                         val;
} icebo_pmon_counter_2_t;
#endif
#define ICEBO_PMON_COUNTER_2_OFFSET 0x58
#define ICEBO_PMON_COUNTER_2_SCOPE 0x01
#define ICEBO_PMON_COUNTER_2_SIZE 64
#define ICEBO_PMON_COUNTER_2_BITFIELD_COUNT 0x01
#define ICEBO_PMON_COUNTER_2_RESET 0x00000000

#define ICEBO_PMON_COUNTER_2_PMON_COUNTER_LSB 0x0000
#define ICEBO_PMON_COUNTER_2_PMON_COUNTER_MSB 0x003f
#define ICEBO_PMON_COUNTER_2_PMON_COUNTER_RANGE 0x0040
#define ICEBO_PMON_COUNTER_2_PMON_COUNTER_MASK 0xffffffffffffffff
#define ICEBO_PMON_COUNTER_2_PMON_COUNTER_RESET_VALUE 0x00000000


// --------------------------------------------------------------------------------------------------------------------------------

#ifndef icebo_pmon_counter_3_FLAG
#define icebo_pmon_counter_3_FLAG
// icebo_pmon_counter_3 desc:  icebo pmon counter
typedef union {
    struct {
        uint64_t  pmon_counter         :  64;    // 

    }                                field;
    uint64_t                         val;
} icebo_pmon_counter_3_t;
#endif
#define ICEBO_PMON_COUNTER_3_OFFSET 0x60
#define ICEBO_PMON_COUNTER_3_SCOPE 0x01
#define ICEBO_PMON_COUNTER_3_SIZE 64
#define ICEBO_PMON_COUNTER_3_BITFIELD_COUNT 0x01
#define ICEBO_PMON_COUNTER_3_RESET 0x00000000

#define ICEBO_PMON_COUNTER_3_PMON_COUNTER_LSB 0x0000
#define ICEBO_PMON_COUNTER_3_PMON_COUNTER_MSB 0x003f
#define ICEBO_PMON_COUNTER_3_PMON_COUNTER_RANGE 0x0040
#define ICEBO_PMON_COUNTER_3_PMON_COUNTER_MASK 0xffffffffffffffff
#define ICEBO_PMON_COUNTER_3_PMON_COUNTER_RESET_VALUE 0x00000000


// --------------------------------------------------------------------------------------------------------------------------------

#ifndef ice_config_FLAG
#define ice_config_FLAG
// ice_config desc:  ice configuration
typedef union {
    struct {
        uint64_t  ice0_id              :   4;    //  ice 0 id
        uint64_t  ice1_id              :   4;    //  ice 1 id
        uint64_t  RSVD_0               :  16;    // Nebulon auto filled RSVD [23:8]
        uint64_t  hw_revision          :   8;    //  HW revision
        uint64_t  RSVD_1               :  32;    // Nebulon auto filled RSVD [63:32]

    }                                field;
    uint64_t                         val;
} ice_config_t;
#endif
#define ICE_CONFIG_OFFSET 0x68
#define ICE_CONFIG_SCOPE 0x01
#define ICE_CONFIG_SIZE 64
#define ICE_CONFIG_BITFIELD_COUNT 0x03
#define ICE_CONFIG_RESET 0x01000000

#define ICE_CONFIG_ICE0_ID_LSB 0x0000
#define ICE_CONFIG_ICE0_ID_MSB 0x0003
#define ICE_CONFIG_ICE0_ID_RANGE 0x0004
#define ICE_CONFIG_ICE0_ID_MASK 0x0000000f
#define ICE_CONFIG_ICE0_ID_RESET_VALUE 0x00000000

#define ICE_CONFIG_ICE1_ID_LSB 0x0004
#define ICE_CONFIG_ICE1_ID_MSB 0x0007
#define ICE_CONFIG_ICE1_ID_RANGE 0x0004
#define ICE_CONFIG_ICE1_ID_MASK 0x000000f0
#define ICE_CONFIG_ICE1_ID_RESET_VALUE 0x00000000

#define ICE_CONFIG_HW_REVISION_LSB 0x0018
#define ICE_CONFIG_HW_REVISION_MSB 0x001f
#define ICE_CONFIG_HW_REVISION_RANGE 0x0008
#define ICE_CONFIG_HW_REVISION_MASK 0xff000000
#define ICE_CONFIG_HW_REVISION_RESET_VALUE 0x00000001


// --------------------------------------------------------------------------------------------------------------------------------

#ifndef A2I_PGI_NO_ICE_POLICY_CP_FLAG
#define A2I_PGI_NO_ICE_POLICY_CP_FLAG
// A2I_PGI_NO_ICE_POLICY_CP desc:  Unit Control Policy Register
typedef union {
    struct {
        uint64_t  sai_mask             :  64;    // 

    }                                field;
    uint64_t                         val;
} A2I_PGI_NO_ICE_POLICY_CP_t;
#endif
#define A2I_PGI_NO_ICE_POLICY_CP_OFFSET 0x00
#define A2I_PGI_NO_ICE_POLICY_CP_SCOPE 0x01
#define A2I_PGI_NO_ICE_POLICY_CP_SIZE 64
#define A2I_PGI_NO_ICE_POLICY_CP_BITFIELD_COUNT 0x01
#define A2I_PGI_NO_ICE_POLICY_CP_RESET 0x40001000208

#define A2I_PGI_NO_ICE_POLICY_CP_SAI_MASK_LSB 0x0000
#define A2I_PGI_NO_ICE_POLICY_CP_SAI_MASK_MSB 0x003f
#define A2I_PGI_NO_ICE_POLICY_CP_SAI_MASK_RANGE 0x0040
#define A2I_PGI_NO_ICE_POLICY_CP_SAI_MASK_MASK 0xffffffffffffffff
#define A2I_PGI_NO_ICE_POLICY_CP_SAI_MASK_RESET_VALUE 0x40001000208


// --------------------------------------------------------------------------------------------------------------------------------

#ifndef A2I_PGI_NO_ICE_POLICY_WAC_FLAG
#define A2I_PGI_NO_ICE_POLICY_WAC_FLAG
// A2I_PGI_NO_ICE_POLICY_WAC desc:  Unit Write Access Register
typedef union {
    struct {
        uint64_t  sai_mask             :  64;    // 

    }                                field;
    uint64_t                         val;
} A2I_PGI_NO_ICE_POLICY_WAC_t;
#endif
#define A2I_PGI_NO_ICE_POLICY_WAC_OFFSET 0x08
#define A2I_PGI_NO_ICE_POLICY_WAC_SCOPE 0x01
#define A2I_PGI_NO_ICE_POLICY_WAC_SIZE 64
#define A2I_PGI_NO_ICE_POLICY_WAC_BITFIELD_COUNT 0x01
#define A2I_PGI_NO_ICE_POLICY_WAC_RESET 0x4000100061f

#define A2I_PGI_NO_ICE_POLICY_WAC_SAI_MASK_LSB 0x0000
#define A2I_PGI_NO_ICE_POLICY_WAC_SAI_MASK_MSB 0x003f
#define A2I_PGI_NO_ICE_POLICY_WAC_SAI_MASK_RANGE 0x0040
#define A2I_PGI_NO_ICE_POLICY_WAC_SAI_MASK_MASK 0xffffffffffffffff
#define A2I_PGI_NO_ICE_POLICY_WAC_SAI_MASK_RESET_VALUE 0x4000100061f


// --------------------------------------------------------------------------------------------------------------------------------

#ifndef A2I_PGI_NO_ICE_POLICY_RAC_FLAG
#define A2I_PGI_NO_ICE_POLICY_RAC_FLAG
// A2I_PGI_NO_ICE_POLICY_RAC desc:  Unit Read Access Register
typedef union {
    struct {
        uint64_t  sai_mask             :  64;    // 

    }                                field;
    uint64_t                         val;
} A2I_PGI_NO_ICE_POLICY_RAC_t;
#endif
#define A2I_PGI_NO_ICE_POLICY_RAC_OFFSET 0x10
#define A2I_PGI_NO_ICE_POLICY_RAC_SCOPE 0x01
#define A2I_PGI_NO_ICE_POLICY_RAC_SIZE 64
#define A2I_PGI_NO_ICE_POLICY_RAC_BITFIELD_COUNT 0x01
#define A2I_PGI_NO_ICE_POLICY_RAC_RESET 0x4000100061f

#define A2I_PGI_NO_ICE_POLICY_RAC_SAI_MASK_LSB 0x0000
#define A2I_PGI_NO_ICE_POLICY_RAC_SAI_MASK_MSB 0x003f
#define A2I_PGI_NO_ICE_POLICY_RAC_SAI_MASK_RANGE 0x0040
#define A2I_PGI_NO_ICE_POLICY_RAC_SAI_MASK_MASK 0xffffffffffffffff
#define A2I_PGI_NO_ICE_POLICY_RAC_SAI_MASK_RESET_VALUE 0x4000100061f


// --------------------------------------------------------------------------------------------------------------------------------

#ifndef A2I_PGI_NO_IA_POLICY_CP_FLAG
#define A2I_PGI_NO_IA_POLICY_CP_FLAG
// A2I_PGI_NO_IA_POLICY_CP desc:  Unit Control Policy Register
typedef union {
    struct {
        uint64_t  sai_mask             :  64;    // 

    }                                field;
    uint64_t                         val;
} A2I_PGI_NO_IA_POLICY_CP_t;
#endif
#define A2I_PGI_NO_IA_POLICY_CP_OFFSET 0x18
#define A2I_PGI_NO_IA_POLICY_CP_SCOPE 0x01
#define A2I_PGI_NO_IA_POLICY_CP_SIZE 64
#define A2I_PGI_NO_IA_POLICY_CP_BITFIELD_COUNT 0x01
#define A2I_PGI_NO_IA_POLICY_CP_RESET 0x40001000208

#define A2I_PGI_NO_IA_POLICY_CP_SAI_MASK_LSB 0x0000
#define A2I_PGI_NO_IA_POLICY_CP_SAI_MASK_MSB 0x003f
#define A2I_PGI_NO_IA_POLICY_CP_SAI_MASK_RANGE 0x0040
#define A2I_PGI_NO_IA_POLICY_CP_SAI_MASK_MASK 0xffffffffffffffff
#define A2I_PGI_NO_IA_POLICY_CP_SAI_MASK_RESET_VALUE 0x40001000208


// --------------------------------------------------------------------------------------------------------------------------------

#ifndef A2I_PGI_NO_IA_POLICY_WAC_FLAG
#define A2I_PGI_NO_IA_POLICY_WAC_FLAG
// A2I_PGI_NO_IA_POLICY_WAC desc:  Unit Write Access Register
typedef union {
    struct {
        uint64_t  sai_mask             :  64;    // 

    }                                field;
    uint64_t                         val;
} A2I_PGI_NO_IA_POLICY_WAC_t;
#endif
#define A2I_PGI_NO_IA_POLICY_WAC_OFFSET 0x20
#define A2I_PGI_NO_IA_POLICY_WAC_SCOPE 0x01
#define A2I_PGI_NO_IA_POLICY_WAC_SIZE 64
#define A2I_PGI_NO_IA_POLICY_WAC_BITFIELD_COUNT 0x01
#define A2I_PGI_NO_IA_POLICY_WAC_RESET 0x40001000208

#define A2I_PGI_NO_IA_POLICY_WAC_SAI_MASK_LSB 0x0000
#define A2I_PGI_NO_IA_POLICY_WAC_SAI_MASK_MSB 0x003f
#define A2I_PGI_NO_IA_POLICY_WAC_SAI_MASK_RANGE 0x0040
#define A2I_PGI_NO_IA_POLICY_WAC_SAI_MASK_MASK 0xffffffffffffffff
#define A2I_PGI_NO_IA_POLICY_WAC_SAI_MASK_RESET_VALUE 0x40001000208


// --------------------------------------------------------------------------------------------------------------------------------

#ifndef A2I_PGI_NO_IA_POLICY_RAC_FLAG
#define A2I_PGI_NO_IA_POLICY_RAC_FLAG
// A2I_PGI_NO_IA_POLICY_RAC desc:  Unit Read Access Register
typedef union {
    struct {
        uint64_t  sai_mask             :  64;    // 

    }                                field;
    uint64_t                         val;
} A2I_PGI_NO_IA_POLICY_RAC_t;
#endif
#define A2I_PGI_NO_IA_POLICY_RAC_OFFSET 0x28
#define A2I_PGI_NO_IA_POLICY_RAC_SCOPE 0x01
#define A2I_PGI_NO_IA_POLICY_RAC_SIZE 64
#define A2I_PGI_NO_IA_POLICY_RAC_BITFIELD_COUNT 0x01
#define A2I_PGI_NO_IA_POLICY_RAC_RESET 0x40001000208

#define A2I_PGI_NO_IA_POLICY_RAC_SAI_MASK_LSB 0x0000
#define A2I_PGI_NO_IA_POLICY_RAC_SAI_MASK_MSB 0x003f
#define A2I_PGI_NO_IA_POLICY_RAC_SAI_MASK_RANGE 0x0040
#define A2I_PGI_NO_IA_POLICY_RAC_SAI_MASK_MASK 0xffffffffffffffff
#define A2I_PGI_NO_IA_POLICY_RAC_SAI_MASK_RESET_VALUE 0x40001000208


// --------------------------------------------------------------------------------------------------------------------------------

// starting the array instantiation section
typedef struct {
    convertor_entry_config_t   convertor_entry_config; // offset 4'h0, width 64
    convertor_disabled_entries_t convertor_disabled_entries; // offset 4'h8, width 64
    idi_config_t               idi_config;       // offset 8'h10, width 32
    axi_user_config_t          axi_user_config;  // offset 8'h14, width 32
    idi_flow_config_t          idi_flow_config;  // offset 8'h18, width 32
    axi_arb_config_t           axi_arb_config;   // offset 8'h1C, width 32
    axi_shared_read_cfg_t      axi_shared_read_cfg; // offset 8'h20, width 32
    axi_shared_read_status_t   axi_shared_read_status; // offset 8'h24, width 32
    dfx_stream_ctl_t           dfx_stream_ctl;   // offset 8'h28, width 32
    hvm_modes_t                hvm_modes;        // offset 8'h2C, width 32
    icebo_pmon_global_t        icebo_pmon_global; // offset 8'h30, width 32
    icebo_pmon_event_0_t       icebo_pmon_event_0; // offset 8'h34, width 32
    icebo_pmon_event_1_t       icebo_pmon_event_1; // offset 8'h38, width 32
    icebo_pmon_event_2_t       icebo_pmon_event_2; // offset 8'h3C, width 32
    icebo_pmon_event_3_t       icebo_pmon_event_3; // offset 8'h40, width 32
    icebo_pmon_status_t        icebo_pmon_status; // offset 8'h44, width 32
    icebo_pmon_counter_0_t     icebo_pmon_counter_0; // offset 8'h48, width 64
    icebo_pmon_counter_1_t     icebo_pmon_counter_1; // offset 8'h50, width 64
    icebo_pmon_counter_2_t     icebo_pmon_counter_2; // offset 8'h58, width 64
    icebo_pmon_counter_3_t     icebo_pmon_counter_3; // offset 8'h60, width 64
    ice_config_t               ice_config;       // offset 8'h68, width 64
    uint8_t                    rsvd0[144];
    A2I_PGI_NO_ICE_POLICY_CP_t A2I_PGI_NO_ICE_POLICY_CP; // offset 12'h100, width 64
    A2I_PGI_NO_ICE_POLICY_WAC_t A2I_PGI_NO_ICE_POLICY_WAC; // offset 12'h108, width 64
    A2I_PGI_NO_ICE_POLICY_RAC_t A2I_PGI_NO_ICE_POLICY_RAC; // offset 12'h110, width 64
    A2I_PGI_NO_IA_POLICY_CP_t  A2I_PGI_NO_IA_POLICY_CP; // offset 12'h118, width 64
    A2I_PGI_NO_IA_POLICY_WAC_t A2I_PGI_NO_IA_POLICY_WAC; // offset 12'h120, width 64
    A2I_PGI_NO_IA_POLICY_RAC_t A2I_PGI_NO_IA_POLICY_RAC; // offset 12'h128, width 64
} axi2idi_regs_t;                                // size:  12'h130


#endif // _AXI2IDI_REGS_REGS_H_

