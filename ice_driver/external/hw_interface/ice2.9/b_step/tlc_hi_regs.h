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

#ifndef _TLC_HI_REGS_H_
#define _TLC_HI_REGS_H_
#define CVE_TLC_HI_BASE 0x3000
#define CVE_TLC_HI_TLC_GP_REG_MMOFFSET 0x0
#define CVE_TLC_HI_TLC_SP_REG0_MMOFFSET 0x100
#define CVE_TLC_HI_TLC_SP_REG1_MMOFFSET 0x104
#define CVE_TLC_HI_TLC_SP_REG2_MMOFFSET 0x108
#define CVE_TLC_HI_TLC_SP_REG3_MMOFFSET 0x10C
#define CVE_TLC_HI_TLC_CR_ACC_CONTROL_MODE_REG_MMOFFSET 0x110
#define CVE_TLC_HI_TLC_ACTIVITY_TIMEOUT_MMOFFSET 0x114
#define CVE_TLC_HI_TLC_DUMP_CONTROL_REG_MMOFFSET 0x118
#define CVE_TLC_HI_TLC_DUMP_BUFFER_CONFIG_REG_MMOFFSET 0x11C
#define CVE_TLC_HI_TLC_DUMP_MARKER_REG_MMOFFSET 0x120
#define CVE_TLC_HI_TLC_MAILBOX_DOORBELL_MMOFFSET 0x124
#define CVE_TLC_HI_TLC_BARRIER_WATCH_CONFIG_REG_MMOFFSET 0x134
#define CVE_TLC_HI_TLC_GENERATE_CONTROL_UCMD_REG_MMOFFSET 0x138
#define CVE_TLC_HI_TLC_DEBUG_REG_MMOFFSET 0x13C
#ifndef TLC_HI_MEM_TLC_GP_REG_FLAG
#define TLC_HI_MEM_TLC_GP_REG_FLAG

/*  TLC_GP_REG desc:  General purpose TLC configuration register; To */
/* be used to */
/* configure/control TLC*/
union TLC_HI_MEM_TLC_GP_REG_t {
	struct {
uint32_t  CFG_PAYLOAD          :  32;
/*   General Purpose Configuration */
	}                                field;
uint32_t                         val;
};
#endif
#define TLC_HI_MEM_TLC_GP_REG_OFFSET 0x00
#define TLC_HI_MEM_TLC_GP_REG_SCOPE 0x01
#define TLC_HI_MEM_TLC_GP_REG_SIZE 32
#define TLC_HI_MEM_TLC_GP_REG_BITFIELD_COUNT 0x01
#define TLC_HI_MEM_TLC_GP_REG_RESET 0x00000000
#define TLC_HI_MEM_TLC_GP_REG_CFG_PAYLOAD_LSB 0x0000
#define TLC_HI_MEM_TLC_GP_REG_CFG_PAYLOAD_MSB 0x001f
#define TLC_HI_MEM_TLC_GP_REG_CFG_PAYLOAD_RANGE 0x0020
#define TLC_HI_MEM_TLC_GP_REG_CFG_PAYLOAD_MASK 0xffffffff
#define TLC_HI_MEM_TLC_GP_REG_CFG_PAYLOAD_RESET_VALUE 0x00000000

/*  ------------------------------------------------------------------ */
/* */
#ifndef TLC_HI_MEM_TLC_SP_REG0_FLAG
#define TLC_HI_MEM_TLC_SP_REG0_FLAG

/*  TLC_SP_REG0 desc:  General purpose TLC configuration register; To */
/* be used to */
/* configure/control TLC*/
union TLC_HI_MEM_TLC_SP_REG0_t {
	struct {
uint32_t  CFG_PAYLOAD          :  32;
/*   General Purpose Configuration */
	}                                field;
uint32_t                         val;
};
#endif
#define TLC_HI_MEM_TLC_SP_REG0_OFFSET 0x00
#define TLC_HI_MEM_TLC_SP_REG0_SCOPE 0x01
#define TLC_HI_MEM_TLC_SP_REG0_SIZE 32
#define TLC_HI_MEM_TLC_SP_REG0_BITFIELD_COUNT 0x01
#define TLC_HI_MEM_TLC_SP_REG0_RESET 0x00000000
#define TLC_HI_MEM_TLC_SP_REG0_CFG_PAYLOAD_LSB 0x0000
#define TLC_HI_MEM_TLC_SP_REG0_CFG_PAYLOAD_MSB 0x001f
#define TLC_HI_MEM_TLC_SP_REG0_CFG_PAYLOAD_RANGE 0x0020
#define TLC_HI_MEM_TLC_SP_REG0_CFG_PAYLOAD_MASK 0xffffffff
#define TLC_HI_MEM_TLC_SP_REG0_CFG_PAYLOAD_RESET_VALUE 0x00000000

/*  ------------------------------------------------------------------ */
/* */
#ifndef TLC_HI_MEM_TLC_SP_REG1_FLAG
#define TLC_HI_MEM_TLC_SP_REG1_FLAG

/*  TLC_SP_REG1 desc:  General purpose TLC configuration register; To */
/* be used to */
/* configure/control TLC*/
union TLC_HI_MEM_TLC_SP_REG1_t {
	struct {
uint32_t  CFG_PAYLOAD          :  32;
/*   General Purpose Configuration */
	}                                field;
uint32_t                         val;
};
#endif
#define TLC_HI_MEM_TLC_SP_REG1_OFFSET 0x04
#define TLC_HI_MEM_TLC_SP_REG1_SCOPE 0x01
#define TLC_HI_MEM_TLC_SP_REG1_SIZE 32
#define TLC_HI_MEM_TLC_SP_REG1_BITFIELD_COUNT 0x01
#define TLC_HI_MEM_TLC_SP_REG1_RESET 0x00000000
#define TLC_HI_MEM_TLC_SP_REG1_CFG_PAYLOAD_LSB 0x0000
#define TLC_HI_MEM_TLC_SP_REG1_CFG_PAYLOAD_MSB 0x001f
#define TLC_HI_MEM_TLC_SP_REG1_CFG_PAYLOAD_RANGE 0x0020
#define TLC_HI_MEM_TLC_SP_REG1_CFG_PAYLOAD_MASK 0xffffffff
#define TLC_HI_MEM_TLC_SP_REG1_CFG_PAYLOAD_RESET_VALUE 0x00000000

/*  ------------------------------------------------------------------ */
/* */
#ifndef TLC_HI_MEM_TLC_SP_REG2_FLAG
#define TLC_HI_MEM_TLC_SP_REG2_FLAG

/*  TLC_SP_REG2 desc:  General purpose TLC configuration register; To */
/* be used to */
/* configure/control TLC*/
union TLC_HI_MEM_TLC_SP_REG2_t {
	struct {
uint32_t  CFG_PAYLOAD          :  32;
/*   General Purpose Configuration */
	}                                field;
uint32_t                         val;
};
#endif
#define TLC_HI_MEM_TLC_SP_REG2_OFFSET 0x08
#define TLC_HI_MEM_TLC_SP_REG2_SCOPE 0x01
#define TLC_HI_MEM_TLC_SP_REG2_SIZE 32
#define TLC_HI_MEM_TLC_SP_REG2_BITFIELD_COUNT 0x01
#define TLC_HI_MEM_TLC_SP_REG2_RESET 0x00000000
#define TLC_HI_MEM_TLC_SP_REG2_CFG_PAYLOAD_LSB 0x0000
#define TLC_HI_MEM_TLC_SP_REG2_CFG_PAYLOAD_MSB 0x001f
#define TLC_HI_MEM_TLC_SP_REG2_CFG_PAYLOAD_RANGE 0x0020
#define TLC_HI_MEM_TLC_SP_REG2_CFG_PAYLOAD_MASK 0xffffffff
#define TLC_HI_MEM_TLC_SP_REG2_CFG_PAYLOAD_RESET_VALUE 0x00000000

/*  ------------------------------------------------------------------ */
/* */
#ifndef TLC_HI_MEM_TLC_SP_REG3_FLAG
#define TLC_HI_MEM_TLC_SP_REG3_FLAG

/*  TLC_SP_REG3 desc:  General purpose TLC configuration register; To */
/* be used to */
/* configure/control TLC*/
union TLC_HI_MEM_TLC_SP_REG3_t {
	struct {
uint32_t  CFG_PAYLOAD          :  32;
/*   General Purpose Configuration */
	}                                field;
uint32_t                         val;
};
#endif
#define TLC_HI_MEM_TLC_SP_REG3_OFFSET 0x0c
#define TLC_HI_MEM_TLC_SP_REG3_SCOPE 0x01
#define TLC_HI_MEM_TLC_SP_REG3_SIZE 32
#define TLC_HI_MEM_TLC_SP_REG3_BITFIELD_COUNT 0x01
#define TLC_HI_MEM_TLC_SP_REG3_RESET 0x00000000
#define TLC_HI_MEM_TLC_SP_REG3_CFG_PAYLOAD_LSB 0x0000
#define TLC_HI_MEM_TLC_SP_REG3_CFG_PAYLOAD_MSB 0x001f
#define TLC_HI_MEM_TLC_SP_REG3_CFG_PAYLOAD_RANGE 0x0020
#define TLC_HI_MEM_TLC_SP_REG3_CFG_PAYLOAD_MASK 0xffffffff
#define TLC_HI_MEM_TLC_SP_REG3_CFG_PAYLOAD_RESET_VALUE 0x00000000

/*  ------------------------------------------------------------------ */
/* */
#ifndef TLC_HI_MEM_TLC_CR_ACC_CONTROL_MODE_REG_FLAG
#define TLC_HI_MEM_TLC_CR_ACC_CONTROL_MODE_REG_FLAG

/*  TLC_CR_ACC_CONTROL_MODE_REG desc:  Special purpose TLC */
/* configuration register; To be used to */
/* configure/control TLC*/
union TLC_HI_MEM_TLC_CR_ACC_CONTROL_MODE_REG_t {
	struct {
uint32_t  BASE_BID_OFFSET      :   8;    /*  Base BID Offset*/
uint32_t  CONTROL_MODE         :   8;    /*  Control Mode*/
uint32_t  RESERVED             :  16;    /*  Reserved*/
	}                                field;
uint32_t                         val;
};
#endif
#define TLC_HI_MEM_TLC_CR_ACC_CONTROL_MODE_REG_OFFSET 0x10
#define TLC_HI_MEM_TLC_CR_ACC_CONTROL_MODE_REG_SCOPE 0x01
#define TLC_HI_MEM_TLC_CR_ACC_CONTROL_MODE_REG_SIZE 32
#define TLC_HI_MEM_TLC_CR_ACC_CONTROL_MODE_REG_BITFIELD_COUNT 0x03
#define TLC_HI_MEM_TLC_CR_ACC_CONTROL_MODE_REG_RESET 0x00000000
#define TLC_HI_MEM_TLC_CR_ACC_CONTROL_MODE_REG_BASE_BID_OFFSET_LSB 0x0000
#define TLC_HI_MEM_TLC_CR_ACC_CONTROL_MODE_REG_BASE_BID_OFFSET_MSB 0x0007
#define TLC_HI_MEM_TLC_CR_ACC_CONTROL_MODE_REG_BASE_BID_OFFSET_RANGE 0x0008
#define TLC_HI_MEM_TLC_CR_ACC_CONTROL_MODE_REG_BASE_BID_OFFSET_MASK 0x000000ff
#define TLC_HI_MEM_TLC_CR_ACC_CONTROL_MODE_REG_BASE_BID_OFFSET_RESET_VALUE 0x00000000
#define TLC_HI_MEM_TLC_CR_ACC_CONTROL_MODE_REG_CONTROL_MODE_LSB 0x0008
#define TLC_HI_MEM_TLC_CR_ACC_CONTROL_MODE_REG_CONTROL_MODE_MSB 0x000f
#define TLC_HI_MEM_TLC_CR_ACC_CONTROL_MODE_REG_CONTROL_MODE_RANGE 0x0008
#define TLC_HI_MEM_TLC_CR_ACC_CONTROL_MODE_REG_CONTROL_MODE_MASK 0x0000ff00
#define TLC_HI_MEM_TLC_CR_ACC_CONTROL_MODE_REG_CONTROL_MODE_RESET_VALUE 0x00000000
#define TLC_HI_MEM_TLC_CR_ACC_CONTROL_MODE_REG_RESERVED_LSB 0x0010
#define TLC_HI_MEM_TLC_CR_ACC_CONTROL_MODE_REG_RESERVED_MSB 0x001f
#define TLC_HI_MEM_TLC_CR_ACC_CONTROL_MODE_REG_RESERVED_RANGE 0x0010
#define TLC_HI_MEM_TLC_CR_ACC_CONTROL_MODE_REG_RESERVED_MASK 0xffff0000
#define TLC_HI_MEM_TLC_CR_ACC_CONTROL_MODE_REG_RESERVED_RESET_VALUE 0x00000000

/*  ------------------------------------------------------------------ */
/* */
#ifndef TLC_HI_MEM_TLC_ACTIVITY_TIMEOUT_FLAG
#define TLC_HI_MEM_TLC_ACTIVITY_TIMEOUT_FLAG

/*  TLC_ACTIVITY_TIMEOUT desc:  General purpose TLC configuration */
/* register; To be used to */
/* configure/control TLC*/
union TLC_HI_MEM_TLC_ACTIVITY_TIMEOUT_t {
	struct {
uint32_t  CFG_PAYLOAD          :  32;
/*   General Purpose Configuration */
	}                                field;
uint32_t                         val;
};
#endif
#define TLC_HI_MEM_TLC_ACTIVITY_TIMEOUT_OFFSET 0x14
#define TLC_HI_MEM_TLC_ACTIVITY_TIMEOUT_SCOPE 0x01
#define TLC_HI_MEM_TLC_ACTIVITY_TIMEOUT_SIZE 32
#define TLC_HI_MEM_TLC_ACTIVITY_TIMEOUT_BITFIELD_COUNT 0x01
#define TLC_HI_MEM_TLC_ACTIVITY_TIMEOUT_RESET 0x00000000
#define TLC_HI_MEM_TLC_ACTIVITY_TIMEOUT_CFG_PAYLOAD_LSB 0x0000
#define TLC_HI_MEM_TLC_ACTIVITY_TIMEOUT_CFG_PAYLOAD_MSB 0x001f
#define TLC_HI_MEM_TLC_ACTIVITY_TIMEOUT_CFG_PAYLOAD_RANGE 0x0020
#define TLC_HI_MEM_TLC_ACTIVITY_TIMEOUT_CFG_PAYLOAD_MASK 0xffffffff
#define TLC_HI_MEM_TLC_ACTIVITY_TIMEOUT_CFG_PAYLOAD_RESET_VALUE 0x00000000

/*  ------------------------------------------------------------------ */
/* */
#ifndef TLC_HI_MEM_TLC_DUMP_CONTROL_REG_FLAG
#define TLC_HI_MEM_TLC_DUMP_CONTROL_REG_FLAG

/*  TLC_DUMP_CONTROL_REG desc:  Special purpose TLC configuration */
/* register; To be used to control the */
/* CVE dump configuration*/
union TLC_HI_MEM_TLC_DUMP_CONTROL_REG_t {
	struct {
uint32_t  dumpTrigger          :   4;    /*  Dump Trigger*/
uint32_t  disableSpDump        :   1;    /*  Disable SP Dump*/
uint32_t  disableDramDump      :   1;
/*   Disable TLC DRAM Dump */
uint32_t  disableTraxDump      :   1;
/*   Disable TRAX Memory Dump */
uint32_t  disableCreditAccDump :   1;
/*   Disable CreditAcc Register */
/* Dump*/
uint32_t  reserved             :  24;    /*  reserved*/
	}                                field;
uint32_t                         val;
};
#endif
#define TLC_HI_MEM_TLC_DUMP_CONTROL_REG_OFFSET 0x18
#define TLC_HI_MEM_TLC_DUMP_CONTROL_REG_SCOPE 0x01
#define TLC_HI_MEM_TLC_DUMP_CONTROL_REG_SIZE 32
#define TLC_HI_MEM_TLC_DUMP_CONTROL_REG_BITFIELD_COUNT 0x06
#define TLC_HI_MEM_TLC_DUMP_CONTROL_REG_RESET 0x00000000
#define TLC_HI_MEM_TLC_DUMP_CONTROL_REG_DUMPTRIGGER_LSB 0x0000
#define TLC_HI_MEM_TLC_DUMP_CONTROL_REG_DUMPTRIGGER_MSB 0x0003
#define TLC_HI_MEM_TLC_DUMP_CONTROL_REG_DUMPTRIGGER_RANGE 0x0004
#define TLC_HI_MEM_TLC_DUMP_CONTROL_REG_DUMPTRIGGER_MASK 0x0000000f
#define TLC_HI_MEM_TLC_DUMP_CONTROL_REG_DUMPTRIGGER_RESET_VALUE 0x00000000
#define TLC_HI_MEM_TLC_DUMP_CONTROL_REG_DISABLESPDUMP_LSB 0x0004
#define TLC_HI_MEM_TLC_DUMP_CONTROL_REG_DISABLESPDUMP_MSB 0x0004
#define TLC_HI_MEM_TLC_DUMP_CONTROL_REG_DISABLESPDUMP_RANGE 0x0001
#define TLC_HI_MEM_TLC_DUMP_CONTROL_REG_DISABLESPDUMP_MASK 0x00000010
#define TLC_HI_MEM_TLC_DUMP_CONTROL_REG_DISABLESPDUMP_RESET_VALUE 0x00000000
#define TLC_HI_MEM_TLC_DUMP_CONTROL_REG_DISABLEDRAMDUMP_LSB 0x0005
#define TLC_HI_MEM_TLC_DUMP_CONTROL_REG_DISABLEDRAMDUMP_MSB 0x0005
#define TLC_HI_MEM_TLC_DUMP_CONTROL_REG_DISABLEDRAMDUMP_RANGE 0x0001
#define TLC_HI_MEM_TLC_DUMP_CONTROL_REG_DISABLEDRAMDUMP_MASK 0x00000020
#define TLC_HI_MEM_TLC_DUMP_CONTROL_REG_DISABLEDRAMDUMP_RESET_VALUE 0x00000000
#define TLC_HI_MEM_TLC_DUMP_CONTROL_REG_DISABLETRAXDUMP_LSB 0x0006
#define TLC_HI_MEM_TLC_DUMP_CONTROL_REG_DISABLETRAXDUMP_MSB 0x0006
#define TLC_HI_MEM_TLC_DUMP_CONTROL_REG_DISABLETRAXDUMP_RANGE 0x0001
#define TLC_HI_MEM_TLC_DUMP_CONTROL_REG_DISABLETRAXDUMP_MASK 0x00000040
#define TLC_HI_MEM_TLC_DUMP_CONTROL_REG_DISABLETRAXDUMP_RESET_VALUE 0x00000000
#define TLC_HI_MEM_TLC_DUMP_CONTROL_REG_DISABLECREDITACCDUMP_LSB 0x0007
#define TLC_HI_MEM_TLC_DUMP_CONTROL_REG_DISABLECREDITACCDUMP_MSB 0x0007
#define TLC_HI_MEM_TLC_DUMP_CONTROL_REG_DISABLECREDITACCDUMP_RANGE 0x0001
#define TLC_HI_MEM_TLC_DUMP_CONTROL_REG_DISABLECREDITACCDUMP_MASK 0x00000080
#define TLC_HI_MEM_TLC_DUMP_CONTROL_REG_DISABLECREDITACCDUMP_RESET_VALUE 0x00000000
#define TLC_HI_MEM_TLC_DUMP_CONTROL_REG_RESERVED_LSB 0x0008
#define TLC_HI_MEM_TLC_DUMP_CONTROL_REG_RESERVED_MSB 0x001f
#define TLC_HI_MEM_TLC_DUMP_CONTROL_REG_RESERVED_RANGE 0x0018
#define TLC_HI_MEM_TLC_DUMP_CONTROL_REG_RESERVED_MASK 0xffffff00
#define TLC_HI_MEM_TLC_DUMP_CONTROL_REG_RESERVED_RESET_VALUE 0x00000000

/*  ------------------------------------------------------------------ */
/* */
#ifndef TLC_HI_MEM_TLC_DUMP_BUFFER_CONFIG_REG_FLAG
#define TLC_HI_MEM_TLC_DUMP_BUFFER_CONFIG_REG_FLAG

/*  TLC_DUMP_BUFFER_CONFIG_REG desc:  Special purpose TLC */
/* configuration register; To be used to configure */
/* the CVE Dump buffer properties*/
union TLC_HI_MEM_TLC_DUMP_BUFFER_CONFIG_REG_t {
	struct {
uint32_t  maxDumpCount         :   6;    /*  Max Dump Count*/
uint32_t  dumpBaseAddress      :  26;    /*  dump Base Address*/
	}                                field;
uint32_t                         val;
};
#endif
#define TLC_HI_MEM_TLC_DUMP_BUFFER_CONFIG_REG_OFFSET 0x1c
#define TLC_HI_MEM_TLC_DUMP_BUFFER_CONFIG_REG_SCOPE 0x01
#define TLC_HI_MEM_TLC_DUMP_BUFFER_CONFIG_REG_SIZE 32
#define TLC_HI_MEM_TLC_DUMP_BUFFER_CONFIG_REG_BITFIELD_COUNT 0x02
#define TLC_HI_MEM_TLC_DUMP_BUFFER_CONFIG_REG_RESET 0x00000000
#define TLC_HI_MEM_TLC_DUMP_BUFFER_CONFIG_REG_MAXDUMPCOUNT_LSB 0x0000
#define TLC_HI_MEM_TLC_DUMP_BUFFER_CONFIG_REG_MAXDUMPCOUNT_MSB 0x0005
#define TLC_HI_MEM_TLC_DUMP_BUFFER_CONFIG_REG_MAXDUMPCOUNT_RANGE 0x0006
#define TLC_HI_MEM_TLC_DUMP_BUFFER_CONFIG_REG_MAXDUMPCOUNT_MASK 0x0000003f
#define TLC_HI_MEM_TLC_DUMP_BUFFER_CONFIG_REG_MAXDUMPCOUNT_RESET_VALUE 0x00000000
#define TLC_HI_MEM_TLC_DUMP_BUFFER_CONFIG_REG_DUMPBASEADDRESS_LSB 0x0006
#define TLC_HI_MEM_TLC_DUMP_BUFFER_CONFIG_REG_DUMPBASEADDRESS_MSB 0x001f
#define TLC_HI_MEM_TLC_DUMP_BUFFER_CONFIG_REG_DUMPBASEADDRESS_RANGE 0x001a
#define TLC_HI_MEM_TLC_DUMP_BUFFER_CONFIG_REG_DUMPBASEADDRESS_MASK 0xffffffc0
#define TLC_HI_MEM_TLC_DUMP_BUFFER_CONFIG_REG_DUMPBASEADDRESS_RESET_VALUE 0x00000000

/*  ------------------------------------------------------------------ */
/* */
#ifndef TLC_HI_MEM_TLC_DUMP_MARKER_REG_FLAG
#define TLC_HI_MEM_TLC_DUMP_MARKER_REG_FLAG

/*  TLC_DUMP_MARKER_REG desc:  Special purpose TLC configuration */
/* register; To be used to set the CVE */
/* dump marker*/
union TLC_HI_MEM_TLC_DUMP_MARKER_REG_t {
	struct {
uint32_t  dumpMarker           :  32;    /*  Dump Marker*/
	}                                field;
uint32_t                         val;
};
#endif
#define TLC_HI_MEM_TLC_DUMP_MARKER_REG_OFFSET 0x20
#define TLC_HI_MEM_TLC_DUMP_MARKER_REG_SCOPE 0x01
#define TLC_HI_MEM_TLC_DUMP_MARKER_REG_SIZE 32
#define TLC_HI_MEM_TLC_DUMP_MARKER_REG_BITFIELD_COUNT 0x01
#define TLC_HI_MEM_TLC_DUMP_MARKER_REG_RESET 0x00000000
#define TLC_HI_MEM_TLC_DUMP_MARKER_REG_DUMPMARKER_LSB 0x0000
#define TLC_HI_MEM_TLC_DUMP_MARKER_REG_DUMPMARKER_MSB 0x001f
#define TLC_HI_MEM_TLC_DUMP_MARKER_REG_DUMPMARKER_RANGE 0x0020
#define TLC_HI_MEM_TLC_DUMP_MARKER_REG_DUMPMARKER_MASK 0xffffffff
#define TLC_HI_MEM_TLC_DUMP_MARKER_REG_DUMPMARKER_RESET_VALUE 0x00000000

/*  ------------------------------------------------------------------ */
/* */
#ifndef TLC_HI_MEM_TLC_MAILBOX_DOORBELL_FLAG
#define TLC_HI_MEM_TLC_MAILBOX_DOORBELL_FLAG

/*  TLC_MAILBOX_DOORBELL desc:  General purpose TLC mailbox register; */
/* To be used to send TLC messages */
union TLC_HI_MEM_TLC_MAILBOX_DOORBELL_t {
	struct {
uint32_t  CFG_PAYLOAD          :  32;
/*   General Purpose Mailbox */
	}                                field;
uint32_t                         val;
};
#endif
#define TLC_HI_MEM_TLC_MAILBOX_DOORBELL_OFFSET 0x24
#define TLC_HI_MEM_TLC_MAILBOX_DOORBELL_SCOPE 0x01
#define TLC_HI_MEM_TLC_MAILBOX_DOORBELL_SIZE 32
#define TLC_HI_MEM_TLC_MAILBOX_DOORBELL_BITFIELD_COUNT 0x01
#define TLC_HI_MEM_TLC_MAILBOX_DOORBELL_RESET 0x00000000
#define TLC_HI_MEM_TLC_MAILBOX_DOORBELL_CFG_PAYLOAD_LSB 0x0000
#define TLC_HI_MEM_TLC_MAILBOX_DOORBELL_CFG_PAYLOAD_MSB 0x001f
#define TLC_HI_MEM_TLC_MAILBOX_DOORBELL_CFG_PAYLOAD_RANGE 0x0020
#define TLC_HI_MEM_TLC_MAILBOX_DOORBELL_CFG_PAYLOAD_MASK 0xffffffff
#define TLC_HI_MEM_TLC_MAILBOX_DOORBELL_CFG_PAYLOAD_RESET_VALUE 0x00000000

/*  ------------------------------------------------------------------ */
/* */
#ifndef TLC_HI_MEM_TLC_BARRIER_WATCH_CONFIG_REG_FLAG
#define TLC_HI_MEM_TLC_BARRIER_WATCH_CONFIG_REG_FLAG

/*  TLC_BARRIER_WATCH_CONFIG_REG desc:  Special purpose TLC */
/* configuration register; To be used to configure */
/* the barrier watch service properties*/
union TLC_HI_MEM_TLC_BARRIER_WATCH_CONFIG_REG_t {
	struct {
uint32_t  watchMode            :   4;    /*  Watch Mode*/
uint32_t  tlcMode              :   4;    /*  TLC Mode*/
uint32_t  sectionID            :  16;    /*  Section ID*/
uint32_t  enableWatch          :   1;    /*  Enable Watch*/
uint32_t  reserved_interruptSent :   1;
/*   not for SW use, set to zero */
uint32_t  reserved_stoppedAtBarrier :   1;
/*   not for SW use, set to zero */
uint32_t  reserved             :   5;    /*  set to zero*/
	}                                field;
uint32_t                         val;
};
#endif
#define TLC_HI_MEM_TLC_BARRIER_WATCH_CONFIG_REG_OFFSET 0x34
#define TLC_HI_MEM_TLC_BARRIER_WATCH_CONFIG_REG_SCOPE 0x01
#define TLC_HI_MEM_TLC_BARRIER_WATCH_CONFIG_REG_SIZE 32
#define TLC_HI_MEM_TLC_BARRIER_WATCH_CONFIG_REG_BITFIELD_COUNT 0x07
#define TLC_HI_MEM_TLC_BARRIER_WATCH_CONFIG_REG_RESET 0x00000000
#define TLC_HI_MEM_TLC_BARRIER_WATCH_CONFIG_REG_WATCHMODE_LSB 0x0000
#define TLC_HI_MEM_TLC_BARRIER_WATCH_CONFIG_REG_WATCHMODE_MSB 0x0003
#define TLC_HI_MEM_TLC_BARRIER_WATCH_CONFIG_REG_WATCHMODE_RANGE 0x0004
#define TLC_HI_MEM_TLC_BARRIER_WATCH_CONFIG_REG_WATCHMODE_MASK 0x0000000f
#define TLC_HI_MEM_TLC_BARRIER_WATCH_CONFIG_REG_WATCHMODE_RESET_VALUE 0x00000000
#define TLC_HI_MEM_TLC_BARRIER_WATCH_CONFIG_REG_TLCMODE_LSB 0x0004
#define TLC_HI_MEM_TLC_BARRIER_WATCH_CONFIG_REG_TLCMODE_MSB 0x0007
#define TLC_HI_MEM_TLC_BARRIER_WATCH_CONFIG_REG_TLCMODE_RANGE 0x0004
#define TLC_HI_MEM_TLC_BARRIER_WATCH_CONFIG_REG_TLCMODE_MASK 0x000000f0
#define TLC_HI_MEM_TLC_BARRIER_WATCH_CONFIG_REG_TLCMODE_RESET_VALUE 0x00000000
#define TLC_HI_MEM_TLC_BARRIER_WATCH_CONFIG_REG_SECTIONID_LSB 0x0008
#define TLC_HI_MEM_TLC_BARRIER_WATCH_CONFIG_REG_SECTIONID_MSB 0x0017
#define TLC_HI_MEM_TLC_BARRIER_WATCH_CONFIG_REG_SECTIONID_RANGE 0x0010
#define TLC_HI_MEM_TLC_BARRIER_WATCH_CONFIG_REG_SECTIONID_MASK 0x00ffff00
#define TLC_HI_MEM_TLC_BARRIER_WATCH_CONFIG_REG_SECTIONID_RESET_VALUE 0x00000000
#define TLC_HI_MEM_TLC_BARRIER_WATCH_CONFIG_REG_ENABLEWATCH_LSB 0x0018
#define TLC_HI_MEM_TLC_BARRIER_WATCH_CONFIG_REG_ENABLEWATCH_MSB 0x0018
#define TLC_HI_MEM_TLC_BARRIER_WATCH_CONFIG_REG_ENABLEWATCH_RANGE 0x0001
#define TLC_HI_MEM_TLC_BARRIER_WATCH_CONFIG_REG_ENABLEWATCH_MASK 0x01000000
#define TLC_HI_MEM_TLC_BARRIER_WATCH_CONFIG_REG_ENABLEWATCH_RESET_VALUE 0x00000000
#define TLC_HI_MEM_TLC_BARRIER_WATCH_CONFIG_REG_RESERVED_INTERRUPTSENT_LSB 0x0019
#define TLC_HI_MEM_TLC_BARRIER_WATCH_CONFIG_REG_RESERVED_INTERRUPTSENT_MSB 0x0019
#define TLC_HI_MEM_TLC_BARRIER_WATCH_CONFIG_REG_RESERVED_INTERRUPTSENT_RANGE 0x0001
#define TLC_HI_MEM_TLC_BARRIER_WATCH_CONFIG_REG_RESERVED_INTERRUPTSENT_MASK 0x02000000
#define TLC_HI_MEM_TLC_BARRIER_WATCH_CONFIG_REG_RESERVED_INTERRUPTSENT_RESET_VALUE 0x00000000
#define TLC_HI_MEM_TLC_BARRIER_WATCH_CONFIG_REG_RESERVED_STOPPEDATBARRIER_LSB 0x001a
#define TLC_HI_MEM_TLC_BARRIER_WATCH_CONFIG_REG_RESERVED_STOPPEDATBARRIER_MSB 0x001a
#define TLC_HI_MEM_TLC_BARRIER_WATCH_CONFIG_REG_RESERVED_STOPPEDATBARRIER_RANGE 0x0001
#define TLC_HI_MEM_TLC_BARRIER_WATCH_CONFIG_REG_RESERVED_STOPPEDATBARRIER_MASK 0x04000000
#define TLC_HI_MEM_TLC_BARRIER_WATCH_CONFIG_REG_RESERVED_STOPPEDATBARRIER_RESET_VALUE 0x00000000
#define TLC_HI_MEM_TLC_BARRIER_WATCH_CONFIG_REG_RESERVED_LSB 0x001b
#define TLC_HI_MEM_TLC_BARRIER_WATCH_CONFIG_REG_RESERVED_MSB 0x001f
#define TLC_HI_MEM_TLC_BARRIER_WATCH_CONFIG_REG_RESERVED_RANGE 0x0005
#define TLC_HI_MEM_TLC_BARRIER_WATCH_CONFIG_REG_RESERVED_MASK 0xf8000000
#define TLC_HI_MEM_TLC_BARRIER_WATCH_CONFIG_REG_RESERVED_RESET_VALUE 0x00000000

/*  ------------------------------------------------------------------ */
/* */
#ifndef TLC_HI_MEM_TLC_GENERATE_CONTROL_UCMD_REG_FLAG
#define TLC_HI_MEM_TLC_GENERATE_CONTROL_UCMD_REG_FLAG

/*  TLC_GENERATE_CONTROL_UCMD_REG desc:  Generate CnC control */
/* uCommands register; To be used for debug only */
union TLC_HI_MEM_TLC_GENERATE_CONTROL_UCMD_REG_t {
	struct {
uint32_t  destCbbid            :   8;
/*   Destination CBBID for control */
/* uCmd packet*/
uint32_t  opcode               :   4;
/*   Opcode for control uCmd */
/* packet*/
uint32_t  isPosted             :   1;
/*   If LOW, the TLC will block */
/* waiting for a reply*/
uint32_t  reserved             :  19;    /*  Set to zero*/
	}                                field;
uint32_t                         val;
};
#endif
#define TLC_HI_MEM_TLC_GENERATE_CONTROL_UCMD_REG_OFFSET 0x38
#define TLC_HI_MEM_TLC_GENERATE_CONTROL_UCMD_REG_SCOPE 0x01
#define TLC_HI_MEM_TLC_GENERATE_CONTROL_UCMD_REG_SIZE 32
#define TLC_HI_MEM_TLC_GENERATE_CONTROL_UCMD_REG_BITFIELD_COUNT 0x04
#define TLC_HI_MEM_TLC_GENERATE_CONTROL_UCMD_REG_RESET 0x00000000
#define TLC_HI_MEM_TLC_GENERATE_CONTROL_UCMD_REG_DESTCBBID_LSB 0x0000
#define TLC_HI_MEM_TLC_GENERATE_CONTROL_UCMD_REG_DESTCBBID_MSB 0x0007
#define TLC_HI_MEM_TLC_GENERATE_CONTROL_UCMD_REG_DESTCBBID_RANGE 0x0008
#define TLC_HI_MEM_TLC_GENERATE_CONTROL_UCMD_REG_DESTCBBID_MASK 0x000000ff
#define TLC_HI_MEM_TLC_GENERATE_CONTROL_UCMD_REG_DESTCBBID_RESET_VALUE 0x00000000
#define TLC_HI_MEM_TLC_GENERATE_CONTROL_UCMD_REG_OPCODE_LSB 0x0008
#define TLC_HI_MEM_TLC_GENERATE_CONTROL_UCMD_REG_OPCODE_MSB 0x000b
#define TLC_HI_MEM_TLC_GENERATE_CONTROL_UCMD_REG_OPCODE_RANGE 0x0004
#define TLC_HI_MEM_TLC_GENERATE_CONTROL_UCMD_REG_OPCODE_MASK 0x00000f00
#define TLC_HI_MEM_TLC_GENERATE_CONTROL_UCMD_REG_OPCODE_RESET_VALUE 0x00000000
#define TLC_HI_MEM_TLC_GENERATE_CONTROL_UCMD_REG_ISPOSTED_LSB 0x000c
#define TLC_HI_MEM_TLC_GENERATE_CONTROL_UCMD_REG_ISPOSTED_MSB 0x000c
#define TLC_HI_MEM_TLC_GENERATE_CONTROL_UCMD_REG_ISPOSTED_RANGE 0x0001
#define TLC_HI_MEM_TLC_GENERATE_CONTROL_UCMD_REG_ISPOSTED_MASK 0x00001000
#define TLC_HI_MEM_TLC_GENERATE_CONTROL_UCMD_REG_ISPOSTED_RESET_VALUE 0x00000000
#define TLC_HI_MEM_TLC_GENERATE_CONTROL_UCMD_REG_RESERVED_LSB 0x000d
#define TLC_HI_MEM_TLC_GENERATE_CONTROL_UCMD_REG_RESERVED_MSB 0x001f
#define TLC_HI_MEM_TLC_GENERATE_CONTROL_UCMD_REG_RESERVED_RANGE 0x0013
#define TLC_HI_MEM_TLC_GENERATE_CONTROL_UCMD_REG_RESERVED_MASK 0xffffe000
#define TLC_HI_MEM_TLC_GENERATE_CONTROL_UCMD_REG_RESERVED_RESET_VALUE 0x00000000

/*  ------------------------------------------------------------------ */
/* */
#ifndef TLC_HI_MEM_TLC_DEBUG_REG_FLAG
#define TLC_HI_MEM_TLC_DEBUG_REG_FLAG

/*  TLC_DEBUG_REG desc:  General purpose TLC configuration register; */
/* To be used to */
/* configure/control TLC*/
union TLC_HI_MEM_TLC_DEBUG_REG_t {
	struct {
uint32_t  CFG_PAYLOAD          :  32;
/*   General Purpose Configuration */
	}                                field;
uint32_t                         val;
};
#endif
#define TLC_HI_MEM_TLC_DEBUG_REG_OFFSET 0x3c
#define TLC_HI_MEM_TLC_DEBUG_REG_SCOPE 0x01
#define TLC_HI_MEM_TLC_DEBUG_REG_SIZE 32
#define TLC_HI_MEM_TLC_DEBUG_REG_BITFIELD_COUNT 0x01
#define TLC_HI_MEM_TLC_DEBUG_REG_RESET 0x00000000
#define TLC_HI_MEM_TLC_DEBUG_REG_CFG_PAYLOAD_LSB 0x0000
#define TLC_HI_MEM_TLC_DEBUG_REG_CFG_PAYLOAD_MSB 0x001f
#define TLC_HI_MEM_TLC_DEBUG_REG_CFG_PAYLOAD_RANGE 0x0020
#define TLC_HI_MEM_TLC_DEBUG_REG_CFG_PAYLOAD_MASK 0xffffffff
#define TLC_HI_MEM_TLC_DEBUG_REG_CFG_PAYLOAD_RESET_VALUE 0x00000000

/*  ------------------------------------------------------------------ */
/* */
/* starting the array instantiation section*/
struct tlc_hi_t {
union TLC_HI_MEM_TLC_GP_REG_t    TLC_GP_REG[64];
/*  offset 4'h0, width 32 */
union TLC_HI_MEM_TLC_SP_REG0_t   TLC_SP_REG0;
/*  offset 12'h100, width 32 */
union TLC_HI_MEM_TLC_SP_REG1_t   TLC_SP_REG1;
/*  offset 12'h104, width 32 */
union TLC_HI_MEM_TLC_SP_REG2_t   TLC_SP_REG2;
/*  offset 12'h108, width 32 */
union TLC_HI_MEM_TLC_SP_REG3_t   TLC_SP_REG3;
/*  offset 12'h10C, width 32 */
union TLC_HI_MEM_TLC_CR_ACC_CONTROL_MODE_REG_t TLC_CR_ACC_CONTROL_MODE_REG;
/*  offset 12'h110, width 32 */
union TLC_HI_MEM_TLC_ACTIVITY_TIMEOUT_t TLC_ACTIVITY_TIMEOUT;
/*  offset 12'h114, width 32 */
union TLC_HI_MEM_TLC_DUMP_CONTROL_REG_t TLC_DUMP_CONTROL_REG;
/*  offset 12'h118, width 32 */
union TLC_HI_MEM_TLC_DUMP_BUFFER_CONFIG_REG_t TLC_DUMP_BUFFER_CONFIG_REG;
/*  offset 12'h11C, width 32 */
union TLC_HI_MEM_TLC_DUMP_MARKER_REG_t TLC_DUMP_MARKER_REG;
/*  offset 12'h120, width 32 */
union TLC_HI_MEM_TLC_MAILBOX_DOORBELL_t TLC_MAILBOX_DOORBELL[4];
/*  offset 12'h124, width 32 */
union TLC_HI_MEM_TLC_BARRIER_WATCH_CONFIG_REG_t TLC_BARRIER_WATCH_CONFIG_REG;
/*  offset 12'h134, width 32 */
union TLC_HI_MEM_TLC_GENERATE_CONTROL_UCMD_REG_t TLC_GENERATE_CONTROL_UCMD_REG;
/*  offset 12'h138, width 32 */
union TLC_HI_MEM_TLC_DEBUG_REG_t TLC_DEBUG_REG[16];
/*  offset 12'h13C, width 32 */
};

#define CVE_TLC_HI_TLC_GP_REG                                  0
#define CVE_TLC_HI_TLC_SP_REG0                                64
#define CVE_TLC_HI_TLC_SP_REG1                                65
#define CVE_TLC_HI_TLC_SP_REG2                                66
#define CVE_TLC_HI_TLC_SP_REG3                                67
#define CVE_TLC_HI_TLC_CR_ACC_CONTROL_MODE_REG                68
#define CVE_TLC_HI_TLC_ACTIVITY_TIMEOUT                       69
#define CVE_TLC_HI_TLC_DUMP_CONTROL_REG                       70
#define CVE_TLC_HI_TLC_DUMP_BUFFER_CONFIG_REG                 71
#define CVE_TLC_HI_TLC_DUMP_MARKER_REG                        72
#define CVE_TLC_HI_TLC_MAILBOX_DOORBELL                       73
#define CVE_TLC_HI_TLC_BARRIER_WATCH_CONFIG_REG               77
#define CVE_TLC_HI_TLC_GENERATE_CONTROL_UCMD_REG              78
#define CVE_TLC_HI_TLC_DEBUG_REG                              79

#endif // _TLC_HI_REGS_H_
