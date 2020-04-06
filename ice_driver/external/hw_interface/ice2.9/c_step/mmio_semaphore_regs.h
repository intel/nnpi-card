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

#ifndef _MMIO_SEMAPHORE_REGS_H_
#define _MMIO_SEMAPHORE_REGS_H_
#define CVE_SEMAPHORE_BASE 0x400
#define CVE_SEMAPHORE_MMIO_CVE_SEM_CMD_MMOFFSET 0x0
#define CVE_SEMAPHORE_MMIO_CVE_SEM_STATUS_MMOFFSET 0x4
#define CVE_SEMAPHORE_HW_REVISION_MMOFFSET 0x8
#define CVE_SEMAPHORE_MMIO_CVE_SEM_GENERAL_MMOFFSET 0x0C
#define CVE_SEMAPHORE_MMIO_CVE_REGISTER_DEMON_ENABLE_MMOFFSET 0x1C
#define CVE_SEMAPHORE_MMIO_CVE_REGISTER_DEMON_CONTROL_MMOFFSET 0x20
#define CVE_SEMAPHORE_MMIO_CVE_REGISTER_DEMON_TABLE_MMOFFSET 0x24
#define CVE_SEMAPHORE_MMIO_CVE_RESET_CONTROL_MMOFFSET 0x0A4
#define CVE_SEMAPHORE_MMIO_UBP_MMOFFSET 0x0A8
#define CVE_SEMAPHORE_MMIO_CVE_BOOT_ADDR_CTRL_MMOFFSET 0x0AC
#ifndef MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_CMD_FLAG
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_CMD_FLAG

/*  MMIO_CVE_SEM_CMD desc:  Power Domain : CVE Gated Reset Domain : */
/* CVE Reset Function Domain : */

/*  CVE Semaphore Register to write the drivers commands to the */
/* semaphore */
union MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_CMD_t {
	struct {
uint32_t  REQ_TYPE             :   1;
/*   The command type: 0:Request ; */
/* 1:Release*/
uint32_t  REQ_OWNER            :   2;
/*   The requesting driver - The */
/* driver that issues the*/
/* command: 1:Host(Atom)*/
/* 2:ISH(AOH)*/
uint32_t  REQ_INT_EN           :   1;
/*   Sets the semaphores interrupt */
/* mode for the requesting*/
/* driver. When enabled, the*/
/* semaphore will interrupt the*/
/* requesting driver once the*/
/* driver gets the semaphore*/
/* (acquires it). 0:Disable*/
/* 1:Enable*/
uint32_t  REQ_SEQURED          :   1;
/*   Enables secured workload */
/* mode. When enabled (in*/
/* 'request' command) the*/
/* semaphore will verify that the*/
/* OCP matrix src_id of the*/
/* corresponding release command*/
/* matches the REQ_OWNER field*/
/* before releasing the*/
/* semaphore. This way the*/
/* semaphore can block any*/
/* attempt of the other driver to*/
/* release the semaphore.*/
/* 0:Disable 1:Enable*/
uint32_t  RSVD_0               :  27;
/*  Nebulon auto filled RSVD [31:5] */
	}                                field;
uint32_t                         val;
};
#endif
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_CMD_OFFSET 0x00
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_CMD_SCOPE 0x01
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_CMD_SIZE 32
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_CMD_BITFIELD_COUNT 0x04
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_CMD_RESET 0x00000000
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_CMD_REQ_TYPE_LSB 0x0000
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_CMD_REQ_TYPE_MSB 0x0000
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_CMD_REQ_TYPE_RANGE 0x0001
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_CMD_REQ_TYPE_MASK 0x00000001
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_CMD_REQ_TYPE_RESET_VALUE 0x00000000
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_CMD_REQ_OWNER_LSB 0x0001
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_CMD_REQ_OWNER_MSB 0x0002
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_CMD_REQ_OWNER_RANGE 0x0002
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_CMD_REQ_OWNER_MASK 0x00000006
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_CMD_REQ_OWNER_RESET_VALUE 0x00000000
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_CMD_REQ_INT_EN_LSB 0x0003
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_CMD_REQ_INT_EN_MSB 0x0003
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_CMD_REQ_INT_EN_RANGE 0x0001
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_CMD_REQ_INT_EN_MASK 0x00000008
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_CMD_REQ_INT_EN_RESET_VALUE 0x00000000
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_CMD_REQ_SEQURED_LSB 0x0004
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_CMD_REQ_SEQURED_MSB 0x0004
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_CMD_REQ_SEQURED_RANGE 0x0001
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_CMD_REQ_SEQURED_MASK 0x00000010
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_CMD_REQ_SEQURED_RESET_VALUE 0x00000000

/*  ------------------------------------------------------------------ */
/* */
#ifndef MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_STATUS_FLAG
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_STATUS_FLAG

/*  MMIO_CVE_SEM_STATUS desc:  Power Domain : CVE Gated Reset Domain : */
/* CVE Reset Function Domain : */
/* CVE Semaphore Register to read the semaphore status*/
union MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_STATUS_t {
	struct {
uint32_t  STATUS_PREV_OWNER    :   2;
/*   The previos driver which */
/* owned the semaphore; 0:none*/
/* 1:Host 2:ISH*/
uint32_t  STATUS_OWNER         :   2;
/*   The semaphore current owner - */
/* The driver which currently*/
/* owns the semaphore; 0:none;*/
/* 1:Host; 2:ISH*/
uint32_t  STATUS_NEXT_OWNER    :   2;
/*   The semaphore next owner - */
/* The driver which reserved the*/
/* semaphore. The 'next' owner*/
/* will become the semaphore*/
/* owner after the current owner*/
/* will 'release' the semaphore.*/
/* 0:none 1:Host 2:ISH Note:*/
/* drivers reserve the semaphore*/
/* by writing a regular request*/
/* command to the command*/
/* register. If the semaphore is*/
/* owned by the other driver when*/
/* the request is received the*/
/* requesting driver becomes the*/
/* 'next' owner. If the semaphore*/
/* is ready (available) when the*/
/* request arrives the requesting*/
/* driver becomes the semaphore*/
/* current owner and the next*/
/* owner is set to 'none'.*/
uint32_t  STATUS_INT_EN        :   1;
/*   The interrupt mode for the */
/* next driver. When interrupts*/
/* are enabled the next driver*/
/* will be interrupted when it*/
/* becomes the semaphore owner.*/
/* 0:Disable 1:Enable*/
uint32_t  STATUS_STATE         :   2;
/*   The semaphore state - used */
/* mainly for debug. 0:Ready :*/
/* The semaphore is ready and is*/
/* not owned by either one of the*/
/* drivers. 1:Acquired : The*/
/* semaphore is owned by one of*/
/* the drivers 2:Reserved : The*/
/* semaphore is owned by one of*/
/* the drivers and the other*/
/* driver has reserved it.*/
uint32_t  STATUS_SECURED       :   1;
/*   The current owner of the */
/* semaphore has enabled secured*/
/* mode in it request. When this*/
/* bit is set the semaphore will*/
/* ignore any release command in*/
/* which the OCP 'src_id' doesn't*/
/* match REQ_OWNER field in the*/
/* command. Secured mode prevents*/
/* the driver that doesn't own*/
/* the semaphore from releasing*/
/* the semaphore 'on behalf' of*/
/* the owner.*/
uint32_t  STATUS_NEXT_SECURED  :   1;
/*   The requested secured mode of */
/* the next driver owner - used*/
/* mainly for debug.*/
uint32_t  RSVD_0               :  21;
/*  Nebulon auto filled RSVD [31:11] */
	}                                field;
uint32_t                         val;
};
#endif
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_STATUS_OFFSET 0x04
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_STATUS_SCOPE 0x01
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_STATUS_SIZE 32
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_STATUS_BITFIELD_COUNT 0x07
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_STATUS_RESET 0x00000000
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_STATUS_STATUS_PREV_OWNER_LSB 0x0000
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_STATUS_STATUS_PREV_OWNER_MSB 0x0001
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_STATUS_STATUS_PREV_OWNER_RANGE 0x0002
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_STATUS_STATUS_PREV_OWNER_MASK 0x00000003
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_STATUS_STATUS_PREV_OWNER_RESET_VALUE 0x00000000
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_STATUS_STATUS_OWNER_LSB 0x0002
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_STATUS_STATUS_OWNER_MSB 0x0003
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_STATUS_STATUS_OWNER_RANGE 0x0002
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_STATUS_STATUS_OWNER_MASK 0x0000000c
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_STATUS_STATUS_OWNER_RESET_VALUE 0x00000000
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_STATUS_STATUS_NEXT_OWNER_LSB 0x0004
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_STATUS_STATUS_NEXT_OWNER_MSB 0x0005
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_STATUS_STATUS_NEXT_OWNER_RANGE 0x0002
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_STATUS_STATUS_NEXT_OWNER_MASK 0x00000030
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_STATUS_STATUS_NEXT_OWNER_RESET_VALUE 0x00000000
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_STATUS_STATUS_INT_EN_LSB 0x0006
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_STATUS_STATUS_INT_EN_MSB 0x0006
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_STATUS_STATUS_INT_EN_RANGE 0x0001
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_STATUS_STATUS_INT_EN_MASK 0x00000040
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_STATUS_STATUS_INT_EN_RESET_VALUE 0x00000000
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_STATUS_STATUS_STATE_LSB 0x0007
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_STATUS_STATUS_STATE_MSB 0x0008
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_STATUS_STATUS_STATE_RANGE 0x0002
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_STATUS_STATUS_STATE_MASK 0x00000180
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_STATUS_STATUS_STATE_RESET_VALUE 0x00000000
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_STATUS_STATUS_SECURED_LSB 0x0009
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_STATUS_STATUS_SECURED_MSB 0x0009
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_STATUS_STATUS_SECURED_RANGE 0x0001
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_STATUS_STATUS_SECURED_MASK 0x00000200
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_STATUS_STATUS_SECURED_RESET_VALUE 0x00000000
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_STATUS_STATUS_NEXT_SECURED_LSB 0x000a
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_STATUS_STATUS_NEXT_SECURED_MSB 0x000a
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_STATUS_STATUS_NEXT_SECURED_RANGE 0x0001
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_STATUS_STATUS_NEXT_SECURED_MASK 0x00000400
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_STATUS_STATUS_NEXT_SECURED_RESET_VALUE 0x00000000

/*  ------------------------------------------------------------------ */
/* */
#ifndef MMIO_SEMAPHORE_MEM_HW_REVISION_FLAG
#define MMIO_SEMAPHORE_MEM_HW_REVISION_FLAG

/*  HW_REVISION desc:  Power Domain : CVE Gated Reset Domain : CVE */
/* Reset Function Domain : */

/*  CVE Info hw: a read-only register. the HW writes the revision */
/* numbers */
/* in it : [br] Upper 16-bits : major revision : same value as*/

/*  RevisionID field : bits 0-7 of PCI register 0x08 [br] Lower 16 */
/* bits : */
/* minor revision*/
union MMIO_SEMAPHORE_MEM_HW_REVISION_t {
	struct {
uint32_t  major_rev            :  16;
/*   Major revision - same value */
/* as the RevisionID field in the*/
/* PCI config register 0x08*/
uint32_t  minor_rev            :  16;    /*  Minor revision*/
	}                                field;
uint32_t                         val;
};
#endif
#define MMIO_SEMAPHORE_MEM_HW_REVISION_OFFSET 0x08
#define MMIO_SEMAPHORE_MEM_HW_REVISION_SCOPE 0x01
#define MMIO_SEMAPHORE_MEM_HW_REVISION_SIZE 32
#define MMIO_SEMAPHORE_MEM_HW_REVISION_BITFIELD_COUNT 0x02
#define MMIO_SEMAPHORE_MEM_HW_REVISION_RESET 0x00000000
#define MMIO_SEMAPHORE_MEM_HW_REVISION_MAJOR_REV_LSB 0x0000
#define MMIO_SEMAPHORE_MEM_HW_REVISION_MAJOR_REV_MSB 0x000f
#define MMIO_SEMAPHORE_MEM_HW_REVISION_MAJOR_REV_RANGE 0x0010
#define MMIO_SEMAPHORE_MEM_HW_REVISION_MAJOR_REV_MASK 0x0000ffff
#define MMIO_SEMAPHORE_MEM_HW_REVISION_MAJOR_REV_RESET_VALUE 0x00000000
#define MMIO_SEMAPHORE_MEM_HW_REVISION_MINOR_REV_LSB 0x0010
#define MMIO_SEMAPHORE_MEM_HW_REVISION_MINOR_REV_MSB 0x001f
#define MMIO_SEMAPHORE_MEM_HW_REVISION_MINOR_REV_RANGE 0x0010
#define MMIO_SEMAPHORE_MEM_HW_REVISION_MINOR_REV_MASK 0xffff0000
#define MMIO_SEMAPHORE_MEM_HW_REVISION_MINOR_REV_RESET_VALUE 0x00000000

/*  ------------------------------------------------------------------ */
/* */
#ifndef MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_GENERAL_FLAG
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_GENERAL_FLAG

/*  MMIO_CVE_SEM_GENERAL desc:  Power Domain : CVE Gated Reset Domain */
/* : CVE Semaphore Reset Function */
/* Domain : CVE Semaphore General Purpse register for semaphores*/
/* Comunication*/
union MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_GENERAL_t {
	struct {
uint32_t  GENERAL              :  32;
/*   Semaphore General Register */
	}                                field;
uint32_t                         val;
};
#endif
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_GENERAL_OFFSET 0x0c
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_GENERAL_SCOPE 0x01
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_GENERAL_SIZE 32
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_GENERAL_BITFIELD_COUNT 0x01
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_GENERAL_RESET 0x00000000
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_GENERAL_GENERAL_LSB 0x0000
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_GENERAL_GENERAL_MSB 0x001f
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_GENERAL_GENERAL_RANGE 0x0020
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_GENERAL_GENERAL_MASK 0xffffffff
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_GENERAL_GENERAL_RESET_VALUE 0x00000000

/*  ------------------------------------------------------------------ */
/* */
#ifndef MMIO_SEMAPHORE_MEM_MMIO_CVE_REGISTER_DEMON_ENABLE_FLAG
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_REGISTER_DEMON_ENABLE_FLAG

/*  MMIO_CVE_REGISTER_DEMON_ENABLE desc:  Register Reader Demon Enable */
/* */
union MMIO_SEMAPHORE_MEM_MMIO_CVE_REGISTER_DEMON_ENABLE_t {
	struct {
uint32_t  DEMON_ENABLE         :   1;
/*   Function: 0:Off ; 1:On */
uint32_t  RSVD_0               :  31;
/*  Nebulon auto filled RSVD [31:1] */
	}                                field;
uint32_t                         val;
};
#endif
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_REGISTER_DEMON_ENABLE_OFFSET 0x1c
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_REGISTER_DEMON_ENABLE_SCOPE 0x01
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_REGISTER_DEMON_ENABLE_SIZE 32
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_REGISTER_DEMON_ENABLE_BITFIELD_COUNT 0x01
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_REGISTER_DEMON_ENABLE_RESET 0x00000000
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_REGISTER_DEMON_ENABLE_DEMON_ENABLE_LSB 0x0000
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_REGISTER_DEMON_ENABLE_DEMON_ENABLE_MSB 0x0000
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_REGISTER_DEMON_ENABLE_DEMON_ENABLE_RANGE 0x0001
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_REGISTER_DEMON_ENABLE_DEMON_ENABLE_MASK 0x00000001
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_REGISTER_DEMON_ENABLE_DEMON_ENABLE_RESET_VALUE 0x00000000

/*  ------------------------------------------------------------------ */
/* */
#ifndef MMIO_SEMAPHORE_MEM_MMIO_CVE_REGISTER_DEMON_CONTROL_FLAG
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_REGISTER_DEMON_CONTROL_FLAG

/*  MMIO_CVE_REGISTER_DEMON_CONTROL desc:  Register Reader Demon */
/* Control */
union MMIO_SEMAPHORE_MEM_MMIO_CVE_REGISTER_DEMON_CONTROL_t {
	struct {
uint32_t  RSVD_0               : 2;
/*  Nebulon auto filled RSVD [0:1] */
uint32_t  IMMIDIATE_READ       :   1;
/*   Generates immediate reads for */
/* all registers in the table*/
uint32_t  RSVD_1               :  29;
/*  Nebulon auto filled RSVD [31:3] */
	}                                field;
uint32_t                         val;
};
#endif
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_REGISTER_DEMON_CONTROL_OFFSET 0x20
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_REGISTER_DEMON_CONTROL_SCOPE 0x01
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_REGISTER_DEMON_CONTROL_SIZE 32
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_REGISTER_DEMON_CONTROL_BITFIELD_COUNT 0x01
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_REGISTER_DEMON_CONTROL_RESET 0x00000000
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_REGISTER_DEMON_CONTROL_IMMIDIATE_READ_LSB 0x0002
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_REGISTER_DEMON_CONTROL_IMMIDIATE_READ_MSB 0x0002
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_REGISTER_DEMON_CONTROL_IMMIDIATE_READ_RANGE 0x0001
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_REGISTER_DEMON_CONTROL_IMMIDIATE_READ_MASK 0x00000004
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_REGISTER_DEMON_CONTROL_IMMIDIATE_READ_RESET_VALUE 0x00000000

/*  ------------------------------------------------------------------ */
/* */
#ifndef MMIO_SEMAPHORE_MEM_MMIO_CVE_REGISTER_DEMON_TABLE_FLAG
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_REGISTER_DEMON_TABLE_FLAG
/* MMIO_CVE_REGISTER_DEMON_TABLE desc:  demon table registers*/
union MMIO_SEMAPHORE_MEM_MMIO_CVE_REGISTER_DEMON_TABLE_t {
	struct {
uint32_t  REGISTER_ADDRESS     :  18;
/*   The address of the first */
/* register to be read*/
uint32_t  RSVD_0               :   2;
/*  Nebulon auto filled RSVD [19:18] */
uint32_t  FREQ_EXPONENT        :   4;
/*   Freq = 256 * 2^FreqExponent */
uint32_t  CONSECUTIVES         :   5;
/*   Number of additional */
/* consecutives registers to read*/
uint32_t  RSVD_1               :   2;
/*  Nebulon auto filled RSVD [30:29] */
uint32_t  ENABLE               :   1;
/*   enable this table entry */
	}                                field;
uint32_t                         val;
};
#endif
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_REGISTER_DEMON_TABLE_OFFSET 0x24
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_REGISTER_DEMON_TABLE_SCOPE 0x01
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_REGISTER_DEMON_TABLE_SIZE 32
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_REGISTER_DEMON_TABLE_BITFIELD_COUNT 0x04
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_REGISTER_DEMON_TABLE_RESET 0x00f00000
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_REGISTER_DEMON_TABLE_REGISTER_ADDRESS_LSB 0x0000
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_REGISTER_DEMON_TABLE_REGISTER_ADDRESS_MSB 0x0011
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_REGISTER_DEMON_TABLE_REGISTER_ADDRESS_RANGE 0x0012
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_REGISTER_DEMON_TABLE_REGISTER_ADDRESS_MASK 0x0003ffff
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_REGISTER_DEMON_TABLE_REGISTER_ADDRESS_RESET_VALUE 0x00000000
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_REGISTER_DEMON_TABLE_FREQ_EXPONENT_LSB 0x0014
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_REGISTER_DEMON_TABLE_FREQ_EXPONENT_MSB 0x0017
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_REGISTER_DEMON_TABLE_FREQ_EXPONENT_RANGE 0x0004
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_REGISTER_DEMON_TABLE_FREQ_EXPONENT_MASK 0x00f00000
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_REGISTER_DEMON_TABLE_FREQ_EXPONENT_RESET_VALUE 0x0000000f
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_REGISTER_DEMON_TABLE_CONSECUTIVES_LSB 0x0018
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_REGISTER_DEMON_TABLE_CONSECUTIVES_MSB 0x001c
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_REGISTER_DEMON_TABLE_CONSECUTIVES_RANGE 0x0005
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_REGISTER_DEMON_TABLE_CONSECUTIVES_MASK 0x1f000000
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_REGISTER_DEMON_TABLE_CONSECUTIVES_RESET_VALUE 0x00000000
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_REGISTER_DEMON_TABLE_ENABLE_LSB 0x001f
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_REGISTER_DEMON_TABLE_ENABLE_MSB 0x001f
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_REGISTER_DEMON_TABLE_ENABLE_RANGE 0x0001
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_REGISTER_DEMON_TABLE_ENABLE_MASK 0x80000000
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_REGISTER_DEMON_TABLE_ENABLE_RESET_VALUE 0x00000000

/*  ------------------------------------------------------------------ */
/* */
#ifndef MMIO_SEMAPHORE_MEM_MMIO_CVE_RESET_CONTROL_FLAG
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_RESET_CONTROL_FLAG
/* MMIO_CVE_RESET_CONTROL desc:  Reset enable register*/
union MMIO_SEMAPHORE_MEM_MMIO_CVE_RESET_CONTROL_t {
	struct {
uint32_t  TLC_BRESET_ENABLE    :   1;    /*  TLC BReset Enable*/
uint32_t  TLC_DRESET_ENABLE    :   1;    /*  TLC DReset Enable*/
uint32_t  TLC_JRESET_ENABLE    :   1;    /*  TLC JReset Enable*/
uint32_t  TLC_OCD_HALT_ON_RESET :   1;
/*   TLC OCD Halt On Reset */
uint32_t  IVP_BRESET_ENABLE    :   1;    /*  IVP BReset Enable*/
uint32_t  IVP_DRESET_ENABLE    :   1;    /*  IVP DReset Enable*/
uint32_t  IVP_JRESET_ENABLE    :   1;    /*  IVP JReset Enable*/
uint32_t  IVP_OCD_HALT_ON_RESET :   1;
/*   IVP OCD Halt On Reset */
uint32_t  ASIP0_BRESET_ENABLE  :   1;    /*  ASIP0 BReset Enable*/
uint32_t  ASIP0_DRESET_ENABLE  :   1;    /*  ASIP0 DReset Enable*/
uint32_t  ASIP0_JRESET_ENABLE  :   1;    /*  ASIP0 JReset Enable*/
uint32_t  ASIP0_OCD_HALT_ON_RESET :   1;
/*   ASIP0 OCD Halt On Reset */
uint32_t  RESERVED             :  20;    /*  Reserved Bits*/
	}                                field;
uint32_t                         val;
};
#endif
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_RESET_CONTROL_OFFSET 0xa4
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_RESET_CONTROL_SCOPE 0x01
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_RESET_CONTROL_SIZE 32
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_RESET_CONTROL_BITFIELD_COUNT 0x0d
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_RESET_CONTROL_RESET 0x00000777
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_RESET_CONTROL_TLC_BRESET_ENABLE_LSB 0x0000
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_RESET_CONTROL_TLC_BRESET_ENABLE_MSB 0x0000
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_RESET_CONTROL_TLC_BRESET_ENABLE_RANGE 0x0001
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_RESET_CONTROL_TLC_BRESET_ENABLE_MASK 0x00000001
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_RESET_CONTROL_TLC_BRESET_ENABLE_RESET_VALUE 0x00000001
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_RESET_CONTROL_TLC_DRESET_ENABLE_LSB 0x0001
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_RESET_CONTROL_TLC_DRESET_ENABLE_MSB 0x0001
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_RESET_CONTROL_TLC_DRESET_ENABLE_RANGE 0x0001
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_RESET_CONTROL_TLC_DRESET_ENABLE_MASK 0x00000002
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_RESET_CONTROL_TLC_DRESET_ENABLE_RESET_VALUE 0x00000001
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_RESET_CONTROL_TLC_JRESET_ENABLE_LSB 0x0002
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_RESET_CONTROL_TLC_JRESET_ENABLE_MSB 0x0002
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_RESET_CONTROL_TLC_JRESET_ENABLE_RANGE 0x0001
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_RESET_CONTROL_TLC_JRESET_ENABLE_MASK 0x00000004
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_RESET_CONTROL_TLC_JRESET_ENABLE_RESET_VALUE 0x00000001
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_RESET_CONTROL_TLC_OCD_HALT_ON_RESET_LSB 0x0003
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_RESET_CONTROL_TLC_OCD_HALT_ON_RESET_MSB 0x0003
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_RESET_CONTROL_TLC_OCD_HALT_ON_RESET_RANGE 0x0001
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_RESET_CONTROL_TLC_OCD_HALT_ON_RESET_MASK 0x00000008
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_RESET_CONTROL_TLC_OCD_HALT_ON_RESET_RESET_VALUE 0x00000000
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_RESET_CONTROL_IVP_BRESET_ENABLE_LSB 0x0004
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_RESET_CONTROL_IVP_BRESET_ENABLE_MSB 0x0004
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_RESET_CONTROL_IVP_BRESET_ENABLE_RANGE 0x0001
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_RESET_CONTROL_IVP_BRESET_ENABLE_MASK 0x00000010
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_RESET_CONTROL_IVP_BRESET_ENABLE_RESET_VALUE 0x00000001
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_RESET_CONTROL_IVP_DRESET_ENABLE_LSB 0x0005
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_RESET_CONTROL_IVP_DRESET_ENABLE_MSB 0x0005
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_RESET_CONTROL_IVP_DRESET_ENABLE_RANGE 0x0001
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_RESET_CONTROL_IVP_DRESET_ENABLE_MASK 0x00000020
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_RESET_CONTROL_IVP_DRESET_ENABLE_RESET_VALUE 0x00000001
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_RESET_CONTROL_IVP_JRESET_ENABLE_LSB 0x0006
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_RESET_CONTROL_IVP_JRESET_ENABLE_MSB 0x0006
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_RESET_CONTROL_IVP_JRESET_ENABLE_RANGE 0x0001
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_RESET_CONTROL_IVP_JRESET_ENABLE_MASK 0x00000040
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_RESET_CONTROL_IVP_JRESET_ENABLE_RESET_VALUE 0x00000001
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_RESET_CONTROL_IVP_OCD_HALT_ON_RESET_LSB 0x0007
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_RESET_CONTROL_IVP_OCD_HALT_ON_RESET_MSB 0x0007
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_RESET_CONTROL_IVP_OCD_HALT_ON_RESET_RANGE 0x0001
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_RESET_CONTROL_IVP_OCD_HALT_ON_RESET_MASK 0x00000080
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_RESET_CONTROL_IVP_OCD_HALT_ON_RESET_RESET_VALUE 0x00000000
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_RESET_CONTROL_ASIP0_BRESET_ENABLE_LSB 0x0008
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_RESET_CONTROL_ASIP0_BRESET_ENABLE_MSB 0x0008
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_RESET_CONTROL_ASIP0_BRESET_ENABLE_RANGE 0x0001
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_RESET_CONTROL_ASIP0_BRESET_ENABLE_MASK 0x00000100
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_RESET_CONTROL_ASIP0_BRESET_ENABLE_RESET_VALUE 0x00000001
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_RESET_CONTROL_ASIP0_DRESET_ENABLE_LSB 0x0009
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_RESET_CONTROL_ASIP0_DRESET_ENABLE_MSB 0x0009
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_RESET_CONTROL_ASIP0_DRESET_ENABLE_RANGE 0x0001
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_RESET_CONTROL_ASIP0_DRESET_ENABLE_MASK 0x00000200
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_RESET_CONTROL_ASIP0_DRESET_ENABLE_RESET_VALUE 0x00000001
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_RESET_CONTROL_ASIP0_JRESET_ENABLE_LSB 0x000a
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_RESET_CONTROL_ASIP0_JRESET_ENABLE_MSB 0x000a
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_RESET_CONTROL_ASIP0_JRESET_ENABLE_RANGE 0x0001
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_RESET_CONTROL_ASIP0_JRESET_ENABLE_MASK 0x00000400
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_RESET_CONTROL_ASIP0_JRESET_ENABLE_RESET_VALUE 0x00000001
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_RESET_CONTROL_ASIP0_OCD_HALT_ON_RESET_LSB 0x000b
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_RESET_CONTROL_ASIP0_OCD_HALT_ON_RESET_MSB 0x000b
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_RESET_CONTROL_ASIP0_OCD_HALT_ON_RESET_RANGE 0x0001
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_RESET_CONTROL_ASIP0_OCD_HALT_ON_RESET_MASK 0x00000800
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_RESET_CONTROL_ASIP0_OCD_HALT_ON_RESET_RESET_VALUE 0x00000000
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_RESET_CONTROL_RESERVED_LSB 0x000c
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_RESET_CONTROL_RESERVED_MSB 0x001f
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_RESET_CONTROL_RESERVED_RANGE 0x0014
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_RESET_CONTROL_RESERVED_MASK 0xfffff000
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_RESET_CONTROL_RESERVED_RESET_VALUE 0x00000000

/*  ------------------------------------------------------------------ */
/* */
#ifndef MMIO_SEMAPHORE_MEM_MMIO_UBP_FLAG
#define MMIO_SEMAPHORE_MEM_MMIO_UBP_FLAG
/* MMIO_UBP desc:  Enable the uBP machine control*/
union MMIO_SEMAPHORE_MEM_MMIO_UBP_t {
	struct {
uint32_t  TLC_UBP_ENABLE       :   1;    /*  TLC Enable uBP*/
uint32_t  ASIP_UBP_ENABLE      :   1;    /*  ASIP Enable uBP*/
uint32_t  IVP_UBP_ENABLE       :   1;    /*  IVP Enable uBP*/
uint32_t  RSVD_0               :  29;
/*  Nebulon auto filled RSVD [31:3] */
	}                                field;
uint32_t                         val;
};
#endif
#define MMIO_SEMAPHORE_MEM_MMIO_UBP_OFFSET 0xa8
#define MMIO_SEMAPHORE_MEM_MMIO_UBP_SCOPE 0x01
#define MMIO_SEMAPHORE_MEM_MMIO_UBP_SIZE 32
#define MMIO_SEMAPHORE_MEM_MMIO_UBP_BITFIELD_COUNT 0x03
#define MMIO_SEMAPHORE_MEM_MMIO_UBP_RESET 0x00000000
#define MMIO_SEMAPHORE_MEM_MMIO_UBP_TLC_UBP_ENABLE_LSB 0x0000
#define MMIO_SEMAPHORE_MEM_MMIO_UBP_TLC_UBP_ENABLE_MSB 0x0000
#define MMIO_SEMAPHORE_MEM_MMIO_UBP_TLC_UBP_ENABLE_RANGE 0x0001
#define MMIO_SEMAPHORE_MEM_MMIO_UBP_TLC_UBP_ENABLE_MASK 0x00000001
#define MMIO_SEMAPHORE_MEM_MMIO_UBP_TLC_UBP_ENABLE_RESET_VALUE 0x00000000
#define MMIO_SEMAPHORE_MEM_MMIO_UBP_ASIP_UBP_ENABLE_LSB 0x0001
#define MMIO_SEMAPHORE_MEM_MMIO_UBP_ASIP_UBP_ENABLE_MSB 0x0001
#define MMIO_SEMAPHORE_MEM_MMIO_UBP_ASIP_UBP_ENABLE_RANGE 0x0001
#define MMIO_SEMAPHORE_MEM_MMIO_UBP_ASIP_UBP_ENABLE_MASK 0x00000002
#define MMIO_SEMAPHORE_MEM_MMIO_UBP_ASIP_UBP_ENABLE_RESET_VALUE 0x00000000
#define MMIO_SEMAPHORE_MEM_MMIO_UBP_IVP_UBP_ENABLE_LSB 0x0002
#define MMIO_SEMAPHORE_MEM_MMIO_UBP_IVP_UBP_ENABLE_MSB 0x0002
#define MMIO_SEMAPHORE_MEM_MMIO_UBP_IVP_UBP_ENABLE_RANGE 0x0001
#define MMIO_SEMAPHORE_MEM_MMIO_UBP_IVP_UBP_ENABLE_MASK 0x00000004
#define MMIO_SEMAPHORE_MEM_MMIO_UBP_IVP_UBP_ENABLE_RESET_VALUE 0x00000000

/*  ------------------------------------------------------------------ */
/* */
#ifndef MMIO_SEMAPHORE_MEM_MMIO_CVE_BOOT_ADDR_CTRL_FLAG
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_BOOT_ADDR_CTRL_FLAG

/*  MMIO_CVE_BOOT_ADDR_CTRL desc:  Alternate Reset Vector for */
/* tensilica */
union MMIO_SEMAPHORE_MEM_MMIO_CVE_BOOT_ADDR_CTRL_t {
	struct {
uint32_t  TLC_BOOT_ADDR_CTRL   :   1;    /*  TLC BReset Enable*/
uint32_t  RSVD_0               :  31;
/*  Nebulon auto filled RSVD [31:1] */
	}                                field;
uint32_t                         val;
};
#endif
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_BOOT_ADDR_CTRL_OFFSET 0xac
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_BOOT_ADDR_CTRL_SCOPE 0x01
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_BOOT_ADDR_CTRL_SIZE 32
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_BOOT_ADDR_CTRL_BITFIELD_COUNT 0x01
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_BOOT_ADDR_CTRL_RESET 0x00000000
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_BOOT_ADDR_CTRL_TLC_BOOT_ADDR_CTRL_LSB 0x0000
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_BOOT_ADDR_CTRL_TLC_BOOT_ADDR_CTRL_MSB 0x0000
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_BOOT_ADDR_CTRL_TLC_BOOT_ADDR_CTRL_RANGE 0x0001
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_BOOT_ADDR_CTRL_TLC_BOOT_ADDR_CTRL_MASK 0x00000001
#define MMIO_SEMAPHORE_MEM_MMIO_CVE_BOOT_ADDR_CTRL_TLC_BOOT_ADDR_CTRL_RESET_VALUE 0x00000000

/*  ------------------------------------------------------------------ */
/* */
/* starting the array instantiation section*/
struct mmio_semaphore_t {
union MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_CMD_t MMIO_CVE_SEM_CMD;
/*  offset 4'h0, width 32 */
union MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_STATUS_t MMIO_CVE_SEM_STATUS;
/*  offset 4'h4, width 32 */
union MMIO_SEMAPHORE_MEM_HW_REVISION_t HW_REVISION;
/*  offset 4'h8, width 32 */
union MMIO_SEMAPHORE_MEM_MMIO_CVE_SEM_GENERAL_t MMIO_CVE_SEM_GENERAL[4];
/*  offset 8'h0C, width 32 */
union MMIO_SEMAPHORE_MEM_MMIO_CVE_REGISTER_DEMON_ENABLE_t MMIO_CVE_REGISTER_DEMON_ENABLE;
/*  offset 8'h1C, width 32 */
union MMIO_SEMAPHORE_MEM_MMIO_CVE_REGISTER_DEMON_CONTROL_t MMIO_CVE_REGISTER_DEMON_CONTROL;
/*  offset 8'h20, width 32 */
union MMIO_SEMAPHORE_MEM_MMIO_CVE_REGISTER_DEMON_TABLE_t MMIO_CVE_REGISTER_DEMON_TABLE[32];
/*  offset 8'h24, width 32 */
union MMIO_SEMAPHORE_MEM_MMIO_CVE_RESET_CONTROL_t MMIO_CVE_RESET_CONTROL;
/*  offset 12'h0A4, width 32 */
union MMIO_SEMAPHORE_MEM_MMIO_UBP_t MMIO_UBP;
/*  offset 12'h0A8, width 32 */
union MMIO_SEMAPHORE_MEM_MMIO_CVE_BOOT_ADDR_CTRL_t MMIO_CVE_BOOT_ADDR_CTRL;
/*  offset 12'h0AC, width 32 */
};

#define CVE_SEMAPHORE_MMIO_CVE_SEM_CMD                         0
#define CVE_SEMAPHORE_MMIO_CVE_SEM_STATUS                      1
#define CVE_SEMAPHORE_HW_REVISION                              2
#define CVE_SEMAPHORE_MMIO_CVE_SEM_GENERAL                     3
#define CVE_SEMAPHORE_MMIO_CVE_REGISTER_DEMON_ENABLE           7
#define CVE_SEMAPHORE_MMIO_CVE_REGISTER_DEMON_CONTROL          8
#define CVE_SEMAPHORE_MMIO_CVE_REGISTER_DEMON_TABLE            9
#define CVE_SEMAPHORE_MMIO_CVE_RESET_CONTROL                  41
#define CVE_SEMAPHORE_MMIO_UBP                                42
#define CVE_SEMAPHORE_MMIO_CVE_BOOT_ADDR_CTRL                 43

#endif // _MMIO_SEMAPHORE_REGS_H_