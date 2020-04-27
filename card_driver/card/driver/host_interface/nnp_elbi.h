/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/
#ifndef _NNP_ELBI_H
#define _NNP_ELBI_H

#include <linux/bitops.h>

/*
 * Macros for accessing bit fields according to mask and shift
 */
#define ELBI_BF_GET(regval, mask, shift)         (((regval) & (mask)) >> (shift))
#define ELBI_BF_VAL(val, mask, shift)            (((val) << (shift)) & (mask))
#define ELBI_BF_SET(regval, val, mask, shift)     \
	((regval) = (((regval) & ~(mask)) | ELBI_BF_VAL((val), (mask), (shift))))

#define ELBI_LINE_BDF                         (ELBI_BASE + 0x4)

/*
 * COMMAND FIFO registers
 */
#define ELBI_COMMAND_WRITE_WO_MSI_LOW         (ELBI_BASE + 0x50)
#define ELBI_COMMAND_WRITE_WO_MSI_HIGH        (ELBI_BASE + 0x54)
#define ELBI_COMMAND_WRITE_W_MSI_LOW          (ELBI_BASE + 0x58)
#define ELBI_COMMAND_WRITE_W_MSI_HIGH         (ELBI_BASE + 0x5C)

#define ELBI_COMMAND_FIFO_0_LOW		      (ELBI_BASE + 0x80)
#define ELBI_COMMAND_FIFO_LOW(i)              (ELBI_COMMAND_FIFO_0_LOW+(i)*8)
#define ELBI_COMMAND_FIFO_HIGH(i)             (ELBI_COMMAND_FIFO_0_LOW+(i)*8+4)
#define ELBI_COMMAND_FIFO_DEPTH               16

#define ELBI_COMMAND_IOSF_CONTROL                         (ELBI_BASE + 0x44)
#define ELBI_COMMAND_IOSF_CONTROL_READ_POINTER_MASK       GENMASK(3, 0)
#define ELBI_COMMAND_IOSF_CONTROL_READ_POINTER_SHIFT      0
#define ELBI_COMMAND_IOSF_CONTROL_WRITE_POINTER_MASK      GENMASK(12, 8)
#define ELBI_COMMAND_IOSF_CONTROL_WRITE_POINTER_SHIFT     8
#define ELBI_COMMAND_IOSF_CONTROL_ALMOST_FULL_TH_MASK     GENMASK(19, 16)
#define ELBI_COMMAND_IOSF_CONTROL_ALMOST_FULL_TH_SHIFT    16
#define ELBI_COMMAND_IOSF_CONTROL_FLUSH_MASK              BIT(24)

#define ELBI_COMMAND_PCI_CONTROL                          (ELBI_BASE + 0x48)
#define ELBI_COMMAND_PCI_CONTROL_ALMOST_EMPTY_TH_MASK     GENMASK(3, 0)
#define ELBI_COMMAND_PCI_CONTROL_ALMOST_EMPTY_TH_SHIFT    0
#define ELBI_COMMAND_PCI_CONTROL_FLUSH_MASK               BIT(8)

/*
 * RESPONSE FIFO registers
 */
#define ELBI_RESPONSE_WRITE_WO_MSI_LOW        (ELBI_BASE + 0x68)
#define ELBI_RESPONSE_WRITE_WO_MSI_HIGH       (ELBI_BASE + 0x6C)
#define ELBI_RESPONSE_WRITE_W_MSI_LOW         (ELBI_BASE + 0x70)
#define ELBI_RESPONSE_WRITE_W_MSI_HIGH        (ELBI_BASE + 0x74)

#define ELBI_RESPONSE_FIFO_0_LOW	      (ELBI_BASE + 0x100)
#define ELBI_RESPONSE_FIFO_LOW(i)             (ELBI_RESPONSE_FIFO_0_LOW+(i)*8)
#define ELBI_RESPONSE_FIFO_HIGH(i)            (ELBI_RESPONSE_FIFO_0_LOW+(i)*8+4)
#define ELBI_RESPONSE_FIFO_DEPTH              16

#define ELBI_RESPONSE_PCI_CONTROL                       (ELBI_BASE + 0x60)
#define ELBI_RESPONSE_PCI_CONTROL_READ_POINTER_MASK     GENMASK(3, 0)
#define ELBI_RESPONSE_PCI_CONTROL_READ_POINTER_SHIFT    0
#define ELBI_RESPONSE_PCI_CONTROL_WRITE_POINTER_MASK    GENMASK(12, 8)
#define ELBI_RESPONSE_PCI_CONTROL_WRITE_POINTER_SHIFT   8
#define ELBI_RESPONSE_PCI_CONTROL_ALMOST_FULL_TH_MASK   GENMASK(19, 16)
#define ELBI_RESPONSE_PCI_CONTROL_ALMOST_FULL_TH_SHIFT  16
#define ELBI_RESPONSE_PCI_CONTROL_FLUSH_MASK            BIT(24)

#define ELBI_RESPONSE_IOSF_CONTROL                       (ELBI_BASE + 0x64)
#define ELBI_RESPONSE_IOSF_CONTROL_ALMOST_EMPTY_TH_MASK  GENAMSK(3, 0)
#define ELBI_RESPONSE_IOSF_CONTROL_ALMOST_EMPTY_TH_SHIFT 0
#define ELBI_RESPONSE_IOSF_CONTROL_FLUSH_MASK            BIT(8)

/*
 * Host side interrupt status & mask register
 */
#define ELBI_PCI_STATUS                       (ELBI_BASE + 0x8)
#define ELBI_PCI_MSI_MASK                     (ELBI_BASE + 0xC)
#define ELBI_PCI_STATUS_COMMAND_FIFO_EMPTY_MASK               BIT(0)
#define ELBI_PCI_STATUS_COMMAND_FIFO_ALMOST_EMPTY_MASK        BIT(1)
#define ELBI_PCI_STATUS_COMMAND_FIFO_READ_UPDATE_MASK         BIT(2)
#define ELBI_PCI_STATUS_COMMAND_FIFO_FLUSH_MASK               BIT(3)
#define ELBI_PCI_STATUS_COMMAND_FIFO_WRITE_ERROR_MASK         BIT(4)
#define ELBI_PCI_STATUS_RESPONSE_FIFO_FULL_MASK               BIT(5)
#define ELBI_PCI_STATUS_RESPONSE_FIFO_ALMOST_FULL_MASK        BIT(6)
#define ELBI_PCI_STATUS_RESPONSE_FIFO_NEW_RESPONSE_MASK       BIT(7)
#define ELBI_PCI_STATUS_RESPONSE_FIFO_FLUSH_MASK              BIT(8)
#define ELBI_PCI_STATUS_RESPONSE_FIFO_READ_ERROR_MASK         BIT(9)
#define ELBI_PCI_STATUS_RESPONSE_FIFO_READ_POINTER_ERROR_MASK BIT(10)
#define ELBI_PCI_STATUS_DOORBELL_MASK                         BIT(11)
#define ELBI_PCI_STATUS_DOORBELL_READ_MASK                    BIT(12)
#define ELBI_PCI_STATUS_FLR_REQUEST_MASK                      BIT(13)
#define ELBI_PCI_STATUS_LOCAL_D3_MASK                         BIT(14)
#define ELBI_PCI_STATUS_LOCAL_FLR_MASK                        BIT(15)


#define ELBI_IOSF_STATUS                                   (ELBI_BASE + 0x10)
#define ELBI_IOSF_MSI_MASK                                 (ELBI_BASE + 0x14)
#define ELBI_IOSF_STATUS_COMMAND_FIFO_FULL_MASK              BIT(0)
#define ELBI_IOSF_STATUS_COMMAND_FIFO_ALMOST_FULL_MASK       BIT(1)
#define ELBI_IOSF_STATUS_COMMAND_FIFO_NEW_COMMAND_MASK       BIT(2)
#define ELBI_IOSF_STATUS_COMMAND_FIFO_FLUSH_MASK             BIT(3)
#define ELBI_IOSF_STATUS_COMMAND_FIFO_READ_ERROR_MASK        BIT(4)
#define ELBI_IOSF_STATUS_COMMAND_FIFO_READ_POINTER_ERROR_MASK BIT(5)
#define ELBI_IOSF_STATUS_RESPONSE_FIFO_EMPTY_MASK            BIT(6)
#define ELBI_IOSF_STATUS_RESPONSE_FIFO_ALMOST_EMPTY_MASK     BIT(7)
#define ELBI_IOSF_STATUS_RESPONSE_FIFO_READ_UPDATE_MASK      BIT(8)
#define ELBI_IOSF_STATUS_RESPONSE_FIFO_FLUSH_MASK            BIT(9)
#define ELBI_IOSF_STATUS_RESPONSE_FIFO_WRITE_ERROR_MASK      BIT(10)
#define ELBI_IOSF_STATUS_DOORBELL_MASK                       BIT(11)
#define ELBI_IOSF_STATUS_DOORBELL_READ_MASK                  BIT(12)
#define ELBI_IOSF_STATUS_LINE_D3_MASK                        BIT(13)
#define ELBI_IOSF_STATUS_D_STATE_CHANGE_MASK                 BIT(14)
#define ELBI_IOSF_STATUS_LINE_FLR_MASK                       BIT(15)
#define ELBI_IOSF_STATUS_HOT_RESET_MASK                      BIT(16)
#define ELBI_IOSF_STATUS_PME_TURN_OFF_MASK                   BIT(17)
#define ELBI_IOSF_STATUS_PERST_B_MASK                        BIT(18)
#define ELBI_IOSF_STATUS_PERST_ASSERTION_MASK                BIT(19)
#define ELBI_IOSF_STATUS_DMA_INT_MASK                        BIT(20)
#define ELBI_IOSF_STATUS_LINE_BME_MASK                       BIT(21)
#define ELBI_IOSF_STATUS_BME_CHANGE_MASK                     BIT(22)
#define ELBI_IOSF_STATUS_D0I3_COMPLETE_MASK                  BIT(23)
#define ELBI_IOSF_STATUS_RST_LOAD_PHY_RECIPE_MASK            BIT(24)
#define ELBI_IOSF_STATUS_RST_LOAD_PHY_FW_MSK                 BIT(25)
#define ELBI_IOSF_STATUS_RST_START_PEP_MASK                  BIT(26)

/* DOORBELL registers */
#define ELBI_PCI_HOST_DOORBELL_VALUE                        (ELBI_BASE + 0x34)
#define ELBI_HOST_PCI_DOORBELL_VALUE                        (ELBI_BASE + 0x38)

/* CPU_STATUS registers */
#define ELBI_CPU_STATUS_0                                   (ELBI_BASE + 0x1b8)  /*< Updated by bios with postcode */
#define ELBI_CPU_STATUS_1                                   (ELBI_BASE + 0x1bc)  /*< Updated by bios with bios flash progress */
#define ELBI_CPU_STATUS_2                                   (ELBI_BASE + 0x1c0)  /*< Updated by card driver - see bitfields below */
#define ELBI_CPU_STATUS_3                                   (ELBI_BASE + 0x1c4)

/* Bitfields updated in ELBI_CPU_STATUS_2 indicating card driver states */
#define ELBI_CPU_STATUS_2_FLR_MODE_MASK                     GENMASK(1, 0)  /* indicates next card reset behaviour:
									    *   00 - warm reset
									    *   01 - cold reset
									    *   10 - ignore FLR (will not reset the card)
									    *   11 - warm reset + bios flash + cold_reset (capsule update)
									    */
#define ELBI_CPU_STATUS_2_FLR_MODE_SHIFT                    0

#endif
