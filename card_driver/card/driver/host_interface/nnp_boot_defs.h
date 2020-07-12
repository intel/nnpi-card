/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/
#ifndef _NNP_DOORBELL_H
#define _NNP_DOORBELL_H

/*
 * Value fields of card->host doorbell status register HOST_PCI_DOORBELL_VALUE
 */
#define NNP_CARD_BOOT_STATE_MASK            0xff
#define NNP_CARD_BOOT_STATE_SHIFT           0
#define NNP_CARD_BIOS_UPDATE_COUNTER_MASK   0xf00
#define NNP_CARD_BIOS_UPDATE_COUNTER_SHIFT  8
#define NNP_CARD_ERROR_MASK                 0xf000
#define NNP_CARD_ERROR_SHIFT                12
#define NNP_CARD_KEEP_ALIVE_MASK            0x00f00000
#define NNP_CARD_KEEP_ALIVE_SHIFT           20

/* Possible values for card boot state */
#define NNP_CARD_BOOT_STATE_NOT_READY       0  /* bios has not yet initialized */
#define NNP_CARD_BOOT_STATE_BIOS_READY      1  /* bios initilaized and waiting for os boot image over pci */
#define NNP_CARD_BOOT_STATE_RECOVERY_BIOS_READY 2  /* recovery bios initilaized, waiting for capsule update */
#define NNP_CARD_BOOT_STATE_BOOT_STARTED    3  /* bios copied boot image successfully, os boot has started */
#define NNP_CARD_BOOT_STATE_DRV_READY       4  /* card has booted and card driver has loaded */
#define NNP_CARD_BOOT_STATE_CARD_READY      8  /* card driver finished initialization and user space daemon has started */
#define NNP_CARD_BOOT_STATE_BIOS_SYSINFO_READY 10  /* bios copied data into the system info structure */
#define NNP_CARD_BOOT_STATE_BIOS_FLASH_STARTED 0x20

/* Possible card error values */
#define NNP_CARD_ERROR_HOST_ERROR           1
#define NNP_CARD_ERROR_BOOT_PARAMS          2
#define NNP_CARD_ERROR_IMAGE_COPY           3
#define NNP_CARD_ERROR_CORRUPTED_IMAGE      4
#define NNP_CARD_ERROR_NOT_CAPSULE          8
#define NNP_CARD_ERROR_CAPSULE_FAILED       9
/*
 * Value fields of host->card doorbell status register PCI_HOST_DOORBELL_VALUE
 */
#define NNP_HOST_BOOT_STATE_MASK            0xf
#define NNP_HOST_BOOT_STATE_SHIFT           0
#define NNP_HOST_ERROR_MASK                 0xf0
#define NNP_HOST_ERROR_SHIFT                4
#define NNP_HOST_DRV_STATE_MASK             0xf00
#define NNP_HOST_DRV_STATE_SHIFT            8
#define NNP_HOST_DRV_REQUEST_SELF_RESET_MASK  0x10000  /* set by the host driver to request card to reset itself (not through FLR flow) */
#define NNP_HOST_DRV_REQUEST_SELF_RESET_SHIFT 16
#define NNP_HOST_KEEP_ALIVE_MASK            0x00f00000
#define NNP_HOST_KEEP_ALIVE_SHIFT           20
#define NNP_HOSY_P2P_POKE_MASK              0xff000000
#define NNP_HOSY_P2P_POKE_SHIFT             24

/* Possible values for host boot state */
#define NNP_HOST_BOOT_STATE_IMAGE_NOT_READY         0             /* boot/bios image is not loaded yet to memory */
#define NNP_HOST_BOOT_STATE_DRV_READY               (0x1 | 0x8)   /* host driver is up and ready */
#define NNP_HOST_BOOT_STATE_DEBUG_OS_IMAGE_READY    (0x2 | 0x8)   /* debug os image is loaded and ready in memory */
#define NNP_HOST_BOOT_STATE_BIOS_IMAGE_READY        (0x3 | 0x8)   /* bios image is loaded and ready in memory */
#define NNP_HOST_BOOT_STATE_DEBUG_BIOS_IMAGE_READY  (0x4 | 0x8)   /* debug bios image is loaded and ready in memory */

/* Possible values for host error */
#define NNP_HOST_ERROR_CANNOT_LOAD_IMAGE     1

/* Possible values for host driver state */
#define NNP_HOST_DRV_STATE_NOT_READY         0   /* driver did not detected the device yet */
#define NNP_HOST_DRV_STATE_READY             1   /* driver initialized and ready */
#define NNP_HOST_DRV_STATE_VERSION_ERROR     2   /* host/card protocol version mismatch */

#endif
