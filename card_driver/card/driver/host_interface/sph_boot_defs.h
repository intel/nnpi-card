/********************************************
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/
#ifndef _SPH_DOORBELL_H
#define _SPH_DOORBELL_H

/*
 * Value fields of card->host doorbell status register PCI_HOST_DOORBELL_VALUE
 */
#define SPH_CARD_BOOT_STATE_MASK            0xf
#define SPH_CARD_BOOT_STATE_SHIFT           0
#define SPH_CARD_BIOS_UPDATE_STATE_MASK     0xf0
#define SPH_CARD_BIOS_UPDATE_STATE_SHIFT    4
#define SPH_CARD_BIOS_UPDATE_COUNTER_MASK   0xf00
#define SPH_CARD_BIOS_UPDATE_COUNTER_SHIFT  8
#define SPH_CARD_ERROR_MASK                 0xf000
#define SPH_CARD_ERROR_SHIFT                12

/* Possible values for card boot state */
#define SPH_CARD_BOOT_STATE_NOT_READY       0  /* bios has not yet initialized */
#define SPH_CARD_BOOT_STATE_BIOS_READY      1  /* bios initilaized and waiting for os boot image over pci */
#define SPH_CARD_BOOT_STATE_BIOS_READY_EMMC 2  /* bios initilaized and is booting from EMMC */
#define SPH_CARD_BOOT_STATE_BOOT_STARTED    3  /* bios copied boot image successfully, os boot has started */
#define SPH_CARD_BOOT_STATE_DRV_READY       4  /* card has booted and card driver has loaded */
#define SPH_CARD_BOOT_STATE_CARD_READY      8  /* card driver finished initialization and user space daemon has started */
#define SPH_CARD_BOOT_STATE_BIOS_SYSINFO_READY 10  /* bios copied data into the system info structure */

/* Possible values for card bios update state */
#define SPH_CARD_BIOS_UPDATE_STATE_NOT_READY     0  /* bios has not yer initialized or bios update is not needed */
#define SPH_CARD_BIOS_UPDATE_BIOS_READY          1  /* bios is waiting for bios image before starting bios update */
#define SPH_CARD_BIOS_UPDATE_WRITING_SPI         2  /* bios started writing image to SPI memory */
#define SPH_CARD_BIOS_UPDATE_DONE                3  /* bios image updated successfully in SPI */


/*
 * Value fields of host->card doorbell status register HOST_PCI_DOORBELL_VALUE
 */
#define SPH_HOST_BOOT_STATE_MASK            0xf
#define SPH_HOST_BOOT_STATE_SHIFT           0
#define SPH_HOST_ERROR_MASK                 0xf0
#define SPH_HOST_ERROR_SHIFT                4
#define SPH_HOST_DRV_STATE_MASK             0xf00
#define SPH_HOST_DRV_STATE_SHIFT            8
#define SPH_HOST_DRV_REQUEST_SELF_RESET_MASK  0x10000  /* set by the host driver to request card to reset itself (not through FLR flow) */
#define SPH_HOST_DRV_REQUEST_SELF_RESET_SHIFT 16

/* Possible values for host boot state */
#define SPH_HOST_BOOT_STATE_IMAGE_NOT_READY         0             /* boot/bios image is not loaded yet to memory */
#define SPH_HOST_BOOT_STATE_DRV_READY               (0x1 | 0x8)   /* host driver is up and ready */
#define SPH_HOST_BOOT_STATE_DEBUG_OS_IMAGE_READY    (0x2 | 0x8)   /* debug os image is loaded and ready in memory */
#define SPH_HOST_BOOT_STATE_BIOS_IMAGE_READY        (0x3 | 0x8)   /* bios image is loaded and ready in memory */
#define SPH_HOST_BOOT_STATE_DEBUG_BIOS_IMAGE_READY  (0x4 | 0x8)   /* debug bios image is loaded and ready in memory */

/* Possible values for host error */
#define SPH_HOST_ERROR_CANNOT_LOAD_IMAGE     1

/* Possible values for host driver state */
#define SPH_HOST_DRV_STATE_NOT_READY         0   /* driver did not detected the device yet */
#define SPH_HOST_DRV_STATE_READY             1   /* driver initialized and ready */
#define SPH_HOST_DRV_STATE_VERSION_ERROR     2   /* host/card protocol version mismatch */

#endif
