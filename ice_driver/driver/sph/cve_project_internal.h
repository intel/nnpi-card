/*
 * NNP-I Linux Driver
 * Copyright (c) 2017-2019, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 */

#ifndef _CVE_PLATFORM_INTERNAL_H_
#define _CVE_PLATFORM_INTERNAL_H_

#define ICEDRV_ENABLE_CACHING_IN_HW 1

#define CVE_DMA_BIT_MASK DMA_BIT_MASK(35)
#ifdef DISABLE_LLC
/* no LLC on FPGA */
#define AXI_ATTRIBUTE_TABLE_0 0
#define AXI_ATTRIBUTE_TABLE_1 0
#define AXI_ATTRIBUTE_TABLE_2 0
#define AXI_ATTRIBUTE_TABLE_3 0
#define CVE_TLC_LLC_CONFIG 0
#define CVE_DSP_LLC_CONFIG 0
#define CVE_ASIP_LLC_CONFIG 0
#define CVE_FW_LLC_CONFIG 0
#define CVE_FIFO_LLC_CONFIG 0
#define CVE_DUMP_LLC_CONFIG 0
#define CVE_PAGE_WALK_AXI_ATTRIBUTES 0

#else /* DISABLE_LLC */

#if ICEDRV_ENABLE_CACHING_IN_HW

#define AXI_ATTRIBUTE_TABLE_0 0
#define AXI_ATTRIBUTE_TABLE_1 0
#define AXI_ATTRIBUTE_TABLE_2 0
#define AXI_ATTRIBUTE_TABLE_3 0

#define CVE_FW_LLC_CONFIG 0x8

#define CVE_FIFO_LLC_CONFIG 0x8
#define CVE_DUMP_LLC_CONFIG 0x2 /*uncached read, cached, allocate on write*/
#define ICE_BAR1_LLC_CONFIG 0
#define CVE_TLC_LLC_CONFIG 0xFF	/* Write back RW allocate */
#define CVE_DSP_LLC_CONFIG 0xFF	 /* TODO is LLC valid for IVP? */
#define CVE_ASIP_LLC_CONFIG 0xFF /* Write back RW allocate */
#define CVE_PAGE_WALK_AXI_ATTRIBUTES 0xFF /* Write back RW allocate */

#else /* ICEDRV_ENABLE_CACHING_IN_HW */

#define AXI_ATTRIBUTE_TABLE_0 0x33221100
#define AXI_ATTRIBUTE_TABLE_1 0xEEEA6E6A
#define AXI_ATTRIBUTE_TABLE_2 0xFFFB7F7B
#define AXI_ATTRIBUTE_TABLE_3 0xF0F0F0F0
/*
 * kernel allocation should have Index in AXI attribute table that will
 * be set in page table
 */

/* Disabling because HSLE doesnot support Cache */
#define CVE_FW_LLC_CONFIG 0	/* 0xFF ==> Write back RW allocate */

#define CVE_FIFO_LLC_CONFIG 0	/* 0x00 ==> cache bypass */
#define CVE_DUMP_LLC_CONFIG 0
#define ICE_BAR1_LLC_CONFIG 0

/*
 * Registers that should be set for default Tensilica cores configuration
 * Should have exact AXIxCache value and not index in AXI attribute table
 */
/* Disabling because HSLE doesnot support Cache */
#define CVE_TLC_LLC_CONFIG 0x0	/* Write back RW allocate */
#define CVE_DSP_LLC_CONFIG 0x0	/* Write back RW allocate */
#define CVE_ASIP_LLC_CONFIG 0x0	/* Write back RW allocate */

/*
 * Configure the page walk when there is a miss in TLB
 * Should have exact AXIxCache value and not index in AXI attribute table
 */
/* Disabling because HSLE doesnot support Cache */
#define CVE_PAGE_WALK_AXI_ATTRIBUTES 0x0 /* Write back RW allocate */
#endif /* ICEDRV_ENABLE_CACHING_IN_HW */
#endif /* DISABLE_LLC */

/*
 * default is 20 - we reconfiguring it to 24 using the device
 * AXI_TABLE_PT_INDEX mmio
 */
#define CVE_LLC_BIT_SHIFT 24U
#define CVE_LLC_MAX_POLICY_NR 16U
#define CVE_PCI_DEVICE_ID 0x45c4
#define AXI_MAX_INFLIGHT_READ_TRANSACTION 63
#define AXI_MAX_INFLIGHT_WRITE_TRANSACTION 63

#define DUMMY_CHACHLINE_SZ 10
#define PLAFTORM_CACHELINE_SZ DUMMY_CHACHLINE_SZ

/* timeout counter threshold bits [19:10]. Counted in Uclks */
/* Set to max possible value */
#define SHARED_READ_TIMEOUT_THRESHOLD 0x3FF

/* as per HAS */
#define DEFAULT_MAX_SHARED_DISTANCE 0x10

#define IA_IICS_BASE (4 * 1024)

#endif /* _CVE_PLATFORM_INTERNAL_H_ */

