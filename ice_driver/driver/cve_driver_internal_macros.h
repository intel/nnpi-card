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

#ifndef _CVE_DRIVER_INTERNAL_MACROS_H_
#define _CVE_DRIVER_INTERNAL_MACROS_H_

#ifdef RING3_VALIDATION
#include <assert.h>
#include <stdint.h>
#include <stdint_ext.h>
#include <errno.h>
#else
#include <linux/types.h>
#endif

#ifndef __KERNEL__
#include <unistd.h>
#include <string.h>
#include <sys/user.h>
#endif

#define CVE_CLEAR_BIT(val, pos) (val &= ~(1 << pos))
#define CVE_INVALID_VIRTUAL_ADDR ((cve_virtual_address_t)-1)
#define ICE_ENABLE_EXTENDED_VA_MODE 1

typedef u64 ice_va_t;

enum cve_memory_type {
	CVE_MEMORY_TYPE_USER,
	CVE_MEMORY_TYPE_KERNEL_CONTIG,
	CVE_MEMORY_TYPE_KERNEL_SG,
	CVE_MEMORY_TYPE_SHARED_BUFFER_SG
};

/*
 *
 * WARNING: BE CAREFUL WHEN CHANGING THIS ENUM VALUES
 *
 * This enum is used for generating the binary FW map file.
 * Changes to this enum requires synchronization with the script
 * which generates the binary FW map file.
 *
 */
enum cve_memory_protection {
	CVE_MM_PROT_READ = 1,
	CVE_MM_PROT_WRITE = 2,
	CVE_MM_PROT_EXEC = 4
};

#ifndef BIT
#define BIT(nr)	(1UL << (nr))
#endif

#ifndef BIT_ULL
#define BIT_ULL(nr)	(1ULL << (nr))
#endif

#ifndef CACHE_LINE_SIZE
#define CACHE_LINE_SIZE 64
#endif

#ifndef DWORD_LO
#define DWORD_LO(_64_bit_int_) ((u32)(_64_bit_int_))
#endif

#ifndef DWORD_HI
#define DWORD_HI(_64_bit_int_) ((u32)(_64_bit_int_ >> 32))
#endif

#undef ASSERT
#ifdef RING3_VALIDATION
#define ASSERT(_e) assert(_e)
#else
#define ASSERT(_e) \
	{ if (!(_e)) { \
	cve_os_log(CVE_LOGLEVEL_ERROR, "ASSERTION FAILED! '%s'\n", #_e); \
	BUG(); } }
#endif

/* a generaic error code that is returned
 * in case no other, more accurate, error code fits
 */
#define CVE_DEFAULT_ERROR_CODE -ENODEV

/* size of a TLC command. TODO - verify this number auto at build time */
#define TLC_COMMAND_SIZE_SHIFT 5

/* number of bits in one BYTE */
#define BITS_PER_BYTE 8

/* CVE Address width */
#define ICE_VA_WIDTH 32
#define ICE_VA_WIDTH_EXTENDED 35
#define ICE_PAGE_SHIFT_4K	12
#define ICE_PAGE_SHIFT_32K	15
#define ICE_PAGE_SHIFT_64K	16
#define ICE_PAGE_SHIFT_128K	17
#define ICE_PAGE_SHIFT_256K	18
#define ICE_PAGE_SHIFT_512K	19
#define ICE_PAGE_SHIFT_1M	20
#define ICE_PAGE_SHIFT_2M	21
#define ICE_PAGE_SHIFT_4M	22
#define ICE_PAGE_SHIFT_8M	23
#define ICE_PAGE_SHIFT_16M	24
#define ICE_PAGE_SHIFT_32M	25
#define ICE_PAGE_SHIFT_64M	26
#define ICE_PAGE_SHIFT_128M	27
#define ICE_PAGE_SHIFT_256M	28


#if ICE_ENABLE_EXTENDED_VA_MODE
#define ICE_DEFAULT_PA_SHIFT 12
#define ICE_DEFAULT_PA_WIDTH 36
#define ICE_DEFAULT_L2_SHIFT 15
#define ICE_DEFAULT_VA_WIDTH 35
#define ICE_DEFAULT_PAGE_SHIFT 15
#define ICE_MIN_PAGE_SIZE_SHIFT 15
#define ICE_MEM_MAX_PARTITION 8
#define ICE_DEFAULT_PDE_VA_SPAN (BIT_ULL(ICE_PAGE_SHIFT_32M))
#else
#define ICE_DEFAULT_PA_SHIFT 12
#define ICE_DEFAULT_PA_WIDTH 36
#define ICE_DEFAULT_L2_SHIFT 12
#define ICE_DEFAULT_VA_WIDTH 32
#define ICE_DEFAULT_PAGE_SHIFT 12
#define ICE_MIN_PAGE_SIZE_SHIFT 12
#define ICE_MEM_MAX_PARTITION 1
#define ICE_DEFAULT_PDE_VA_SPAN (BIT_ULL(ICE_PAGE_SHIFT_4M))
#endif


#define ICE_DEFAULT_PAGE_SZ BIT_ULL(ICE_DEFAULT_PAGE_SHIFT)

/* os page size */
#define OS_PAGE_SHIFT		PAGE_SHIFT
#define OS_PAGE_SIZE		PAGE_SIZE
#define OS_PAGE_MASK		PAGE_MASK

#define ICE_PAGE_SZ(page_shift) BIT_ULL(page_shift)
#define ICE_PAGE_MASK(page_shift) (~(ICE_PAGE_SZ(page_shift) - 1))

#define ICE_PAGE_SZ_4K (BIT_ULL(ICE_PAGE_SHIFT_4K))
#define ICE_PAGE_SZ_32K (BIT_ULL(ICE_PAGE_SHIFT_32K))
#define ICE_PAGE_SZ_4M (BIT_ULL(ICE_PAGE_SHIFT_4M))
#define ICE_PAGE_SZ_16M (BIT_ULL(ICE_PAGE_SHIFT_16M))
#define ICE_PAGE_SZ_32M (BIT_ULL(ICE_PAGE_SHIFT_32M))
#define ICE_PAGE_SZ_256M (BIT_ULL(ICE_PAGE_SHIFT_256M))

#define ICE_PHY_ADDR_WIDTH 36
#define ICE_PHY_ADDR_WIDTH_EXTENDED 39

/* 15GB */
#define ICE_VA_HIGH_PHY_SZ 0x3C0000000
/* 28GB */
#define ICE_VA_HIGH_TOTAL_SZ 0x700000000

#define ICE_VA_HIGH_4GB_START  0x100000000

#define ICE_VA_HIGH_18GB_32KB_END  0x480000000
#define ICE_VA_HIGH_18GB_START  0x480000000

#define ICE_VA_HIGH_18G_256MB_16MB_END  0x490000000
#define ICE_VA_HIGH_18G_256MB_START     0x490000000

#define ICE_VA_HIGH_23GB_32KB_END  0x600000000
#define ICE_VA_HIGH_24GB_START  0x600000000

#define ICE_VA_HIGH_27GB_16MB_END  0x700000000
#define ICE_VA_HIGH_28GB_START  0x700000000

#define ICE_VA_HIGH_31GB_32MB_END  0x800000000

#define ICE_VA_LOW_HW_START 0x0
#define ICE_VA_LOW_SW_START 0x10000000
/* NOTE: Was 0xC0000000 which would result in corruption of upto page size
 *  * into 3-4 GB memory space which belongs to the HW area
*/
#define ICE_VA_LOW_HW_END 0x10000000
#define ICE_VA_LOW_SW_END 0xC0000000

#define ICE_VA_RANGE_LOW_4KB_START ICE_VA_LOW_SW_START
#define ICE_VA_RANGE_LOW_4KB_END ICE_VA_LOW_SW_END

#define ICE_VA_RANGE_LOW_32KB_HW_START ICE_VA_LOW_HW_START
#define ICE_VA_RANGE_LOW_32KB_HW_END ICE_VA_LOW_HW_END

#define ICE_VA_RANGE_LOW_32KB_START ICE_VA_LOW_SW_START
#define ICE_VA_RANGE_LOW_32KB_END ICE_VA_LOW_SW_END

#define ICE_VA_RANGE_HIGH_32KB_START ICE_VA_HIGH_4GB_START
#define ICE_VA_RANGE_HIGH_32KB_END ICE_VA_HIGH_18GB_32KB_END

#define ICE_VA_RANGE_HIGH_16MB_START ICE_VA_HIGH_18GB_START
#define ICE_VA_RANGE_HIGH_16MB_END ICE_VA_HIGH_18G_256MB_16MB_END

#define ICE_VA_RANGE_HIGH_32MB_START ICE_VA_HIGH_18G_256MB_START
#define ICE_VA_RANGE_HIGH_32MB_END ICE_VA_HIGH_31GB_32MB_END

#define ICE_VA_RANGE_HIGHER_32KB_START 0x4C0000000

#define ICE_VA_RANGE_LOW_IDC_BAR1_START 0xFFFF0000
#define ICE_VA_RANGE_LOW_IDC_BAR1_END 0xFFFF7FFF



/* For each ICE IDC reserves 16KB area in BAR1
 * within which first 2KB is for counters and immediately following that
 * is counter notification register offset
 */
#if ICE_ENABLE_EXTENDED_VA_MODE
/* In 35 bit mode both odd and even ICE share same MMU mapping w.r.t BAR1 */
#define IDC_BAR1_ICE_REGION_SPILL_SZ __BAR1_ICE_REGION_SPILL_SZ
#else
/* Unlike 35 bit mode, in 32 bit mode there is no spilling of ICE's mapping
 * in MMU. Default page for 32 bit mode is 4KB and driver maps 4 pages in MMU
 * for each ICE. Hence spill size if zero.
 */
#define IDC_BAR1_ICE_REGION_SPILL_SZ 0
#endif

/* Each CVE PAGE_SIZE register defines page size for 32MB address range */
#define ICE_PAGE_SIZE_REG_SHIFT 25

#define round_down_cve_pagesize(v, page_sz) ((v) & ~((u64)page_sz - 1))

#define round_up_cve_pagesize(v, page_sz) \
	(((((u64)v)+page_sz - 1)) & ~((u64)(page_sz - 1)))

#define CHECK_ALIGNMENT(x, a)	(((x) & ((u64)(a) - 1)) == 0)

/* test whether an address (unsigned long long) is aligned to
 * ICE_DEFAULT_PAGE_SZ
 */
#define IS_ADDR_ALIGNED(addr) \
	CHECK_ALIGNMENT((u64)(addr), ICE_DEFAULT_PAGE_SZ)

static inline u32 bytes_to_cve_pages(u64 size_byte, u8 page_shift)
{
	return (round_up_cve_pagesize(size_byte, ICE_PAGE_SZ(page_shift))
			>> page_shift);
}

static inline int is_power_of_two(u32 v)
{
	return ((v != 0) && ((v & (v - 1)) == 0));
}

static inline uintptr_t round_down_os_pagesize(uintptr_t v)
{
	return (v & ~(OS_PAGE_SIZE - 1));
}

static inline uintptr_t round_up_os_pagesize(uintptr_t v)
{
	return ((v + OS_PAGE_SIZE - 1) & ~(OS_PAGE_SIZE - 1));
}

static inline u32 bytes_to_os_pages(u64 size_byte)
{
	return (round_up_os_pagesize(size_byte) >> OS_PAGE_SHIFT);
}

#endif /* _CVE_DRIVER_INTERNAL_MACROS_H_ */
