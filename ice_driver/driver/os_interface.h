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

#ifndef _OS_INTERFACE_H_
#define _OS_INTERFACE_H_


#ifdef RING3_VALIDATION
#include "os_interface_stub.h"
#include "unistd.h"
#else
#include "os_interface_impl.h"
#include "sph_log.h"
#include "linux/sched.h"
#endif

#include "cve_fw_structs.h"
#include "cve_driver_internal_types.h"
#include "cve_debug.h"
#include "sph_device_regs.h"

#include <linux/string.h>

#define MAX_DEVICE_GROUPS_NR 1
#define MAX_CVE_DEVICES_NR 12
#define MAX_NUM_ICEBO (MAX_CVE_DEVICES_NR / 2)
#define MAX_IDC_POOL_NR 6
#define VALID_ICE_MASK 0xFFF
#define ICE_KMD_CATEGORY ICE_LOG
#define ICE_FREQ_SHIFT 24
#define ICE_FREQ_DEFAULT 800

#ifndef RING3_VALIDATION
#define SPH_LOGGER 1
#else
#define SPH_LOGGER 0
#endif

extern u32 g_icemask;
extern u32 disable_embcb;
extern u32 core_mask;
extern int enable_llc;
extern u32 ice_fw_select;
extern u32 block_mmu;
extern u32 enable_b_step;
extern u32 disable_clk_gating;
extern u32 pin_atu;

typedef u32 cve_virtual_address_t;
typedef u32 pt_entry_t;
extern struct config cfg_a;
extern struct config cfg_b;
extern struct config cfg_c;
extern struct config cfg_default;

#ifdef RING3_VALIDATION
#define xstr(s) str(s)
#define str(s) #s

/* Macro to check whether user has set coral perf mode or not*/
#define PERF_MODE 1

#endif

#define declare_u32_var(x) u32 x __attribute__((unused)); x = 0
#define declare_u64_var(x) u64 x __attribute__((unused)); x = 0
#define declare_u16_var(x) u16 x __attribute__((unused)); x = 0
#define declare_u8_var(x)  u8  x __attribute__((unused)); x = 0

#define declare_int_var(x) int x __attribute__((unused)); x = 0

enum dg_settings_types {
	DG_SETTINGS_DEFAULT = 0,
	DG_SETTINGS_SINGLE_DEVICE_PER_GROUP,
	DG_SETTINGS_SINGLE_GROUP_ALL_DEVICES,
	DG_SETTINGS_SINGLE_GROUP_SINGLE_DEVICE
};

struct cve_device_group_config {
	u32 devices_nr;
	u32 llc_size;
};

struct cve_device_groups_config {
	u32 groups_nr;
	u32 devices_nr;
	struct cve_device_group_config groups[MAX_DEVICE_GROUPS_NR];
};

struct dg_params {
	int devices_nr;
	int devices_arr[MAX_DEVICE_GROUPS_NR];
	int llc_nr;
	int llc_arr[MAX_DEVICE_GROUPS_NR];
};

#define __FILENAME__ \
	(strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)
/* instead of including the cve_device.h and creating a cyclic
 * include, we will only declare the struct here.
 */
struct cve_device;
struct idc_device;

#define cve_os_write_idc_mmio(cve_dev, register_offset, value) \
	cve_os_write_idc_mmio_bar_nr(cve_dev, 0, register_offset, value)
#define cve_os_write_mmio_32(cve_dev, register_offset, value) \
	cve_os_write_mmio_32_bar_nr(cve_dev, 0, register_offset, value)
#define cve_os_write_mmio_32_bar2(cve_dev, register_offset, value) \
	cve_os_write_mmio_32_bar_nr(cve_dev, 2, register_offset, value)
#define cve_os_read_icemask(idc_dev) \
	cve_os_read_icemask_bar0(idc_dev, false)
#define cve_os_read_idc_mmio(cve_dev, offset_bytes) \
	cve_os_read_idc_mmio_bar_nr(cve_dev, 0, offset_bytes, false)
#define cve_os_read_mmio_32(cve_dev, offset_bytes) \
	cve_os_read_mmio_32_bar_nr(cve_dev, 0, offset_bytes, false)
#define cve_os_read_mmio_32_force_print(cve_dev, offset_bytes) \
	cve_os_read_mmio_32_bar_nr(cve_dev, 0, offset_bytes, true)
#define cve_os_read_mmio_32_bar2(cve_dev, offset_bytes) \
	cve_os_read_mmio_32_bar_nr(cve_dev, 2, offset_bytes)
#define cve_os_read_modify_write_mmio_32(cve_dev, register_offset, value) \
	cve_os_read_modify_write_mmio_32_bar_nr(cve_dev, \
			0, \
			register_offset, \
			value)
#define cve_os_read_modify_write_mmio_32_bar2(cve_dev, register_offset, value) \
	cve_os_read_modify_write_mmio_32_bar_nr(cve_dev, \
			2, \
			register_offset, \
			value)
#define idc_mmio_read64(dev, offset_bytes) \
	idc_mmio_read64_bar_x(dev, 0, offset_bytes, false)
#define idc_mmio_write64(dev, offset, val) \
	idc_mmio_write64_bar_x(dev, 0, offset, val)

/* logging facility */
enum cve_log_level {
	CVE_LOGLEVEL_ERROR = 0,
	CVE_LOGLEVEL_WARNING = 1,
	CVE_LOGLEVEL_INFO = 2,
	CVE_LOGLEVEL_DEBUG = 3
};

#ifdef _DEBUG
#if SPH_LOGGER == 1
#define _cve_os_log(level, fmt, ...) do {\
		switch (level) {\
		case CVE_LOGLEVEL_DEBUG:\
			sph_log_debug(ICE_KMD_CATEGORY, fmt, ##__VA_ARGS__);\
			break;\
		case CVE_LOGLEVEL_ERROR:\
			sph_log_err(ICE_KMD_CATEGORY, fmt, ##__VA_ARGS__);\
			break;\
		case CVE_LOGLEVEL_WARNING:\
			sph_log_warn(ICE_KMD_CATEGORY, fmt, ##__VA_ARGS__);\
			break;\
		case CVE_LOGLEVEL_INFO:\
			sph_log_info(ICE_KMD_CATEGORY, fmt, ##__VA_ARGS__);\
			break;\
		} \
	} while (0)
#else
#define _cve_os_log(level, fmt, ...) do {\
		switch (level) {\
		case CVE_LOGLEVEL_DEBUG:\
			pr_debug(fmt, ##__VA_ARGS__);\
			break;\
		case CVE_LOGLEVEL_ERROR:\
			pr_err(fmt, ##__VA_ARGS__);\
			break;\
		case CVE_LOGLEVEL_WARNING:\
			pr_warn(fmt, ##__VA_ARGS__);\
			break;\
		case CVE_LOGLEVEL_INFO:\
			pr_info(fmt, ##__VA_ARGS__);\
			break;\
		} \
	} while (0)
#endif
#else
#define _cve_os_log(level, fmt, ...) {}
#endif

/* Logging facility mainly for release build */
#if SPH_LOGGER == 1
#define cve_os_log_default(level, fmt, ...) do {\
		switch (level) {\
		case CVE_LOGLEVEL_ERROR:\
			sph_log_err(ICE_KMD_CATEGORY, fmt, ##__VA_ARGS__);\
			break;\
		case CVE_LOGLEVEL_WARNING:\
			sph_log_warn(ICE_KMD_CATEGORY, fmt, ##__VA_ARGS__);\
			break;\
		case CVE_LOGLEVEL_INFO:\
			sph_log_info(ICE_KMD_CATEGORY, fmt, ##__VA_ARGS__);\
			break;\
		} \
	} while (0)
#define _cve_os_log_default(level, fmt, ...) do {\
		switch (level) {\
		case CVE_LOGLEVEL_ERROR:\
			sph_log_err(ICE_KMD_CATEGORY, fmt, ##__VA_ARGS__);\
			break;\
		case CVE_LOGLEVEL_WARNING:\
			sph_log_warn(ICE_KMD_CATEGORY, fmt, ##__VA_ARGS__);\
			break;\
		case CVE_LOGLEVEL_INFO:\
			sph_log_info(ICE_KMD_CATEGORY, fmt, ##__VA_ARGS__);\
			break;\
		} \
	} while (0)
#define cve_os_dev_log_default(level, cve_dev, fmt, ...) \
		_cve_os_log_default(level, \
			"[PID:%d] %s(%d) : ICE%d: "fmt, current->pid, \
			__FILENAME__, __LINE__, cve_dev, ##__VA_ARGS__)
#else
#define cve_os_log_default(level, fmt, ...) do {\
		switch (level) {\
		case CVE_LOGLEVEL_ERROR:\
			pr_err(fmt, ##__VA_ARGS__);\
			break;\
		case CVE_LOGLEVEL_WARNING:\
			pr_warn(fmt, ##__VA_ARGS__);\
			break;\
		case CVE_LOGLEVEL_INFO:\
			pr_info(fmt, ##__VA_ARGS__);\
			break;\
		} \
	} while (0)
#define _cve_os_log_default(level, fmt, ...) do {\
		switch (level) {\
		case CVE_LOGLEVEL_ERROR:\
			pr_err(fmt, ##__VA_ARGS__);\
			break;\
		case CVE_LOGLEVEL_WARNING:\
			pr_warn(fmt, ##__VA_ARGS__);\
			break;\
		case CVE_LOGLEVEL_INFO:\
			pr_info(fmt, ##__VA_ARGS__);\
			break;\
		} \
	} while (0)
#define cve_os_dev_log_default(level, cve_dev, fmt, ...) \
		_cve_os_log_default(level, \
			"ICE : [PID:%d] %s(%d) :%s: ICE%d: "fmt, \
			getpid(), __FILENAME__, \
			__LINE__, __func__, cve_dev, ##__VA_ARGS__)
#endif


#if SPH_LOGGER == 1
#define cve_os_log(level, fmt, ...) \
		_cve_os_log(level, "[PID:%d] %s(%d): " fmt, \
				current->pid, __FILENAME__, __LINE__, \
					##__VA_ARGS__)
#else
#define cve_os_log(level, fmt, ...)\
		_cve_os_log(level, "ICE : [PID:%d] %s(%d) :%s: "fmt,\
				 getpid(), __FILENAME__, \
				__LINE__, __func__, ##__VA_ARGS__)
#endif

#if SPH_LOGGER == 1
#define cve_os_dev_log(level, cve_dev, fmt, ...) \
		_cve_os_log(level, \
			"[PID:%d] %s(%d) : ICE%d: "fmt, current->pid, \
			__FILENAME__, __LINE__, cve_dev, ##__VA_ARGS__)
#else
#define cve_os_dev_log(level, cve_dev, fmt, ...) \
		_cve_os_log(level, \
			"ICE : [PID:%d] %s(%d) :%s: ICE%d: "fmt, \
			getpid(), __FILENAME__, \
			__LINE__, __func__, cve_dev, ##__VA_ARGS__)
#endif

/* memory os common definitions */
struct cve_dma_handle {
	enum cve_memory_type mem_type;
	union {
		cve_dma_addr_t dma_address;
		struct sg_table *sgt;
	} mem_handle;
	void *priv;
};

/* allocation address, either virtual address or file descriptor
 * in case of buffer sharing
 */
union allocation_address {
	void *vaddr;
	u64 fd;
};
#ifdef _DEBUG

struct ice_drv_memleak {
	void *caller_fn;
	void *caller_fn2;
	struct cve_dle_t list;
	void *va;
	u32 size;
};

#endif


#ifdef ENABLE_MEM_DETECT

#define OS_ALLOC_ZERO(size_bytes, out_ptr) ({ \
	int ret = __cve_os_malloc_zero(size_bytes, out_ptr); \
	if (mem_detect_en) \
		cve_os_log(CVE_LOGLEVEL_ERROR, \
		"Allocated non-dma block. size=%u vaddress=%p\n", \
		(u32)size_bytes, *out_ptr); \
	ret; \
})

#define OS_FREE(base_address, size_bytes) ({ \
	int ret = __cve_os_free(base_address, size_bytes); \
	if (mem_detect_en) \
		cve_os_log(CVE_LOGLEVEL_ERROR, \
			"Freed non-dma block. size=%u vaddr=%p\n", \
			(u32)size_bytes, base_address); \
	ret; \
})

#define OS_ALLOC_DMA_CONTIG(cve_dev, size_of_elem, num_of_elem, \
		out_vaddr, out_dma_addr, aligned) ({ \
	int ret = __cve_os_alloc_dma_contig(cve_dev, size_of_elem, \
		num_of_elem, out_vaddr, out_dma_addr, aligned); \
	if (mem_detect_en) \
		cve_os_log(CVE_LOGLEVEL_ERROR, \
		"Allocated contig dma block. size=%u dma_addr=%p vaddr=%p\n", \
		(u32)size_of_elem*num_of_elem, \
		(void *)(uintptr_t)(out_dma_addr)->mem_handle.dma_address, \
		*out_vaddr); \
	ret; \
})

#define OS_FREE_DMA_CONTIG(cve_dev, size_of_elem, vaddr, dma_addr, aligned) ({ \
	__cve_os_free_dma_contig(cve_dev, size_of_elem, \
		vaddr, dma_addr, aligned); \
	if (mem_detect_en) \
		cve_os_log(CVE_LOGLEVEL_ERROR, \
		"Freed contig dma block. size=%u dma_addr=%p vaddr=%p\n", \
		(u32)size_of_elem, \
		(void *)(uintptr_t)(dma_addr)->mem_handle.dma_address, \
		vaddr); \
})

#define OS_ALLOC_DMA_SG(cve_dev, size_of_elem, num_of_elem, \
		out_dma_addr) ({ \
	int ret = __cve_os_alloc_dma_sg(cve_dev, size_of_elem, \
		num_of_elem, out_dma_addr); \
	if (mem_detect_en) \
		cve_os_log(CVE_LOGLEVEL_ERROR, \
		"Allocated sg dma block. size=%u dma_addr=%p\n", \
		(u32)size_of_elem*num_of_elem, \
		(void *)(uintptr_t)(out_dma_addr)->mem_handle.dma_address); \
	ret; \
})

#define OS_FREE_DMA_SG(cve_dev, size_of_elem, dma_addr) ({ \
	__cve_os_free_dma_sg(cve_dev, size_of_elem, dma_addr); \
	if (mem_detect_en) \
		cve_os_log(CVE_LOGLEVEL_ERROR, \
		"Freed sg dma block. size=%u dma_addr=%p\n", \
		(u32)size_of_elem, \
		(void *)(uintptr_t)(dma_addr)->mem_handle.dma_address); \
})

#else /* ENABLE_MEM_DETECT */

#define OS_ALLOC_ZERO(size_bytes, out_ptr) ({ \
	int ret = __cve_os_malloc_zero(size_bytes, out_ptr); \
	ret; \
})

#define OS_FREE(base_address, size_bytes) ({ \
	__cve_os_free(base_address, size_bytes); \
})

#define OS_ALLOC_DMA_CONTIG(cve_dev, size_of_elem, num_of_elem, \
		out_vaddr, out_dma_addr, aligned) ({ \
	int ret = __cve_os_alloc_dma_contig(cve_dev, size_of_elem, \
			num_of_elem, out_vaddr, out_dma_addr, aligned); \
	ret; \
})

#define OS_FREE_DMA_CONTIG(cve_dev, size_of_elem, vaddr, dma_addr, aligned) ({ \
	__cve_os_free_dma_contig(cve_dev, size_of_elem, \
		vaddr, dma_addr, aligned); \
})

#define OS_ALLOC_DMA_SG(cve_dev, size_of_elem, num_of_elem, out_dma_addr) ({ \
	int ret = __cve_os_alloc_dma_sg(cve_dev, size_of_elem, \
			num_of_elem, out_dma_addr); \
	ret; \
})

#define OS_FREE_DMA_SG(cve_dev, size_of_elem, dma_addr) ({ \
	__cve_os_free_dma_sg(cve_dev, size_of_elem, dma_addr); \
})
#endif

/*
 * Tensilica debugger specific
 * SW to allow debugger proper work
 * should not be needed on non - debug mode.
 * will be replaced with a dynamically capability
 * #define DEBUG_TENSILICA_ENABLE 1
 */

 /* creates a timer
 * inputs : handler - the function that handles the timer events
 * outputs: out_timer - holds the timer-handle on success
 * returns: 0 on success, an negative error code on failure
 */
int cve_os_timer_create(
	cve_os_timer_function handler,
	cve_os_timer_t *out_timer);

/*
 * set a timer
 * inputs :
 *	timer - the timer to set
 *	usecs - the expiration period given in micro-seconds.
 *	overwrites a previous setting. a period '0' cancels the timer.
 *	param - the param to be passed to the handler on expiration
 * outputs:
 * returns: 0 on success, an negative error code on failure
 */
int cve_os_timer_set(
	cve_os_timer_t timer,
	cve_timer_period_t usecs,
	cve_timer_param_t param);

/*
 * reclaim all resources taken for the given timer.
 * if the timer is set then it
 * is canceled
 * inputs : timer - the timer to set
 * outputs:
 * returns:
 */
void cve_os_timer_remove(cve_os_timer_t timer);

/*
 * initialize the os abstraction layer
 * inputs :
 * outputs:
 * returns: 0 on success, a negative error value on failure
 */
int cve_os_interface_init(void);

/*
 * cleanup the os abstraction layer
 * inputs :
 * outputs:
 * returns:
 */
void cve_os_interface_cleanup(void);

/* locking mechanism */
int cve_os_lock_init(cve_os_lock_t *lock);
#define CVE_NON_INTERRUPTIBLE 0
#define CVE_INTERRUPTIBLE 1
int cve_os_lock(cve_os_lock_t *lock, int is_interruptible);
void cve_os_unlock(cve_os_lock_t *lock);

/*
 * copy memory from user provided buffer to kernel space
 * inputs :
 *	base_address - user's buffer address
 *	size_bytes - buffer's size in bytes
 *	kernel_copy - a pointer to a buffer in kernel space where the user's
 *			buffer is to be copied to
 * returns : 0 on success, one of the following on error:
 *			 -EACCES : (part of) user's buffer is not mapped to
 *			 user space
 */
int cve_os_read_user_memory(void *base_address,
		u32 size_bytes,
		void *kernel_copy);

/*
 * copy memory from user provided buffer to kernel space
 * inputs :
 *	base_address - user's buffer address
 *	size_bytes - buffer's size in bytes
 *	kernel_copy - a pointer to a buffer in kernel space where the user's
 *			buffer is to be copied from
 * returns : 0 on success, one of the following on error:
 *			 -EACCES : (part of) user's buffer is not mapped to
 *			 user space
 */
int cve_os_write_user_memory(
	void *base_address,
	u32 size_bytes,
	void *kernel_copy);

/*
 * allocate memory and zero it
 * inputs : size_bytes - the size of the quested memory chunk
 * outputs:
 *	out_ptr - the address of the newly allocated buffer
 *		will be written to this address
 * returns : 0 on success, one of the following on error:
 *		   -ENOMEM : failed to allocate the memory
 */
int __cve_os_malloc_zero(u32 size_bytes,
		void **out_ptr);

/*
 * free memory that was allocated using os_malloc_zero
 * inputs :
 *	base_address - the base address of the buffer to be freed
 *	size_bytes - the size of the allocated buffer
 * returns : 0 on success, one of the following on error:
 *	   <TODO - which error codes should go here ?>
 */
int __cve_os_free(void *base_address,
		u32 size_bytes);

/*
 * allocate scatter gather pages in physical memory and mapped them to DMA.
 * inputs : num_of_elem - number of pages to allocate
 * size_of_elem - size of element
 * outputs:
 *	out_vaddr - the address of the newly allocated buffer
 *		will be written to this address
 *	out_dma_handle - the dma handle of the newly allocated buffer
 *		will be written to this address
 * returns : 0 on success, one of the following on error:
 *	   -ENOMEM : failed to allocate the memory
 *	   -EINVAL: size isn't aligned
 */
int __cve_os_alloc_dma_sg(struct cve_device *cve_dev,
		u32 size_of_elem,
		u32 num_of_elem,
		struct cve_dma_handle *out_dma_handle);

/*
 * free contig physical memory that was allocated with cve_os_alloc_dma_sg
 * inputs :
 *	vaddr - the memory address
 *	size_of_elem - size of element
 * returns:
 */
void __cve_os_free_dma_sg(struct cve_device *cve_dev,
		u32 size,
		struct cve_dma_handle *dma_handle);

/*
 * allocate contig physical memory aligned on page size, suitable for DMA.
 * check that every element size is aligned to cache line size
 * inputs : num_of_elem - number of pages to allocate
 * size_of_elem - size of element
 * outputs:
 *	out_vaddr - the address of the newly allocated buffer
 *		will be written to this address
 *	out_dma_handle - the dma handle of the newly allocated buffer
 *		will be written to this address
 * returns : 0 on success, one of the following on error:
 *	   -ENOMEM : failed to allocate the memory
 *	   -EINVAL: size isn't aligned
 */
int __cve_os_alloc_dma_contig(struct cve_device *cve_dev,
		u32 size_of_elem,
		u32 num_of_elem,
		void **out_vaddr,
		struct cve_dma_handle *out_dma_handle,
		int aligned);

/*
 * free contig physical memory that was allocated with cve_os_alloc_dma_contig
 * inputs :
 *	vaddr - the memory address
 *	size_of_elem - size of element
 * returns:
 */
void __cve_os_free_dma_contig(struct cve_device *cve_dev,
		u32 size_of_elem,
		void *vaddr,
		struct cve_dma_handle *dma_handle,
		int aligned);

/*
 * read a 32 bit value from the given address in the MMIO space
 * based on given bar number
 * inputs : bar_nr - the bar number want to write to (0-6)
 * offset_bytes - the offset from the beginning of the MMIO space
 * outputs:
 * returns: the content of the MMIO register
 */
u32 cve_os_read_mmio_32_bar_nr(struct cve_device *cve_dev,
		u32 bar_nr,
		u32 offset_bytes,
		bool force_print);
u32 cve_os_read_idc_mmio_bar_nr(struct cve_device *cve_dev,
		u32 bar_nr,
		u32 offset_bytes,
		bool force_print);
u32 cve_os_read_icemask_bar0(struct idc_device *idc_dev,
		bool force_print);

u64 idc_mmio_read64_bar_x(struct cve_device *dev,
		u32 bar_nr,
		u32 offset_bytes,
		bool force_print);

/*
 * write a 32 bit value into the given address in the MMIO space
 * based on given bar number
 * inputs : bar_nr - the bar number which should read from (0-6)
 * offset_bytes - the offset from the beginning of the MMIO space
 * value - the value which should be written
 * outputs:
 * returns:
 */
void cve_os_write_mmio_32_bar_nr(struct cve_device *cve_dev,
		u32 bar_nr,
		u32 offset_bytes,
		u32 value);
void cve_os_write_idc_mmio_bar_nr(struct cve_device *cve_dev,
		u32 bar_nr,
		u32 offset_bytes,
		u64 value);

void idc_mmio_write64_bar_x(struct cve_device *dev, u32 bar, u32 offset,
		u64 val);

/*
 * read-modify-write a 32 bit value into the given address in the MMIO space
 * based on given bar number.
 * uses for modifying particular register fields and not all the bits.
 * inputs : bar_nr - the bar number which should read from (0-6)
 * offset_bytes - the offset from the beginning of the MMIO space
 * value - the value which should be written
 * outputs:
 * returns:
 */
static inline void cve_os_read_modify_write_mmio_32_bar_nr(
		struct cve_device *cve_dev,
		u32 bar_nr,
		u32 offset_bytes,
		u32 value)
{
	u32 curr_reg_val = cve_os_read_mmio_32_bar_nr(cve_dev,
			bar_nr,
			offset_bytes,
			false);
	u32 new_reg_val = curr_reg_val | value;

	cve_os_log(CVE_LOGLEVEL_DEBUG,
			"[MMIO] read-modify-write, val before %x, val after %x\n",
			curr_reg_val,
			new_reg_val);

	cve_os_write_mmio_32_bar_nr(cve_dev, bar_nr,
			offset_bytes,
			new_reg_val);
}

/* atomic set */

/* atomic increment the given 64 bit unsigned integer
 * return the value of the integer after the it was incremented
 */
u64 cve_os_atomic_increment_64(atomic64_t *n);

/* return the current time stamp */
u64 cve_os_get_time_stamp(void);

/* return the number of CVE devices in the system */
u32 cve_os_cve_devices_nr(void);

/*
 * time_after_in_msec(a,b) returns true if the time a is after time b.
 * value should be 32 bit unsigned integer.
 */
#define time_after_in_msec(a, b)  ((s32)((b) - (a)) < 0)

/* return the current time stamp in msec (based on jiffies) */
uint32_t cve_os_get_msec_time_stamp(void);

/*
 * initialize to given wait que
 * inputs : que
 * outputs:
 * returns: 0 on success, a negative error value otherwise
 */
int cve_os_init_wait_que(cve_os_wait_que_t *que);

/* wakes up the given job (which is blocked on os_block(void)) */
void cve_os_wakeup(cve_os_wait_que_t *que);

/* ensure visibility of all memory writes before the call
 * to this function to all reads after it.
 */
void cve_os_memory_barrier(void);

/* add a few hundred of cycles delay */
void cve_os_pause(void);

/* writes to user memory
 * inputs :
 *	user_addr - address
 *	value -
 * outputs:
 * returns: 0 on success, a negative error code on failure
 */
int cve_os_write_user_memory_64(u64 *user_addr, u64 val);
int cve_os_write_user_memory_32(u32 *user_addr, u32 val);
/* reads from user memory
 * inputs :
 *	user_addr - address
 *	value -
 * outputs:
 * returns: 0 on success, a negative error code on failure
 */
int cve_os_read_user_memory_64(u64 *user_addr, u64 *val);
/* checks if the given address is in kernel memory
 * inputs : vaddr
 * outputs:
 * returns: 1 if the given address is in kernel memory, 0 otherwise
 */
int cve_os_is_kernel_memory(uintptr_t vaddr);

/*
 * Makes the changes in memory, done by the user space/driver,
 * visible to device.
 * inputs: sgt - scatter gather table of the memory
 */
void cve_os_sync_sg_memory_to_device(struct cve_device *cve_dev,
		struct sg_table *sgt);

/*
 * Makes the changes in memory, done by device, visible to user space/driver.
 * inputs: sgt - scatter gather table of the memory
 */
void cve_os_sync_sg_memory_to_host(struct cve_device *cve_dev,
		struct sg_table *sgt);

/* Sync the given sgt pages to llc
 * inputs : sgt - scatter gather table of the memory
 * outputs:
 * returns: 0 on success, a negative error code on failure
 */
int cve_sync_sgt_to_llc(struct sg_table *sgt);

/*
 * Copy data from the given buffer to the given dma handle
 * inputs:
 *		buffer - buffer in kernel space
 *		size_bytes - number of bytes to copy
 * outputs:
 *		dma_handle - dma handle to copy the data to
 * returns: 0 on success, a negative error code on failure
 */
int cve_os_dma_copy_from_buffer(struct cve_dma_handle *dma_handle,
		void *buffer,
		u32 size_bytes);

/*
 * Print user buffer.
 *
 * inputs:
 *		pages - pages array of user allocation
 *		pages_nr - number of pages
 *		buffer_addr - buffer address in user space
 *		size_bytes - size of buffer
 *		buf_name - buffer name
 *
 *      NOTE : X86 ts virtual memory area is ilimited to 128MB
 *      user buffer print will use virtuall address on demand
 */
void cve_os_print_user_buffer(void **pages,
		u32 pages_nr,
		void *buffer_addr,
		u32 size_bytes,
		const char *buf_name);

void cve_os_print_kernel_buffer(
		void *buffer_addr,
		u32 size_bytes,
		const char *buf_name);

void cve_os_print_shared_buffer(
		void *buffer_addr,
		u32 size_bytes,
		const char *buf_name);
/**
 * Maps the dma handle to OS virtual address space. On 32 bit platform
 * should be used with cautions because of limited virtual address range
 * (VMALLOC_START ... VMALLOC_END)
 * @param dma_handle
 *
 * returns NULL on failure, valid virtual address otherwise
 */
void *cve_os_vmap_dma_handle(struct cve_dma_handle *dma_handle);

/**
 * Unmaps the dma handle previously mapped by cve_os_vmap_dma_handle
 * @param vaddr
 */
void cve_os_vunmap_dma_handle(void *vaddr);

uint32_t get_process_pid(void);

void ice_os_read_clos(void *pmclos);
void ice_os_set_clos(void *pmclos);
void ice_os_reset_clos(void *pmclos);

int set_llc_freq(void *llc_freq_config);
uint64_t get_llc_freq(void);
uint64_t get_ice_freq(void);

#ifdef RING3_VALIDATION

#define ice_sch_preemption() 1
#define os_disable_preemption() do {} while (0)
#define os_enable_preemption() do {} while (0)

#else /* RING3_VALIDATION */

#ifdef _DEBUG

#define ice_sch_preemption() 1
#define os_disable_preemption() do {} while (0)
#define os_enable_preemption() do {} while (0)

#else /* #ifdef _DEBUG */

#define ice_sch_preemption() ice_sch_allow_preemption()
#define os_disable_preemption() preempt_disable()
#define os_enable_preemption() preempt_enable()

#endif /* #ifdef _DEBUG */

#endif /*RING3_VALIDATION*/

#ifndef RING3_VALIDATION

#ifdef DEBUG_SPINLOCKS

#define ICEDRV_SPIN_LOCK(x) {                            \
	unsigned long max_jiffies = jiffies + 1*HZ;   \
	while (!spin_trylock(x)) {                    \
		if (time_after(jiffies, max_jiffies)) { \
			BUG();                        \
			max_jiffies = jiffies + 1*HZ; \
		}                                     \
	}                                             \
}

#define ICEDRV_SPIN_LOCK_BH(x) {                         \
	unsigned long max_jiffies = jiffies + 1*HZ;   \
	while (!spin_trylock_bh(x)) {                 \
		if (time_after(jiffies, max_jiffies)) {\
			BUG();                        \
			max_jiffies = jiffies + 1*HZ; \
		}                                     \
	}                                             \
}

#define ICEDRV_SPIN_LOCK_IRQSAVE(x, f) {                 \
	unsigned long max_jiffies = jiffies + 1*HZ;   \
	while (!spin_trylock_irqsave(x, f)) {         \
		if (time_after(jiffies, max_jiffies)) {\
			BUG();                        \
			max_jiffies = jiffies + 1*HZ; \
		}                                     \
	}                                             \
}

#else
#define ICEDRV_SPIN_LOCK(x)            spin_lock(x)
#define ICEDRV_SPIN_LOCK_BH(x)         spin_lock_bh(x)
#define ICEDRV_SPIN_LOCK_IRQSAVE(x, f) spin_lock_irqsave(x, f)
#endif

#define ICEDRV_SPIN_UNLOCK(x)               spin_unlock(x)
#define ICEDRV_SPIN_UNLOCK_BH(x)            spin_unlock_bh(x)
#define ICEDRV_SPIN_UNLOCK_IRQRESTORE(x, f) spin_unlock_irqrestore(x, f)

#endif /* #ifndef RING3_VALIDATION*/

#endif /* _OS_INTERFACE_H_ */

