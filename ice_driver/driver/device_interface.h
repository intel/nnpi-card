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

#ifndef _DEVICE_INTERFACE_H_
#define _DEVICE_INTERFACE_H_

#ifdef RING3_VALIDATION
#include <stdint.h>
#include <stdint_ext.h>
#else
#include <linux/types.h>
#endif
#include "project_device_interface.h"
#include "cve_driver_internal_types.h"
#include "memory_manager.h"
#include "dispatcher.h"

#ifdef IDC_ENABLE
#include "idc_device.h"
#endif

/*
 * reset source enum .
 */
enum cve_device_reset_reason {
	CVE_DI_RESET_DUE_NTW_SWITCH = 0x01,
	CVE_DI_RESET_DUE_CVE_ERROR =   0x02,
	CVE_DI_RESET_DUE_JOB_NOT_COMP = 0x04,
	CVE_DI_RESET_DUE_TIME_OUT = 0x8,
	CVE_DI_RESET_DUE_POWER_ON = 0x10
};

int set_idc_registers(struct cve_device *dev, uint8_t lock);
int unset_idc_registers(struct cve_device *dev, uint8_t lock);

/*
 * Power off bunch of ICEs in single go
 * icemask [in] Mask of ICEs to be turned off
 */
int unset_idc_registers_multi(u32 icemask, uint8_t lock);

/*
 * clean up the device interface
 * inputs :
 * outputs:
 * returns:
 */
void cve_di_cleanup(void);

/*
 * bring the device into a well-known state -
 *	1) FIFO_HEAD = FIFO_TAIL = 0
 *	2) FIFO_SIZE = a pre-defined value
 * When the function returns the device is in run-stall state.
 * inputs :
 *	cve_dev - cve device
 * outputs:
 * returns:
 */
void cve_di_reset_device(struct cve_device *cve_dev);

/*
 * Start the device
 * Used after device reset, and after setting the device page table.
 * When the function returns the device is guaranteed to be ready to receive
 * command buffers
 * inputs : cve_dev - cve device
 * outputs:
 * returns:
 */
void cve_di_start_running(struct cve_device *cve_dev);

/*
 * destroy the sub_job memory
 * input:
 *	sub_job handle pointer
 * output: None
 * returns: None
 */
void cve_di_sub_job_handle_destroy(cve_di_subjob_handle_t *subjob_handle);

/*
 * This function create a subjob with the given parameters
 * inputs:
 *	cb_address - CVE virtual address which is mapped to this cb
 *	cb_command_buffer - base address of the command buffer
 *	cb_commands_nr - number of commands
 *	embedded_sub_job - 1 if this subjob contains
 *		embedded cb and 0 otherwise
 *	cve_dev - cve device
 * outputs :
 *	out_subjob_handle - a pointer to the subjob created handle
 * returns:
 *	0 - on success
 *	other on failure
 */
int cve_di_create_subjob(cve_virtual_address_t cb_address,
		u64 cb_command_buffer,
		u16 cb_commands_nr,
		u32 embedded_sub_job,
		cve_di_job_handle_t *out_subjob_handle);

/*
 * ISR for handling CVE interrupts.
 * it is assumed to run in highest priority with interrupts disabled
 * returns 1 if a DPC should be invoked 0 otherwise
 * inputs: cve_dev - cve device
 */
#ifdef IDC_ENABLE

void cve_set_hw_sync_regs(struct idc_device *idc_dev,
		u32 counter_number, int8_t pool_id);
void cve_reset_hw_sync_regs(struct idc_device *idc_dev,
					u32 counter_number);
int cve_di_interrupt_handler(struct idc_device *idc_dev);
#else
int cve_di_interrupt_handler(struct cve_device *cve_dev);
#endif

/*
 * deferred procedure for interrupt handling
 * inputs : cve_dev - cve device
 * outputs:
 * returns:
 */
#ifdef IDC_ENABLE
void cve_di_interrupt_handler_deferred_proc(struct idc_device *dev);
#else
void cve_di_interrupt_handler_deferred_proc(struct cve_device *dev);
#endif

/*
 * set the address of the device's page table
 * inputs :
 *	addr - the page table base address
 *	cve_dev - cve device
 * outputs:
 * returns:
 */
void cve_di_set_page_directory_base_addr(struct cve_device *cve_dev,
		u32 dma_addr);

/*
 * set the addressing mode of the device's ATU based on VA width
 * inputs :
 *	cve_dev - cve device
 * outputs:
 * returns:
 */
void ice_di_set_mmu_address_mode(struct cve_device *ice);

/*
 * invalidate page table base address register
 * inputs : cve_dev - cve device
 * outputs:
 * returns:
 */
void cve_di_invalidate_page_table_base_address(struct cve_device *cve_dev);

/*
 * free di_job and all sub_jobs that assosicated with this di_job
 * inputs : cve_di_job_handle_t hjob - di_job handle
 * outputs:
 * returns:
 */
void remove_di_job(cve_di_job_handle_t hjob);

/*
 * open an entry for a new command buffer
 * inputs :
 *	buf_list - list of user buffers
 *	ds_hjob - the dispatcher's job handle
 *	command_buffers_nr - the number of command buffers
 *	kcb_descriptor - list of command buffers descriptor for submission
 * outputs: out_hjob - a job handle to be used in consequent functions
 * returns: 0 on success, a negative error code on failure
 */
int cve_di_handle_submit_job(
		struct cve_ntw_buffer *buf_list,
		cve_ds_job_handle_t ds_hjob,
		struct cve_job *job_desc,
		struct cve_command_buffer_descriptor *kcb_descriptor,
		cve_di_job_handle_t *out_hjob);

/*
 * dispatch the given job for execution on the device
 * inputs :
 *	hjob - the handle of the job
 *	e_cbs - pointer to embedded cbs list for specific
 *	cve device
 *	cve_dev - cve device
 * outputs:
 * returns:
 */
void cve_di_dispatch_job(struct cve_device *cve_dev,
		cve_di_job_handle_t hjob,
		cve_di_subjob_handle_t *e_cbs);

/* sets device interface reset flag
 * inputs :
 *     value  - enum cve_device_reset_reason
 *     cve_dev - cve device
 * outputs: None
 * returns: None
 */
void cve_di_set_device_reset_flag(struct cve_device *cve_dev, u32 value);

/*
 * get device interface reset flag value
 * inputs : cve_dev - cve device
 * outputs:
 * returns: reset flag value enum cve_device_reset_reason
 */
u32 cve_di_get_device_reset_flag(struct cve_device *cve_dev);

/*
 * Masks device interrupts
 * inputs : cve_dev - cve device
 * outputs: None
 * returns: None
 */
void cve_di_mask_interrupts(struct cve_device *cve_dev);

/*
 * Set address of registers array and its size
 * outputs :regs - address of registers array
 *	num_of_regs - address where number of registers will be set
 */
void cve_di_get_debugfs_regs_list(const struct debugfs_reg32 **regs,
		u32 *num_of_regs);

void cve_di_set_hw_counters(struct cve_device *cve_dev);

/**
 * Returns the CB virtual address
 * @param subjob_handle
 */
void *cve_di_get_sub_job_kaddr(cve_di_subjob_handle_t *subjob_handle);

/**
 * Configure the control register of cve_dump according to device info
 * @param cve_dev
 * @param dumpTrigger
 * @param ice_dump_buf
 */
void cve_di_set_cve_dump_control_register(struct cve_device *cve_dev,
		uint8_t dumpTrigger, struct di_cve_dump_buffer ice_dump_buf);

/**
 * Configure the configuration register of cve_dump according to device info
 *   so it writes in the mapped address addr
 * @param cve_dev
 * @param ice_dump_buf
 */
void cve_di_set_cve_dump_configuration_register(struct cve_device *cve_dev,
		struct di_cve_dump_buffer ice_dump_buf);

/**
 * returns number of devices that have an active job with specifed network ID
 * @param network id
 * @param device group pointer
 */
int ice_di_is_network_under_execution(u64 ntw_id, struct cve_device_group *dg);

/**
 * resets CB ICE VA in CBDT for the given device network ID
 *
 * Indirectly induce a TLC abort by setting CB address as NULL which will
 * in page fault. To be called during forced network exit
 *
 * @param dev pointer to the ICE device
 */
void ice_di_reset_cbdt_cb_addr(struct cve_device *dev);

void cve_di_set_pool_registers(struct cve_device *dev,
			int8_t pool_number);
void cve_di_unset_pool_registers(u8 pool_number);

u32 ice_di_get_icemask(struct idc_device *dev);


/*
 * retrieve Job handle from ICE device struct
 * inputs :
 *	ice - pointer to ICE device
 * outputs
 *	ds_job_handle - pointer to job handle, to be filled by the function
 * returns:
 */
void ice_di_get_job_handle(struct cve_device *ice,
		cve_ds_job_handle_t *ds_job_handle);

/*
 *  Unless driver is activated, Interrupt handler will not be executed
*/
void ice_di_activate_driver(void);

/*
 * This function should be called during Driver termination so that
 * illegal interrupts are not being served
 */
void ice_di_deactivate_driver(void);

void ice_di_set_shared_read_reg(struct cve_device *dev,
			struct ice_network *ntw, u8 enable_shared_read);

int ice_di_mmu_block_entrance(struct cve_device *cve_dev);

void ice_di_mmu_unblock_entrance(struct cve_device *cve_dev);

struct cve_device *get_first_device(void);

void ice_di_reset_counter(uint32_t cntr_id);

u8 ice_di_is_cold_run(cve_di_job_handle_t hjob);

void ice_di_set_cold_run(cve_di_job_handle_t hjob);

void ice_di_tlb_invalidate_full(struct cve_device *cve_dev);

#endif /* _DEVICE_INTERFACE_H_ */
