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

#ifdef RING3_VALIDATION
#include "coral.h"
#include <string.h>
#include <linux_kernel_mock.h>
#endif

#include "device_interface.h"
#include <CVG_MMU_1_system_map_regs.h>
#include "os_interface.h"
#include "doubly_linked_list.h"
#include "cve_driver_internal.h"
#include "device_interface_internal.h"
#include "project_settings.h"
#include "cve_driver_utils.h"
#include "cve_firmware.h"
#include "ice_mmu_inner_regs.h"
#include "cve_driver_internal.h"
#include "sph_device_regs.h"
#include "ice_debug.h"
#include "tlc_regs.h"
#include "TLC_command_formats_values_no_ifdef.h"


#ifdef RING3_VALIDATION
#include "coral.h"
#else
#include "linux/delay.h"
#include "ice_sw_counters.h"
#endif

#include "ice_debug_event.h"

#ifdef IDC_ENABLE
#include "idc_regs_regs.h"

#define ICE_TLC_DOORBELL_MAILBOX (ICE_CBBID_TLC_OFFSET + \
			ICE_TLC_HI_TLC_MAILBOX_DOORBELL_MMOFFSET)
#endif

#define PART_SUBMISSION_STEP (CVE_FIFO_ENTRIES_NR/2)

/* We expect 5 because the same value has been programmed in ECB */
#define ECB_SUCCESS_STATUS 5

/* Use: To avoid spurious interrupt */
int is_driver_active;

/* DATA TYPES */
struct di_command_buffer {
	/* number of commands */
	u16 commands_nr;
	/* base address of the command buffer in user space. */
	u64 command_buffer;
	/* the allocation which is associated with this buffer */
	cve_mm_allocation_t allocation;
	/* the CVE virtual address which is mapped to this cb */
	cve_virtual_address_t address;
	/** flag, if set, configures CBDT entry to allow TLC to relaod the CB*/
	u16 is_reloadable;
};

/* holds sub-job info */
struct di_job;
struct sub_job {
	/* link to the job's subjobs list */
	struct cve_dle_t list;
	/* parent job. May be NULL*/
	struct di_job *parent;
	/* should this subjob be deleted at the end of the parent job
	 * (used by designated cb loading)
	 */
	u32 embedded_sub_job;
	/* cb data */
	struct di_command_buffer cb;
};

/* hold job info */
struct di_job {
	/* link to the context's jobs list */
	struct cve_dle_t list;
	/* array of sub-jobs */
	struct sub_job *sub_jobs;
	/* next subjob to dispatch */
	u32 next_subjob;
	/* job's dispatcher's handle */
	cve_ds_job_handle_t ds_hjob;
	/* dispatch time */
	u64 dispatch_time_stamp;
	/* device cycles of all sub-jobs */
	u32 total_device_cycles;
	/* number of subjobs */
	u32 subjobs_nr;
	/* number of allocated sub jobs*/
	u32 allocated_subjobs_nr;
	/* number of remaining sub-jobs to dispatch */
	u32 remaining_subjobs_nr;
	/* Index of first CBD in the CBDT. Corresponding ICEVA
	 * will be written to CBD Base Address Register.
	 */
	u32 first_cb_desc;
	/* Index of last valid CBD in CBDT */
	u32 last_cb_desc;
	/* Is this the Cold run of Job */
	u8 cold_run;
	/* Does this Job has SCB */
	u8 has_scb;
};

/* MODULE LEVEL VARIABLES */
/* hold offsets to ATU's MMIO registers */
static u32 m_atu_mmio_offset_bytes[4] = {
	ICE_MMU_ATU0_BASE,
	ICE_MMU_ATU1_BASE,
	ICE_MMU_ATU2_BASE,
	ICE_MMU_ATU3_BASE,
};

/* rgisters to be exposed through debugfs*/
static struct debugfs_reg32 registers[] = {
	{"atu0_tlb_misses", ICE_MMU_BASE + ICE_MMU_ATU_MISSES_MMOFFSET},
	{"atu1_tlb_misses", ICE_MMU_BASE + ICE_MMU_ATU_MISSES_MMOFFSET + 4},
	{"atu2_tlb_misses", ICE_MMU_BASE + ICE_MMU_ATU_MISSES_MMOFFSET + 8},
	{"atu3_tlb_misses", ICE_MMU_BASE + ICE_MMU_ATU_MISSES_MMOFFSET + 12},
	{"atu0_tlb_hits", ICE_MMU_BASE + ICE_MMU_ATU_TRANSACTIONS_MMOFFSET},
	{"atu1_tlb_hits", ICE_MMU_BASE + ICE_MMU_ATU_TRANSACTIONS_MMOFFSET + 4},
	{"atu2_tlb_hits", ICE_MMU_BASE + ICE_MMU_ATU_TRANSACTIONS_MMOFFSET + 8},
	{"atu3_tlb_hits", ICE_MMU_BASE + ICE_MMU_ATU_TRANSACTIONS_MMOFFSET +
			12},
	{"mmu_reads", ICE_MMU_BASE + ICE_MMU_READ_ISSUED_MMOFFSET},
	{"mmu_writes", ICE_MMU_BASE + ICE_MMU_WRITE_ISSUED_MMOFFSET},
	{"atu0_pt", ICE_MMU_ATU0_BASE +
			ICE_MMU_ATU_PAGE_TABLE_BASE_ADDRESS_MMOFFSET},
	{"atu1_pt", ICE_MMU_ATU1_BASE +
			ICE_MMU_ATU_PAGE_TABLE_BASE_ADDRESS_MMOFFSET},
	{"atu2_pt", ICE_MMU_ATU2_BASE +
			ICE_MMU_ATU_PAGE_TABLE_BASE_ADDRESS_MMOFFSET},
	{"atu3_pt", ICE_MMU_ATU3_BASE +
			ICE_MMU_ATU_PAGE_TABLE_BASE_ADDRESS_MMOFFSET},

	};

/* INTERNAL FUNCTIONS */
/*
 * This function is part of adding an embedded command buffer flow.
 * It performs SHALLOW COPY of subjob to the beginning of a given job.
 * inputs:
 *	 di_job - device interface job handle to add the subjob to
 *	 subjob - handle to be added to the di_job->subjob list
 * outputs:
 * returns:
 */
static void add_embedded_cb_to_job(struct di_job *di_job,
		cve_di_subjob_handle_t subjob)
{
	struct sub_job *di_subjob = (struct sub_job *)subjob;

	di_job->sub_jobs[0] = *di_subjob;
	di_job->sub_jobs[0].parent = di_job;
}

/* return the pointer to the subjob of the given descriptor */
static inline struct sub_job *get_desc_subjob(
		union cve_shared_cb_descriptor *desc)
{
	struct sub_job *subjob = NULL;
	union {
		u32 *u32;
		struct sub_job **jobptr;
	} desc_subjob;

	desc_subjob.u32 = &desc->driver_reserved0;
	subjob = *desc_subjob.jobptr;
	return subjob;
}

/* set the subjob address in the given descriptor */
static inline void set_desc_subjob(
		union cve_shared_cb_descriptor *desc, struct sub_job *subjob)
{
	union {
		u32 *u32;
		struct sub_job **jobptr;
	} desc_subjob;

	desc_subjob.u32 = &desc->driver_reserved0;
	*desc_subjob.jobptr = subjob;
}

struct cve_device *get_first_device(void)
{
	struct cve_device *device = NULL;
	struct cve_device_group *dg = g_cve_dev_group_list;
	int i;

	for (i = 0; i < MAX_NUM_ICEBO; i++) {
		device = dg->dev_info.icebo_list[i].dev_list;
		if (!device)
			continue;
		break;
	}

	return device;
}

/* enable an outside module to cleanup a sub job */
void cve_di_sub_job_handle_destroy(cve_di_subjob_handle_t *subjob_handle)
{
	struct sub_job *sub_job_p = (struct sub_job *)(*subjob_handle);

	if (sub_job_p)
		OS_FREE(sub_job_p, sizeof(*sub_job_p));

	*subjob_handle = NULL;
}

void *cve_di_get_sub_job_kaddr(cve_di_subjob_handle_t *subjob_handle)
{
	struct sub_job *sub_job_p = (struct sub_job *)(*subjob_handle);

	if (sub_job_p)
		return (void *)(uintptr_t)sub_job_p->cb.command_buffer;
	else
		return NULL;
}

void remove_di_job(cve_di_job_handle_t hjob)
{
	struct di_job *job = (struct di_job *)hjob;

	OS_FREE(job->sub_jobs, sizeof(struct sub_job) *
			job->allocated_subjobs_nr);
	job->subjobs_nr = 0;
	job->allocated_subjobs_nr = 0;
	OS_FREE(job, sizeof(*job));
}

/*
 * Block MMU transaction from CVE
 * inputs :
 * returns: This function validate that
 * MMU transactions are not blocked already.
 *	return "0" - If transactions already blocked
 *				 (no need to block again)
 *	return "1" - If transactions were blocked in this function
 */
static int mmu_transactions_wait_and_block(struct cve_device *cve_dev)
{
	union ICE_MMU_INNER_MEM_MMU_CONFIG_t reg;
	int new_block_performed = 0;
	u32 offset_bytes = ICE_MMU_BASE + ICE_MMU_MMU_CONFIG_MMOFFSET;
	u32 wait_timeout = 0;
	/* validate that we are 32bit aligned */
	ASSERT(((offset_bytes >> 2) << 2) == offset_bytes);

	/* read current register value */
	reg.val = cve_os_read_mmio_32(cve_dev, offset_bytes);

	cve_os_dev_log(CVE_LOGLEVEL_DEBUG,
			cve_dev->dev_index,
			"Read BLOCK_ENTRANCE bit in MMU Config Register. reg.val = 0x%08x\n",
			reg.val);

	/* validate that MMU transactions are not blocked already
	 * (if they are blocked, there is no need to block again)
	 */
	if (!reg.field.BLOCK_ENTRANCE) {
		cve_os_dev_log(CVE_LOGLEVEL_DEBUG,
			cve_dev->dev_index,
			"Block CVE to send any NEW memory transactions to MMU\n");
		/* wait till all active transaction finished
		 * NOTE: This should take only several cycles
		 * (most likely first read of ACTIVE_TRANSACTIONS
		 * would return value 0) however due to
		 * page walks / unknown SoC latencies it may take
		 * even several iterations.
		 * Timeout wait time = 1 sec
		 */
		wait_timeout = cve_os_get_msec_time_stamp() + 10000;
		do {
			/* BLOCK_ENTRANCE = 1 :
			 * block CVE to send any NEW memory transactions to MMU
			 * The switching between
			 * BLOCK_ENTRANCE = 0/BLOCK_ENTRANCE = 1
			 * in loop is necessary due to HW design
			 */
			reg.field.BLOCK_ENTRANCE = 0;
			cve_os_write_mmio_32(cve_dev, offset_bytes, reg.val);
			reg.field.BLOCK_ENTRANCE = 1;
			cve_os_write_mmio_32(cve_dev, offset_bytes, reg.val);
			/* read register value for ACTIVE_TRANSACTIONS
			 * field check
			 */
			reg.val = cve_os_read_mmio_32(cve_dev, offset_bytes);
			if (time_after_in_msec(cve_os_get_msec_time_stamp(),
				wait_timeout)) {

				cve_os_dev_log(CVE_LOGLEVEL_ERROR,
				cve_dev->dev_index,
				"Timeout due to continues MMU transaction\n");

				break;
			}
		} while (reg.field.ACTIVE_TRANSACTIONS == 1);
		cve_os_dev_log(CVE_LOGLEVEL_DEBUG,
			cve_dev->dev_index,
			"All active MMU transaction from CVE finished...!\n");
		new_block_performed = 1;
	}
	return new_block_performed;
}

int ice_di_mmu_block_entrance(struct cve_device *cve_dev)
{
	return mmu_transactions_wait_and_block(cve_dev);
}

static void mmu_transactions_unblock(struct cve_device *cve_dev)
{
	union ICE_MMU_INNER_MEM_MMU_CONFIG_t reg;
	u32 offset_bytes = ICE_MMU_BASE + ICE_MMU_MMU_CONFIG_MMOFFSET;
	/* validate that we are 32bit aligned */
	ASSERT(((offset_bytes >> 2) << 2) == offset_bytes);

	/* read current register value */
	reg.val = cve_os_read_mmio_32(cve_dev, offset_bytes);
	/* allow CVE to send NEW memory transactions to MMU */
	reg.field.BLOCK_ENTRANCE = 0;
	cve_os_write_mmio_32(cve_dev, offset_bytes, reg.val);

	cve_os_dev_log(CVE_LOGLEVEL_DEBUG,
		cve_dev->dev_index,
		"Allow CVE to send NEW memory transactions to MMU. reg.val = 0x%08x\n",
		reg.val);
}

static void print_kernel_buffer(
		void *buffer_addr,
		u32 size_bytes,
		const char *buf_name)
{
#ifdef __KERNEL__
#ifdef CONFIG_DYNAMIC_DEBUG
	DEFINE_DYNAMIC_DEBUG_METADATA(descriptor, "enable kernel buffer print");

	if (unlikely(descriptor.flags & _DPRINTK_FLAGS_PRINT))

#endif
#else
	if (print_debug)
#endif
		cve_os_print_kernel_buffer(buffer_addr, size_bytes, buf_name);

}

static void ice_di_enable_tlc_bp(struct cve_device *ice_dev)
{
	union TLC_MEM_TLC_BARRIER_WATCH_CONFIG_REG_t reg;
	u32 offset_bytes = CVE_TLC_BASE +
		CVE_TLC_TLC_BARRIER_WATCH_CONFIG_REG_MMOFFSET;

	reg.field.enableWatch = 1;
	reg.field.watchMode = STOP_ALL_BARRIERS;
	reg.field.tlcMode = BLOCK_INCOMING_CNC_MESSAGES;
	/*reg.field.sectionID = bp->section_id;*/

	cve_os_write_mmio_32(ice_dev, offset_bytes, reg.val);

	cve_os_dev_log(CVE_LOGLEVEL_DEBUG, ice_dev->dev_index,
						"Wrote to TLC BP register\n");
}

static void __prepare_cbdt(struct di_job *job,
		struct cve_device *dev)
{
	u32 i;
	u32 last_cb_desc = 0;

	last_cb_desc = (job->remaining_subjobs_nr - 1);

	for (i = 0; i < job->remaining_subjobs_nr; i++) {
		u64 cb = 0;
		union cve_shared_cb_descriptor *descp = NULL;
		union cve_shared_cb_descriptor desc;
		struct sub_job *subjob = &job->sub_jobs[job->next_subjob];

		cb = subjob->cb.command_buffer;
		descp = &dev->fifo_desc->fifo.cb_desc_vaddr[i];

		/* initialize the command buffer descriptor */
		desc.address = subjob->cb.address;
		/* Splitting and storing 64bit VA into two u32 variables */
		desc.host_haddress = (u32)(cb & 0xffffffff);
		desc.host_haddress_reserved = (u32)((cb >> 32) & 0xffffffff);
		desc.commands_nr = subjob->cb.commands_nr;
		set_desc_subjob(&desc, subjob);
		desc.status = CVE_STATUS_DISPATCHED;
		/* Always setting this flag because same CBD is being executed
		 * by all InferRequests. No CBD reset is performed by Driver.
		 */
		desc.flags.isReloadable = 1;
		desc.flags.disable_CB_COMPLETED_int = (i != last_cb_desc);
		desc.flags.isPreloadable = 1;

		if (subjob->embedded_sub_job)
			print_kernel_buffer((void *)(uintptr_t)cb,
				desc.commands_nr << TLC_COMMAND_SIZE_SHIFT,
				"Command Buffer (embedded)");
		else
			cve_mm_print_user_buffer(subjob->cb.allocation,
				(void *)(uintptr_t)cb,
				desc.commands_nr << TLC_COMMAND_SIZE_SHIFT,
				"Command Buffer");

		*descp = desc;

		print_kernel_buffer(descp,
				sizeof(*descp), "Command Buffer Descriptor");

		cve_os_dev_log(CVE_LOGLEVEL_DEBUG,
			dev->dev_index,
			"CBD_Idx=%u, CBD_ID=0x%lx:\n\tICEVA=0x%x\n\tCommandsCount=%u\n\tFlags=0x%x\n",
			i, (uintptr_t)descp,
			desc.address, desc.commands_nr, desc.flags.fixed_size);

		job->next_subjob++;
	}

	job->remaining_subjobs_nr = 0;
	job->last_cb_desc = last_cb_desc;
}

/*
 * dispatch the next subjobs of the given job
 */
static void dispatch_next_subjobs(struct di_job *job,
		struct cve_device *dev)
{
	u32 db = 0;
	u32 cbd_size = sizeof(union cve_shared_cb_descriptor);
	cve_virtual_address_t iceva;
	struct ice_network *ntw = (struct ice_network *) dev->dev_network_id;

	if (job->cold_run)
		__prepare_cbdt(job, dev);

	job->first_cb_desc = 0;
	iceva = dev->fifo_desc->fifo_alloc.ice_vaddr;
	db = job->last_cb_desc;

	if (job->cold_run) {
		/* Cold Run */
		if (disable_embcb) {
			job->first_cb_desc = 1;

			cve_os_log(CVE_LOGLEVEL_INFO,
				"Cold Run (Skipping EmbCB)\n");
		} else {
			cve_os_log(CVE_LOGLEVEL_INFO,
				"Cold Run (With EmbCB)\n");
		}

		job->cold_run = 0;

	} else if (job->has_scb) {
		/* Warm Run with SCB */
		job->first_cb_desc = 2;

		cve_os_log(CVE_LOGLEVEL_INFO,
			"Warm Run (Skipping SCB)\n");

	} else {
		/* Warm run without SCB */
		job->first_cb_desc = 1;

		cve_os_log(CVE_LOGLEVEL_INFO,
			"Warm Run\n");
	}

	iceva += (job->first_cb_desc * cbd_size);
	db -= job->first_cb_desc;

	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"CBDT Base Address = %x, CBDT Entries = %d, Doorbell = %d\n",
		iceva, dev->fifo_desc->fifo.entries, db);

	/* allow CVE to send NEW memory transactions to MMU */
	mmu_transactions_unblock(dev);

	/* call project hook right before ringing the doorbell */
	project_hook_dispatch_new_job(dev, ntw);

	/* make sure the compiler doesn't reorder the instructions */
	cve_os_memory_barrier();

#ifndef RING3_VALIDATION
	ice_swc_counter_add(dev->hswc,
		ICEDRV_SWC_DEVICE_COUNTER_COMMANDS,
		(db + 1));
#endif

	cve_os_dev_log(CVE_LOGLEVEL_INFO,
		dev->dev_index,
		"NtwID:0x%llx Ring the doorbell\n",
		ntw->network_id);

	/* To check if break point needs to be set */
	if (ntw->reserve_resource & ICE_SET_BREAK_POINT)
		ice_di_enable_tlc_bp(dev);

	/* reset the TLC FIFO indexes */
	cve_os_write_mmio_32(dev,
	 CVE_MMIO_HUB_COMMAND_BUFFER_DESCRIPTORS_BASE_ADDRESS_MMOFFSET,
	 iceva);
	cve_os_write_mmio_32(dev,
	 CVE_MMIO_HUB_COMMAND_BUFFER_DESCRIPTORS_ENTRIES_NR_MMOFFSET,
	 dev->fifo_desc->fifo.entries);

	/* ring the doorbell once with the last descriptor */
	cve_os_write_mmio_32(dev,
		CVE_MMIO_HUB_NEW_COMMAND_BUFFER_DOOR_BELL_MMOFFSET,
		db);
}


static void do_tlb_flush_full(struct cve_device *cve_dev)
{
	u32 i;
	union CVG_MMU_1_SYSTEM_MAP_MEM_INVALIDATE_t reg;

	reg.val = 0;
	reg.field.MMU_INVALIDATE = 0xffff; /* invalidate all streams */
	for (i = 0; i < ARRAY_SIZE(m_atu_mmio_offset_bytes); i++) {
		u32 offset_bytes = m_atu_mmio_offset_bytes[i] +
				CVG_MMU_1_SYSTEM_MAP_MEM_INVALIDATE_OFFSET;
		ASSERT(((offset_bytes >> 2) << 2) == offset_bytes);
		cve_os_write_mmio_32(cve_dev, offset_bytes, reg.val);
	}
}

/* write to page table base address MMIO register of all ATU's*/
static inline void write_to_page_table_base_address(
	struct cve_device *cve_dev,
	const union CVG_MMU_1_SYSTEM_MAP_MEM_PAGE_TABLE_BASE_ADDRESS_t reg)
{
	u32 i;

	cve_os_dev_log(CVE_LOGLEVEL_DEBUG,
			cve_dev->dev_index,
			"write_to_page_table_base_address executed\n");

	for (i = 0; i < ARRAY_SIZE(m_atu_mmio_offset_bytes); i++) {
		u32 offset_bytes = m_atu_mmio_offset_bytes[i] +
			CVG_MMU_1_SYSTEM_MAP_MEM_PAGE_TABLE_BASE_ADDRESS_OFFSET;
		ASSERT(((offset_bytes >> 2) << 2) == offset_bytes);
		cve_os_write_mmio_32(cve_dev, offset_bytes, reg.val);
	}

	/* the TLB's in CVE use prefetching. it means that
	 * once the page table is configured, any change to its content
	 * requires a full TLB flush, even in cases a flush is not required
	 * in other agents (e.g. CPU), like adding a mapping.
	 */

	/* flush the TLB */
	do_tlb_flush_full(cve_dev);

#ifdef _DEBUG
	cve_os_write_mmio_32(cve_dev,
		ICE_DEBUG_CFG_REG, reg.val);
#endif

}


/* INTERFACE FUNCTIONS */

void cve_di_mask_interrupts(struct cve_device *cve_dev)
{
#ifdef IDC_ENABLE
	/* First check if the device is PE, then update */
	uint64_t value, mask;

	mask = (1 << cve_dev->dev_index) << 4;

	value = cve_os_read_idc_mmio(cve_dev,
		IDC_REGS_IDC_MMIO_BAR0_MEM_ICEPE_MMOFFSET);

	if (!(value & mask))
		return;
#endif
	cve_os_write_mmio_32(cve_dev,
			CVE_MMIO_HUB_INTERRUPT_MASK_MMOFFSET,
			(u32)-1);
}

void cve_di_cleanup(void)
{
/*
** (meaningless in cve2, removed in cve2.6)
*#ifdef RING3_VALIDATION
*	coral_exit();
*#endif
*/
}

void ice_di_set_shared_read_reg(struct cve_device *dev, struct ice_network *ntw,
			u8 enable_shared_read)
{
	int bo_id = dev->dev_index / 2;
	axi_shared_read_cfg_t cfg_reg;
	u32 offset;

	offset = ICEDC_ICEBO_OFFSET(bo_id) + AXI_SHARED_READ_CFG_OFFSET;

	if (!enable_shared_read) {
		cfg_reg.field.shared_read_enable = 0;
		cve_os_write_idc_mmio(dev, offset, cfg_reg.val);
		return;
	}

	cfg_reg.field.shared_read_enable = 1;
	cfg_reg.field.max_shared_distance = ntw->max_shared_distance;
	cfg_reg.field.enable_timeout = 1;
	cfg_reg.field.timeout_threshold = SHARED_READ_TIMEOUT_THRESHOLD;

	cve_os_write_idc_mmio(dev, offset, cfg_reg.val);
}


#ifdef IDC_ENABLE
int set_idc_registers(struct cve_device *dev, uint8_t lock)
{
	uint64_t value, mask;
	int ret = 0;
	struct hw_revision_t hw_rev;
	struct idc_device *idc = ice_to_idc(dev);
	struct cve_device_group *dg = dev->dg;

	if (lock) {
		ret = cve_os_lock(&dg->poweroff_dev_list_lock,
				CVE_INTERRUPTIBLE);
		if (ret != 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
					"Error:%d PowerOff Lock not aquired\n",
					ret);
			return ret;
		}
	}

	if (dev->power_state == ICE_POWER_ON) {

		cve_os_log(CVE_LOGLEVEL_INFO,
			"ICE-%d is already Power enabled\n",
			dev->dev_index);

		goto out;
	}

	/* TODO HACK: Always check if its enabled by reading MMIO */
	mask = (1ULL << dev->dev_index) << 4;

	/*PE 1 ICE without disturbing other  */
	value = cve_os_read_idc_mmio(dev,
		IDC_REGS_IDC_MMIO_BAR0_MEM_ICEPE_MMOFFSET);

	/* Device is already ON */
	if ((value & mask) == mask) {
		cve_os_log(CVE_LOGLEVEL_INFO,
			"ICE-%d is already Power enabled\n",
			dev->dev_index);

		/* In case Power state was unknown */
		dev->power_state = ICE_POWER_ON;

		goto out;
	}

	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"Power enabling ICE-%d\n", dev->dev_index);

	value |= mask;

	cve_os_write_idc_mmio(dev,
		IDC_REGS_IDC_MMIO_BAR0_MEM_ICEPE_MMOFFSET, value);

	/* Check if ICEs are Ready */
	/* Driver is not yet sure how long to wait for ICERDY */
	{
		int8_t count = 8;

		while (count) {
			value = cve_os_read_idc_mmio(dev,
				IDC_REGS_IDC_MMIO_BAR0_MEM_ICERDY_MMOFFSET);

			if ((value & mask) == mask)
				break;
			count--;
			usleep_range(1000, 3000);
		}
	}

	if ((value & mask) != mask) {
		uint64_t val64 = (value & ~mask);

		/* Power Disable the faulty ICE */
		cve_os_write_idc_mmio(dev,
				IDC_REGS_IDC_MMIO_BAR0_MEM_ICEPE_MMOFFSET,
				val64);

		cve_os_log(CVE_LOGLEVEL_ERROR,
			"Initialization of ICE-%d failed\n",
			dev->dev_index);
		ret = -ICEDRV_KERROR_ICE_DOWN;
		goto out;
	}

	dev->power_state = ICE_POWER_ON;

	cve_di_set_device_reset_flag(dev,
		CVE_DI_RESET_DUE_POWER_ON);

	/* Enable interrupts from ICE */
	value = cve_os_read_idc_mmio(dev,
		IDC_REGS_IDC_MMIO_BAR0_MEM_ICEINTEN_MMOFFSET);
	cve_os_write_idc_mmio(dev,
		IDC_REGS_IDC_MMIO_BAR0_MEM_ICEINTEN_MMOFFSET,
		value | mask);

	/* Enable error interrupts from ICE */
	value = cve_os_read_idc_mmio(dev,
		IDC_REGS_IDC_MMIO_BAR0_MEM_ICEINTEN_MMOFFSET + 4);
	cve_os_write_idc_mmio(dev,
		IDC_REGS_IDC_MMIO_BAR0_MEM_ICEINTEN_MMOFFSET + 4,
		value | mask);

	value = atomic64_read(&idc->idc_err_intr_enable);
	if (value != ICEDC_ERROR_INTR_ENABLE_ALL) {
		value = ICEDC_ERROR_INTR_ENABLE_ALL;
		atomic64_set(&idc->idc_err_intr_enable, value);

		/* Enable lower 32 bits of IDC interrupt */
		cve_os_write_idc_mmio(dev, ICEDC_INTR_ENABLE_OFFSET,
		get_low_dword(value));

		/* Enable upper 32 bits of IDC interrupt */
		cve_os_write_idc_mmio(dev, ICEDC_INTR_ENABLE_OFFSET + 4,
		get_high_dword(value));
	}

	/* Verify if this is the best place to keep because */
	/* in this case we will read same info multiple time */
	get_hw_revision(dev, &hw_rev);
	dev->version_info.major = hw_rev.major_rev;
	dev->version_info.minor = hw_rev.minor_rev;

out:
	if (lock)
		cve_os_unlock(&dg->poweroff_dev_list_lock);

	return ret;
}
#endif

int unset_idc_registers(struct cve_device *dev, uint8_t lock)
{
	u32 mask;

	if (dev)
		mask = (1 << dev->dev_index);
	else
		mask = 0xFFF;

	return unset_idc_registers_multi(mask, lock);
}

/* Power off multiple devices in single go */
int unset_idc_registers_multi(u32 icemask, uint8_t lock)
{
	u32 i, temp_mask = icemask;
	int ret = 0;
	/* 1 if all ICEs are off */
	uint8_t all_powered_off = 0;
	uint64_t value, mask;
	struct idc_device *idc;
	struct cve_device *dev;
	struct cve_device_group *dg;

	dev = get_first_device();
	ASSERT(dev != NULL);
	idc = ice_to_idc(dev);
	dg = dev->dg;

	if (lock) {
		ret = cve_os_lock(&dg->poweroff_dev_list_lock,
				CVE_INTERRUPTIBLE);
		if (ret != 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
					"Error:%d PowerOff Lock not aquired\n",
					ret);
			return ret;
		}
	}

	mask = ((uint64_t)(icemask) << 4);

	while (temp_mask) {
		i = __builtin_ctz(temp_mask);
		temp_mask &= ~((u32)1 << i);

		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Power disabling ICE-%d. Mask=%x\n", i, icemask);
	}

	/* Power Off all ICEs */
	value = cve_os_read_idc_mmio(dev,
		IDC_REGS_IDC_MMIO_BAR0_MEM_ICEPE_MMOFFSET);
	value &= ~mask;
	if (!value)
		all_powered_off = 1;

	/* Acces PE regsiter only on real SOC */
	if (ice_is_soc())
		cve_os_write_idc_mmio(dev,
				IDC_REGS_IDC_MMIO_BAR0_MEM_ICEPE_MMOFFSET,
				value);

	/* Disable interrupts from ICE */
	value = cve_os_read_idc_mmio(dev,
		IDC_REGS_IDC_MMIO_BAR0_MEM_ICEINTEN_MMOFFSET);
	cve_os_write_idc_mmio(dev,
		IDC_REGS_IDC_MMIO_BAR0_MEM_ICEINTEN_MMOFFSET,
		value & (~mask));

	/* Disable error interrupts from ICE */
	value = cve_os_read_idc_mmio(dev,
		IDC_REGS_IDC_MMIO_BAR0_MEM_ICEINTEN_MMOFFSET + 4);
	cve_os_write_idc_mmio(dev,
		IDC_REGS_IDC_MMIO_BAR0_MEM_ICEINTEN_MMOFFSET + 4,
		value & (~mask));

	/* ICENOTE is automatically cleared with 0 write to PE */

	if (all_powered_off) {
		mask = atomic64_xchg(&idc->idc_err_intr_enable, 0);
		/* Disable lower 32 bits of IDC interrupt */
		value = cve_os_read_idc_mmio(dev, ICEDC_INTR_ENABLE_OFFSET);
		cve_os_write_idc_mmio(dev, ICEDC_INTR_ENABLE_OFFSET,
			value & (~mask));
		/* Disable higher 32 bits of IDC interrupt */
		value = cve_os_read_idc_mmio(dev, ICEDC_INTR_ENABLE_OFFSET + 4);
		cve_os_write_idc_mmio(dev, ICEDC_INTR_ENABLE_OFFSET + 4,
			value & (~mask));
	}

	if (lock)
		cve_os_unlock(&dg->poweroff_dev_list_lock);

	return 0;
}

void cve_di_reset_device(struct cve_device *cve_dev)
{
	uint8_t idc_reset;

	/* Wait till active memory transactions
	 * finished and block CVE to send any
	 * NEW memory transactions to MMU.
	 */
	mmu_transactions_wait_and_block(cve_dev);

	/* Do not perform IDC reset for this ICE if
	 * it was just powered on
	 */
	idc_reset = (cve_dev->di_cve_needs_reset & CVE_DI_RESET_DUE_POWER_ON) ?
			0 : 1;

	if (do_reset_device(cve_dev, idc_reset))
		cve_os_dev_log(CVE_LOGLEVEL_ERROR,
				cve_dev->dev_index,
				"Encountered an error to perform a device reset\n");

	cve_os_dev_log(CVE_LOGLEVEL_DEBUG,
			cve_dev->dev_index,
			"Perform Reset Device Reason=0x%08x, Ntw=%d, IceErr=%d, Job=%d, Timeout=%d, Power=%d\n",
			cve_dev->di_cve_needs_reset,
			((cve_dev->di_cve_needs_reset &
				CVE_DI_RESET_DUE_NTW_SWITCH) != 0),
			((cve_dev->di_cve_needs_reset &
				CVE_DI_RESET_DUE_CVE_ERROR) != 0),
			((cve_dev->di_cve_needs_reset &
				CVE_DI_RESET_DUE_JOB_NOT_COMP) != 0),
			((cve_dev->di_cve_needs_reset &
				CVE_DI_RESET_DUE_TIME_OUT) != 0),
			((cve_dev->di_cve_needs_reset &
				CVE_DI_RESET_DUE_POWER_ON) != 0));

	cve_dev->di_cve_needs_reset = 0;
}

static inline void di_enable_interrupts(struct cve_device *cve_dev)
{
	union MMIO_HUB_MEM_INTERRUPT_MASK_t mask;

	mask.val = 0;
	mask.field.TLC_FIFO_EMPTY = 1;

	/* Enable interrupts */
	cve_os_write_mmio_32(cve_dev, CVE_MMIO_HUB_INTERRUPT_MASK_MMOFFSET,
			mask.val);
}

void cve_di_start_running(struct cve_device *cve_dev)
{
	/* Enable the IDLE clock gating logic */
	/* TODO: 2000 is a temporary initial value for CVE bring-up
	 * (should be between 100 to 200)
	 */

	cve_os_write_mmio_32(cve_dev,
			CVE_MMIO_HUB_PRE_IDLE_DELAY_COUNT_MMOFFSET,
			2000);
	cve_os_write_mmio_32(cve_dev, CVE_MMIO_HUB_CVE_CONFIG_MMOFFSET,
		MMIO_HUB_MEM_CVE_CONFIG_CVE_IDLE_ENABLE_MASK);

	/* enable all the interrupts beside the FIFO empty */
	di_enable_interrupts(cve_dev);

#if !defined RING3_VALIDATION
/*
 * delay is needed to work around debugger
 * re-connected upon CVE reset
 * with CVE2.0 Silicon , this W/A is not needed
 * a fix is available via register setting
 * refer to cve_decouple_debuger_reset()
 */
	if (cve_debug_get(DEBUG_TENS_EN)) {

		cve_os_dev_log(CVE_LOGLEVEL_ERROR,
				cve_dev->dev_index,
				"BEFORE! STALL FOR DEBUGGER RECONNECT 10sec\n");

		mdelay(10000);
		cve_os_dev_log(CVE_LOGLEVEL_ERROR,
				cve_dev->dev_index,
				"AFTER! STALL FOR DEBUGGER RECONNECT 10sec\n");
	}
#endif
	/* Release all stalled cores */
	cve_os_write_mmio_32(cve_dev,
		CVE_MMIO_HUB_PROG_CORES_CONTROL_MMOFFSET, core_mask);

#ifdef _DEBUG
	cve_os_write_mmio_32(cve_dev,
		ICE_DEBUG_CFG_REG, 0xabababab);
	cve_os_write_mmio_32(cve_dev,
		ICE_DEBUG_CFG_REG, get_process_pid());
#endif
}

int cve_di_create_subjob(cve_virtual_address_t cb_address,
		u64 cb_command_buffer,
		u16 cb_commands_nr,
		u32 embedded_sub_job,
		cve_di_subjob_handle_t *out_subjob_handle){
	int retval = CVE_DEFAULT_ERROR_CODE;
	struct sub_job *p_sub_job = NULL;

	retval = OS_ALLOC_ZERO(sizeof(struct sub_job),
			(void **)(&p_sub_job));
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR, "os_malloc_failed %d\n", retval);
		goto out;
	}

	p_sub_job->cb.address = cb_address;
	p_sub_job->cb.command_buffer = cb_command_buffer;
	p_sub_job->cb.commands_nr = cb_commands_nr;
	p_sub_job->embedded_sub_job = embedded_sub_job;

	*out_subjob_handle = (cve_di_subjob_handle_t)p_sub_job;
out:
	return retval;
}

void ice_di_reset_counter(uint32_t cntr_id)
{
	struct cve_device *dev = get_first_device();
	uint32_t offset = IA_IICS_BASE + (cntr_id * 32) +
				IDC_REGS_IDC_MMIO_BAR1_MEM_EVCTICE0_MMOFFSET;

	ASSERT(dev != NULL);
	if (cntr_id >= MAX_HW_COUNTER_NR) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
		"Counter:%d out of range (valid range [0 - %d]\n",
		cntr_id, MAX_HW_COUNTER_NR);
		goto out;
	}

	cve_os_write_idc_mmio(dev, offset, 0x0);
out:
	return;
}

void cve_di_set_pool_registers(struct cve_device *dev,
			int8_t pool_number)
{
	u32 i;
	u32 mask, value, reg, device_index_bit;
	u32 dev_index = dev->dev_index;

	reg = IDC_REGS_IDC_MMIO_BAR0_MEM_ICEPOOL0_MMOFFSET
			+ (pool_number * 8);
	device_index_bit = (1<<(4+dev_index)) & 0xffff;

	/* Unregister this ICE from any Pool that it is registered with */
	for (i = 0; i < NUM_POOL_REG; i++) {
		u32 reg_offset = IDC_REGS_IDC_MMIO_BAR0_MEM_ICEPOOL0_MMOFFSET
					+ (i * 8);
		u32 read = cve_os_read_idc_mmio(dev, reg_offset);

		if (device_index_bit & read) {
			u32 unregister_ice = (~device_index_bit) & 0xffff;

			unregister_ice = unregister_ice & read;
			cve_os_write_idc_mmio(dev, reg_offset,
						unregister_ice);
		}
	}

	/* Register this ICE with specified Pool */
	value  = cve_os_read_idc_mmio(dev, reg);
	mask  = (1<<(4+dev_index)) & 0xffff;

	value = value & 0xffff;
	mask = value | mask;
	cve_os_write_idc_mmio(dev, reg, mask);
}

void cve_di_unset_pool_registers(u8 pool_number)
{
	u32 reg = IDC_REGS_IDC_MMIO_BAR0_MEM_ICEPOOL0_MMOFFSET;
	struct cve_os_device *os_dev = to_cve_os_device(get_first_device());

	reg = IDC_REGS_IDC_MMIO_BAR0_MEM_ICEPOOL0_MMOFFSET +
		(pool_number * 8);

	cve_os_write_idc_mmio(
		os_dev->idc_dev.cve_dev, reg, 0);

}

/*
 * Linking given counter (ctr_nr) with the pool of given context (context_id).
 * Notification address is set to current Default.
*/
void cve_set_hw_sync_regs(struct idc_device *idc_dev,
					u32 ctr_nr, int8_t pool_id)
{
	u32 reg = IDC_REGS_IDC_MMIO_BAR0_MEM_EVCTPROT0_MMOFFSET + (ctr_nr * 32);
	IDC_REGS_EVCTPROT0_t evct_prot_reg;
	int value = 32 + pool_id;

	evct_prot_reg.val = cve_os_read_idc_mmio(idc_dev->cve_dev, reg);

	if ((evct_prot_reg.field.value == value) &&
		(evct_prot_reg.field.OVFIE == 1))
		return;

	evct_prot_reg.field.value = value;
	/* Overflow Interrupt enable. In case the overflow is an error
	 * condition, setting the bit will enable triggering an
	 * interrupt on the occurrence of the event. When enabled, a 1
	 * in the bit will set CTROVFERR in IDCINTST register when OVF
	 * bit is set.
	 */
	evct_prot_reg.field.OVFIE = 1;

	/* Links Counter to Pool */
	cve_os_write_idc_mmio(idc_dev->cve_dev, reg, evct_prot_reg.val);

	/* We use TLC doorbell mechanism instead of MMIO polling
	 * to improve latency.
	 */
	cve_os_write_idc_mmio(idc_dev->cve_dev,
		IDC_REGS_IDC_MMIO_BAR0_MEM_ICENOTA0_MMOFFSET,
		ICE_TLC_DOORBELL_MAILBOX);
}

void cve_reset_hw_sync_regs(struct idc_device *idc_dev,
					u32 ctr_nr)
{
	u32 reg = IDC_REGS_IDC_MMIO_BAR0_MEM_EVCTPROT0_MMOFFSET + (ctr_nr * 32);
	u32 value = 0;

	cve_os_write_idc_mmio(idc_dev->cve_dev, reg, value);
}

static int identify_ice_and_clear(u32 *interrupt_status)
{
	/*
	 * This function combines Normal-Int and Error-Int
	 * and only return ICE Id that generated the interrupt.
	 * Error handling will be done during DPC.
	*/
	int i;
	u32 status = *interrupt_status;

	status >>= 4;
	for (i = 0; i < 12; i++) {
		if (status & 0x1) {
			*interrupt_status ^= (1 << (i + 4));
			return i;
		}
		status >>= 1;
	}
	return -1;
}
static int is_embedded_cb_error(struct cve_device *cve_dev)
{
	u32 reg_val;

	reg_val = cve_os_read_mmio_32(cve_dev, ICE_MMIO_GP_RESET_REG_ADDR);

	return ((reg_val == ECB_SUCCESS_STATUS) ? 0 : 1);
}

static void cve_executed_cbs_time_log(struct cve_device *dev,
	struct di_job *job, u64 *exec_time)
{
	u32 i;
	union cve_shared_cb_descriptor *cb_descriptor = NULL;

	*exec_time = 0;

	for (i = job->first_cb_desc; i <= job->last_cb_desc; i++) {

		cb_descriptor = &dev->fifo_desc->fifo.cb_desc_vaddr[i];

#ifndef RING3_VALIDATION
		ice_swc_counter_add(dev->hswc,
			ICEDRV_SWC_DEVICE_COUNTER_RUNTIME,
			(cb_descriptor->completion_time -
			cb_descriptor->start_time));
#endif

		cve_os_dev_log(CVE_LOGLEVEL_DEBUG, dev->dev_index,
			"CBD_ID=0x%lx, StartTime=%u, EndTime=%u\n",
			(uintptr_t)cb_descriptor,
			cb_descriptor->start_time,
			cb_descriptor->completion_time);

		*exec_time += (cb_descriptor->completion_time -
				cb_descriptor->start_time);
	}
}

/* Return ntw if counter has overflowed */
static struct ice_network *__get_ntw_of_overflowed_cntr(int cntr_id,
		struct idc_device *dev)
{
	struct cve_device_group *dg = cve_dg_get();
	u32 reg = IDC_REGS_IDC_MMIO_BAR0_MEM_EVCTPROT0_MMOFFSET +
		(cntr_id * 32);
	IDC_REGS_EVCTPROT0_t evct_prot_reg;
	struct ice_network *ntw = NULL;

	/* Check overflow bit of all the counters with which a valid NTW ID
	 * is associated.
	 * base_addr_hw_cntr holds the base address of HW CNTR array and can be
	 * used to get the network ID to which a given counter belongs.
	 */
	if (dg->base_addr_hw_cntr[cntr_id].network_id != INVALID_NETWORK_ID) {
		evct_prot_reg.val = cve_os_read_idc_mmio(dev->cve_dev, reg);
		if (evct_prot_reg.field.OVF) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
			"Error: NtwID:0x%llx Counter:%x overflow\n",
			dg->base_addr_hw_cntr[cntr_id].network_id, cntr_id);
			ntw = (struct ice_network *)
				dg->base_addr_hw_cntr[cntr_id].network_id;
		}
	}

	return ntw;
}

int cve_di_interrupt_handler(struct idc_device *idc_dev)
{
	int index;
	int need_dpc = 0;
	u32 status_32 = 0;
	u32 status_lo, status_hi, status_hl;
	struct cve_device *cve_dev = NULL;

	u32 head = atomic_read(&idc_dev->status_q_head);
	u32 tail = atomic_read(&idc_dev->status_q_tail);
	struct dev_isr_status *isr_status_node;

	if (!is_driver_active) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"Received Illegal Interrupt\n");
		return need_dpc;
	}


	if (((head + 1) % IDC_ISR_BH_QUEUE_SZ) == tail) {
		/* Q FULL*/
		cve_os_log(CVE_LOGLEVEL_ERROR, "BH ISR Q FULL\n");
	}


	isr_status_node = &idc_dev->isr_status[head];
	/* Set the valid to 0 as not data is yet processed
	 * Set to one if some relevant data is filled
	 */
	isr_status_node->valid = 0;

	status_lo = cve_os_read_idc_mmio(idc_dev->cve_dev,
			ICEDC_INTR_STATUS_OFFSET);
	status_hi = cve_os_read_idc_mmio(idc_dev->cve_dev,
			ICEDC_INTR_STATUS_OFFSET + 4);
	isr_status_node->idc_status = (((u64)status_hi << 32) | status_lo);

	cve_os_write_idc_mmio(idc_dev->cve_dev,
		ICEDC_INTR_STATUS_OFFSET, status_lo);
	cve_os_write_idc_mmio(idc_dev->cve_dev,
		ICEDC_INTR_STATUS_OFFSET + 4, status_hi);

	if (status_lo || status_hi) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
			"Received IceDC error interrupt\n");
		need_dpc = 1;
		isr_status_node->valid = 1;
	}

	status_lo = cve_os_read_idc_mmio(idc_dev->cve_dev,
			IDC_REGS_IDC_MMIO_BAR0_MEM_ICEINTST_MMOFFSET);
	status_hi = cve_os_read_idc_mmio(idc_dev->cve_dev,
			IDC_REGS_IDC_MMIO_BAR0_MEM_ICEINTST_MMOFFSET + 4);

	isr_status_node->ice_status = (((u64)status_hi << 32) | status_lo);
	cve_os_log(CVE_LOGLEVEL_INFO,
			"IsrQNode[%d]:0x%p Current ICE Status=0x%llx IntrStatus:0x%x ErrorStatus:0x%x\n",
			head, isr_status_node, isr_status_node->ice_status,
			status_lo, status_hi);

	cve_os_write_idc_mmio(idc_dev->cve_dev,
			IDC_REGS_IDC_MMIO_BAR0_MEM_ICEINTST_MMOFFSET,
			status_lo & 0x0000FFF0);
	cve_os_write_idc_mmio(idc_dev->cve_dev,
			IDC_REGS_IDC_MMIO_BAR0_MEM_ICEINTST_MMOFFSET + 4,
			status_hi & 0x0000FFF0);

	/* Spurious Interrupt */
	if (!isr_status_node->ice_status && !need_dpc) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"Spurious ISR IsrQNode[%d] IDC Status:0x%llx ICE Status=0x%llx\n",
				head,
				isr_status_node->idc_status,
				isr_status_node->ice_status);
		goto exit;
	}

	/* Currently only serving ICE Int Request, not Ice Error request */
	status_hl = status_lo | status_hi;
	while (1) {
		index = identify_ice_and_clear(&status_hl);
		if (index < 0)
			break;

		cve_dev = &idc_dev->cve_dev[index];

		project_hook_interrupt_handler_entry(cve_dev);

		status_32 = cve_os_read_mmio_32(cve_dev,
				CVE_MMIO_HUB_INTERRUPT_STATUS_MMOFFSET);
		isr_status_node->ice_isr_status[index] = status_32;
		cve_os_dev_log(CVE_LOGLEVEL_INFO,
			index,
			"Received interrupt from IDC. Status=0x%x\n",
			status_32);

		need_dpc |= (status_32 != 0);
		isr_status_node->valid = need_dpc;

		project_hook_interrupt_handler_exit(cve_dev,
				status_32);
	}

	head = ((head + 1) % IDC_ISR_BH_QUEUE_SZ);
	atomic_set(&idc_dev->status_q_head, head);

exit:
	return need_dpc;
}

/** Empty the Q and read all node updated by ISR */
static inline void __read_isr_q(struct idc_device *dev,
		u64 *idc_status, u64 *ice_status, u32 *q_tail)
{
	u32 head = atomic_read(&dev->status_q_head);
	u32 tail = atomic_read(&dev->status_q_tail);
	struct dev_isr_status *qnode;
	struct cve_device *ice = NULL;
	u32 status_lo = 0, status_hi = 0, status_hl = 0, index = 0, status;

	while (tail != head) {
		index = 0;
		qnode = &dev->isr_status[tail];
		if (qnode->valid) {
			qnode->valid = 0;
			*idc_status |= qnode->idc_status;
			*ice_status |= qnode->ice_status;
			status_lo = (qnode->ice_status & 0xFFFF);
			status_hi = ((qnode->ice_status >> 32) & 0xFFFF);
			status_hl = status_hi | status_lo;
			cve_os_log(CVE_LOGLEVEL_DEBUG,
					"IsrQNode[%d] idc_status:0x%llx ice_status:0x%llx\n",
					tail, *idc_status, *ice_status);

			status_hl >>= 4;
			while (status_hl && index < NUM_ICE_UNIT) {
				if (status_hl & 0x1) {
					ice = &dev->cve_dev[index];
					status = qnode->ice_isr_status[index];
					ice->interrupts_status = status;
					cve_os_log(CVE_LOGLEVEL_DEBUG,
							"IsrQNode[%d] ice%d status:0x%x\n",
							tail, index,
							ice->interrupts_status);
				}
				status_hl = (status_hl >> 1);
				index++;
			}
			tail = (tail + 1) % IDC_ISR_BH_QUEUE_SZ;
		}
	}
	*q_tail = tail;
}


void cve_di_interrupt_handler_deferred_proc(struct idc_device *dev)
{
	int index, i;
	u32 status;
	u32 status_lo = 0, status_hi = 0, status_hl = 0;
	union icedc_intr_status_t idc_err_status;
	u64 exec_time, ice_status = 0, idc_status = 0;
	struct di_job *job;
	union cve_shared_cb_descriptor *cb_descriptor;
	enum cve_job_status job_status;
	struct cve_device *cve_dev = NULL;
	struct sub_job *sub_job;
	struct di_fifo *fifo;

	u32 head, tail;
	struct dev_isr_status *isr_status_node;

	cve_os_lock(&g_cve_driver_biglock, CVE_NON_INTERRUPTIBLE);

	head = atomic_read(&dev->status_q_head);
	tail = atomic_read(&dev->status_q_tail);

	if (tail == head) {
		/* Q Empty*/
		cve_os_log(CVE_LOGLEVEL_ERROR, "ISR-BH Q IS EMPTY\n");
		goto end;
	}

	isr_status_node = &dev->isr_status[tail];
	if (!isr_status_node->valid) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"Spurious BH IsrQNode[%d] idc_status:0x%llx ice_status:0x%llx\n",
				tail, isr_status_node->idc_status,
				isr_status_node->ice_status);
		goto end;
	}

	__read_isr_q(dev, &idc_status, &ice_status, &tail);

	atomic_set(&dev->status_q_tail, tail);

	idc_err_status.val = idc_status;

	if (idc_err_status.val) {
		uint8_t cntr_overflow = idc_err_status.field.cntr_oflow_err;

		cve_os_log(CVE_LOGLEVEL_ERROR,
				"ICEDC Errro Interrupt Status = %llu, ILGACC:%x ICERERR:%x ICEWERR:%x ASF_ICE1_ERR:%x ASF_ICE0_ERR:%x ICECNERR:%x ICESEERR:%x ICEARERR:%x CTROVFERR:%x IACNTNOT:%x SEMFREE:%x\n",
		idc_err_status.val,
		idc_err_status.field.illegal_access,
		idc_err_status.field.ice_read_err,
		idc_err_status.field.ice_write_err,
		idc_err_status.field.asf_ice1_err,
		idc_err_status.field.asf_ice0_err,
		idc_err_status.field.cntr_err,
		idc_err_status.field.sem_err,
		idc_err_status.field.attn_err,
		idc_err_status.field.cntr_oflow_err,
		idc_err_status.field.ia_cntr_not,
		idc_err_status.field.ia_sem_free_not);

		if (cntr_overflow) {
			struct ice_network *ntw;

			for (i = 0; i < MAX_HW_COUNTER_NR; i++) {
				ntw = __get_ntw_of_overflowed_cntr(i, dev);
				if (ntw)
					ntw->icedc_err_status =
							idc_err_status.val;
			}
		}

		for (i = 0; i < NUM_ICE_UNIT; i++) {
			if (dev->cve_dev[i].state == CVE_DEVICE_IDLE)
				continue;

			cve_os_dev_log(CVE_LOGLEVEL_ERROR,
				i,
				"Received error interrupt from IceDC\n");

			cve_dev = &dev->cve_dev[i];
			/* notify the dispatcher */
			ice_ds_handle_ntw_error(&dev->cve_dev[i],
				idc_err_status.val, cntr_overflow);
		}

	}

	status_lo = (ice_status & 0xFFFF);
	status_hi = ((ice_status >> 32) & 0xFFFF);

	status_hl = status_lo | status_hi;
	cve_os_log(CVE_LOGLEVEL_INFO,
			"Status_hl=0x%x status_lo:0x%x status_hi:0x%x ice_status:0x%llx\n",
			status_hl, status_lo, status_hi, ice_status);

	if (!status_hl)
		goto end;

	while (1) {
		index = identify_ice_and_clear(&status_hl);
		if (index < 0) {
			cve_os_log(CVE_LOGLEVEL_INFO,
					"Exit status_hl:0x%x Index:%d\n",
					status_hl, index);
			break;
		}

		cve_dev = &dev->cve_dev[index];

		status = cve_dev->interrupts_status;
		cve_os_dev_log(CVE_LOGLEVEL_INFO,
			index,
			"Received interrupt[BH] from IDC. Status=0x%x\n",
			status);

		/* we might enter here with status 0
		 * this is a valid situation.
		 */
		if (!status)
			continue;

		if (cve_dev->state == CVE_DEVICE_IDLE) {
			cve_os_dev_log(CVE_LOGLEVEL_ERROR,
				cve_dev->dev_index,
				"device IDLE interrupt out of context status= 0x%08x",
				 status);
			cve_di_set_device_reset_flag(cve_dev,
				CVE_DI_RESET_DUE_CVE_ERROR);
			continue;
		}

		fifo = &cve_dev->fifo_desc->fifo;

		cb_descriptor = &fifo->cb_desc_vaddr[0];
		job = get_desc_subjob(cb_descriptor)->parent;

		/* Get the first CBD that was executed by this Job */
		cb_descriptor = &fifo->cb_desc_vaddr[job->first_cb_desc];
		sub_job = get_desc_subjob(cb_descriptor);

		cve_executed_cbs_time_log(cve_dev, job, &exec_time);

		if (is_tlc_bp_interrupt(status)) {
			cve_os_dev_log(CVE_LOGLEVEL_ERROR,
				cve_dev->dev_index,
				"TLC BP interrupt received status= 0x%08x\n",
				 status);
			ice_debug_create_event_node(cve_dev, job->ds_hjob);
			goto end;
		}

		/* check ECB error only if one sub job was subbmitted */
		if (sub_job->embedded_sub_job) {
			if (is_embedded_cb_error(cve_dev)) {
				cve_os_log(CVE_LOGLEVEL_ERROR,
			"Interrupt Status = 0x%08x Embedded CB Error = %d\n",
			status, is_embedded_cb_error(cve_dev));
				job_status = CVE_JOBSTATUS_ABORTED;
				cve_di_set_device_reset_flag(cve_dev,
					CVE_DI_RESET_DUE_CVE_ERROR);
				goto handle_interrupt_check_completion;
			}
		}

		/* If dsram error detected store error count in SW counter */
		/* TODO: card level reset for fatal errors */
		if (is_dsram_error(status)) {
			store_ecc_err_count(cve_dev);
			ice_ds_handle_ice_error(cve_dev, status);
		}


		if (is_ice_dump_completed(status) &&
			cve_dev->debug_control_buf.is_dump_now) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
				"ICE_DUMP_NOW completed ICE ID:%d, status:0x%08x\n",
				cve_dev->dev_index, status);
			status = unset_ice_dump_status(status);
			cve_dev->debug_control_buf.is_allowed_tlc_dump = 0;
			cve_dev->debug_control_buf.is_cve_dump_on_error = 1;
			cve_os_wakeup(&cve_dev->debug_control_buf.dump_wqs_que);
			if (!status)
				continue;
		}

		/*If error detected and recovery enabled*/
		if (is_cve_error(status)) {
			job_status = CVE_JOBSTATUS_ABORTED;
			cve_di_set_device_reset_flag(cve_dev,
				CVE_DI_RESET_DUE_CVE_ERROR);
			cve_os_dev_log(CVE_LOGLEVEL_ERROR,
					cve_dev->dev_index,
					"It seems that some errors occurred or ICE_DUMP_COMPLETED because of some TLC error\n");
			cve_os_log(CVE_LOGLEVEL_ERROR,
					"Interrupt Status = 0x%08x, TLC ERROR = %d, MMU Error = %d\n CB Completed = %d, Queue Empty = %d, Page Fault Error = %d\n Bus Error = %d WD Error =%d , BTRS Error = %d, TLC Panic = %d, ICE_DUMP_COMPLETED = %d\n",
					status,
					is_tlc_error(status),
					is_mmu_error(status),
					is_cb_complete(status),
					is_que_empty(status),
					is_page_fault_error(status),
					is_bus_error(status),
					is_wd_error(status),
					is_butress_error(status),
					is_tlc_panic(status),
					is_ice_dump_completed(status));
			cve_print_mmio_regs(cve_dev);
			ice_ds_handle_ice_error(&dev->cve_dev[index], status);
			/* Signal dump was created */
			if (is_ice_dump_completed(status)) {
				/* Don't allow TLC to further
				 * write to cve dump buffer
				 */
				cve_dev->cve_dump_buf.is_allowed_tlc_dump = 0;
			}

		} else {
			if (ice_ds_is_network_active(cve_dev->dev_network_id)
					== 0) {
				job_status = CVE_JOBSTATUS_ABORTED;
				cve_os_log(CVE_LOGLEVEL_INFO,
						"NtwID:0x%llx is not active\n",
						cve_dev->dev_network_id);
			} else {
				/* if job is entirely completed */
				cve_os_log(CVE_LOGLEVEL_DEBUG,
						"job completed\n");
				job_status = CVE_JOBSTATUS_COMPLETED;
			}


		}

handle_interrupt_check_completion:

		cve_os_dev_log(CVE_LOGLEVEL_DEBUG,
				cve_dev->dev_index,
				"NtwID:0x%llx Block MMU transactions in Bottom Half\n",
				cve_dev->dev_network_id);
		project_hook_interrupt_dpc_handler_entry(cve_dev);
		mmu_transactions_wait_and_block(cve_dev);
		project_hook_interrupt_dpc_handler_exit(cve_dev, status);

		/* notify the dispatcher */
		cve_ds_handle_job_completion(cve_dev,
				job->ds_hjob,
				job_status,
				exec_time);
	}

end:
#ifdef RING3_VALIDATION
	cve_os_log(CVE_LOGLEVEL_DEBUG, "Execute ICEs\n");
	coral_trigger_simulation();
#endif

	cve_os_unlock(&g_cve_driver_biglock);
}

void cve_di_dispatch_job(struct cve_device *cve_dev,
		cve_di_job_handle_t hjob,
		cve_di_subjob_handle_t *e_cbs)
{
	struct di_job *job = (struct di_job *)hjob;

	ASSERT(job->sub_jobs);

	if (e_cbs != NULL) {
		/* Add the context switch embedded command buffer
		 * to the list of subjobs. SCB, if any, will always
		 * be executed in this case.
		 * Can only be executed during Cold run.
		 */
		ASSERT(job->cold_run);

		add_embedded_cb_to_job(job,
				e_cbs[GET_CB_INDEX(CVE_FW_CB1_TYPE)]);

		cve_os_dev_log(CVE_LOGLEVEL_DEBUG,
				cve_dev->dev_index,
				"Embedded CB was added to job = 0x%p\n",
				job);
		job->next_subjob = 0;
		job->remaining_subjobs_nr = job->subjobs_nr + 1;
	} else {
		/* Can only be executed during Warm run */
		ASSERT(!job->cold_run);

		if (job->has_scb) {
			job->next_subjob = 2;
			job->remaining_subjobs_nr = job->subjobs_nr - 1;

			if (!job->remaining_subjobs_nr)
				return;
		} else {
			job->next_subjob = 1;
			job->remaining_subjobs_nr = job->subjobs_nr;
		}
	}

	job->dispatch_time_stamp = cve_os_get_time_stamp();

	dispatch_next_subjobs(job, cve_dev);
}

void cve_di_set_page_directory_base_addr(struct cve_device *cve_dev,
		u32 base_addr)
{
	union CVG_MMU_1_SYSTEM_MAP_MEM_PAGE_TABLE_BASE_ADDRESS_t reg;

	reg.val = 0;
	reg.field.MMU_PAGE_TABLE_BASE_ADDRESS = base_addr;
	cve_os_dev_log(CVE_LOGLEVEL_DEBUG,
		cve_dev->dev_index,
		"PD base addr = 0x%x\n",
		base_addr);
	write_to_page_table_base_address(cve_dev, reg);
}

void cve_di_invalidate_page_table_base_address(struct cve_device *cve_dev)
{
	union CVG_MMU_1_SYSTEM_MAP_MEM_PAGE_TABLE_BASE_ADDRESS_t reg;

	reg.val = 0;
	write_to_page_table_base_address(cve_dev, reg);
}

int cve_di_handle_submit_job(
	struct cve_user_buffer *buf_list,
	cve_ds_job_handle_t ds_hjob,
	u32 command_buffers_nr,
	struct cve_command_buffer_descriptor *kcb_descriptor,
	cve_di_job_handle_t *out_hjob)
{
	int retval = 0;
	struct di_job *job = NULL;
	u32 sub_job_idx;
	u32 cb_idx;
	u64 address;
	ice_va_t cve_vaddr;
	u32 offset;
	struct cve_user_buffer *buffer;

	/* create a new job object */
	retval = OS_ALLOC_ZERO(sizeof(*job), (void **)&job);
	if (retval != 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"os_malloc_zero failed %d\n", retval);
		goto out;
	}

	/* one per CB plus one more for embedded CB*/
	job->allocated_subjobs_nr = command_buffers_nr + 1;
	job->subjobs_nr = command_buffers_nr;
	job->has_scb = 0;

	/* allocate "sub_jobs": one per CB plus one more for embedded CB*/
	retval = OS_ALLOC_ZERO(sizeof(struct sub_job)*job->allocated_subjobs_nr,
			(void **)&job->sub_jobs);
	if (retval < 0) {
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"os_malloc_zero failed %d\n", retval);
		goto err_subjobs;
	}

	for (sub_job_idx = 1, cb_idx = 0;
			sub_job_idx < job->allocated_subjobs_nr;
			sub_job_idx++, cb_idx++) {

		buffer = cve_dle_lookup(
				buf_list,
				list,
				buffer_id,
				kcb_descriptor[cb_idx].bufferid);
		if (!buffer) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
				"Cannot find surface ID %llu!\n",
				kcb_descriptor[cb_idx].bufferid);
			retval = -ICEDRV_KERROR_CB_INVAL_BUFFER_ID;
			goto err;
		}

		retval = cve_mm_get_buffer_addresses(buffer->allocation,
				&cve_vaddr, &offset, &address);

		if (retval < 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
					"Buf:%p alloc_info:%p failed(%d) to get va\n",
					buffer, buffer->allocation, retval);
			goto err;
		}

		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"CBD_Idx=%d, SubJobIdx=%d, CB_BufferID=0x%llx, ICEVA:0x%llx, IAVA=0x%lx, Offset:%u\n",
			cb_idx, sub_job_idx, kcb_descriptor[cb_idx].bufferid,
			cve_vaddr, (uintptr_t)address, offset);

		if ((cb_idx == 0) &&
		 (buffer->surface_type == ICE_BUFFER_TYPE_DEEP_SRAM_CB)) {

			job->has_scb = 1;
		}

		job->sub_jobs[sub_job_idx].cb.address =
			((u32)cve_vaddr) + offset;
		job->sub_jobs[sub_job_idx].cb.command_buffer = address;
		job->sub_jobs[sub_job_idx].cb.commands_nr =
				kcb_descriptor[cb_idx].commands_nr;
		job->sub_jobs[sub_job_idx].embedded_sub_job = 0;

		job->sub_jobs[sub_job_idx].cb.is_reloadable =
			kcb_descriptor[cb_idx].is_reloadable;

		/*
		 * save pointer to buffer's allocation struct inside
		 * the cb struct for future use
		 */
		job->sub_jobs[sub_job_idx].cb.allocation = buffer->allocation;

		/* update the sub-job and the context */
		job->sub_jobs[sub_job_idx].parent = job;

	}

	/* success */
	job->cold_run = 1;
	job->ds_hjob = ds_hjob;
	*out_hjob = job;

	return 0;
err:
	OS_FREE(job->sub_jobs, sizeof(struct sub_job)*
		job->allocated_subjobs_nr);
err_subjobs:
	OS_FREE(job, sizeof(*job));
out:
	return retval;
}

void cve_di_set_device_reset_flag(struct cve_device *cve_dev, u32 value)
{
	cve_dev->di_cve_needs_reset |= value;
}

u32 cve_di_get_device_reset_flag(struct cve_device *cve_dev)
{
	return cve_dev->di_cve_needs_reset;
}

void cve_di_get_debugfs_regs_list(const struct debugfs_reg32 **regs,
		u32 *num_of_regs)
{
	*regs = registers;
	*num_of_regs = ARRAY_SIZE(registers);
}

void cve_di_set_hw_counters(struct cve_device *cve_dev)
{
	union ICE_MMU_INNER_MEM_MMU_CONFIG_t reg;
	u32 offset_bytes = ICE_MMU_BASE + ICE_MMU_MMU_CONFIG_MMOFFSET;

	/* validate that we are 32bit aligned */
	ASSERT(((offset_bytes >> 2) << 2) == offset_bytes);

	/* read current register value */
	reg.val = cve_os_read_mmio_32(cve_dev, offset_bytes);

	/* Enable/Disable HW counters */
	reg.field.ACTIVATE_PERFORMANCE_COUNTERS =
			cve_dev->is_hw_counters_enabled;

	cve_os_write_mmio_32(cve_dev, offset_bytes, reg.val);
}

void ice_di_reset_cbdt_cb_addr(struct cve_device *dev)
{
	union cve_shared_cb_descriptor *cb_descriptor = NULL;
	u32 i;

	for (i = 0; i < dev->fifo_desc->fifo.entries; i++) {
		cb_descriptor = &dev->fifo_desc->fifo.cb_desc_vaddr[i];
		cb_descriptor->address = 0;
	}
}


int ice_di_is_network_under_execution(u64 ntw_id, struct cve_device_group *dg)
{
	struct cve_device *dev, *dev_head;
	u32 count = 0, i;

	for (i = 0; i < MAX_NUM_ICEBO; i++) {
		dev_head = dg->dev_info.icebo_list[i].dev_list;
		dev = dev_head;
		if (!dev)
			continue;
		do {
			if (dev->dev_network_id == ntw_id &&
				dev->state == CVE_DEVICE_BUSY) {
				count++;

				ice_di_reset_cbdt_cb_addr(dev);
			}
			dev = cve_dle_next(dev, bo_list);
		} while (dev != dev_head);
	}

	return count;
}

u32 ice_di_get_icemask(struct idc_device *dev)
{

	/* Right shift by 4 because last 4 bits are reserved*/
	return ((cve_os_read_icemask(dev) >> 4) & VALID_ICE_MASK);
}

void ice_di_get_job_handle(struct cve_device *dev,
		cve_ds_job_handle_t *ds_job_handle)
{
	struct di_job *job;
	union cve_shared_cb_descriptor *cb_descriptor;

	cb_descriptor = &dev->fifo_desc->fifo.cb_desc_vaddr[0];
	job = get_desc_subjob(cb_descriptor)->parent;
	*ds_job_handle = job->ds_hjob;
}

void ice_di_activate_driver(void)
{
	is_driver_active = 1;
}

void ice_di_deactivate_driver(void)
{
	is_driver_active = 0;
}

void ice_di_set_mmu_address_mode(struct cve_device *ice)
{
	union ICE_MMU_INNER_MEM_MMU_CONFIG_t reg;
	u32 offset_bytes = ICE_MMU_BASE + ICE_MMU_MMU_CONFIG_MMOFFSET;

	/* read current register value */
	reg.val = cve_os_read_mmio_32(ice, offset_bytes);
	if (ICE_DEFAULT_VA_WIDTH == ICE_VA_WIDTH_EXTENDED)
		reg.field.ATU_WITH_LARGER_LINEAR_ADDRESS = 0xf;
	else
		reg.field.ATU_WITH_LARGER_LINEAR_ADDRESS = 0x0;

	cve_os_write_mmio_32(ice, offset_bytes, reg.val);
}

u8 ice_di_is_cold_run(cve_di_job_handle_t hjob)
{
	struct di_job *job = (struct di_job *)hjob;

	return job->cold_run;
}

