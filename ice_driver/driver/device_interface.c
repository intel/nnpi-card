/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/



#ifdef RING3_VALIDATION
#include <stdint.h>
#include <string.h>
#include "coral.h"
#include <linux_kernel_mock.h>
#endif

#include "device_interface.h"
#include "os_interface.h"
#include "doubly_linked_list.h"
#include "cve_driver_internal.h"
#include "device_interface_internal.h"
#include "project_settings.h"
#include "cve_driver_utils.h"
#include "cve_firmware.h"
#include "cve_driver_internal.h"
#include "ice_debug.h"
#include "sph_device_regs.h"
#include "dev_context.h"
#include "sph_ice_error_status.h"

#ifdef RING3_VALIDATION
#include "coral.h"
#include <icedrv_sw_trace_stub.h>
#else
#include "icedrv_sw_trace.h"
#include "linux/delay.h"
#endif

#include "ice_sw_counters.h"
#ifndef RING3_VALIDATION
#include "intel_sphpb.h"
#else
#include "dummy_intel_sphpb.h"
#endif



#define CNC_CONTROL_MSG_TIMEOUT 200
#define ICCP_THROTTLING_OPCODE 0x3
#define ICCP_NO_THROTTLING_OPCODE 0x4

#define PART_SUBMISSION_STEP (CVE_FIFO_ENTRIES_NR/2)

/* We expect 5 because the same value has been programmed in ECB */
#define ECB_SUCCESS_STATUS 5

#define __dump_wait_mode_reg(ice, msg)				\
{								\
	union mmio_hub_mem_p_wait_mode_t __reg;			\
								\
	__reg.val = cve_os_read_mmio_32(cve_dev,		\
			cfg_default.mmio_hub_p_wait_mode_offset);\
	cve_os_dev_log_default(CVE_LOGLEVEL_WARNING,		\
			ice->dev_index,				\
			"%s TLC:%d IVP:%d ASIP:%d DSE:%d"	\
			"MMU:%d MMIO:%d Delphi%d\n",		\
			msg, __reg.field.TLC_P_WAIT_MODE,	\
			__reg.field.IVP_P_WAIT_MODE,		\
			__reg.field.ASIP_P_WAIT_MODE,		\
			__reg.field.DSE_GCLK_DISABLE,		\
			__reg.field.MMU_DONE,			\
			__reg.field.ALL_CORES_DONE,		\
			__reg.field.DELPHI_DONE);		\
}



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
	/* ddr BW in mbps*/
	__u32 ddr_bw;
	/* Ring to ICE clock frequency ratio*/
	__u16 ring_to_ice_ratio;
	/* ICE to ICE clock frequency ratio*/
	__u8 ice_to_ice_ratio;
	/* cdyn budget value required for the job */
	__u16 cdyn_val;
};

/* MODULE LEVEL VARIABLES */
/* hold offsets to ATU's MMIO registers */
#define MAX_ATU_COUNT 4
/* ATU to CBB mapping */
#define DELPHI_ATU_MAPPING 0
#define DSE_ATU_MAPPING 1
#define IVP_ATU_MAPPING 2
#define TLC_ATU_MAPPING 3
#define MAX_DEBUGFS_REG_NR 14

#ifdef _DEBUG
static void __dump_mmu_pmon(struct cve_device *ice);
static void __dump_delphi_pmon(struct cve_device *ice);
#endif

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

static uint64_t __icedc_err_intr_enable_all(void)
{
	uint64_t icedc_error_intr_enable_all =
	((1UL << cfg_default.icedc_intr_bit_ilgacc) |
	(1UL << cfg_default.icedc_intr_bit_icererr) |
	(1UL << cfg_default.icedc_intr_bit_icewerr) |
	(1UL << cfg_default.icedc_intr_bit_asf_ice1_err) |
	(1UL << cfg_default.icedc_intr_bit_asf_ice0_err) |
	(1UL << cfg_default.icedc_intr_bit_icecnerr) |
	(1UL << cfg_default.icedc_intr_bit_iceseerr) |
	(1UL << cfg_default.icedc_intr_bit_icearerr) |
	(1UL << cfg_default.icedc_intr_bit_ctrovferr) |
	(15UL << cfg_default.icedc_intr_bit_iacntnot) |
	(15UL << cfg_default.icedc_intr_bit_semfree));

	return icedc_error_intr_enable_all;
}

/* return the pointer to the subjob of the given descriptor */
static inline struct sub_job *get_desc_subjob(
		union CVE_SHARED_CB_DESCRIPTOR *desc)
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
		union CVE_SHARED_CB_DESCRIPTOR *desc, struct sub_job *subjob)
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
int ice_di_mmu_block_entrance(struct cve_device *cve_dev)
{
	union ice_mmu_inner_mem_mmu_config_t reg;
	int new_block_performed = 0;
	u32 offset_bytes = cfg_default.mmu_base + cfg_default.mmu_cfg_offset;
	u32 wait_timeout = 0, attempt = 0;
	/* validate that we are 32bit aligned */
	ASSERT(((offset_bytes >> 2) << 2) == offset_bytes);

	/* read current register value */
	reg.val = cve_os_read_mmio_32(cve_dev, offset_bytes);
	cve_os_dev_log(CVE_LOGLEVEL_DEBUG,
			cve_dev->dev_index,
			"Pntw:0x%llx Ntw:0x%llx Read BLOCK_ENTRANCE bit in MMU Config Register. reg.val = 0x%08x\n",
				cve_dev->dev_pntw_id,
				cve_dev->dev_ntw_id,
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
			attempt++;

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

			if (reg.field.ACTIVE_TRANSACTIONS == 0)
				break;

			if (unlikely(time_after_in_msec(
					cve_os_get_msec_time_stamp(),
					wait_timeout))) {
				__dump_wait_mode_reg(cve_dev,
						"MMU Block Failed: ");

				cve_os_dev_log_default(CVE_LOGLEVEL_ERROR,
				cve_dev->dev_index,
				"Timeout due to continues MMU transaction\n");

				break;

			}
		} while (1);

		cve_os_dev_log(CVE_LOGLEVEL_DEBUG,
				cve_dev->dev_index,
				"Pntw:0x%llx Ntw:0x%llx Blocked MMU transactions\n",
				cve_dev->dev_pntw_id,
				cve_dev->dev_ntw_id);
		new_block_performed = 1;
	}
	return new_block_performed;
}

void ice_di_mmu_unblock_entrance(struct cve_device *cve_dev)
{
	union ice_mmu_inner_mem_mmu_config_t reg;
	u32 offset_bytes = cfg_default.mmu_base + cfg_default.mmu_cfg_offset;
	/* validate that we are 32bit aligned */
	ASSERT(((offset_bytes >> 2) << 2) == offset_bytes);

	/* read current register value */
	reg.val = cve_os_read_mmio_32(cve_dev, offset_bytes);
	/* allow CVE to send NEW memory transactions to MMU */
	reg.field.BLOCK_ENTRANCE = 0;
	reg.field.ATU_WITH_LARGER_LINEAR_ADDRESS = 0xf;
	cve_os_write_mmio_32(cve_dev, offset_bytes, reg.val);

	cve_os_dev_log(CVE_LOGLEVEL_DEBUG,
		cve_dev->dev_index,
		"Pntw:0x%llx Ntw:0x%llx Unblock MMU transactions reg.val = 0x%08x\n",
		cve_dev->dev_pntw_id,
		cve_dev->dev_ntw_id,
		reg.val);
}

static void print_kernel_buffer(
		void *buffer_addr,
		u32 size_bytes,
		const char *buf_name)
{
	struct cve_device_group __maybe_unused *dg = cve_dg_get();
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
	union tlc_mem_tlc_barrier_watch_config_reg_t reg;
	u32 offset_bytes = cfg_default.ice_tlc_base +
		cfg_default.ice_tlc_barrier_watch_cfg_offset;

	reg.field.enableWatch = 1;
	reg.field.watchMode = cfg_default.stop_all_barriers;
	reg.field.tlcMode = cfg_default.block_incoming_cnc_messages;
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
		union CVE_SHARED_CB_DESCRIPTOR *descp = NULL;
		union CVE_SHARED_CB_DESCRIPTOR desc;
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
		desc.status = cfg_default.cve_status_dispatched;
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
	u32 cbd_size = sizeof(union CVE_SHARED_CB_DESCRIPTOR);
	cve_virtual_address_t iceva;
	struct job_descriptor __maybe_unused *inf_job =
		(struct job_descriptor *)job->ds_hjob;
	struct ice_network *ntw = (struct ice_network *) dev->dev_ntw_id;
	struct ice_infer *inf = ntw->curr_exe;
	struct cve_device_group *dg = cve_dg_get();
	const struct sphpb_callbacks *sphpb_cbs;
	int ret;

	if (job->cold_run)
		__prepare_cbdt(job, dev);

	job->first_cb_desc = 0;
	iceva = dev->fifo_desc->fifo_alloc.ice_vaddr;
	db = job->last_cb_desc;
	if (job->cold_run) {
		if (!dg) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
				"null dg pointer (%d) !!\n", -EINVAL);
			sphpb_cbs = NULL;
		} else {
			sphpb_cbs = dg->sphpb.sphpb_cbs;
		}
		if (sphpb_cbs && sphpb_cbs->request_ice_dvfs_values &&
			(job->ring_to_ice_ratio || job->ice_to_ice_ratio
			 || job->ddr_bw)) {
			cve_os_dev_log(CVE_LOGLEVEL_DEBUG,
				dev->dev_index,
			"ddr_bw %d, ring2ice_ratio 0x%x, ice2ice_ratio 0x%x\n",
					job->ddr_bw, job->ring_to_ice_ratio,
					job->ice_to_ice_ratio);

			ret = sphpb_cbs->request_ice_dvfs_values(dev->dev_index,
					job->ddr_bw,
					job->ring_to_ice_ratio,
					job->ice_to_ice_ratio);
			if (ret) {
				cve_os_dev_log(CVE_LOGLEVEL_ERROR,
					dev->dev_index,
					"failed in setting dvfs values (%d)\n",
					ret);
			}
		}
		/* Cold Run */
		if (disable_embcb) {
			job->first_cb_desc = 1;

			cve_os_log(CVE_LOGLEVEL_INFO,
				"ICE%d: Cold Run (Skipping EmbCB)\n",
				dev->dev_index);
		} else {
			cve_os_log(CVE_LOGLEVEL_INFO,
				"ICE:%d: Cold Run (With EmbCB)\n",
				dev->dev_index);
		}

		if (!dev->is_cold_run) {
			job->first_cb_desc = 1;
			cve_os_dev_log(CVE_LOGLEVEL_DEBUG,
					dev->dev_index,
				"PntwId:0x%llx NtwId:0x%llx JobId:%u GraphId:%u DummyGraphId:%u Cold Job Warm Run Skip ECB\n",
				ntw->pntw->pntw_id,
				ntw->network_id,
				inf_job->id,
				inf_job->graph_ice_id,
				inf_job->dummy_ice_id);
		}

		job->cold_run = 0;

		/* call project hook right before ringing the doorbell */
		project_hook_dispatch_new_job(dev, ntw);

		if (dev->prev_reg_config.cbd_entries_nr !=
			cfg_default.mmio_cbd_entries_nr_offset) {
			/** Configure CBDT entry size only for cold run*/
			cve_os_write_mmio_32(dev,
				cfg_default.mmio_cbd_entries_nr_offset,
				dev->fifo_desc->fifo.entries);
			dev->prev_reg_config.cbd_entries_nr =
				cfg_default.mmio_cbd_entries_nr_offset;
		}
	} else {
		ASSERT(dev->is_cold_run == 0);
		if (job->has_scb) {
			/* Warm Run with SCB */
			job->first_cb_desc = 2;

			cve_os_dev_log(CVE_LOGLEVEL_DEBUG,
					dev->dev_index,
					"PntwId:0x%llx NtwId:0x%llx JobId:%u GraphId:%u DummyGraphId:%u Warm Run (Skipping SCB)\n",
					ntw->pntw->pntw_id, ntw->network_id,
					inf_job->id, inf_job->graph_ice_id,
					inf_job->dummy_ice_id);

		} else {
			/* Warm run without SCB */
			job->first_cb_desc = 1;

			cve_os_dev_log(CVE_LOGLEVEL_DEBUG,
					dev->dev_index,
					"PntwId:0x%llx NtwId:0x%llx JobId:%u GraphId:%u DummyGraphId:%u Warm Run\n",
					ntw->pntw->pntw_id, ntw->network_id,
					inf_job->id, inf_job->graph_ice_id,
					inf_job->dummy_ice_id);
		}
	}
	iceva += (job->first_cb_desc * cbd_size);
	db -= job->first_cb_desc;

	cve_os_log(CVE_LOGLEVEL_INFO,
			"PntwId:0x%llx NtwId:0x%llx JobId:%u GraphId:%u DummyGraphId:%u CBDBase:%x, CBDCount:%d Doorbell:%d\n",
			ntw->pntw->pntw_id, ntw->network_id, inf_job->id,
			inf_job->graph_ice_id, inf_job->dummy_ice_id,
			iceva, dev->fifo_desc->fifo.entries, db);

	/* If true => Unblock before each Doorbell */
	if (block_mmu)
		ice_di_mmu_unblock_entrance(dev);


	ice_swc_counter_add(dev->hswc,
		ICEDRV_SWC_DEVICE_COUNTER_COMMANDS,
		(db + 1));

	if (inf->hswc)
		ice_swc_counter_inc(inf->hswc,
			ICEDRV_SWC_INFER_COUNTER_REQUEST_SENT);

	/* To check if break point needs to be set */
	if (ntw->ntw_enable_bp)
		ice_di_enable_tlc_bp(dev);

	dev->cbd_base_va = iceva;
	dev->db_cbd_id = db;
}


void ice_di_tlb_invalidate_full(struct cve_device *cve_dev)
{
	u32 i;
	union cvg_mmu_1_system_map_mem_invalidate_t reg;

	reg.val = 0;
	reg.field.MMU_INVALIDATE = 0xffff; /* invalidate all streams */
	for (i = 0; i < MAX_ATU_COUNT; i++) {
		u32 offset_bytes = cfg_default.mmu_atu0_base +
		(i * (cfg_default.mmu_atu1_base - cfg_default.mmu_atu0_base)) +
		cfg_default.ice_mmu_1_system_map_mem_invalidate_offset;
		ASSERT(((offset_bytes >> 2) << 2) == offset_bytes);
		cve_os_write_mmio_32(cve_dev, offset_bytes, reg.val);
	}
}

/* write to page table base address MMIO register of all ATU's*/
static inline void write_to_page_table_base_address(
	struct cve_device *cve_dev,
	const union cvg_mmu_1_system_map_mem_page_table_base_address_t reg)
{
	u32 i;

	cve_os_dev_log(CVE_LOGLEVEL_DEBUG,
			cve_dev->dev_index,
			"write_to_page_table_base_address executed\n");

	for (i = 0; i < MAX_ATU_COUNT; i++) {
		u32 offset_bytes = cfg_default.mmu_atu0_base +
		(i * (cfg_default.mmu_atu1_base - cfg_default.mmu_atu0_base)) +
		cfg_default.ice_mmu_1_system_map_mem_pt_base_addr_offset;
		ASSERT(((offset_bytes >> 2) << 2) == offset_bytes);
		cve_os_write_mmio_32(cve_dev, offset_bytes, reg.val);
	}

	/* the TLB's in CVE use prefetching. it means that
	 * once the page table is configured, any change to its content
	 * requires a full TLB flush, even in cases a flush is not required
	 * in other agents (e.g. CPU), like adding a mapping.
	 */

	/* flush the TLB */
	ice_di_tlb_invalidate_full(cve_dev);

#ifdef _DEBUG
	cve_os_write_mmio_32(cve_dev,
	(cfg_default.ice_dbg_cbbid_base +
	cfg_default.ice_dbg_cbbid_cfg_offset + (1 * 4)), reg.val);
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
		cfg_default.bar0_mem_icepe_offset);

	if (!(value & mask))
		return;
#endif
	cve_os_write_mmio_32(cve_dev,
			cfg_default.mmio_intr_mask_offset,
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
	AXI_SHARED_READ_CFG_T cfg_reg;
	u32 offset;

	offset = ICEDC_ICEBO_OFFSET(bo_id) +
				cfg_default.axi_shared_read_cfg_offset;

	if (!enable_shared_read) {
		cfg_reg.field.shared_read_enable = 0;
		cve_os_write_idc_mmio(dev, offset, cfg_reg.val);
		return;
	}

	cfg_reg.field.shared_read_enable = 1;
	cfg_reg.field.max_shared_distance = ntw->pntw->max_shared_distance;
	cfg_reg.field.enable_timeout = 1;
	cfg_reg.field.timeout_threshold = SHARED_READ_TIMEOUT_THRESHOLD;

	cve_os_write_idc_mmio(dev, offset, cfg_reg.val);
}


#ifdef IDC_ENABLE
int set_idc_registers(struct ice_network *ntw, uint8_t lock)
{
	uint64_t value, val64, ice_pe_val;
	int ret = 0;
	struct hw_revision_t hw_rev;
	struct idc_device *idc;
	struct cve_device_group *dg = g_cve_dev_group_list;
	const struct sphpb_callbacks *sphpb_cbs;
	struct cve_device *dev;
	bool all_on = true;
	uint64_t mask = 0;
	u64 t;
	struct ice_pnetwork *pntw = ntw->pntw;

	if (lock) {
		ret = cve_os_lock(&dg->poweroff_dev_list_lock,
				CVE_INTERRUPTIBLE);
		if (ret != 0) {
			cve_os_log_default(CVE_LOGLEVEL_ERROR,
					"Error:%d PowerOff Lock not aquired\n",
					ret);
			return ret;
		}
	}

	dev = pntw->ice_list;
	do {
		if (dev->power_state == ICE_POWER_ON) {

			cve_os_log(CVE_LOGLEVEL_INFO,
				"ICE-%d is already Power enabled\n",
				dev->dev_index);

		} else if (dev->power_state == ICE_POWER_OFF_INITIATED) {

			/* Will enter here only during RR */
			cve_os_log(CVE_LOGLEVEL_INFO,
				"Removing ICE-%d from Power off list\n",
				dev->dev_index);

			ice_dev_set_power_state(dev, ICE_POWER_ON);
			ice_swc_counter_set(dev->hswc,
				ICEDRV_SWC_DEVICE_COUNTER_POWER_STATE,
				ICE_POWER_ON);

			cve_dle_remove_from_list(dg->poweroff_dev_list,
				poweroff_list, dev);

		} else {
			mask |= (1ULL << (dev->dev_index + 4));
			all_on = false;
		}

		dev = cve_dle_next(dev, owner_list);

	} while (dev != pntw->ice_list);

	if (all_on)
		goto out;

	idc = ice_to_idc(dev);

	/*PE 1 ICE without disturbing other  */
	value = cve_os_read_idc_mmio(dev,
		cfg_default.bar0_mem_icepe_offset);

	/*
	 * This if condition should be replaced with ASSERT.
	 * https://jira.devtools.intel.com/browse/ICE-23144
	 */

	/* Device is already ON */
	if ((value & mask) == mask) {
		cve_os_log(CVE_LOGLEVEL_INFO,
			"ICEs are already Power enabled. Mask=%llx\n",
			mask);

		do {
			ice_dev_set_power_state(dev, ICE_POWER_ON);
			ice_swc_counter_set(dev->hswc,
				ICEDRV_SWC_DEVICE_COUNTER_POWER_STATE,
				ICE_POWER_ON);

			dev = cve_dle_next(dev, owner_list);
		} while (dev != pntw->ice_list);

		goto out;
	}

	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"Power enabling ICEs. Mask=%llx\n", mask);

	value |= mask;

	cve_os_write_idc_mmio(dev,
		cfg_default.bar0_mem_icepe_offset, value);

	/* Check if ICEs are Ready */
	/* Driver is not yet sure how long to wait for ICERDY */
	__wait_for_ice_rdy(dev, value, mask,
					cfg_default.bar0_mem_icerdy_offset);
	if ((value & mask) != mask) {
		uint64_t val64 = (value & ~mask);

		/* Power Disable the faulty ICE */
		cve_os_write_idc_mmio(dev,
				cfg_default.bar0_mem_icepe_offset,
				val64);

		do {
			ice_dev_set_power_state(dev, ICE_POWER_OFF);
			ice_swc_counter_set(dev->hswc,
				ICEDRV_SWC_DEVICE_COUNTER_POWER_STATE,
				ICE_POWER_OFF);

			dev = cve_dle_next(dev, owner_list);
		} while (dev != pntw->ice_list);

		cve_os_log_default(CVE_LOGLEVEL_ERROR,
			"Initialization of ICEs failed. Expected=%llx, Received=%llx\n",
			mask, value);

		ret = -ICEDRV_KERROR_ICE_DOWN;
		goto out;
	}

	ice_pe_val = value;
	sphpb_cbs = dg->sphpb.sphpb_cbs;
	t = trace_clock_global();

	do {
		if (mask & (1ULL << (dev->dev_index + 4))) {
			ice_dev_set_power_state(dev, ICE_POWER_ON);
			ice_swc_counter_set(dev->hswc,
					ICEDRV_SWC_DEVICE_COUNTER_POWER_STATE,
					ICE_POWER_ON);

			dev->idle_start_time = t;
			ice_swc_counter_set(dev->hswc,
				ICEDRV_SWC_DEVICE_COUNTER_IDLE_START_TIME,
				nsec_to_usec(dev->idle_start_time));

			if (sphpb_cbs && sphpb_cbs->set_power_state) {
				ret = sphpb_cbs->set_power_state(dev->dev_index,
						true);
				if (ret) {
					cve_os_dev_log(CVE_LOGLEVEL_ERROR,
							dev->dev_index,
							"failed in setting power state as ON with power balancer (%d)\n",
							ret);
				}
				ret = 0;
			}

			cve_di_set_device_reset_flag(dev,
					CVE_DI_RESET_DUE_POWER_ON);
		}

		dev = cve_dle_next(dev, owner_list);
	} while (dev != pntw->ice_list);

	/* based on the Power Enabled ICE mask, prepare an equivalent ICE
	 * normal/error interrupt mask. This avoid reading those MMIOs
	 */
	val64 = (((ice_pe_val) << 32) | (ice_pe_val));
	idc_mmio_write64(dev, cfg_default.bar0_mem_iceinten_offset, val64);

	value = atomic64_read(&idc->idc_err_intr_enable);
	if (value != __icedc_err_intr_enable_all()) {
		value = __icedc_err_intr_enable_all();
		atomic64_set(&idc->idc_err_intr_enable, value);

		/* Enable IDC interrupt */
		idc_mmio_write64(dev, cfg_default.bar0_mem_idcinten_offset,
				value);
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
	uint64_t value, mask, val64, ice_pe_val;
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
			cve_os_log_default(CVE_LOGLEVEL_ERROR,
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
			"Power disabling ICE-%d. Mask=0x%x\n", i, icemask);
	}

	/* Power Off all ICEs */
	value = cve_os_read_idc_mmio(dev,
		cfg_default.bar0_mem_icepe_offset);
	value &= ~mask;
	if (!value)
		all_powered_off = 1;

	/* Acces PE regsiter only on real SOC */
	if (ice_is_soc())
		cve_os_write_idc_mmio(dev,
				cfg_default.bar0_mem_icepe_offset,
				value);

	/* based on the Power Enabled ICE mask, prepare an equivalent ICE
	 * normal/error interrupt mask. This avoid reading those MMIOs
	 */
	ice_pe_val = value;
	val64 = (((ice_pe_val) << 32) | (ice_pe_val));
	idc_mmio_write64(dev, cfg_default.bar0_mem_iceinten_offset, val64);

	/* ICENOTE is automatically cleared with 0 write to PE */
	if (all_powered_off) {
		mask = atomic64_xchg(&idc->idc_err_intr_enable, 0);
		/* Disable lower 32 bits of IDC interrupt */

		value = idc_mmio_read64(dev,
				cfg_default.bar0_mem_idcinten_offset);
		val64 = (value & (~mask));
		idc_mmio_write64(dev,
				cfg_default.bar0_mem_idcinten_offset, val64);
	}

	if (lock)
		cve_os_unlock(&dg->poweroff_dev_list_lock);

	return 0;
}

void cve_di_reset_device(struct ice_network *ntw)
{
	uint8_t idc_reset;
	uint32_t needs_reset;
	struct cve_device *cve_dev;
	uint64_t value, mask = 0;
	int retval = 0;
	struct cve_device_group *dg = g_cve_dev_group_list;
	struct ice_pnetwork *pntw = ntw->pntw;

	cve_dev = pntw->ice_list;
	do {
		/* Do not perform IDC reset for this ICE if
		 * it was just powered on
		 */
		needs_reset = (cve_dev->di_cve_needs_reset &
				~(CVE_DI_RESET_DUE_POWER_ON |
				CVE_DI_RESET_DUE_PNTW_SWITCH));
		idc_reset = (needs_reset) ? 1 : 0;

		if (idc_reset)
			mask |= (1ULL << (cve_dev->dev_index + 4));

		cve_dev = cve_dle_next(cve_dev, owner_list);
	} while (cve_dev != pntw->ice_list);

	value = mask;

	if (mask) {
		cve_os_log(CVE_LOGLEVEL_DEBUG, "Performing IDC Reset\n");

		retval = cve_os_lock(&dg->poweroff_dev_list_lock,
				CVE_INTERRUPTIBLE);
		if (retval != 0) {
			cve_os_log_default(CVE_LOGLEVEL_ERROR,
					"Error:%d PowerOff Lock not acquired\n",
					retval);
			return;
		}

		cve_os_write_idc_mmio(cve_dev,
			cfg_default.bar0_mem_icerst_offset, value);

		/* Check if ICEs are Ready */
		/* Driver is not yet sure how long to wait for ICERDY */
		__wait_for_ice_rdy(cve_dev, value, mask,
					cfg_default.bar0_mem_icerdy_offset);
		if ((value & mask) != mask) {
			cve_os_log_default(CVE_LOGLEVEL_ERROR,
				"Resetting of ICEs failed. Expected=%llx, Received=%llx\n",
				mask, value);
			goto unlock;
		}

		cve_os_unlock(&dg->poweroff_dev_list_lock);
	}

	cve_dev = pntw->ice_list;
	do {
		if (!cve_di_get_device_reset_flag(cve_dev)) {
			cve_dev = cve_dle_next(cve_dev, owner_list);
			continue;
		}

		needs_reset = (cve_dev->di_cve_needs_reset &
				~(CVE_DI_RESET_DUE_POWER_ON |
				CVE_DI_RESET_DUE_PNTW_SWITCH));
		idc_reset = (needs_reset) ? 1 : 0;

		do_reset_device(cve_dev, idc_reset);

		cve_os_dev_log(CVE_LOGLEVEL_DEBUG,
				cve_dev->dev_index,
				"Perform Reset(%d) (needs_reset:0x%x) Reason=0x%08x, PNTW=%d Ntw=%d, Job=%d, Timeout=%d, Power=%d Context=%d\n",
				idc_reset, needs_reset,
				cve_dev->di_cve_needs_reset,
				((cve_dev->di_cve_needs_reset &
				  CVE_DI_RESET_DUE_PNTW_SWITCH) != 0),
				((cve_dev->di_cve_needs_reset &
				  CVE_DI_RESET_DUE_NTW_SWITCH) != 0),
				((cve_dev->di_cve_needs_reset &
					CVE_DI_RESET_DUE_JOB_NOT_COMP) != 0),
				((cve_dev->di_cve_needs_reset &
					CVE_DI_RESET_DUE_TIME_OUT) != 0),
				((cve_dev->di_cve_needs_reset &
					CVE_DI_RESET_DUE_POWER_ON) != 0),
				((cve_dev->di_cve_needs_reset &
					CVE_DI_RESET_DUE_CTX_SWITCH) != 0));

		if (cve_dev->di_cve_needs_reset & ~CVE_DI_RESET_DUE_PNTW_SWITCH)
			ice_reset_prev_reg_config(&cve_dev->prev_reg_config);

		cve_dev = cve_dle_next(cve_dev, owner_list);
	} while (cve_dev != pntw->ice_list);

	return;

unlock:
	cve_os_unlock(&dg->poweroff_dev_list_lock);
}

static inline void di_enable_interrupts(struct cve_device *cve_dev)
{
#define __MASK_TLC_PARITY_ERR 0x4

	union mmio_hub_mem_interrupt_mask_t mask;

	mask.val = 0;
	mask.field.TLC_FIFO_EMPTY = 1;

	/*Disable Single ECC error as its recoverable. In BH, sw counters
	 * can be updated based on Single ECC status in interrupt status.
	 */
	/*
	 * Disabling these three errors because during execution these errors
	 * are generated multiple times. For these errors our approach is to get
	 * either Completion or WD event. Post this we will check following
	 * fields and take action accordingly.
	 */
	mask.field.DSRAM_SINGLE_ERR_INTERRUPT = 1;
	mask.field.DSRAM_DOUBLE_ERR_INTERRUPT = 1;
	mask.field.SRAM_PARITY_ERR_INTERRUPT = 1;

	/*TODO HACK:
	 * For parity errors, mask TLC parity error interrupt as
	 * a WA for ICE-19832. Intrrupt status will still show the parity error
	 */
	cve_os_write_mmio_32(cve_dev,
			cfg_default.mmio_parity_high_err_mask,
			__MASK_TLC_PARITY_ERR);

	/* Enable interrupts */
	cve_os_write_mmio_32(cve_dev, cfg_default.mmio_intr_mask_offset,
			mask.val);
}
static inline void enable_dsp_clock_gating(struct cve_device *cve_dev)
{
	if (!ice_get_a_step_enable_flag()) {
		union mmio_hub_mem_cve_dpcg_control_reg_t reg;

		reg.val = 0;
		/*Need to set DPCG_CTRL_SW_DISABLE bit to 0
		 *to enable clk gating from sw
		 */
		reg.field.DPCG_CTRL_SW_DISABLE = 0;
		/*DPCG_CTRL_MSB_COUNTER_BITS are 2 MSBits
		 *of 5 bits counters , LSB are 3'b111
		 *This controls the extra time given before CG
		 */
		reg.field.DPCG_CTRL_MSB_COUNTER_BITS = 0x3;

		cve_os_write_mmio_32(cve_dev,
				cfg_default.mmio_dpcg_control, reg.val);
	}
}

static int get_ice_dump(struct cve_device *dev)
{
	uint32_t status_32 = 0;
	int ret = 0;
	uint32_t count = 100;

	if (dev->cve_dump_buf &&
		dev->cve_dump_buf->is_allowed_tlc_dump) {

		cve_di_mask_interrupts(dev);
		cve_di_reset_cve_dump(dev, cfg_default.ice_dump_now,
					dev->cve_dump_buf);

		while (count) {
			usleep_range(1000, 1100);
			status_32 = cve_os_read_mmio_32(dev,
				cfg_default.mmio_intr_status_offset);

			if (is_ice_dump_completed(status_32)) {
				dev->cve_dump_buf->is_allowed_tlc_dump = 0;
				ret = 1;
				break;
			}
			count--;
		}
		di_enable_interrupts(dev);
	}
	return ret;
}

void cve_di_start_running(struct cve_device *cve_dev)
{
	/* Enable the IDLE clock gating logic */
	/* TODO: 2000 is a temporary initial value for CVE bring-up
	 * (should be between 100 to 200)
	 */

	cve_os_write_mmio_32(cve_dev,
			cfg_default.mmio_pre_idle_delay_cnt_offset,
			2000);
	cve_os_write_mmio_32(cve_dev, cfg_default.mmio_cve_config_offset,
		cfg_default.mmio_cfg_idle_enable_mask);

	/*Enable dsp clock gating */
	if (!disable_clk_gating)
		enable_dsp_clock_gating(cve_dev);

	/* enable ICE interrupts including errors */
	di_enable_interrupts(cve_dev);

	/* Release all stalled cores */
	cve_os_write_mmio_32(cve_dev,
		cfg_default.ice_prog_cores_ctrl_offset, core_mask);

#ifdef _DEBUG
	cve_os_write_mmio_32(cve_dev,
	(cfg_default.ice_dbg_cbbid_base +
	cfg_default.ice_dbg_cbbid_cfg_offset + (1 * 4)), 0xabababab);
	cve_os_write_mmio_32(cve_dev,
	(cfg_default.ice_dbg_cbbid_base + cfg_default.ice_dbg_cbbid_cfg_offset +
	(1 * 4)), get_process_pid());
#endif
}

int cve_di_create_subjob(cve_virtual_address_t  cb_address,
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
				cfg_default.bar0_mem_evctice0_offset;

	ASSERT(dev != NULL);
	if (cntr_id >= MAX_HW_COUNTER_NR) {
		cve_os_log_default(CVE_LOGLEVEL_ERROR,
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

	reg = cfg_default.bar0_mem_icepool0_offset + (pool_number * 8);
	device_index_bit = (1<<(4+dev_index)) & 0xffff;

	/* Unregister this ICE from any Pool that it is registered with */
	for (i = 0; i < NUM_POOL_REG; i++) {
		u32 reg_offset = cfg_default.bar0_mem_icepool0_offset + (i * 8);
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
	u32 reg = cfg_default.bar0_mem_icepool0_offset;
	struct cve_os_device *os_dev = to_cve_os_device(get_first_device());

	reg = cfg_default.bar0_mem_icepool0_offset + (pool_number * 8);

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
	u32 reg = cfg_default.bar0_mem_evctprot0_offset + (ctr_nr * 32);
	idc_regs_evctprot0_t evct_prot_reg;
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
		cfg_default.bar0_mem_icenota0_offset,
		cfg_default.cbbid_tlc_offset +
		cfg_default.ice_tlc_hi_mailbox_doorbell_offset);
}

void cve_reset_hw_sync_regs(struct idc_device *idc_dev,
					u32 ctr_nr)
{
	u32 reg = cfg_default.bar0_mem_evctprot0_offset + (ctr_nr * 32);
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

	reg_val = cve_os_read_mmio_32(cve_dev,
			(cfg_default.mmio_gp_regs_offset +
			 ICE_MMIO_GP_RESET_REG_ADDR_OFFSET));

	return ((reg_val == ECB_SUCCESS_STATUS) ? 0 : 1);
}

static void __calc_cb_executon_time(struct cve_device *dev,
	struct di_job *job, u64 *exec_time, u32 ice_err)
{
	u32 i;
	u32 first_cb_start_time, last_cb_end_time;
	union CVE_SHARED_CB_DESCRIPTOR *cb_descriptor = NULL;

	*exec_time = 0;
	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"idle_start_time(usec)=%llu\n",
		nsec_to_usec(dev->idle_start_time));
	cb_descriptor =
		&dev->fifo_desc->fifo.cb_desc_vaddr[job->first_cb_desc];
	first_cb_start_time = cb_descriptor->start_time;
	cb_descriptor =
		&dev->fifo_desc->fifo.cb_desc_vaddr[job->last_cb_desc];
	last_cb_end_time = cb_descriptor->completion_time;
	for (i = job->first_cb_desc; i <= job->last_cb_desc; i++) {

		cb_descriptor = &dev->fifo_desc->fifo.cb_desc_vaddr[i];

		cve_os_dev_log(CVE_LOGLEVEL_DEBUG, dev->dev_index,
			"CBD_ID[%d]=0x%lx, StartTime=%u, EndTime=%u\n",
			i, (uintptr_t)cb_descriptor,
			cb_descriptor->start_time,
			cb_descriptor->completion_time);

		if (unlikely(ice_err)) {
			cve_os_log_default(CVE_LOGLEVEL_ERROR,
					"ICE:%d CBD_ID[%d] Start:%u End:%u Status:0x%x cbdId:%d tlcStartCmdWinIp:%u tlcEndCmdWinIp:%u\n",
					dev->dev_index, i,
					cb_descriptor->start_time,
					cb_descriptor->completion_time,
					cb_descriptor->status,
					cb_descriptor->cbdId,
					cb_descriptor->tlcStartCmdWinIp,
					cb_descriptor->tlcEndCmdWinIp);
		}
		/*reset the time stamp variable for next reuse */
		cb_descriptor->completion_time = 0;
		cb_descriptor->start_time = 0;
	}
	ice_swc_counter_add(dev->hswc,
		ICEDRV_SWC_DEVICE_COUNTER_RUNTIME,
		(last_cb_end_time -
		 first_cb_start_time));

	*exec_time = last_cb_end_time - first_cb_start_time;
}

/* Return ntw if counter has overflowed */
static struct ice_pnetwork *__get_pntw_of_overflowed_cntr(int cntr_id,
		struct idc_device *dev)
{
	struct cve_device_group *dg = cve_dg_get();
	u32 reg = cfg_default.bar0_mem_evctprot0_offset + (cntr_id * 32);
	idc_regs_evctprot0_t evct_prot_reg;
	struct ice_pnetwork *pntw = NULL;

	/* Check overflow bit of all the counters with which a valid NTW ID
	 * is associated.
	 * base_addr_hw_cntr holds the base address of HW CNTR array and can be
	 * used to get the network ID to which a given counter belongs.
	 */
	if (dg->base_addr_hw_cntr[cntr_id].cntr_pntw_id != INVALID_NETWORK_ID) {
		evct_prot_reg.val = cve_os_read_idc_mmio(dev->cve_dev, reg);
		if ((evct_prot_reg.field.OVF) ||
			ice_os_get_user_idc_intst()) {
			/* Shouldn't we clead OVF by writing 1? */
			cve_os_log_default(CVE_LOGLEVEL_ERROR,
			"Error: NtwID:0x%llx Counter:%x overflow\n",
			dg->base_addr_hw_cntr[cntr_id].cntr_pntw_id, cntr_id);
			pntw = (struct ice_pnetwork *)
				dg->base_addr_hw_cntr[cntr_id].cntr_pntw_id;
		}
	}

	return pntw;
}

int cve_di_interrupt_handler(struct idc_device *idc_dev)
{
	int index;
	int need_dpc = 0;
	u32 status_32 = 0;
	u64 status64, userIDCIntStatus;
	u32 status_lo = 0, status_hi = 0, status_hl = 0;
	struct cve_device *cve_dev = NULL;
	u64 cur_ts;

	u32 head, tail;
	struct dev_isr_status *isr_status_node;

	if (!is_driver_active) {
		cve_os_log_default(CVE_LOGLEVEL_ERROR,
			"Received Illegal Interrupt\n");
		return need_dpc;
	}

	head = atomic_read(&idc_dev->status_q_head);
	tail = atomic_read(&idc_dev->status_q_tail);
	DO_TRACE(trace__icedrvTopHalf(
				SPH_TRACE_OP_STATE_START,
				0, 0, 0,
				SPH_TRACE_OP_STATUS_Q_HEAD, head));

	if (((head + 1) % IDC_ISR_BH_QUEUE_SZ) == tail) {
		/* Q FULL*/
		cve_os_log_default(CVE_LOGLEVEL_ERROR, "BH ISR Q FULL\n");
	}

	isr_status_node = &idc_dev->isr_status[head];
	/* Set the valid to 0 as not data is yet processed
	 * Set to one if some relevant data is filled
	 */
	isr_status_node->valid = 0;

	status64 = idc_mmio_read64(idc_dev->cve_dev,
			cfg_default.bar0_mem_idcintst_offset);
	userIDCIntStatus = ice_os_get_user_idc_intst();
	userIDCIntStatus |= status64;
	isr_status_node->idc_status = userIDCIntStatus;
	idc_mmio_write64(idc_dev->cve_dev,
			cfg_default.bar0_mem_idcintst_offset, status64);

	if (userIDCIntStatus) {
		cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Received IceDC error interrupt\n");
		need_dpc = 1;
		isr_status_node->valid = 1;
	}

	status64 = idc_mmio_read64(idc_dev->cve_dev,
			cfg_default.bar0_mem_iceintst_offset);
	isr_status_node->ice_status = status64;

	cve_os_log(CVE_LOGLEVEL_INFO,
			"IsrQNode[%d]:0x%p IDC_Status=0x%llx, ICE_Status=0x%llx\n",
			head, isr_status_node,
			isr_status_node->idc_status,
			isr_status_node->ice_status);

	idc_mmio_write64(idc_dev->cve_dev,
			cfg_default.bar0_mem_iceintst_offset,
			(status64 & 0x0000FFF00000FFF0));

	/* Spurious Interrupt */
	if (!isr_status_node->ice_status && !need_dpc) {
		cve_os_log_default(CVE_LOGLEVEL_ERROR,
				"Spurious ISR IsrQNode[%d] IDC Status:0x%llx ICE Status=0x%llx\n",
				head,
				isr_status_node->idc_status,
				isr_status_node->ice_status);
		goto exit;
	}

	isr_status_node->int_jiffy = ice_os_get_current_jiffy();
	cur_ts = trace_clock_global();

	/* Currently only serving ICE Int Request, not Ice Error request */
	status_lo = (status64 & 0x0000FFF0);
	status_hi = ((status64 >> 32) & 0x0000FFF0);
	status_hl = status_lo | status_hi;
	while (status_hl) {
		index = identify_ice_and_clear(&status_hl);
		if (index < 0)
			goto exit;
		cve_dev = &idc_dev->cve_dev[index];

		cve_dev->idle_start_time = cur_ts;

		ice_swc_counter_set(cve_dev->hswc,
			ICEDRV_SWC_DEVICE_COUNTER_IDLE_START_TIME,
			nsec_to_usec(cve_dev->idle_start_time));
		ice_swc_counter_add(cve_dev->hswc,
			ICEDRV_SWC_DEVICE_COUNTER_BUSY_TIME,
			nsec_to_usec(cve_dev->idle_start_time -
			cve_dev->busy_start_time));

		project_hook_interrupt_handler_entry(cve_dev);

		status_32 = cve_os_read_mmio_32(cve_dev,
				cfg_default.mmio_intr_status_offset);
		status_32 |= ice_os_get_user_intst(cve_dev->dev_index);
		isr_status_node->ice_isr_status[index] = status_32;
		cve_os_dev_log(CVE_LOGLEVEL_INFO,
			index,
			"Received interrupt from IDC. Status=0x%x\n",
			status_32);

		need_dpc |= (status_32 != 0);
		isr_status_node->valid = need_dpc;

		/* Do not disable WDT as its only enabled once during cold run
		 *
		 * project_hook_interrupt_handler_exit(cve_dev, status_32);
		 */
	}

	head = ((head + 1) % IDC_ISR_BH_QUEUE_SZ);
	atomic_set(&idc_dev->status_q_head, head);

exit:
	DO_TRACE(trace__icedrvTopHalf(
				SPH_TRACE_OP_STATE_COMPLETE,
				isr_status_node->idc_status,
				(status_lo >> 4), (status_hi >> 4),
				SPH_TRACE_OP_STATUS_Q_HEAD, head));
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
	u32 status_lo = 0, status_hi = 0, status_hl = 0, index = 0;

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

					if (qnode->int_jiffy >= ice->db_jiffy) {

						ice->interrupts_status |=
						qnode->ice_isr_status[index];

						cve_os_log(CVE_LOGLEVEL_DEBUG,
						"IsrQNode[%d] ice%d status:0x%x\n",
						tail, index,
						ice->interrupts_status);
					} else {
					 cve_os_log_default(CVE_LOGLEVEL_ERROR,
						"Discarding outdated interrupt of ICE%d status:0x%x DB_jiffy=%lu Int_jiffy=%lu\n",
						index,
						qnode->ice_isr_status[index],
						ice->db_jiffy,
						qnode->int_jiffy);
					}
				}
				status_hl = (status_hl >> 1);
				index++;
			}
			tail = (tail + 1) % IDC_ISR_BH_QUEUE_SZ;
		}
	}
	*q_tail = tail;
}

static void __block_pntw(struct cve_device_group *dg,
		union icedc_intr_status_t idc_err_status)
{
	struct ice_pnetwork *pntw, *pntw_head;

	/* Affects all networks */
	pntw_head = dg->pntw_with_resources;
	pntw = pntw_head;

	cve_os_log(CVE_LOGLEVEL_ERROR,
			"Received error interrupt from IceDC\n");
	if (!pntw)
		goto exit;

	do {
		/* TODO: Segregate IDC error */
		if (pntw->pntw_running)
			ice_ds_block_network(pntw, NULL,
					idc_err_status.val, false);


		pntw =  cve_dle_next(pntw, list);
	} while (pntw != pntw_head);

exit:
	return;
}

void cve_di_interrupt_handler_deferred_proc(struct idc_device *dev)
{
	int index, i;
	u32 status;
	u32 status_lo = 0, status_hi = 0, status_hl = 0, ice_err = 0;
	union icedc_intr_status_t idc_err_status;
	u64 exec_time = 0, ice_status = 0, idc_status = 0;
	struct di_job *job;
	union CVE_SHARED_CB_DESCRIPTOR *cb_descriptor;
	enum cve_job_status job_status;
	struct cve_device *cve_dev = NULL;
	struct sub_job *sub_job;
	struct di_fifo *fifo;
	struct cve_device_group *dg;

	u32 head, tail;
	struct dev_isr_status *isr_status_node;

	DO_TRACE(trace__icedrvBottomHalf(
				SPH_TRACE_OP_STATE_QUEUED,
				0, 0, 0,
				SPH_TRACE_OP_STATUS_LOCATION, __LINE__));

	cve_os_lock(&g_cve_driver_biglock, CVE_NON_INTERRUPTIBLE);

	if (!is_driver_active) {
		cve_os_log_default(CVE_LOGLEVEL_ERROR,
			"Received Illegal Interrupt [BH]\n");
		cve_os_unlock(&g_cve_driver_biglock);
		return;
	}

	dg = cve_dg_get();

	head = atomic_read(&dev->status_q_head);
	tail = atomic_read(&dev->status_q_tail);

	if (tail == head) {
		/* Q Empty*/
		cve_os_log(CVE_LOGLEVEL_INFO,
			"ISR-BH Q is EMPTY, nothing to do\n");
		goto end;
	}

	isr_status_node = &dev->isr_status[tail];
	if (!isr_status_node->valid) {
		cve_os_log_default(CVE_LOGLEVEL_ERROR,
				"Spurious BH IsrQNode[%d] idc_status:0x%llx ice_status:0x%llx\n",
				tail, isr_status_node->idc_status,
				isr_status_node->ice_status);
		goto end;
	}

	__read_isr_q(dev, &idc_status, &ice_status, &tail);

	atomic_set(&dev->status_q_tail, tail);

	idc_err_status.val = idc_status;
	status_lo = (ice_status & 0xFFFF);
	status_hi = ((ice_status >> 32) & 0xFFFF);


	DO_TRACE(trace__icedrvBottomHalf(
				SPH_TRACE_OP_STATE_START,
				idc_status, (status_lo >> 4), (status_hi >> 4),
				SPH_TRACE_OP_STATUS_Q_TAIL, tail));


	if (idc_err_status.val) {

		cve_os_log_default(CVE_LOGLEVEL_ERROR,
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

		if (idc_err_status.field.illegal_access ||
			idc_err_status.field.sem_err ||
			idc_err_status.field.ice_write_err ||
			idc_err_status.field.ice_read_err ||
			idc_err_status.field.asf_ice1_err ||
			idc_err_status.field.asf_ice0_err ||
			idc_err_status.field.attn_err ||
			idc_err_status.field.cntr_err) {

			__block_pntw(dg, idc_err_status);

			if (!idc_err_status.field.attn_err &&
				!idc_err_status.field.cntr_err) {
				/* TODO: Disable rmmod based on this */
				dg->icedc_state =
				ICEDC_STATE_CARD_RESET_REQUIRED;
			}

		} else if (idc_err_status.field.cntr_oflow_err) {

			struct ice_pnetwork *pntw;

			/* Affects all Networks that are using counter */
			for (i = 0; i < MAX_HW_COUNTER_NR; i++) {
				pntw = __get_pntw_of_overflowed_cntr(i, dev);

				if (pntw)
					ice_ds_block_network(pntw, NULL,
						idc_err_status.val, false);
			}
		}
	}

	status_hl = status_lo | status_hi;
	cve_os_log(CVE_LOGLEVEL_INFO,
			"Status_hl=0x%x status_lo:0x%x status_hi:0x%x ice_status:0x%llx\n",
			status_hl, status_lo, status_hi, ice_status);

	if (!status_hl)
		goto end;

	while (1) {

		struct ice_network *ntw;

		index = identify_ice_and_clear(&status_hl);
		if (index < 0) {
			cve_os_log(CVE_LOGLEVEL_INFO,
					"Exit status_hl:0x%x Index:%d\n",
					status_hl, index);
			break;
		}

		cve_dev = &dev->cve_dev[index];

		/*Can enable read to get LLC PMON counter values after
		 * job completion. Commented code can be removed after
		 * LLC PMON sysfs implementation is matured enough.
		 *
		 *if (!dg->dev_info.icebo_list[cve_dev->dev_index
		 *				/ 2].disable_llc_pmon)
		 *ice_di_read_llc_pmon(cve_dev);
		 */

		status = cve_dev->interrupts_status;
		cve_dev->interrupts_status = 0;
		cve_os_dev_log(CVE_LOGLEVEL_INFO,
			index,
			"IsrBH IsrStatus=0x%x PNtwId:0x%llx NtwId:0x%llx IsColdRun:%d DbCbdId:%u IdleSTime:%llu BusySTime:%llu\n",
			status,
			cve_dev->dev_pntw_id,
			cve_dev->dev_ntw_id,
			cve_dev->is_cold_run,
			cve_dev->db_cbd_id,
			cve_dev->idle_start_time,
			cve_dev->busy_start_time);

		/* we might enter here with status 0
		 * this is a valid situation.
		 */
		if (!status)
			continue;

		if (cve_dev->state == CVE_DEVICE_IDLE) {
			cve_os_dev_log_default(CVE_LOGLEVEL_ERROR,
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

		/* check ECB error only if one sub job was subbmitted */
		if (sub_job->embedded_sub_job) {
			if (is_embedded_cb_error(cve_dev)) {
				cve_os_log_default(CVE_LOGLEVEL_ERROR,
			"Interrupt Status = 0x%08x Embedded CB Error = %d\n",
			status, is_embedded_cb_error(cve_dev));

				cve_os_log_default(CVE_LOGLEVEL_ERROR,
					"ICE:%d Start:%u End:%u Status:0x%x cbdId:%d tlcStartCmdWinIp:%u tlcEndCmdWinIp:%u\n",
					cve_dev->dev_index,
					cb_descriptor->start_time,
					cb_descriptor->completion_time,
					cb_descriptor->status,
					cb_descriptor->cbdId,
					cb_descriptor->tlcStartCmdWinIp,
					cb_descriptor->tlcEndCmdWinIp);

				job_status = CVE_JOBSTATUS_ABORTED;

				/* Error Handling ??? */
				cve_di_set_device_reset_flag(cve_dev,
					CVE_DI_RESET_DUE_CVE_ERROR);

				goto handle_interrupt_check_completion;
			}
		}

		/* If dsram error detected store error count in SW counter */
		/* TODO: card level reset for fatal errors */
		if (is_dsram_error(status)) {

			store_ecc_err_count(cve_dev);
			/* Ignore single bit error*/
			status = unset_single_ecc_err(status);

			if (status)
				ice_ds_handle_ice_error(cve_dev, status);

			/*TODO HACK:
			 * Ignore Memory errors w.r.t job abort flow
			 * for now as WA, let the ICE continue till
			 * completion or WD
			 */
			status = unset_sram_parity_err(status);

			if (!status)
				continue;
		}

		ice_err = is_cve_error(status);
		__calc_cb_executon_time(cve_dev, job, &exec_time, ice_err);

		if (is_ice_dump_completed(status) &&
			cve_dev->debug_control_buf.is_dump_now) {
			cve_os_log_default(CVE_LOGLEVEL_ERROR,
				"ICE_DUMP_NOW completed ICE ID:%d, status:0x%08x\n",
				cve_dev->dev_index, status);
			status = unset_ice_dump_status(status);
			cve_dev->debug_control_buf.is_allowed_tlc_dump = 0;
			cve_dev->debug_control_buf.is_cve_dump_on_error = 1;
			cve_os_wakeup(&cve_dev->debug_control_buf.dump_wqs_que);
			if (!status)
				continue;
		}

		if (is_wd_error(status)) {
			__dump_wait_mode_reg(cve_dev,
					"WD Detected: ");
			if (get_ice_dump(cve_dev)) {
				status = status |
				cfg_default.
				mmio_intr_status_dump_completed_mask;
			}
		}

		ntw = (struct ice_network *)cve_dev->dev_ntw_id;

		/*If error detected and recovery enabled*/
		if (ice_err) {

			if (is_fatal_error_in_ice(status))
				dg->icedc_state =
					ICEDC_STATE_CARD_RESET_REQUIRED;

			ice_ds_block_network(NULL, job->ds_hjob, status, true);

			job_status = CVE_JOBSTATUS_ABORTED;

			cve_os_dev_log(CVE_LOGLEVEL_ERROR,
					cve_dev->dev_index,
					"It seems that some errors occurred or ICE_DUMP_COMPLETED because of some TLC error\n");
			cve_os_log_default(CVE_LOGLEVEL_ERROR,
					"IntrStatus:0x%08x TlcErr:%d MmuErr:%d WDErr:%d PageFault:%d CBComplete:%d, QEmpty:%d BusErr:%d BTRSErr:%d TLCPanic:%d IceDumpDone:%d\n",
					status,
					is_tlc_error(status),
					is_mmu_error(status),
					is_wd_error(status),
					is_page_fault_error(status),
					is_cb_complete(status),
					is_que_empty(status),
					is_bus_error(status),
					is_butress_error(status),
					is_tlc_panic(status),
					is_ice_dump_completed(status));

			if (is_page_fault_error(status))
				print_page_fault_errors(status);

			ice_dump_hw_err_info(cve_dev);
			ice_dump_hw_cntr_info(ntw);
			ice_ds_handle_ice_error(&dev->cve_dev[index], status);
			cve_di_set_device_reset_flag(cve_dev,
					CVE_DI_RESET_DUE_CVE_ERROR);
			/* Signal dump was created */
			if (is_ice_dump_completed(status)) {
				/* Don't allow TLC to further
				 * write to cve dump buffer
				 */
				cve_dev->cve_dump_buf->is_allowed_tlc_dump = 0;
			}

			DO_TRACE(trace_icedrvScheduleJob(
						SPH_TRACE_OP_STATE_BH,
						cve_dev->dev_index,
						cve_dev->dev_ctx_id,
						cve_dev->dev_pntw_id, 0,
						cve_dev->dev_ntw_id, 0,
						(void *)job->ds_hjob,
						SPH_TRACE_OP_STATUS_FAIL,
						status));
		} else if ((dg->icedc_state ==
				ICEDC_STATE_CARD_RESET_REQUIRED) ||
				ntw->reset_ntw) {
			job_status = CVE_JOBSTATUS_ABORTED;

		} else {
			/* if job is entirely completed */
			cve_os_log(CVE_LOGLEVEL_DEBUG,
					"job completed\n");
			job_status = CVE_JOBSTATUS_COMPLETED;

		}
		if (dg->dump_ice_mmu_pmon) {
			get_ice_mmu_pmon_regs(cve_dev);

			#ifdef _DEBUG
			__dump_mmu_pmon(cve_dev);
			#endif
		}
		if (dg->dump_ice_delphi_pmon) {
			get_ice_delphi_pmon_regs(cve_dev);

			#ifdef _DEBUG
			__dump_delphi_pmon(cve_dev);
			#endif
		}

handle_interrupt_check_completion:

		project_hook_interrupt_dpc_handler_entry(cve_dev);

		/* If true => Block after Job completion */
		if (block_mmu)
			ice_di_mmu_block_entrance(cve_dev);

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
	DO_TRACE(trace__icedrvBottomHalf(
				SPH_TRACE_OP_STATE_COMPLETE,
				idc_status, (status_lo >> 4), (status_hi >> 4),
				SPH_TRACE_OP_STATUS_Q_TAIL, tail));

	cve_os_unlock(&g_cve_driver_biglock);
}

void cve_di_dispatch_job(struct cve_device *cve_dev,
		cve_di_job_handle_t hjob,
		cve_di_subjob_handle_t *e_cbs,
		cve_di_subjob_handle_t *warm_dev_ecb)
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
		cve_dev->is_cold_run = 1;
	} else if (e_cbs == NULL && job->cold_run == 1) {
		/* this is a special case when same warm ICE from a parent
		 * is used to run a new infer from a new network. In this case
		 * ecb is bypassed as device is warm but job is cold
		 */
		ASSERT(warm_dev_ecb);
		add_embedded_cb_to_job(job,
				warm_dev_ecb[GET_CB_INDEX(CVE_FW_CB1_TYPE)]);
		job->next_subjob = 0;
		job->remaining_subjobs_nr = job->subjobs_nr + 1;
		cve_dev->is_cold_run = 0;
		cve_os_dev_log(CVE_LOGLEVEL_DEBUG,
				cve_dev->dev_index,
				"WARM ECB was added to job:0x%p\n", job);

	} else {
		/*TODO for warm device and warm job, there is chance that
		 * previous network has overiden the deep sram content of
		 * current job
		 */

		/* Can only be executed during Warm run */
		ASSERT(!job->cold_run);
		cve_dev->is_cold_run = 0;

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
	cve_dev->hjob = hjob;
}

void cve_di_do_job_db(struct cve_device *ice, cve_di_job_handle_t hjob)
{
	struct di_job __maybe_unused *job = (struct di_job *)hjob;
	struct ice_network __maybe_unused *ntw =
		(struct ice_network *) ice->dev_ntw_id;
	struct job_descriptor __maybe_unused *inf_job =
		(struct job_descriptor *)job->ds_hjob;

	cve_os_dev_log(CVE_LOGLEVEL_INFO,
			ice->dev_index,
			"PntwId:0x%llx NtwID:0x%llx JobId:%u GraphId:%u DummyGraphId:%u DbCbId:%u Ring the doorbell\n",
			ntw->pntw->pntw_id,
			ntw->network_id,
			inf_job->id,
			inf_job->graph_ice_id,
			inf_job->dummy_ice_id,
			ice->db_cbd_id);

	/* reset the TLC FIFO indexes */
	cve_os_write_mmio_32(ice,
	 cfg_default.mmio_cbd_base_addr_offset, ice->cbd_base_va);

	/* ring the doorbell once with the last descriptor */
	cve_os_write_mmio_32(ice,
		cfg_default.mmio_cb_doorbell_offset, ice->db_cbd_id);

	DO_TRACE(trace_icedrvScheduleJob(
				SPH_TRACE_OP_STATE_START,
				ice->dev_index,
				ntw->pntw->wq->context->swc_node.sw_id,
				ntw->pntw->swc_node.sw_id,
				ntw->swc_node.sw_id, ntw->network_id,
				ntw->curr_exe->swc_node.sw_id,
				(void *)job->ds_hjob,
				SPH_TRACE_OP_STATUS_EXEC_TYPE,
				ice->is_cold_run));

}

void cve_di_set_counters(struct cve_device *ice,
		u64 busy_start_time,
		unsigned long db_jiffy)
{

	ice->db_jiffy = db_jiffy;
	ice->busy_start_time = busy_start_time;
	ice_swc_counter_set(ice->hswc,
		ICEDRV_SWC_DEVICE_COUNTER_BUSY_START_TIME,
		(nsec_to_usec(ice->busy_start_time)));
	ice_swc_counter_add(ice->hswc, ICEDRV_SWC_DEVICE_COUNTER_IDLE_TIME,
		nsec_to_usec(ice->busy_start_time - ice->idle_start_time));
	cve_os_log(CVE_LOGLEVEL_DEBUG,
		"busy_start_time(usec)=%llu\n",
		nsec_to_usec(ice->busy_start_time));

}


void cve_di_set_page_directory_base_addr(struct cve_device *cve_dev,
		u32 base_addr)
{
	union cvg_mmu_1_system_map_mem_page_table_base_address_t reg;

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
	union cvg_mmu_1_system_map_mem_page_table_base_address_t reg;

	reg.val = 0;
	write_to_page_table_base_address(cve_dev, reg);
}

int cve_di_handle_submit_job(
	struct cve_ntw_buffer *buf_list,
	cve_ds_job_handle_t ds_hjob,
	struct cve_job *job_desc,
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
	struct cve_ntw_buffer *buffer;
	u32 command_buffers_nr = job_desc->cb_nr;

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
	job->ddr_bw = job_desc->ddr_bw_in_mbps;
	job->ring_to_ice_ratio = job_desc->ring_to_ice_ratio;
	job->ice_to_ice_ratio = job_desc->ice_to_ice_ratio;
	job->cdyn_val = job_desc->cdyn_val;

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
			cve_os_log_default(CVE_LOGLEVEL_ERROR,
				"Cannot find surface ID %llu!\n",
				kcb_descriptor[cb_idx].bufferid);
			retval = -ICEDRV_KERROR_CB_INVAL_BUFFER_ID;
			goto err;
		}

		retval = cve_mm_map_kva(buffer->ntw_buf_alloc);
		if (retval < 0) {
			cve_os_log(CVE_LOGLEVEL_ERROR,
					"cve_mm_map_kva failed %d\n", retval);
			goto err;
		}

		cve_mm_get_buffer_addresses(buffer->ntw_buf_alloc,
			&cve_vaddr, &offset, &address);


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
		job->sub_jobs[sub_job_idx].cb.allocation =
			buffer->ntw_buf_alloc;

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

void cve_di_set_hw_counters(struct cve_device *cve_dev)
{
	union ice_mmu_inner_mem_mmu_config_t reg;
	struct cve_device_group *dg = cve_dg_get();
	u32 offset_bytes = cfg_default.mmu_base + cfg_default.mmu_cfg_offset;

	/* validate that we are 32bit aligned */
	ASSERT(((offset_bytes >> 2) << 2) == offset_bytes);

	/* read current register value */
	reg.val = cve_os_read_mmio_32(cve_dev, offset_bytes);

	/* Enable/Disable HW counters */
	if (dg->dump_ice_mmu_pmon)
		reg.field. ACTIVATE_PERFORMANCE_COUNTERS = 1;

	cve_os_write_mmio_32(cve_dev, offset_bytes, reg.val);
}

void ice_di_reset_cbdt_cb_addr(struct cve_device *dev)
{
	union CVE_SHARED_CB_DESCRIPTOR *cb_descriptor = NULL;
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
			if (dev->dev_ntw_id == ntw_id &&
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
	union CVE_SHARED_CB_DESCRIPTOR *cb_descriptor;

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

u8 ice_di_is_driver_active(void)
{
	return is_driver_active;
}

/* address mode is set along with MMU unblock on silicon. For ring3,
 * its done seperatly due to a different flow of MMU unblock
 */
void ice_di_set_mmu_address_mode(struct cve_device *ice)
{
#ifdef RING3_VALIDATION
	union ice_mmu_inner_mem_mmu_config_t reg;
	u32 offset_bytes = cfg_default.mmu_base + cfg_default.mmu_cfg_offset;

	/* read current register value */
	reg.val = cve_os_read_mmio_32(ice, offset_bytes);
#if ICE_DEFAULT_VA_WIDTH == ICE_VA_WIDTH_EXTENDED
		reg.field.ATU_WITH_LARGER_LINEAR_ADDRESS = 0xf;
#else
		reg.field.ATU_WITH_LARGER_LINEAR_ADDRESS = 0x0;
#endif
	cve_os_write_mmio_32(ice, offset_bytes, reg.val);
#endif
}

u8 ice_di_is_cold_run(cve_di_job_handle_t hjob)
{
	struct di_job *job = (struct di_job *)hjob;

	return job->cold_run;
}

void ice_di_set_cold_run(cve_di_job_handle_t hjob)
{
	struct di_job *job = (struct di_job *)hjob;

	job->cold_run = 1;
}

static int ice_trigger_cnc_control_msg(struct cve_device *dev, u32 destCbbid,
				u32 opcode, u32 isPosted, u32 controlPayload)
{
	/*triggering cnc control message using mmio of ice*/
	u32 TLC_GENERATE_CONTROL_UCMD_REG_data;
#if ENABLE_GPR_WAIT
	u32 gp_reg_14_init_val;
#endif
	/*write 0x0 to GENERAL_PURPOSE_REG_15*/
	cve_os_write_mmio_32(dev,
		cfg_default.mmio_gp_regs_offset +
			ICE_MMIO_GP_15_REG_ADDR_OFFSET, 0x0);

#if ENABLE_GPR_WAIT
	/*read GENERAL_PURPOSE_REG_14*/
	gp_reg_14_init_val = cve_os_read_mmio_32(dev,
		cfg_default.mmio_gp_regs_offset +
			ICE_MMIO_GP_14_REG_ADDR_OFFSET);
	dev->gp_reg14_val = gp_reg_14_init_val;
#endif

	/*write control payload data */
	cve_os_write_mmio_32(dev,
		cfg_default.ice_tlc_hi_base +
		cfg_default.ice_tlc_hi_tlc_debug_reg_offset,
		controlPayload);

	/*Write the TLC_GENERATE_CONTROL_UCMD_REG,
	 *specifying the desired DstCbbid, Opcode,
	 *and isPosted values of the CnC
	 */
	TLC_GENERATE_CONTROL_UCMD_REG_data = (destCbbid & 0xFF) |
					((opcode & 0xF) << 8) |
					((isPosted & 0x1) << 12);
	cve_os_write_mmio_32(dev,
		cfg_default.ice_tlc_hi_base +
		cfg_default.ice_tlc_hi_tlc_control_ucmd_reg_offset,
		TLC_GENERATE_CONTROL_UCMD_REG_data);

	cve_os_log(CVE_LOGLEVEL_DEBUG,
			"Writing cdyn  @offset 0x%x  = 0x%x\n",
			cfg_default.ice_tlc_hi_tlc_debug_reg_offset,
			controlPayload);
#if ENABLE_GPR_WAIT
	dev->cdyn_requested = 1;
	dev->tlc_reg_val = TLC_GENERATE_CONTROL_UCMD_REG_data;
#endif
	return 0;
}

int ice_iccp_license_ack(struct cve_device *dev)
{
	u32 gp_reg_15_val;
	u32 gp_reg_14_current_val, gp_reg_14_init_val = dev->gp_reg14_val;
	u16 timeout = CNC_CONTROL_MSG_TIMEOUT;
	int ret = 1;

	/*wait for completion:
	 *READ GP 15 until its value reflect value written to
	 *TLC_GENERATE_CONTROL_UCMD_REG,
	 *READ GP 14 until its value differs from initial GP 14 val
	 */

	gp_reg_14_current_val = gp_reg_14_init_val;
	gp_reg_15_val = cve_os_read_mmio_32(dev,
			cfg_default.mmio_gp_regs_offset +
			ICE_MMIO_GP_15_REG_ADDR_OFFSET);

	while ((gp_reg_14_init_val == gp_reg_14_current_val) &&
		(gp_reg_15_val != dev->tlc_reg_val) &&
		(timeout)) {
		usleep_range(10, 12);
		timeout--;

		gp_reg_15_val = cve_os_read_mmio_32(dev,
			cfg_default.mmio_gp_regs_offset +
			ICE_MMIO_GP_15_REG_ADDR_OFFSET);

		gp_reg_14_current_val = cve_os_read_mmio_32(dev,
			cfg_default.mmio_gp_regs_offset +
			ICE_MMIO_GP_14_REG_ADDR_OFFSET);
	}

	if (timeout)
		ret = 0;
	else
		cve_os_log(CVE_LOGLEVEL_ERROR,
				"ice_iccp_license_ack timeout\n");

	dev->cdyn_requested = 0;

	return ret;
}

int ice_iccp_license_request(struct cve_device *dev, bool throttling,
				uint16_t license_value)
{
	int ret;

	if (throttling) {
		cve_os_dev_log(CVE_LOGLEVEL_DEBUG,
			dev->dev_index,
			" icp_license_request sent with throttling mode enabled\n");
		ret = ice_trigger_cnc_control_msg(dev, 0,
				ICCP_THROTTLING_OPCODE, 0, license_value);
	} else {
		cve_os_dev_log(CVE_LOGLEVEL_DEBUG,
			dev->dev_index,
			" icp_license_request sent with throttling mode disabled\n");
		ret = ice_trigger_cnc_control_msg(dev, 0,
				ICCP_NO_THROTTLING_OPCODE, 0, license_value);
	}
	return ret;
}

uint16_t cve_di_get_cdyn_val(cve_di_job_handle_t hjob)
{
	struct di_job *job = (struct di_job *) hjob;

	return job->cdyn_val;
}

#ifdef _DEBUG
static void __dump_mmu_pmon(struct cve_device *ice)
{
	int i = 0;

	for (i = 0; i < ICE_MAX_MMU_PMON; i++) {
		cve_os_dev_log(CVE_LOGLEVEL_INFO,
		ice->dev_index,
		"%s\t:%u\n",
		ice->mmu_pmon[i].pmon_name,
		ice->mmu_pmon[i].pmon_value);
	}
}
static void __dump_delphi_pmon(struct cve_device *ice)
{
	int i = 0;
	ICE_PMON_DELPHI_GEMM_CNN_STARTUP_COUNTER startup_cnt_reg;
	ICE_PMON_DELPHI_CFG_CREDIT_LATENCY latency_cnt_reg;
	ICE_PMON_DELPHI_OVERFLOW_INDICATION ovr_flow_reg;
	ICE_PMON_DELPHI_DBG_PERF_STATUS_REG_T perf_status_reg;

	for (i = 0; i < ICE_MAX_DELPHI_PMON; i++) {
		if (ice_get_a_step_enable_flag()) {
			if (i >= ICE_MAX_A_STEP_DELPHI_PMON)
				break;
		}
		switch (i) {

		case ICE_DELPHI_PMON_PER_LAYER_CYCLES:
		case ICE_DELPHI_PMON_TOTAL_CYCLES:
		case ICE_DELPHI_PMON_GEMM_COMPUTE_CYCLES:
		case ICE_DELPHI_PMON_GEMM_OUTPUT_WRITE_CYCLES:
		case ICE_DELPHI_PMON_CNN_COMPUTE_CYCLES:
		case ICE_DELPHI_PMON_CNN_OUTPUT_WRITE_CYCLES:

			cve_os_dev_log(CVE_LOGLEVEL_INFO,
				ice->dev_index,
				"%s\t:%u\n",
				ice->delphi_pmon[i].pmon_name,
				ice->delphi_pmon[i].pmon_value);
		break;

		case ICE_DELPHI_PMON_CYCLES_COUNT_OVERFLOW:
			perf_status_reg.val = ice->delphi_pmon[i].pmon_value;

				cve_os_dev_log(CVE_LOGLEVEL_INFO,
					ice->dev_index,
				"Per_Layer_Cycles_Overflow\t:%u\nTotal_Cycles_Overflow\t:%u\n",
				perf_status_reg.field.per_lyr_cyc_cnt_saturated,
				perf_status_reg.field.total_cyc_cnt_saturated);
		break;

		case ICE_DELPHI_PMON_GEMM_CNN_STARTUP:
			startup_cnt_reg.val = ice->delphi_pmon[i].pmon_value;

				cve_os_dev_log(CVE_LOGLEVEL_INFO,
					ice->dev_index,
				"CNN_Startup_Count\t:%u\nGemm_Startup_Count\t:%u\n",
				startup_cnt_reg.field.pe_startup_perf_cnt,
				startup_cnt_reg.field.gemm_startup_perf_cnt);

		break;

		case ICE_DELPHI_PMON_CONFIG_CREDIT_LATENCY:
			latency_cnt_reg.val = ice->delphi_pmon[i].pmon_value;

				cve_os_dev_log(CVE_LOGLEVEL_INFO,
					ice->dev_index,
				"Credit_Reset_Latency_Count\t:%u\nCfg_Latency_Count\t:%u\n",
				latency_cnt_reg.field.
						credit_reset_latency_perf_cnt,
				latency_cnt_reg.field.cfg_latency_perf_cnt);
		break;

		case ICE_DELPHI_PMON_PERF_COUNTERS_OVR_FLW:
			ovr_flow_reg.val = ice->delphi_pmon[i].pmon_value;

				cve_os_dev_log(CVE_LOGLEVEL_INFO,
					ice->dev_index,
				"CNN_Startup_Overflow\t:%u\nGemm_Startup_Overflow\t:%u\nGemm_Compute_Overflow\t:%u\nGemm_Teardown_Overflow\t:%u\nCNN_Compute_Overflow\t:%u\nCNN_Teardown_Overflow\t:%u\nCredit_Reset_latency_Overflow\t:%u\nCfg_Latency_Overflow\t:%u\n",
			ovr_flow_reg.field.pe_startup_perf_cnt_ovr_flow,
			ovr_flow_reg.field.gemm_startup_perf_cnt_ovr_flow,
			ovr_flow_reg.field.gemm_compute_perf_cnt_ovr_flow,
			ovr_flow_reg.field.gemm_teardown_perf_cnt_ovr_flow,
			ovr_flow_reg.field.pe_compute_perf_cnt_ovr_flow,
			ovr_flow_reg.field.pe_teardown_perf_cnt_ovr_flow,
			ovr_flow_reg.field.
					credit_reset_latency_perf_cnt_ovr_flow,
			ovr_flow_reg.field.cfg_latency_perf_cnt_ovr_flow);
		break;

		default:
			cve_os_log(CVE_LOGLEVEL_ERROR,
				"__dump_delphi_pmon index error\n");
		}
	}
}
#endif

/* Update network's shared read error if exists */
u32 ice_di_is_shared_read_error(struct cve_device *dev)
{
	AXI_SHARED_READ_STATUS_T err_reg;
	u32 offset, icebo_offset, ret = 0;
	int bo_id = (dev->dev_index / 2);

	icebo_offset = ICEDC_ICEBO_OFFSET(bo_id);
	offset = icebo_offset + cfg_default.axi_shared_read_status_offset;
	err_reg.val = cve_os_read_idc_mmio(dev, offset);

	if (err_reg.field.error_flag) {

		ret = err_reg.val;
		err_reg.field.error_flag = 0;
		cve_os_write_idc_mmio(dev, offset, err_reg.val);
	}

	return ret;
}

int ice_di_check_mmu_regs(u32 *reg_list, u32 num_regs)
{
	int ret = 0;
	u32 i, offset;
	u32 mmu_last_reg = cfg_default.mmu_axi_tbl_pt_idx_bits_offset;
	u32 atu0_first_reg = cfg_default.mmu_atu0_base - cfg_default.mmu_base;
	u32 atu0_last_reg = atu0_first_reg +
				cfg_default.ice_mmu_1_system_map_stream_id_l2_7;
	u32 atu1_first_reg = cfg_default.mmu_atu1_base - cfg_default.mmu_base;
	u32 atu1_last_reg = atu1_first_reg +
				cfg_default.ice_mmu_1_system_map_stream_id_l2_7;
	u32 atu2_first_reg = cfg_default.mmu_atu2_base - cfg_default.mmu_base;
	u32 atu2_last_reg = atu2_first_reg +
				cfg_default.ice_mmu_1_system_map_stream_id_l2_7;
	u32 atu3_first_reg = cfg_default.mmu_atu3_base - cfg_default.mmu_base;
	u32 atu3_last_reg = atu3_first_reg +
				cfg_default.ice_mmu_1_system_map_stream_id_l2_7;

	for (i = 0; i < num_regs; i++) {

		offset = reg_list[2 * i];

		if (offset & 0x3)
			ret = -ICEDRV_KERROR_INVALID_MMU_REG_OFFSET;
		else if ((offset > mmu_last_reg) && (offset < atu0_first_reg))
			ret = -ICEDRV_KERROR_INVALID_MMU_REG_OFFSET;
		else if ((offset > atu0_last_reg) && (offset < atu1_first_reg))
			ret = -ICEDRV_KERROR_INVALID_MMU_REG_OFFSET;
		else if ((offset > atu1_last_reg) && (offset < atu2_first_reg))
			ret = -ICEDRV_KERROR_INVALID_MMU_REG_OFFSET;
		else if ((offset > atu2_last_reg) && (offset < atu3_first_reg))
			ret = -ICEDRV_KERROR_INVALID_MMU_REG_OFFSET;
		else if (offset > atu3_last_reg)
			ret = -ICEDRV_KERROR_INVALID_MMU_REG_OFFSET;

		if (ret < 0)
			break;
	}

	return ret;
}

void ice_di_config_mmu_regs(struct cve_device *ice, u32 *reg_list,
		u32 num_regs)
{
	u32 i, offset;

	for (i = 0; i < num_regs; i++) {
		offset = cfg_default.mmu_base + reg_list[2 * i];
		cve_os_write_mmio_32(ice, offset, reg_list[(2 * i) + 1]);
	}
}

#ifndef RING3_VALIDATION
void ice_di_job_info_print(struct seq_file *m,
					struct jobgroup_descriptor *jobgroup)
{
	struct job_descriptor *job;
	struct di_job *djob;
	struct sub_job *subjob;
	int i, j, commands_nr;

	job = jobgroup->jobs;

	for (i = 0; i < jobgroup->submitted_jobs_nr; i++) {
		commands_nr = 0;
		djob = (struct di_job *)job->di_hjob;
		seq_printf(m, "sub jobs = %d\tallocated subjobs = %d\tremaining sub jobs = %d",
			djob->subjobs_nr,
			djob->allocated_subjobs_nr,
			djob->remaining_subjobs_nr);

		for (j = 0; j < djob->subjobs_nr; j++) {
			subjob = &djob->sub_jobs[j];
			commands_nr += subjob->cb.commands_nr;
		}

		seq_printf(m, "\tTotal Commands = %d\n",
					commands_nr);

		/* increment the next dispatch pointer */
		job = cve_dle_next(job, list);
	}
}
#endif
