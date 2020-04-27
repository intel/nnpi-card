/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/slab.h>
#include <linux/kmsg_dump.h>
#include <linux/dma-mapping.h>
#include <linux/version.h>

#if KERNEL_VERSION(4, 16, 1) <= LINUX_VERSION_CODE /* SPH_IGNORE_STYLE_CHECK */
#include <linux/dma-direct.h>
#endif

#include <linux/spinlock.h>
#include "ipc_protocol.h"
#include "sphcs_crash_dump.h"
#include "sph_log.h"
#include "sphcs_cs.h"
#include "sphcs_dma_sched.h"
#include "nnp_inbound_mem.h"

struct crash_dump_desc {
	dma_addr_t card_dma_addr;
	void *card_vaddr;
	bool  alloced;
	spinlock_t lock_irq;
	dma_addr_t host_dma_addr;
	size_t actually_copied;
} crash_dump_desc;

static const char *get_reason_str(enum kmsg_dump_reason reason)
{
	switch (reason) {
	case KMSG_DUMP_PANIC:
		return "Panic";
	case KMSG_DUMP_OOPS:
		return "Oops";
	case KMSG_DUMP_EMERG:
		return "Emergency";
	case KMSG_DUMP_RESTART:
		return "Restart";
	case KMSG_DUMP_HALT:
		return "Halt";
	case KMSG_DUMP_POWEROFF:
		return "Poweroff";
	default:
		return "Unknown";
	}
}
int sphcs_crash_dump_dma_complete_callback(struct sphcs *sphcs,
		void *ctx,
		const void *user_data,
		int status,
		u32 xferTimeUS)
{
	union c2h_EventReport event;

	if (status == SPHCS_DMA_STATUS_FAILED) {
		/* dma failed */
		/* TODO: send error event to host */
	} else if (sphcs->host_doorbell_val != 0) {
		/* Notify Host */
		event.value = 0;
		event.opcode = NNP_IPC_C2H_OP_EVENT_REPORT;
		event.eventCode = NNP_IPC_ERROR_OS_CRASHED;
		event.eventVal = 0;
		event.objID = (crash_dump_desc.actually_copied & 0xffff);
		event.objID_2 = (crash_dump_desc.actually_copied >> 16) & 0xffff;
		event.objValid = 1;
		event.objValid_2 = 1;
		sphcs->hw_ops->write_mesg(sphcs->hw_handle,
					  &event.value,
					  1);
	}

	return 0;
}

static void dump(struct kmsg_dumper *dumper, enum kmsg_dump_reason reason)
{
	bool rc;
	dma_addr_t host_dma_addr;
	union c2h_EventReport event;
	unsigned long flags;

	sph_log_debug(GENERAL_LOG, "dump %s\n", get_reason_str(reason));

	rc = kmsg_dump_get_buffer(dumper,
			false,
			crash_dump_desc.card_vaddr,
			NNP_CRASH_DUMP_SIZE,
			&crash_dump_desc.actually_copied);

	sph_log_debug(GENERAL_LOG, "actually_copied %zu, rc %d\n", crash_dump_desc.actually_copied, rc);

	if (!g_the_sphcs)
		return;

	if (g_the_sphcs->inbound_mem) {
		g_the_sphcs->inbound_mem->crash_dump_size = crash_dump_desc.actually_copied;
		/*
		 * Notify Host - with zero copied size since DMA did not yet
		 * started, crash dump data is in the inbound memory region.
		 * After DMA will complete, will notify again with the copied
		 * size.
		 */
		event.value = 0;
		event.opcode = NNP_IPC_C2H_OP_EVENT_REPORT;
		event.eventCode = NNP_IPC_ERROR_OS_CRASHED;
		event.eventVal = 0;
		if (g_the_sphcs->host_doorbell_val != 0)
			g_the_sphcs->hw_ops->write_mesg(g_the_sphcs->hw_handle,
							&event.value,
							1);
	}

	NNP_SPIN_LOCK_IRQSAVE(&crash_dump_desc.lock_irq, flags);
	host_dma_addr = crash_dump_desc.host_dma_addr;
	NNP_SPIN_UNLOCK_IRQRESTORE(&crash_dump_desc.lock_irq, flags);

	if (host_dma_addr) {
		rc = sphcs_dma_sched_start_xfer_single(g_the_sphcs->dmaSched,
						       &g_dma_desc_c2h_high,
						       crash_dump_desc.card_dma_addr,
						       host_dma_addr,
						       crash_dump_desc.actually_copied,
						       sphcs_crash_dump_dma_complete_callback,
						       NULL,
						       NULL,
						       0);
		if (rc)
			sph_log_err(GENERAL_LOG, "Failed to start DMA xfer!\n");
	}
}

static struct kmsg_dumper dumper = {
	.dump = dump
};

int sphcs_crash_dump_init(void)
{
	int retval;
	struct page *crash_dump_pages[NNP_CRASH_DUMP_SIZE_PAGES];
	int i;

	/* setup crash dump memory */
	if (g_the_sphcs->inbound_mem_dma_addr) {

		for (i = 0; i < NNP_CRASH_DUMP_SIZE_PAGES; i++)
			crash_dump_pages[i] = pfn_to_page(__phys_to_pfn(dma_to_phys(g_the_sphcs->hw_device, g_the_sphcs->inbound_mem_dma_addr + i*PAGE_SIZE)));

		g_the_sphcs->inbound_mem = vm_map_ram(crash_dump_pages, NNP_CRASH_DUMP_SIZE_PAGES, -1, PAGE_KERNEL);

		if (!g_the_sphcs->inbound_mem) {
			sph_log_err(START_UP_LOG,
				    "Failed to map inbound memory region\n");
			return -ENOMEM;
		}

		g_the_sphcs->inbound_mem->magic = NNP_INBOUND_MEM_MAGIC;
		g_the_sphcs->inbound_mem->crash_dump_size = 0;

		crash_dump_desc.card_vaddr = &g_the_sphcs->inbound_mem->crash_dump[0];
		crash_dump_desc.card_dma_addr =
			g_the_sphcs->inbound_mem_dma_addr +
			offsetof(union nnp_inbound_mem, crash_dump);

	} else {
		crash_dump_desc.card_vaddr =
			dma_alloc_coherent(g_the_sphcs->hw_device,
					   NNP_CRASH_DUMP_SIZE,
					   &crash_dump_desc.card_dma_addr,
					   GFP_KERNEL);

		if (!crash_dump_desc.card_vaddr) {
			sph_log_err(START_UP_LOG, "Failed to allocate crash dump buffer\n");
			return -ENOMEM;
		}

	}

	sph_log_info(START_UP_LOG, "Crash log buffer at: 0x%llx\n",
		     dma_to_phys(g_the_sphcs->hw_device, crash_dump_desc.card_dma_addr));

	/* initialize first bytes in the crash buffer to zero */
	*((uint64_t *)crash_dump_desc.card_vaddr) = 0;

	spin_lock_init(&crash_dump_desc.lock_irq);
	crash_dump_desc.host_dma_addr = 0;

	retval = kmsg_dump_register(&dumper);
	if (retval < 0) {
		sph_log_err(START_UP_LOG, "failed to register dump %d\n", retval);
		goto failed_to_register_dump;
	}

	return 0;

failed_to_register_dump:
	if (g_the_sphcs->inbound_mem_dma_addr)
		vm_unmap_ram(g_the_sphcs->inbound_mem, NNP_CRASH_DUMP_SIZE_PAGES);
	else
		dma_free_coherent(g_the_sphcs->hw_device,
				  NNP_CRASH_DUMP_SIZE,
				  crash_dump_desc.card_vaddr,
				  crash_dump_desc.card_dma_addr);

	return retval;
}

void sphcs_crash_dump_cleanup(void)
{
	kmsg_dump_unregister(&dumper);
	if (g_the_sphcs->inbound_mem_dma_addr)
		vm_unmap_ram(g_the_sphcs->inbound_mem, NNP_CRASH_DUMP_SIZE_PAGES);
	else
		dma_free_coherent(g_the_sphcs->hw_device,
				  NNP_CRASH_DUMP_SIZE,
				  crash_dump_desc.card_vaddr,
				  crash_dump_desc.card_dma_addr);

}

void sphcs_crash_dump_setup_host_addr(u64 host_dma_addr)
{
	unsigned long flags;

	NNP_SPIN_LOCK_IRQSAVE(&crash_dump_desc.lock_irq, flags);
	crash_dump_desc.host_dma_addr = host_dma_addr;
	NNP_SPIN_UNLOCK_IRQRESTORE(&crash_dump_desc.lock_irq, flags);

	sph_log_info(CREATE_COMMAND_LOG, "Host Crash Dump: dma_addr - %pad\n",
			&crash_dump_desc.host_dma_addr);
}
