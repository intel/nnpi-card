// SPDX-License-Identifier: GPL-2.0-or-later

/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 ********************************************/

#include <linux/module.h>
#include <linux/pci.h>
#include <linux/delay.h>
#include <linux/interrupt.h>
#include <linux/spinlock.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/kref.h>
#include <linux/atomic.h>
#include <linux/aer.h>
#include <linux/mutex.h>
#include <linux/timer.h>
#include "pcie.h"
#define ELBI_BASE         0  /* MMIO offset of ELBI registers */
#include "nnp_elbi.h"
#include "nnp_log.h"
#include "nnp_time.h"
#include "nnp_inbound_mem.h"
#include "nnp_boot_defs.h"

/*
 * SpringHill PCI card identity settings
 */
#define NNP_PCI_DEVICE_ID		0x45c6
#define NNP_PCI_VENDOR_ID		PCI_VENDOR_ID_INTEL
#define NNP_PCI_DEVFN                   0
#define NNP_PCI_MMIO_BAR                0
#define NNP_PCI_INBOUND_MEM_BAR         2

#ifdef CONFIG_64BIT
#define USE_64BIT_MMIO
#endif

/* error injection debug feature registers */
#define NNP_RAS_DES_VSEC_ID   0x2
#define EINJ_ENABLE_REG_OFF       0x30
#define EINJ_ENABLE_REG_CRC_ERR  BIT(0)
#define EINJ_ENABLE_REG_SEQ_ERR  BIT(1)
#define EINJ_ENABLE_REG_DUP_ERR  BIT(5)
#define EINJ_ENABLE_REG_TLP_ERR  BIT(6)

#define EINJ0_CRC_REG_OFF         0x34

static const char nnp_driver_name[] = "nnp_pcie";
static const struct nnpdrv_device_hw_callbacks *s_nnp_callbacks;

static DEFINE_MUTEX(s_mutex);
struct workqueue_struct *s_rescan_wq;
struct kref s_rescan_wq_kref = KREF_INIT(0);

/* interrupt mask bits we enable and handle at interrupt level */
static u32 s_card_status_int_mask =
		   ELBI_PCI_STATUS_COMMAND_FIFO_READ_UPDATE_MASK;

/* interrupt mask bits we enable and handle at threaded interrupt level */
static u32 s_card_status_threaded_mask =
		   ELBI_PCI_STATUS_RESPONSE_FIFO_NEW_RESPONSE_MASK |
		   ELBI_PCI_STATUS_DOORBELL_MASK;

/* pcie_err_reset_mode
 *    0 = do not auto issue FLR on non-fatal uncorrectable error
 *    1 = issue FLR on non-fatal uncorrectable error
 */
int pcie_err_reset_mode;
module_param(pcie_err_reset_mode,  int, 0400);

/* Interrupts mask check timer interval */
static u32 interrupts_mask_check_timer_ms = 3000;
module_param(interrupts_mask_check_timer_ms, uint, 0644);

static int disable_keep_alive;
module_param(disable_keep_alive, int, 0644);

struct nnp_memdesc {
	phys_addr_t   pa;
	void __iomem *va;
	size_t        len;
};

struct nnp_pci_device {
	struct kref     ref;
	struct pci_dev *pdev;
	struct pci_dev *port_dev;
	struct device  *dev;
	struct nnp_device *nnpdev;

	struct nnp_hw_device_info device_info;
	struct nnp_memdesc mmio;
	struct nnp_memdesc mem_bar;
	int             ras_des_off;
	int             aer_pos;
	u32             aer_cor_mask;
	u32             aer_uncor_mask;
	u32             aer_uncor_severity;

	spinlock_t      irq_lock; /* protects cmdq_free_slots calculation */
	u64             response_buf[ELBI_RESPONSE_FIFO_DEPTH];
	atomic_t        new_response;
	atomic_t        doorbell_changed;
	u32             card_doorbell_val;

	spinlock_t      cmdq_lock; /* for cmdq write serialization */
	u32             cmdq_free_slots;

	u32               card_status;
	wait_queue_head_t card_status_wait;
	u32               cmd_read_update_count;

	u32                initted;
	u32                needs_reset;
	struct work_struct reset_work;

	int                keep_alive;
	bool               hang;
	bool               periodic_on;
	bool               removing;

	u32		   port_aer_uncor_mask;
	struct timer_list  interrupts_mask_timer;
};

static int nnp_init_pci_device(struct nnp_pci_device *nnp_pci);
static void nnp_fini_pci_device(struct nnp_pci_device *nnp_pci);

static void start_reset_work(struct nnp_pci_device *nnp_pci,
			     struct workqueue_struct *wq,
			     work_func_t            handler);

static void nnp_reset_prepare(struct pci_dev *dev);
static void nnp_reset_done(struct pci_dev *dev);

static void destroy_rescan_wq(struct kref *kref)
{
	destroy_workqueue(s_rescan_wq);
	s_rescan_wq = NULL;
}

static void free_nnp_pci(struct kref *kref)
{
	struct nnp_pci_device *nnp_pci = container_of(kref,
						      struct nnp_pci_device,
						      ref);

	pci_set_drvdata(nnp_pci->pdev, NULL);
	pci_dev_put(nnp_pci->pdev);
	kref_put(&s_rescan_wq_kref, destroy_rescan_wq);
	kfree(nnp_pci);
}

static int nnp_pci_get(struct nnp_pci_device *nnp_pci)
{
	return kref_get_unless_zero(&nnp_pci->ref);
}

static int nnp_pci_put(struct nnp_pci_device *nnp_pci)
{
	return kref_put(&nnp_pci->ref, free_nnp_pci);
}

static inline void nnp_mmio_write(struct nnp_pci_device *nnp_pci,
				  u32                    off,
				  u32                    val)
{
	iowrite32(val, nnp_pci->mmio.va + off);
}

static inline u32 nnp_mmio_read(struct nnp_pci_device *nnp_pci,
				u32               off)
{
	u32 ret;

	ret = ioread32(nnp_pci->mmio.va + off);

	return ret;
}

static inline void nnp_mmio_write_8b(struct nnp_pci_device *nnp_pci,
				     u32                    off,
				     u64                    val)
{
#ifdef USE_64BIT_MMIO
	writeq(val, nnp_pci->mmio.va + off);
#else
	nnp_mmio_write(nnp_pci,
		       off,
		       lower_32_bits(val));
	nnp_mmio_write(nnp_pci,
		       off,
		       upper_32_bits(val));
#endif
}

static inline u64 nnp_mmio_read_8b(struct nnp_pci_device *nnp_pci,
				   u32                    off)
{
#ifdef USE_64BIT_MMIO
	u64 ret;

	ret = readq(nnp_pci->mmio.va + off);

	return ret;
#else
	u32 low, high;
	u64 ret;

	low = nnp_mmio_read(nnp_pci,
			    ELBI_RESPONSE_FIFO_LOW(off));
	high = nnp_mmio_read(nnp_pci,
			     ELBI_RESPONSE_FIFO_HIGH(off));
	ret = (high << 32) | low;
	return ret;
#endif
}

static void nnp_process_commands(struct nnp_pci_device *nnp_pci)
{
	u32 response_pci_control;
	u32 read_pointer;
	u32 write_pointer;
	u32 avail_slots;
	int i;

	response_pci_control = nnp_mmio_read(nnp_pci,
					     ELBI_RESPONSE_PCI_CONTROL);
	read_pointer =
		ELBI_BF_GET(response_pci_control,
			    ELBI_RESPONSE_PCI_CONTROL_READ_POINTER_MASK,
			    ELBI_RESPONSE_PCI_CONTROL_READ_POINTER_SHIFT);
	write_pointer =
		ELBI_BF_GET(response_pci_control,
			    ELBI_RESPONSE_PCI_CONTROL_WRITE_POINTER_MASK,
			    ELBI_RESPONSE_PCI_CONTROL_WRITE_POINTER_SHIFT);
	if (read_pointer > write_pointer) {
		nnp_log_err(START_UP_LOG,
			    "Mismatched read and write pointers\n");
		return;
	}

	/* Commands to read */
	avail_slots = write_pointer - read_pointer;

	if (!avail_slots)
		return;

	for (i = 0; i < avail_slots; i++) {
		read_pointer = (read_pointer + 1) % ELBI_RESPONSE_FIFO_DEPTH;

		nnp_pci->response_buf[i] =
			nnp_mmio_read_8b(nnp_pci,
					 ELBI_RESPONSE_FIFO_LOW(read_pointer));
	}

	/*
	 * HW restriction - we cannot update the read pointer with the same
	 * value it currently have. This will be the case if we need to advance
	 * it by FIFO_DEPTH locations. In this case we will update it in two
	 * steps, first advance by 1, then to the proper value.
	 */
	if (avail_slots == ELBI_COMMAND_FIFO_DEPTH) {
		u32 next_read_pointer =
			(read_pointer + 1) % ELBI_RESPONSE_FIFO_DEPTH;

		ELBI_BF_SET(response_pci_control,
			    next_read_pointer,
			    ELBI_RESPONSE_PCI_CONTROL_READ_POINTER_MASK,
			    ELBI_RESPONSE_PCI_CONTROL_READ_POINTER_SHIFT);
		nnp_mmio_write(nnp_pci,
			       ELBI_RESPONSE_PCI_CONTROL,
			       response_pci_control);
	}

	ELBI_BF_SET(response_pci_control,
		    read_pointer,
		    ELBI_RESPONSE_PCI_CONTROL_READ_POINTER_MASK,
		    ELBI_RESPONSE_PCI_CONTROL_READ_POINTER_SHIFT);
	nnp_mmio_write(nnp_pci,
		       ELBI_RESPONSE_PCI_CONTROL,
		       response_pci_control);

	if (nnp_pci->nnpdev)
		s_nnp_callbacks->process_messages(nnp_pci->nnpdev,
						  nnp_pci->response_buf,
						  avail_slots);
}

static irqreturn_t interrupt_handler(int irq, void *data)
{
	struct nnp_pci_device *nnp_pci = (struct nnp_pci_device *)data;
	irqreturn_t ret;
	unsigned long flags;
	bool should_wake = false;
	u32 card_boot_state;

	spin_lock_irqsave(&nnp_pci->irq_lock, flags);

	/* clear interrupts mask */
	nnp_mmio_write(nnp_pci,
		       ELBI_PCI_MSI_MASK,
		       UINT_MAX);

	nnp_pci->card_status = nnp_mmio_read(nnp_pci, ELBI_PCI_STATUS);

#ifdef ULT
	INT_STAT_INC(int_stats,
		     (nnp_pci->card_status &
		      (s_card_status_int_mask | s_card_status_threaded_mask)));
#endif

	nnp_mmio_write(nnp_pci,
		       ELBI_PCI_STATUS,
		       nnp_pci->card_status &
		       (s_card_status_int_mask | s_card_status_threaded_mask));

	if (nnp_pci->card_status &
	    ELBI_PCI_STATUS_COMMAND_FIFO_READ_UPDATE_MASK) {
		should_wake = true;
		nnp_pci->cmd_read_update_count++;
	}

	if (nnp_pci->card_status &
	    ELBI_PCI_STATUS_RESPONSE_FIFO_NEW_RESPONSE_MASK) {
		atomic_set(&nnp_pci->new_response, 1);
	}

	if (nnp_pci->card_status &
	    ELBI_PCI_STATUS_DOORBELL_MASK) {
		nnp_pci->card_doorbell_val =
			nnp_mmio_read(nnp_pci, ELBI_HOST_PCI_DOORBELL_VALUE);

		/* reset keep alive counter if card driver is down */
		card_boot_state =
			((nnp_pci->card_doorbell_val & NNP_CARD_BOOT_STATE_MASK)
			 >> NNP_CARD_BOOT_STATE_SHIFT);
		if (card_boot_state != NNP_CARD_BOOT_STATE_DRV_READY &&
		    card_boot_state != NNP_CARD_BOOT_STATE_CARD_READY)
			nnp_pci->keep_alive = 0;

		atomic_set(&nnp_pci->doorbell_changed, 1);
	}

	if (nnp_pci->card_status & s_card_status_threaded_mask)
		ret = IRQ_WAKE_THREAD;
	else
		ret = IRQ_HANDLED;

	/* Enable desired interrupts */
	nnp_mmio_write(nnp_pci,
		       ELBI_PCI_MSI_MASK,
		       ~(s_card_status_int_mask | s_card_status_threaded_mask));

	spin_unlock_irqrestore(&nnp_pci->irq_lock, flags);

	if (should_wake)
		wake_up_all(&nnp_pci->card_status_wait);

	return ret;
}

static irqreturn_t threaded_interrupt_handler(int irq, void *data)
{
	struct nnp_pci_device *nnp_pci = (struct nnp_pci_device *)data;

	if (atomic_xchg(&nnp_pci->doorbell_changed, 0)) {
		if (nnp_pci->nnpdev)
			s_nnp_callbacks->card_doorbell_value_changed(
						nnp_pci->nnpdev,
						nnp_pci->card_doorbell_val);
	}

	if (atomic_xchg(&nnp_pci->new_response, 0))
		nnp_process_commands(nnp_pci);

	return IRQ_HANDLED;
}

static int nnp_setup_interrupts(struct nnp_pci_device *nnp_pci,
				struct pci_dev        *pdev)
{
	int rc;

	rc = pci_enable_msi(pdev);
	if (rc) {
		nnp_log_err(START_UP_LOG, "Error enabling MSI. rc = %d\n", rc);
		return rc;
	}

	rc = request_threaded_irq(pdev->irq,
				  interrupt_handler,
				  threaded_interrupt_handler,
				  IRQF_ONESHOT,
				  "nnpi-msi",
				  nnp_pci);
	if (rc) {
		nnp_log_err(START_UP_LOG, "Error allocating MSI interrupt\n");
		goto err_irq_req_fail;
	}

	nnp_log_debug(START_UP_LOG, "nnp_pcie MSI irq setup done\n");

	return 0;

err_irq_req_fail:
	pci_disable_msi(pdev);
	return rc;
}

static void nnp_free_interrupts(struct nnp_pci_device *nnp_pci,
				struct pci_dev        *pdev)
{
	free_irq(pdev->irq, nnp_pci);
	pci_disable_msi(pdev);
}

static int nnp_cmdq_write_mesg_nowait(struct nnp_pci_device *nnp_pci,
				      u64                   *msg,
				      u32                    size,
				      u32                   *read_update_count)
{
	u32 cmd_iosf_control;
	u32 read_pointer, write_pointer;
	unsigned long flags;
	int i;

	if (!nnp_pci->initted)
		return -ENODEV;

	if (size < 1)
		return 0;

	spin_lock(&nnp_pci->cmdq_lock);

	if (nnp_pci->cmdq_free_slots < size) {
		/* read command fifo pointers and compute free slots in fifo */
		spin_lock_irqsave(&nnp_pci->irq_lock, flags);
		cmd_iosf_control = nnp_mmio_read(nnp_pci,
						 ELBI_COMMAND_IOSF_CONTROL);
		read_pointer =
			ELBI_BF_GET(cmd_iosf_control,
				  ELBI_COMMAND_IOSF_CONTROL_READ_POINTER_MASK,
				  ELBI_COMMAND_IOSF_CONTROL_READ_POINTER_SHIFT);
		write_pointer =
			ELBI_BF_GET(cmd_iosf_control,
				 ELBI_COMMAND_IOSF_CONTROL_WRITE_POINTER_MASK,
				 ELBI_COMMAND_IOSF_CONTROL_WRITE_POINTER_SHIFT);

		nnp_pci->cmdq_free_slots = ELBI_COMMAND_FIFO_DEPTH -
					   (write_pointer - read_pointer);

		if (nnp_pci->cmdq_free_slots < size) {
			*read_update_count = nnp_pci->cmd_read_update_count;
			spin_unlock_irqrestore(&nnp_pci->irq_lock, flags);
			spin_unlock(&nnp_pci->cmdq_lock);
			return -EAGAIN;
		}
		spin_unlock_irqrestore(&nnp_pci->irq_lock, flags);
	}

	/* Write all but the last message without generating msi on card */
	for (i = 0; i < size - 1; i++) {
		nnp_mmio_write_8b(nnp_pci,
				  ELBI_COMMAND_WRITE_WO_MSI_LOW,
				  msg[i]);
	}

	/* Write last message with generating interrupt on card */
	nnp_mmio_write_8b(nnp_pci,
			  ELBI_COMMAND_WRITE_W_MSI_LOW,
			  msg[i]);

	nnp_pci->cmdq_free_slots -= size;

	spin_unlock(&nnp_pci->cmdq_lock);

	return 0;
}

static int nnp_cmdq_write_mesg(void *hw_handle,
			       u64  *msg,
			       u32   size,
			       u64 *timed_wait)
{
	struct nnp_pci_device *nnp_pci = (struct nnp_pci_device *)hw_handle;
	int rc;
	u32 read_update_count = 0;
	u64 start = 0;

	rc = nnp_cmdq_write_mesg_nowait(hw_handle, msg, size,
					&read_update_count);
	if (rc == -EAGAIN && timed_wait) {
		start = nnp_time_us();
	} else if (timed_wait) {
		*timed_wait = 0;
		timed_wait = NULL;
	}

	while (rc == -EAGAIN) {
		rc = wait_event_interruptible(
			nnp_pci->card_status_wait,
			read_update_count != nnp_pci->cmd_read_update_count ||
			!nnp_pci->initted);
		if (rc)
			break;

		rc = nnp_cmdq_write_mesg_nowait(hw_handle, msg, size,
						&read_update_count);
	}

	if (timed_wait)
		*timed_wait = nnp_time_us() - start;

	if (rc)
		nnp_log_err(GENERAL_LOG,
			    "failed to write message size %d rc=%d!!\n",
			    size, rc);

	return rc;
}

static int nnp_cmdq_flush(void *hw_handle)
{
	struct nnp_pci_device *nnp_pci = (struct nnp_pci_device *)hw_handle;

	if (!nnp_pci->initted)
		return -ENODEV;

	nnp_mmio_write(nnp_pci,
		       ELBI_COMMAND_PCI_CONTROL,
		       ELBI_COMMAND_PCI_CONTROL_FLUSH_MASK);

	return 0;
}

static u32 nnp_get_card_doorbell_value(void *hw_handle)
{
	struct nnp_pci_device *nnp_pci = (struct nnp_pci_device *)hw_handle;
	u32 doorbell_val;

	if (!nnp_pci->initted)
		return 0xfffffffe;

	doorbell_val = nnp_mmio_read(nnp_pci, ELBI_HOST_PCI_DOORBELL_VALUE);
	return doorbell_val;
}

static int nnp_set_host_doorbell_value(void *hw_handle, u32 value)
{
	struct nnp_pci_device *nnp_pci = (struct nnp_pci_device *)hw_handle;

	if (!nnp_pci->initted)
		return -ENODEV;

	/*
	 * The SELF_RESET bit is set only by the h/w layer,
	 * do not allow higher layer to set it
	 */
	value &= ~(NNP_HOST_DRV_REQUEST_SELF_RESET_MASK);

	nnp_mmio_write(nnp_pci, ELBI_PCI_HOST_DOORBELL_VALUE, value);

	return 0;
}

static void rescan_work_handler(struct work_struct *work)
{
	struct nnp_pci_device *nnp_pci = container_of(work,
						      struct nnp_pci_device,
						      reset_work);
	struct pci_dev *port_dev = nnp_pci->port_dev;
	struct pci_bus *bus;
	struct pci_dev *pdev;
	int aer_pos;
	u32 uncor_status;
	int retries = 0;

	/* Get AER uncorrected status of the port device */
	aer_pos = pci_find_ext_capability(port_dev, PCI_EXT_CAP_ID_ERR);
	if (!aer_pos)
		goto done;

	/*
	 * continue with device remove/rescan only if surpriose remove has
	 * happened
	 */
	pci_read_config_dword(port_dev,
			      aer_pos + PCI_ERR_UNCOR_STATUS,
			      &uncor_status);
	if ((uncor_status & PCI_ERR_UNC_SURPDN) == 0)
		goto done;

	bus = port_dev->subordinate;
	pdev = pci_get_slot(bus, PCI_DEVFN(0, 0));
	if (!pdev) {
		nnp_log_err(GENERAL_LOG,
			    "NNP-I device at bus %s already removed!!\n",
			    pci_name(port_dev));
		goto done;
	}

	/* remove device */
	nnp_pci_put(nnp_pci);
	pci_stop_and_remove_bus_device_locked(pdev);
	pci_dev_put(pdev);

	/* rescan port device to re-enumerate the card */
	do {
		if (retries > 0)
			nnp_log_err(GENERAL_LOG,
				    "NNP-I device rescan retry %d\n", retries);

		pci_lock_rescan_remove();
		pci_scan_child_bus(bus);
		pci_assign_unassigned_bridge_resources(port_dev);
		pci_bus_add_devices(bus);
		pci_unlock_rescan_remove();

		pdev = pci_get_slot(bus, PCI_DEVFN(0, 0));
		if (pdev) {
			pci_dev_put(pdev);
			break;
		}
		msleep(2000);
	} while (retries++ < 10);

	return;

done:
	nnp_pci_put(nnp_pci);
}

static bool pre_surprise_down_reset(struct nnp_pci_device *nnp_pci)
{
	struct pci_dev *port_dev;
	int ret;
	int aer_pos;
	u16 slot_ctrl;

	port_dev = pci_upstream_bridge(nnp_pci->pdev);
	if (!port_dev)
		return false;

	ret = pcie_capability_read_word(port_dev, PCI_EXP_SLTCTL, &slot_ctrl);
	if (ret)
		return false;

	nnp_log_debug(GENERAL_LOG,
		      "has pciehp %d (0x%x)\n",
		      (slot_ctrl & PCI_EXP_SLTCTL_HPIE) != 0, slot_ctrl);
	if ((slot_ctrl & PCI_EXP_SLTCTL_HPIE) != 0)
		return false;

	aer_pos = pci_find_ext_capability(port_dev, PCI_EXT_CAP_ID_ERR);
	if (!aer_pos)
		return false;

	/*
	 * No hot-plug driver installed on the port device,
	 * We will need to re-enumerate the device after the link will go
	 * down.
	 * Mask the surprise-down error to prevent the error to be handled
	 * (since this is expected and will be handled in the
	 * post_surprise_down) function
	 */
	pci_read_config_dword(port_dev, aer_pos + PCI_ERR_UNCOR_MASK,
			      &nnp_pci->port_aer_uncor_mask);
	if ((nnp_pci->port_aer_uncor_mask & PCI_ERR_UNC_SURPDN) == 0) {
		pci_write_config_dword(port_dev,
				       aer_pos + PCI_ERR_UNCOR_MASK,
				       nnp_pci->port_aer_uncor_mask |
				       PCI_ERR_UNC_SURPDN);
	}

	/*
	 * flag that post_surprise_down function need to be called after the
	 * reset
	 */
	return true;
}

static int post_surprise_down_reset(struct nnp_pci_device *nnp_pci)
{
	struct pci_dev *port_dev;
	int retries = 5;
	int aer_pos;
	u32 uncor_status;

	port_dev = pci_upstream_bridge(nnp_pci->pdev);
	if (!port_dev)
		return -EINVAL;

	aer_pos = pci_find_ext_capability(port_dev, PCI_EXT_CAP_ID_ERR);
	if (!aer_pos)
		return -EINVAL;

	/* Wait for surprise-removal to happen */
	do {
		pci_read_config_dword(port_dev,
				      aer_pos + PCI_ERR_UNCOR_STATUS,
				      &uncor_status);
		if ((uncor_status & PCI_ERR_UNC_SURPDN) == 0) {
			msleep(100);
		} else {
			/*
			 * surprise remove happened - schedule device
			 * re-enumeration
			 */
			start_reset_work(nnp_pci,
					 s_rescan_wq, rescan_work_handler);
			break;
		}
	} while (--retries);

	if (!retries)
		nnp_log_err(GENERAL_LOG,
			    "Surprise remove has not been detected for %s\n",
			    pci_name(port_dev));

	return 0;
}

static int nnp_reset(void *hw_handle)
{
	struct nnp_pci_device *nnp_pci = (struct nnp_pci_device *)hw_handle;
	u32 card_state;
	u32 card_flr_mode = 0;

	if (nnp_pci->initted) {
		card_state = nnp_mmio_read(nnp_pci, ELBI_CPU_STATUS_2);
		card_flr_mode =
			(card_state & ELBI_CPU_STATUS_2_FLR_MODE_MASK) >>
			ELBI_CPU_STATUS_2_FLR_MODE_SHIFT;
	}

	/* if card flr_mode is cold reset,
	 * the card will be surprised removed.
	 * So we better request the card to reset itself not through
	 * FLR flow since we know we wont be recover without re-enumerating
	 * the device.
	 * The hot-plug driver will detect the surprise removal and link-up when
	 * the card reset completes. If no hot-plug driver exist we will
	 * initiate a work to remove and re-enumerate the device after the
	 * reset.
	 */
	if (card_flr_mode == 1) {
		u32 host_db_val;
		bool need_post_surprise_down;

		/* stop periodic timer which detect device reset */
		if (nnp_pci->periodic_on) {
			del_timer(&nnp_pci->interrupts_mask_timer);
			nnp_pci->periodic_on = false;
		}

		need_post_surprise_down = pre_surprise_down_reset(nnp_pci);
		if (s_nnp_callbacks->reset_prepare)
			s_nnp_callbacks->reset_prepare(nnp_pci->nnpdev, false);

		msleep(200);
		host_db_val = nnp_mmio_read(nnp_pci,
					    ELBI_PCI_HOST_DOORBELL_VALUE);
		host_db_val |= NNP_HOST_DRV_REQUEST_SELF_RESET_MASK;
		nnp_mmio_write(nnp_pci,
			       ELBI_PCI_HOST_DOORBELL_VALUE, host_db_val);

		if (need_post_surprise_down)
			post_surprise_down_reset(nnp_pci);

		return 0;
	}

	return pci_reset_function(nnp_pci->pdev);
}

u32 nnp_get_postcode(void *hw_handle)
{
	struct nnp_pci_device *nnp_pci = (struct nnp_pci_device *)hw_handle;
	u32 val;

	if (!nnp_pci->initted)
		return 0xfffffffe;

	/* bios post-code is reported in CPU_STATUS_0 register */
	val = nnp_mmio_read(nnp_pci, ELBI_CPU_STATUS_0);

	return val;
}

u32 nnp_get_bios_flash_progress(void *hw_handle)
{
	struct nnp_pci_device *nnp_pci = (struct nnp_pci_device *)hw_handle;
	u32 val;

	if (!nnp_pci->initted)
		return 0xfffffffe;

	/* bios flash progress is reported in CPU_STATUS_1 register */
	val = nnp_mmio_read(nnp_pci, ELBI_CPU_STATUS_1);

	return val;
}

int nnp_get_membar_addr(void *hw_handle,
			u64   *out_phy_addr,
			void **out_vaddr,
			size_t *out_size)
{
	struct nnp_pci_device *nnp_pci = (struct nnp_pci_device *)hw_handle;

	if (out_phy_addr)
		*out_phy_addr = nnp_pci->mem_bar.pa;

	if (out_vaddr)
		*out_vaddr = nnp_pci->mem_bar.va;

	if (out_size)
		*out_size = nnp_pci->mem_bar.len;

	return 0;
}

static int nnp_error_inject(void *hw_handle,
			    int   err_type)
{
	struct nnp_pci_device *nnp_pci = (struct nnp_pci_device *)hw_handle;
	u32 inj_enable = 0;

	if (nnp_pci->ras_des_off == 0)
		return -EFAULT;

	switch (err_type) {
	case NNP_PCIE_INJECT_RESTORE:
		pci_write_config_dword(nnp_pci->pdev,
				       nnp_pci->aer_pos + PCI_ERR_COR_MASK,
				       nnp_pci->aer_cor_mask);
		pci_write_config_dword(nnp_pci->pdev,
				       nnp_pci->aer_pos + PCI_ERR_UNCOR_MASK,
				       nnp_pci->aer_uncor_mask);
		pci_write_config_dword(nnp_pci->pdev,
				       nnp_pci->aer_pos + PCI_ERR_UNCOR_SEVER,
				       nnp_pci->aer_uncor_severity);
		break;
	case NNP_PCIE_INJECT_CORR:
		/* unmask all corrected errors */
		pci_write_config_dword(nnp_pci->pdev,
				       nnp_pci->aer_pos + PCI_ERR_COR_MASK,
				       0x0);
		/* mask all corrected errors */
		pci_write_config_dword(nnp_pci->pdev,
				       nnp_pci->aer_pos + PCI_ERR_UNCOR_MASK,
				       0xffffffff);
		/* set completion timeout error to be non-fatal error */
		pci_write_config_dword(nnp_pci->pdev,
				       nnp_pci->aer_pos + PCI_ERR_UNCOR_SEVER,
				       (nnp_pci->aer_uncor_severity &
					~(PCI_ERR_UNC_COMP_TIME)));
		break;
	case NNP_PCIE_INJECT_UNCORR:
		/* mask all corrected errors */
		pci_write_config_dword(nnp_pci->pdev,
				       nnp_pci->aer_pos + PCI_ERR_COR_MASK,
				       0xffffffff);
		/* unmask completion timeout error */
		pci_write_config_dword(nnp_pci->pdev,
				       nnp_pci->aer_pos + PCI_ERR_UNCOR_MASK,
				       (nnp_pci->aer_uncor_mask &
					~(PCI_ERR_UNC_COMP_TIME)));
		/* set completion timeout error to be non-fatal error */
		pci_write_config_dword(nnp_pci->pdev,
				       nnp_pci->aer_pos + PCI_ERR_UNCOR_SEVER,
				       (nnp_pci->aer_uncor_severity &
					~(PCI_ERR_UNC_COMP_TIME)));
		break;
	case NNP_PCIE_INJECT_UNCORR_FATAL:
		/* mask all corrected errors */
		pci_write_config_dword(nnp_pci->pdev,
				       nnp_pci->aer_pos + PCI_ERR_COR_MASK,
				       0xffffffff);
		/* unmask completion timeout error */
		pci_write_config_dword(nnp_pci->pdev,
				       nnp_pci->aer_pos + PCI_ERR_UNCOR_MASK,
				       (nnp_pci->aer_uncor_mask &
					~(PCI_ERR_UNC_COMP_TIME)));
		/* set completion timeout error to be fatal error */
		pci_write_config_dword(nnp_pci->pdev,
				       nnp_pci->aer_pos + PCI_ERR_UNCOR_SEVER,
				       (nnp_pci->aer_uncor_severity |
					PCI_ERR_UNC_COMP_TIME));
		break;
	default:
		return -EFAULT;
	}

	if (err_type != NNP_PCIE_INJECT_RESTORE) {
		/*
		 * insert new TLP with ECRC error - will cause completion
		 * timeout error
		 */
		inj_enable = EINJ_ENABLE_REG_CRC_ERR;

		nnp_log_info(GENERAL_LOG, "Injecting %s PCIe error\n",
			     (err_type == NNP_PCIE_INJECT_CORR ? "corrected" :
			      err_type == NNP_PCIE_INJECT_UNCORR ?
			      "uncorrected" : "uncorrected-fatal"));
		if (err_type != NNP_PCIE_INJECT_CORR) {
			pci_write_config_word(nnp_pci->pdev,
					      nnp_pci->ras_des_off +
					      EINJ0_CRC_REG_OFF,
					      0x3 << 8 | 1);
		} else {
			pci_write_config_word(nnp_pci->pdev,
					      nnp_pci->ras_des_off +
					      EINJ0_CRC_REG_OFF,
					      0x4 << 8 | 1);
		}
	} else {
		nnp_log_info(GENERAL_LOG, "Restoring pcie error masks\n");
	}

#ifdef DEBUG
	{
		u32 cor_mask, uncor_mask, uncor_sev;

		pci_read_config_dword(nnp_pci->pdev,
				      nnp_pci->aer_pos + PCI_ERR_COR_MASK,
				      &cor_mask);
		pci_read_config_dword(nnp_pci->pdev,
				      nnp_pci->aer_pos + PCI_ERR_UNCOR_MASK,
				      &uncor_mask);
		pci_read_config_dword(nnp_pci->pdev,
				      nnp_pci->aer_pos + PCI_ERR_UNCOR_SEVER,
				      &uncor_sev);

		nnp_log_debug(GENERAL_LOG, "inj_enable = %d\n", inj_enable);
		nnp_log_debug(GENERAL_LOG, "corr_mask = 0x%x\n", cor_mask);
		nnp_log_debug(GENERAL_LOG,
			      "uncorr_mask = 0x%x ComplTO%c\n", uncor_mask,
			      (uncor_mask & PCI_ERR_UNC_COMP_TIME) ? '+' : '-');
		nnp_log_debug(GENERAL_LOG,
			      "uncorr_sever = 0x%x ComplTO%c\n", uncor_sev,
			      (uncor_sev & PCI_ERR_UNC_COMP_TIME) ? '+' : '-');
	}
#endif

	pci_write_config_word(nnp_pci->pdev,
			      nnp_pci->ras_des_off + EINJ_ENABLE_REG_OFF,
			      inj_enable);

	return 0;
}

static dma_addr_t nnp_get_host_doorbell_addr(void *hw_handle)
{
	struct nnp_pci_device *nnp_pci = (struct nnp_pci_device *)hw_handle;

	/* Doorbell is a shared resource. For peer-to-peer we use only MSB */
	return (nnp_pci->mmio.pa + ELBI_PCI_HOST_DOORBELL_VALUE + 3);
}

static struct nnpdrv_device_hw_ops pcie_nnp_ops = {
	.write_mesg        = nnp_cmdq_write_mesg,
	.flush_command_fifo = nnp_cmdq_flush,
	.get_card_doorbell_value = nnp_get_card_doorbell_value,
	.set_host_doorbell_value = nnp_set_host_doorbell_value,
	.reset = nnp_reset,
	.get_postcode = nnp_get_postcode,
	.get_bios_flash_progress = nnp_get_bios_flash_progress,
	.get_membar_addr = nnp_get_membar_addr,
	.error_inject = nnp_error_inject,
	.get_host_doorbell_addr = nnp_get_host_doorbell_addr
};

static void pcie_dev_reinit_work_handler(struct work_struct *work)
{
	struct nnp_pci_device *nnp_pci = container_of(work,
						      struct nnp_pci_device,
						      reset_work);

	if (!nnp_pci->removing) {
		nnp_reset_prepare(nnp_pci->pdev);
		nnp_reset_done(nnp_pci->pdev);
	}

	nnp_pci_put(nnp_pci);
}

static void nnp_interrupts_mask_reg_check(struct timer_list *timer)
{
	struct nnp_pci_device *nnp_pci = from_timer(nnp_pci,
						    timer,
						    interrupts_mask_timer);
	u32 interrupts_mask_val;
	unsigned long flags;
	u32 en_interrupts_mask = (s_card_status_int_mask |
				  s_card_status_threaded_mask);
	u32 card_doorbell;
	u32 host_doorbell;
	u8 card_boot_state;
	bool sched_reset_work = false;

	spin_lock_irqsave(&nnp_pci->irq_lock, flags);
	interrupts_mask_val = nnp_mmio_read(nnp_pci, ELBI_PCI_MSI_MASK);

	if (interrupts_mask_val & en_interrupts_mask) {
		nnp_log_info(GENERAL_LOG,
			     "NNPI Device %s configuration changed, device had reset ??? starting recovery...",
			     nnp_pci->device_info.name);

		nnp_mmio_write(nnp_pci,
			       ELBI_PCI_MSI_MASK,
			       ~en_interrupts_mask);

		/* Do pcie hw device reset */
		sched_reset_work = true;
	} else if (!nnp_pci->hang &&
		   !nnp_pci->removing &&
		   !disable_keep_alive) {
		/*
		 * if card driver is up - send keep alive doorbell interrupt
		 * to card. Card driver should responde with the keep alive
		 * value, if card does not respond within two periodic timer
		 * interrupts (i.e. 6 seconds) then the card is in hanged state.
		 */
		card_doorbell = nnp_mmio_read(nnp_pci,
					      ELBI_HOST_PCI_DOORBELL_VALUE);
		card_boot_state = ((card_doorbell & NNP_CARD_BOOT_STATE_MASK) >>
				   NNP_CARD_BOOT_STATE_SHIFT);
		if (card_boot_state == NNP_CARD_BOOT_STATE_DRV_READY ||
		    card_boot_state == NNP_CARD_BOOT_STATE_CARD_READY) {
			if (nnp_pci->keep_alive > 0) {
				int card_keep_alive =
					(int)((card_doorbell &
					       NNP_CARD_KEEP_ALIVE_MASK) >>
					      NNP_CARD_KEEP_ALIVE_SHIFT);
				int d = nnp_pci->keep_alive - card_keep_alive;

				if (d > 1 || d < -1) {
					/* Card is hang !!! */
					nnp_log_info(GENERAL_LOG, "NNPI Device %s hang detected !!!\n",
						     nnp_pci->device_info.name);
					sched_reset_work = true;
					nnp_pci->hang = true;
					nnp_pci->keep_alive = 0;
				}
			}

			if (!sched_reset_work) {
				if (nnp_pci->keep_alive < 14)
					nnp_pci->keep_alive++;
				else
					nnp_pci->keep_alive = 1;

				host_doorbell = nnp_mmio_read(nnp_pci,
						ELBI_PCI_HOST_DOORBELL_VALUE);
				host_doorbell &= ~(NNP_HOST_KEEP_ALIVE_MASK);
				host_doorbell |= (nnp_pci->keep_alive <<
						  NNP_HOST_KEEP_ALIVE_SHIFT);
				nnp_mmio_write(nnp_pci,
					       ELBI_PCI_HOST_DOORBELL_VALUE,
					       host_doorbell);
			}
		} else {
			nnp_pci->keep_alive = 0;
		}
	}

	spin_unlock_irqrestore(&nnp_pci->irq_lock, flags);

	if (sched_reset_work)
		start_reset_work(nnp_pci,
				 s_rescan_wq, pcie_dev_reinit_work_handler);
	else
		mod_timer(&nnp_pci->interrupts_mask_timer,
			  jiffies +
			  msecs_to_jiffies(interrupts_mask_check_timer_ms));
}

static int nnp_init_pci_device(struct nnp_pci_device *nnp_pci)
{
	struct pci_dev *pdev = nnp_pci->pdev;
	u32 doorbell_val, status;
	int rc;
	u32 line_bdf;

	/* enable device */
	rc = pci_enable_device(pdev);
	if (rc) {
		nnp_log_err(START_UP_LOG,
			    "failed to enable pci device. rc=%d\n", rc);
		return rc;
	}

	/* enable bus master capability on device */
	pci_set_master(pdev);

	rc = pci_request_regions(pdev, nnp_driver_name);
	if (rc) {
		nnp_log_err(START_UP_LOG, "failed to get pci regions.\n");
		goto disable_device;
	}

	nnp_pci->mmio.pa = pci_resource_start(pdev, NNP_PCI_MMIO_BAR);
	nnp_pci->mmio.len = pci_resource_len(pdev, NNP_PCI_MMIO_BAR);
	nnp_pci->mmio.va = pci_ioremap_bar(pdev, NNP_PCI_MMIO_BAR);
	if (!nnp_pci->mmio.va) {
		nnp_log_err(START_UP_LOG, "Cannot remap MMIO BAR\n");
		rc = -EIO;
		goto release_regions;
	}

	/* Map inbound memory region BAR */
	nnp_pci->mem_bar.pa = pci_resource_start(pdev, NNP_PCI_INBOUND_MEM_BAR);
	nnp_pci->mem_bar.len = pci_resource_len(pdev, NNP_PCI_INBOUND_MEM_BAR);
	nnp_pci->mem_bar.va = pci_ioremap_bar(pdev, NNP_PCI_INBOUND_MEM_BAR);
	if (!nnp_pci->mem_bar.va) {
		nnp_log_err(START_UP_LOG, "Cannot remap INBOUND_MEM BAR\n");
		rc = -EIO;
		goto unmap_mmio;
	}

	/*
	 * Check that the pci link is in good state:
	 * mmio read should return valid value.
	 */
	line_bdf = nnp_mmio_read(nnp_pci, ELBI_LINE_BDF);
	if (line_bdf == 0xffffffff) {
		nnp_log_err(START_UP_LOG,
			    "PCIe link in bad state line_bdf=0x%x\n", line_bdf);
		rc = -EIO;
		goto unmap_mem_bar;
	}

	nnp_log_info(GENERAL_LOG, "LINE_BDF After init 0x%x\n", line_bdf);

	nnp_log_debug(START_UP_LOG, "Mapped mem bar, len=0x%lx pa=0x%lx va=0x%lx\n",
		      nnp_pci->mem_bar.len,
		      (uintptr_t)nnp_pci->mem_bar.pa,
		      (uintptr_t)nnp_pci->mem_bar.va);

	nnp_log_debug(START_UP_LOG,
		      "nnp_pcie mmio_start is 0x%llx\n", nnp_pci->mmio.pa);
	nnp_log_debug(START_UP_LOG,
		      "nnp_pcie mmio_len   is 0x%zx\n", nnp_pci->mmio.len);

	rc = pci_set_dma_mask(pdev, DMA_BIT_MASK(64));
	if (rc) {
		nnp_log_err(START_UP_LOG, "Cannot set DMA mask\n");
		goto unmap_mem_bar;
	}

	/* clear interrupts mask */
	nnp_mmio_write(nnp_pci,
		       ELBI_PCI_MSI_MASK,
		       UINT_MAX);

	rc = nnp_setup_interrupts(nnp_pci, pdev);
	if (rc) {
		nnp_log_err(START_UP_LOG,
			    "nnp_setup_interrupts failed %d\n", rc);
		goto unmap_mem_bar;
	}

	rc = pci_enable_pcie_error_reporting(pdev);
	if (rc)
		nnp_log_err(START_UP_LOG,
			    "pci_enable_pcie_error_reporting returned %d\n",
			    rc);

	/*
	 * done setting up the new pci device,
	 * add it to the set of NNP-I devices
	 */
	if (!nnp_pci->nnpdev) {
		rc = s_nnp_callbacks->create_nnp_device(nnp_pci,
							&nnp_pci->device_info,
							&pcie_nnp_ops,
							&nnp_pci->nnpdev);
		if (rc) {
			nnp_log_err(START_UP_LOG, "failed to register enumarated NNP-I device");
			goto free_interrupts;
		}
	}

	/* notify bios that host driver is up */
	nnp_cmdq_flush(nnp_pci);
	doorbell_val = nnp_mmio_read(nnp_pci, ELBI_PCI_HOST_DOORBELL_VALUE);
	doorbell_val = (doorbell_val & ~(NNP_HOST_BOOT_STATE_MASK)) |
		NNP_HOST_BOOT_STATE_DRV_READY << NNP_HOST_BOOT_STATE_SHIFT;
	nnp_mmio_write(nnp_pci, ELBI_PCI_HOST_DOORBELL_VALUE, doorbell_val);

	/* Update upper layer with current value of card doorbell value */
	doorbell_val = nnp_mmio_read(nnp_pci, ELBI_HOST_PCI_DOORBELL_VALUE);
	s_nnp_callbacks->card_doorbell_value_changed(nnp_pci->nnpdev,
						     doorbell_val);
	status = nnp_mmio_read(nnp_pci, ELBI_PCI_STATUS);
	if (status & ELBI_PCI_STATUS_DOORBELL_MASK)
		nnp_mmio_write(nnp_pci,
			       ELBI_PCI_STATUS, ELBI_PCI_STATUS_DOORBELL_MASK);

	/* process any exising command in the response queue */
	nnp_process_commands(nnp_pci);

	/* Enable desired interrupts */
	nnp_mmio_write(nnp_pci,
		       ELBI_PCI_MSI_MASK,
		       ~(s_card_status_int_mask | s_card_status_threaded_mask));

	/*
	 * Register periodic timer to check interrupts mask register
	 * in case card crashed, host won't receive any interrupt since
	 * all interrupts are masked.
	 */
	nnp_pci->hang = false;
	timer_setup(&nnp_pci->interrupts_mask_timer,
		    nnp_interrupts_mask_reg_check,
		    0);
	mod_timer(&nnp_pci->interrupts_mask_timer,
		  jiffies + msecs_to_jiffies(interrupts_mask_check_timer_ms));
	nnp_pci->periodic_on = true;

	nnp_log_debug(START_UP_LOG, "nnp_pcie init_pci done.\n");

	nnp_pci->initted = true;
	return 0;

free_interrupts:
	nnp_free_interrupts(nnp_pci, pdev);
unmap_mem_bar:
	iounmap(nnp_pci->mem_bar.va);
unmap_mmio:
	iounmap(nnp_pci->mmio.va);
release_regions:
	pci_release_regions(pdev);
disable_device:
	pci_disable_device(pdev);

	return rc;
}

static void nnp_fini_pci_device(struct nnp_pci_device *nnp_pci)
{
	if (!nnp_pci->initted)
		return;

	nnp_pci->initted = false;
	if (nnp_pci->periodic_on) {
		del_timer(&nnp_pci->interrupts_mask_timer);
		nnp_pci->periodic_on = false;
	}
	wake_up_all(&nnp_pci->card_status_wait);
	nnp_free_interrupts(nnp_pci, nnp_pci->pdev);
	iounmap(nnp_pci->mem_bar.va);
	iounmap(nnp_pci->mmio.va);
	pci_release_regions(nnp_pci->pdev);
	pci_disable_device(nnp_pci->pdev);
}

static void find_ras_des_cap(struct nnp_pci_device *nnp_pci)
{
	int vsec = 0;
	u16 val;

	/* find vendor-specific capability matches RAS_DES */
	do {
		nnp_pci->ras_des_off =
			pci_find_next_ext_capability(nnp_pci->pdev,
						     vsec,
						     PCI_EXT_CAP_ID_VNDR);
		if (nnp_pci->ras_des_off) {
			pci_read_config_word(nnp_pci->pdev,
					     nnp_pci->ras_des_off + 0x4,
					     &val);
			if (val == NNP_RAS_DES_VSEC_ID)
				break;
		}
	} while (nnp_pci->ras_des_off);

	if (!nnp_pci->ras_des_off)
		nnp_log_err(START_UP_LOG, "failed to find RAS DES vendor-specific capability - pcie error injection will not be available!!\n");
}

static int nnp_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	struct nnp_pci_device *nnp_pci = NULL;
	int rc = -ENODEV;

	if (PCI_FUNC(pdev->devfn) != NNP_PCI_DEVFN) {
		nnp_log_err(START_UP_LOG, "unsupported pci.devfn=%u (driver only supports pci.devfn=%u)\n",
			    PCI_FUNC(pdev->devfn), NNP_PCI_DEVFN);
		return -ENODEV;
	}

	nnp_pci = kzalloc(sizeof(*nnp_pci), GFP_KERNEL);
	if (!nnp_pci) {
		rc = -ENOMEM;
		nnp_log_err(START_UP_LOG, "nnp_pci kmalloc failed rc %d\n", rc);
		goto do_exit;
	}

	kref_init(&nnp_pci->ref);
	nnp_pci->pdev = pdev;
	nnp_pci->port_dev = pci_upstream_bridge(pdev);
	nnp_pci->dev = &pdev->dev;
	pci_set_drvdata(pdev, nnp_pci);

	nnp_pci->device_info.hw_device = nnp_pci->dev;
	nnp_pci->device_info.pci_slot = PCI_SLOT(pdev->devfn);
	nnp_pci->device_info.pci_bus = pdev->bus->number;
	nnp_pci->device_info.name = pci_name(pdev);

	init_waitqueue_head(&nnp_pci->card_status_wait);
	spin_lock_init(&nnp_pci->cmdq_lock);
	spin_lock_init(&nnp_pci->irq_lock);

	/*
	 * create global singlethread workqueue to be use for device
	 * rescan/reset. Only take refcount if alreadt exist.
	 */
	mutex_lock(&s_mutex);
	if (!s_rescan_wq) {
		s_rescan_wq = create_singlethread_workqueue("nnp_rescan");
		if (!s_rescan_wq) {
			rc = -EFAULT;
			nnp_log_err(START_UP_LOG, "failed to create global rescan workqueue");
			mutex_unlock(&s_mutex);
			goto do_exit;
		}
	}
	kref_get(&s_rescan_wq_kref);
	mutex_unlock(&s_mutex);

	rc = nnp_init_pci_device(nnp_pci);
	if (rc) {
		kref_put(&s_rescan_wq_kref, destroy_rescan_wq);
		goto do_exit;
	}

	/* Initialize aer masks and severity settings */
	nnp_pci->aer_pos = pci_find_ext_capability(pdev, PCI_EXT_CAP_ID_ERR);
	if (!nnp_pci->aer_pos) {
		rc = -EFAULT;
		nnp_log_err(START_UP_LOG, "Device does not have AER extension? Is it possible?\n");
		goto do_exit;
	}

	pci_read_config_dword(nnp_pci->pdev,
			      nnp_pci->aer_pos + PCI_ERR_COR_MASK,
			      &nnp_pci->aer_cor_mask);
	pci_read_config_dword(nnp_pci->pdev,
			      nnp_pci->aer_pos + PCI_ERR_UNCOR_MASK,
			      &nnp_pci->aer_uncor_mask);
	pci_read_config_dword(nnp_pci->pdev,
			      nnp_pci->aer_pos + PCI_ERR_UNCOR_SEVER,
			      &nnp_pci->aer_uncor_severity);

	/* find vendor-specific capability for error injection */
	find_ras_des_cap(nnp_pci);

	/*
	 * Take refcount to the device which will be released only when
	 * nnpi_pci struct is freed
	 */
	pci_dev_get(nnp_pci->pdev);

	nnp_log_debug(START_UP_LOG, "nnp_pcie probe done.\n");

	return 0;

do_exit:
	if (nnp_pci)
		nnp_fini_pci_device(nnp_pci);
	kfree(nnp_pci);
	pci_set_drvdata(pdev, NULL);
	nnp_log_err(START_UP_LOG, "Probe failed rc %d\n", rc);
	return rc;
}

static void nnp_remove(struct pci_dev *pdev)
{
	struct nnp_pci_device *nnp_pci = NULL;

	nnp_pci = pci_get_drvdata(pdev);
	if (!nnp_pci)
		return;

	nnp_pci->removing = true;

	/* inform card that host driver is down */
	if (nnp_pci->initted)
		nnp_mmio_write(nnp_pci, ELBI_PCI_HOST_DOORBELL_VALUE, 0);

	/* restore device aer mask and severity settings */
	pci_write_config_dword(nnp_pci->pdev,
			       nnp_pci->aer_pos + PCI_ERR_COR_MASK,
			       nnp_pci->aer_cor_mask);
	pci_write_config_dword(nnp_pci->pdev,
			       nnp_pci->aer_pos + PCI_ERR_UNCOR_MASK,
			       nnp_pci->aer_uncor_mask);
	pci_write_config_dword(nnp_pci->pdev,
			       nnp_pci->aer_pos + PCI_ERR_UNCOR_SEVER,
			       nnp_pci->aer_uncor_severity);

	nnp_fini_pci_device(nnp_pci);
	s_nnp_callbacks->destroy_nnp_device(nnp_pci->nnpdev);

	nnp_pci_put(nnp_pci);
}

static void start_reset_work(struct nnp_pci_device *nnp_pci,
			     struct workqueue_struct *wq,
			     work_func_t            handler)
{
	if (!nnp_pci_get(nnp_pci))
		return;

	/* cancel or wait for previous pending reset work */
	if (work_pending(&nnp_pci->reset_work))
		cancel_work_sync(&nnp_pci->reset_work);

	spin_lock(&nnp_pci->cmdq_lock);
	INIT_WORK(&nnp_pci->reset_work, handler);
	if (wq)
		queue_work(wq, &nnp_pci->reset_work);
	else
		schedule_work(&nnp_pci->reset_work);
	spin_unlock(&nnp_pci->cmdq_lock);
}

static pci_ers_result_t nnp_pci_err_error_detected(struct pci_dev *dev,
						   enum pci_channel_state error)
{
	struct nnp_pci_device *nnp_pci = NULL;

	nnp_log_err(GENERAL_LOG, "pci error detected error=%d\n", error);

	nnp_pci = pci_get_drvdata(dev);
	if (!nnp_pci || !s_nnp_callbacks)
		return PCI_ERS_RESULT_NONE;

	if (error == pci_channel_io_normal) {
		/* non-fatal error */

		/* report the event upstream */
		s_nnp_callbacks->pci_error_detected(nnp_pci->nnpdev,
						    NNP_PCIE_NON_FATAL_ERROR);

		/* request to issue FLR when recovery is done */
		nnp_pci->needs_reset = (pcie_err_reset_mode == 1 ? 1 : 0);

		/* no need to reset the PCI bus */
		return PCI_ERS_RESULT_CAN_RECOVER;
	} else if (error == pci_channel_io_frozen) {
		/* fatal error */

		/* report the event upstream */
		s_nnp_callbacks->pci_error_detected(nnp_pci->nnpdev,
						    NNP_PCIE_FATAL_ERROR);

		/* need to reset the link */
		return PCI_ERS_RESULT_NEED_RESET;
	} else if (error == pci_channel_io_perm_failure) {
		/* cannot be recovered */

		/* report the event upstream */
		s_nnp_callbacks->pci_error_detected(nnp_pci->nnpdev,
						    NNP_PCIE_PERMANENT_FAILURE);

		return PCI_ERS_RESULT_DISCONNECT;
	}

	return PCI_ERS_RESULT_NONE;
}

static pci_ers_result_t nnp_pci_err_mmio_enabled(struct pci_dev *dev)
{
	nnp_log_err(GENERAL_LOG, "pci error mmio_enabled\n");
	return PCI_ERS_RESULT_NONE;
}

static pci_ers_result_t nnp_pci_err_slot_reset(struct pci_dev *dev)
{
	u32 cmd;

	nnp_log_err(GENERAL_LOG, "pci error slot_reset\n");

	pci_read_config_dword(dev, 0x4, &cmd);
	if (cmd != 0xffffffff)
		return PCI_ERS_RESULT_RECOVERED;
	else
		return PCI_ERS_RESULT_DISCONNECT;
}

static void nnp_reset_work_handler(struct work_struct *work)
{
	struct nnp_pci_device *nnp_pci = container_of(work,
						      struct nnp_pci_device,
						      reset_work);

	if (nnp_pci->needs_reset && !nnp_pci->removing) {
		nnp_pci->needs_reset = 0;
		nnp_reset(nnp_pci);
	}

	nnp_pci_put(nnp_pci);
}

static void nnp_pci_err_resume(struct pci_dev *dev)
{
	struct nnp_pci_device *nnp_pci = NULL;

	nnp_pci = pci_get_drvdata(dev);
	if (!nnp_pci || !s_nnp_callbacks)
		return;

	nnp_log_err(GENERAL_LOG, "pci error resume\n");

	/* request FLR - h/w may be recovered but need to restart s/w */
	if (nnp_pci->needs_reset)
		start_reset_work(nnp_pci, NULL, nnp_reset_work_handler);
}

static void nnp_reset_prepare(struct pci_dev *dev)
{
	struct nnp_pci_device *nnp_pci = NULL;
	bool is_hang;

	nnp_pci = pci_get_drvdata(dev);
	if (!nnp_pci || !s_nnp_callbacks)
		return;

	nnp_log_info(GENERAL_LOG, "reset_prepare\n");

	is_hang = (nnp_pci->initted && nnp_pci->hang);

	nnp_fini_pci_device(nnp_pci);

	if (s_nnp_callbacks->reset_prepare)
		s_nnp_callbacks->reset_prepare(nnp_pci->nnpdev, is_hang);
}

static void nnp_reset_done(struct pci_dev *dev)
{
	struct nnp_pci_device *nnp_pci = NULL;
	int rc = 0;
	u32 cmd;
	int t = 30;

	nnp_pci = pci_get_drvdata(dev);
	if (!nnp_pci || !s_nnp_callbacks)
		return;

	nnp_log_info(GENERAL_LOG, "reset_done\n");

	do {
		if (nnp_pci->removing)
			break;
		pci_read_config_dword(dev, 0x4, &cmd);
		nnp_log_info(GENERAL_LOG,
			     "config after reset t=%d cmd0 = 0x%x\n", t, cmd);
		if (cmd != 0xffffffff)
			break;
		msleep(100);
	} while (t-- > 0);

	if (nnp_pci->removing) {
		nnp_log_info(GENERAL_LOG, "Device has removed - give up reset/reload\n");
		return;
	}

	if (cmd != 0xffffffff)
		rc = nnp_init_pci_device(nnp_pci);

	if (cmd == 0xffffffff || rc) {
		u32 err = (cmd == 0xffffffff || rc == -EIO ?
			   NNP_PCIE_LINK_RETRAIN_REQUIRED :
			   NNP_PCIE_PERMANENT_FAILURE);

		nnp_log_err(GENERAL_LOG, "failed to initialize pci device after FLR/Reset!!\n");
		if (err == NNP_PCIE_LINK_RETRAIN_REQUIRED)
			nnp_log_err(GENERAL_LOG, "Remove and Rescan device may help.\n");
		if (nnp_pci->nnpdev)
			s_nnp_callbacks->pci_error_detected(nnp_pci->nnpdev,
							    err);
	} else {
		if (s_nnp_callbacks->reset_done)
			s_nnp_callbacks->reset_done(nnp_pci->nnpdev);
	}
}

static struct pci_error_handlers nnp_pci_err_handlers = {
	.error_detected = nnp_pci_err_error_detected,
	.mmio_enabled = nnp_pci_err_mmio_enabled,
	.slot_reset = nnp_pci_err_slot_reset,
	.reset_prepare = nnp_reset_prepare,
	.reset_done = nnp_reset_done,
	.resume = nnp_pci_err_resume
};

static const struct pci_device_id nnp_pci_tbl[] = {
	{PCI_DEVICE(NNP_PCI_VENDOR_ID, NNP_PCI_DEVICE_ID)},
	/* required last entry */
	{ 0, }
};

static struct pci_driver nnp_driver = {
	.name = nnp_driver_name,
	.id_table = nnp_pci_tbl,
	.probe = nnp_probe,
	.remove = nnp_remove,
	.err_handler = &nnp_pci_err_handlers
};

int nnpdrv_pci_init(struct nnpdrv_device_hw_callbacks *nnp_callbacks)
{
	int ret;

	nnp_log_debug(START_UP_LOG, "nnp_pci hw_init\n");

	if (!nnp_callbacks)
		return -EINVAL;

	s_nnp_callbacks = nnp_callbacks;

	ret = pci_register_driver(&nnp_driver);
	if (ret) {
		nnp_log_err(START_UP_LOG,
			    "pci_register_driver failed ret %d\n", ret);
		goto error;
	}

	return ret;

error:
	nnp_log_err(START_UP_LOG, "init failed ret %d\n", ret);
	return ret;
}

void nnpdrv_hw_cleanup(void)
{
	nnp_log_debug(GO_DOWN_LOG, "Cleanup");
	pci_unregister_driver(&nnp_driver);
	s_nnp_callbacks = NULL;
}

