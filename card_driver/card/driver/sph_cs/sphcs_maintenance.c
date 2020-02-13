/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/i2c.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <linux/workqueue.h>
#include "ioctl_maintenance.h"
#include "sphcs_maintenance.h"
#include "sphcs_power.h"
#include "sph_log.h"
#include "sphcs_cs.h"
#include "sphcs_response_page_pool.h"
#include "ipc_protocol.h"
#include "sphcs_dma_sched.h"
#include "dma_page_pool.h"

#define SPH_FPGA_SMBUS_ADDRESS   0x16

#define FPGA_THERMAL_SENSOR_REG         0
#define FPGA_MEMORY_THERMAL_STATUS_REG  1
#define FPGA_AVG_POWER_REG              2
#define FPGA_BIOS_VERSION_REG           3
#define FPGA_INBAND_BIOS_UPDATE_REG     4
#define FPGA_MAX_THERMAL_SENSOR_REG     5
#define FPGA_BOM_ID_REG                 6
#define FPGA_FAB_ID_REG                 7
#define FPGA_TDP_REG                    8
#define FPGA_UPPER_THERMAL_REG          9
#define FPGA_LOWER_THERMAL_REG         10
#define FPGA_REVISION_REG              11
#define FPGA_SCRATCHPAD_REG            12
#define FPGA_FRU_PRD_SERIAL_BASE_REG   13
#define FPGA_FRU_PRD_SERIAL_LEN         6
#define FPGA_FRU_BRD_PART_NO_BASE_REG  20
#define FPGA_FRU_BRD_PART_NO_LEN        5

static struct cdev s_cdev;
static dev_t       s_devnum;
static struct class *s_class;
static struct device *s_dev;
static struct i2c_client *s_fpga_client;
static bool s_force_update_fpga;
static u16 s_board_id;
static u16 s_fab_id;
static u16 s_fpga_rev;
static unsigned char s_prd_serial[SPH_PRD_SERIAL_LEN];
static unsigned char s_brd_part_no[SPH_PART_NUM_LEN];


static struct sph_sys_info s_sys_info_packet;
static bool                s_sys_info_packet_valid;


/*****************************************************************************
 * service file ops operations
 *****************************************************************************/
static inline int is_maint_file(struct file *f);

static int sphcs_maint_open(struct inode *inode, struct file *f)
{
	if (unlikely(!is_maint_file(f)))
		return -EINVAL;

	f->private_data = NULL;

	return 0;
}

static int sphcs_maint_release(struct inode *inode, struct file *f)
{
	if (unlikely(!is_maint_file(f)))
		return -EINVAL;

	return 0;
}

static long thermal_trip(void __user *arg)
{
	int ret = 0;
	struct maint_ioctl_thermal_trip trip_info;

	ret = copy_from_user(&trip_info, arg, sizeof(trip_info));
	if (unlikely(ret != 0))
		return -EIO;

	if (!g_the_sphcs)
		return -ENODEV;

	sphcs_send_event_report_ext(g_the_sphcs,
				    SPH_IPC_THERMAL_TRIP_EVENT,
				    trip_info.trip_num,
				    -1,
				    trip_info.trip_temperature & 0xffff,
				    trip_info.temperature & 0xffff);

	return 0;
}

struct sys_info_dma_data {
	dma_addr_t  host_dma_addr;
	page_handle host_handle;
	dma_addr_t  dma_addr;
	page_handle handle;
};

static int send_sys_info_dma_completed(struct sphcs *sphcs,
				       void *ctx,
				       const void *user_data,
				       int status, u32 timeUS)
{
	struct sys_info_dma_data *dma_data = (struct sys_info_dma_data *)user_data;
	union c2h_SysInfo msg;

	if (status == SPHCS_DMA_STATUS_FAILED) {
		/* dma failed */
		sphcs_response_pool_put_back_response_page(0,
						  dma_data->host_dma_addr,
						  dma_data->host_handle);
	} else {
		msg.value = 0;
		msg.opcode = C2H_OPCODE_NAME(SYS_INFO);
		msg.host_page_hndl = dma_data->host_handle;

		sphcs_msg_scheduler_queue_add_msg(sphcs->public_respq,
						  &msg.value, 1);
	}

	dma_page_pool_set_page_free(sphcs->dma_page_pool,
				    dma_data->handle);

	return 0;
}

static void send_sys_info_handler(struct work_struct *work)
{
	int ret;
	struct sys_info_dma_data dma_data;
	void *vptr;

	if (!s_sys_info_packet_valid)
		return;

	if (!g_the_sphcs)
		return;

	ret = sphcs_response_pool_get_response_page_wait(SPH_MAIN_RESPONSE_POOL_INDEX,
						&dma_data.host_dma_addr,
						&dma_data.host_handle);
	if (ret)
		return;

	ret = dma_page_pool_get_free_page(g_the_sphcs->dma_page_pool,
					  &dma_data.handle,
					  &vptr,
					  &dma_data.dma_addr);
	if (ret) {
		sphcs_response_pool_put_back_response_page(0,
						  dma_data.host_dma_addr,
						  dma_data.host_handle);
		return;
	}

	memcpy(vptr, &s_sys_info_packet, sizeof(s_sys_info_packet));

	ret = sphcs_dma_sched_start_xfer_single(g_the_sphcs->dmaSched,
						&g_dma_desc_c2h_low,
						dma_data.dma_addr,
						dma_data.host_dma_addr,
						sizeof(s_sys_info_packet),
						send_sys_info_dma_completed,
						NULL,
						&dma_data,
						sizeof(dma_data));
	if (ret) {
		dma_page_pool_set_page_free(g_the_sphcs->dma_page_pool,
					    dma_data.handle);

		sphcs_response_pool_put_back_response_page(0,
						  dma_data.host_dma_addr,
						  dma_data.host_handle);
		return;
	}
}

static DECLARE_WORK(s_sys_info_work, send_sys_info_handler);

int sphcs_maint_send_sys_info(void)
{
	schedule_work(&s_sys_info_work);
	return 0;
}

static long set_sys_info(void __user *arg)
{
	int ret = 0;
	struct maint_ioctl_sys_info sys_info;

	ret = copy_from_user(&sys_info, arg, sizeof(sys_info));
	if (unlikely(ret != 0))
		return -EIO;

	s_sys_info_packet.ice_mask = sys_info.ice_mask;
	s_sys_info_packet.totalUnprotectedMemory = sys_info.total_unprotected_memory;
	s_sys_info_packet.totalEccMemory = sys_info.total_ecc_memory;
	memcpy(s_sys_info_packet.bios_version,
	       sys_info.bios_version,
	       SPH_BIOS_VERSION_LEN);
	memcpy(s_sys_info_packet.board_name,
	       sys_info.board_name,
	       SPH_BOARD_NAME_LEN);
	memcpy(s_sys_info_packet.image_version,
	       sys_info.image_version,
	       SPH_IMAGE_VERSION_LEN);
	memcpy(s_sys_info_packet.prd_serial,
	       s_prd_serial,
	       sizeof(s_prd_serial));
	memcpy(s_sys_info_packet.brd_part_no,
	       s_brd_part_no,
	       sizeof(s_brd_part_no));
	s_sys_info_packet.fpga_rev = s_fpga_rev;
	s_sys_info_packet.stepping = sys_info.stepping;
	s_sys_info_packet_valid = true;

	sphcs_maint_send_sys_info();

	return 0;
}

static u16 milli_celcius_to_fpga_units(uint32_t mc)
{
	u16 ret;

	ret = (u16)(((mc / 1000) & 0x7f) << 8);

	return ret;
}

static u16 milli_watt_to_fpga_units(uint32_t mW)
{
	u16 ret;

	ret = (u16)(((mW / 1000) & 0xFF) << 8) |
	      (u16)(((mW % 1000) / 4) & 0xFF);

	return ret;
}

static long fpga_update(void __user *arg)
{
	int ret = 0;
	struct maint_ioctl_fpga_update data;
	u16 temp, max_temp;
	u16 thermal_event;
	u16 mem_therm_status;
	u16 avg_power;
	u16 PLone;
	uint32_t max_thermal;
	static u16 prev_temp, prev_max_temp;
	static u16 prev_mem_therm_status;
	static u16 prev_thermal_event;
	static u16 prev_avg_power;
	static u16 prev_PLone;
	static uint32_t prev_max_thermal;

	ret = copy_from_user(&data, arg, sizeof(data));
	if (unlikely(ret != 0))
		return -EIO;

	if (!s_fpga_client)
		return -ENODEV;

	temp = milli_celcius_to_fpga_units(data.temperature_mc);
	max_temp = milli_celcius_to_fpga_units(data.max_temperature_mc);
	thermal_event = milli_celcius_to_fpga_units(data.thermal_event_mc);
	mem_therm_status = data.DDR_thermal_status & 0x7;
	avg_power = milli_watt_to_fpga_units(data.avg_power_mW);
	PLone = milli_watt_to_fpga_units(data.power_limit1_mW);

	power_hw_get_ratl(&max_thermal, NULL, NULL, false);

	if (temp != prev_temp || s_force_update_fpga) {
		i2c_smbus_write_word_data(s_fpga_client,
					  FPGA_THERMAL_SENSOR_REG,
					  temp);
		prev_temp = temp;
	}

	if (max_temp != prev_max_temp || s_force_update_fpga) {
		i2c_smbus_write_word_data(s_fpga_client,
					  FPGA_MAX_THERMAL_SENSOR_REG,
					  max_temp);
		prev_max_temp = max_temp;
	}

	if (max_thermal != prev_max_thermal || s_force_update_fpga) {
		i2c_smbus_write_word_data(s_fpga_client,
					  FPGA_UPPER_THERMAL_REG,
					  max_thermal);
		prev_max_thermal = max_thermal;
	}

	if (thermal_event != prev_thermal_event || s_force_update_fpga) {
		i2c_smbus_write_word_data(s_fpga_client,
					  FPGA_LOWER_THERMAL_REG,
					  thermal_event);
		prev_thermal_event = thermal_event;
	}

	if (avg_power != prev_avg_power || s_force_update_fpga) {
		i2c_smbus_write_word_data(s_fpga_client,
					  FPGA_AVG_POWER_REG,
					  avg_power);
		prev_avg_power = avg_power;
	}

	if (mem_therm_status != prev_mem_therm_status || s_force_update_fpga) {
		i2c_smbus_write_word_data(s_fpga_client,
					  FPGA_MEMORY_THERMAL_STATUS_REG,
					  mem_therm_status);
		prev_mem_therm_status = mem_therm_status;
	}

	if (PLone != prev_PLone || s_force_update_fpga) {
		i2c_smbus_write_word_data(s_fpga_client,
					  FPGA_TDP_REG,
					  PLone);

		prev_PLone = PLone;
	}

	s_force_update_fpga = false;

	return 0;
}

static long set_bios_update_state(void __user *arg)
{
	uint32_t bios_update_state;
	int ret;

	ret = copy_from_user(&bios_update_state, arg, sizeof(uint32_t));
	if (unlikely(ret != 0))
		return -EIO;

	if (!s_fpga_client)
		return -ENODEV;

	i2c_smbus_write_word_data(s_fpga_client,
				  FPGA_INBAND_BIOS_UPDATE_REG,
				  bios_update_state & 1);

	return 0;
}

static long sphcs_maint_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	long ret = 0;

	if (unlikely(!is_maint_file(f)))
		return -EINVAL;

	switch (cmd) {
	case IOCTL_MAINT_GET_TCC:
		sph_log_debug(MAINTENANCE_LOG, "got IOCTL_MAINT_GET_TCC\n");
		ret = power_handle_get_tcc((void __user *)arg);
		break;
	case IOCTL_MAINT_GET_POWER_INFO:
		sph_log_debug(MAINTENANCE_LOG, "got IOCTL_MAINT_GET_POWER_INFO\n");
		ret = power_handle_get_power_info((void __user *)arg);
		break;
	case IOCTL_MAINT_SET_RATL:
		sph_log_debug(MAINTENANCE_LOG, "got IOCTL_MAINT_SET_RATL\n");
		ret = power_handle_set_ratl((void __user *)arg);
		break;
	case IOCTL_MAINT_GET_RATL:
		sph_log_debug(MAINTENANCE_LOG, "got IOCTL_MAINT_GET_RATL\n");
		ret = power_handle_get_ratl((void __user *)arg);
		break;
	case IOCTL_MAINT_THERMAL_TRIP:
		sph_log_debug(MAINTENANCE_LOG, "got IOCTL_MAINT_THERMAL_TRIP\n");
		ret = thermal_trip((void __user *)arg);
		break;
	case IOCTL_MAINT_SYS_INFO:
		ret = set_sys_info((void __user *)arg);
		break;
	case IOCTL_MAINT_FPGA_UPDATE:
		ret = fpga_update((void __user *)arg);
		break;
	case IOCTL_MAINT_SET_BIOS_UPDATE_STATE:
		ret = set_bios_update_state((void __user *)arg);
		break;
	default:
		sph_log_err(MAINTENANCE_LOG, "got invalid cmd: %u\n", cmd);
		ret = -EINVAL;
	}

	return ret;
}

static unsigned int sphcs_maint_poll(struct file *f, struct poll_table_struct *pt)
{
	if (unlikely(!is_maint_file(f)))
		return -EINVAL;

	return 0;
}

static const struct file_operations sphcs_maint_fops = {
	.owner = THIS_MODULE,
	.open = sphcs_maint_open,
	.release = sphcs_maint_release,
	.unlocked_ioctl = sphcs_maint_ioctl,
	.compat_ioctl = sphcs_maint_ioctl,
	.poll = sphcs_maint_poll
};

static inline int is_maint_file(struct file *f)
{
	return f->f_op == &sphcs_maint_fops;
}

static int sphcs_maint_attach_fpga(struct device *dev, void *dummy)
{
	struct i2c_adapter *adap;
	struct i2c_board_info info;
	u16 *sptr;
	int i;

	// return if already attached
	if (s_fpga_client)
		return 1;

	// Check device is i2c adapter
	if (dev->type != &i2c_adapter_type)
		return 0;

	// Check if adapter is PCH smbus
	adap = to_i2c_adapter(dev);
	if (strncmp(adap->name, "SMBus I801 adapter at ", 22))
		return 0;

	// Create i2c client for the FPGA device
	memset(&info, 0, sizeof(info));
	strcpy(info.type, "sph_fpga");
	info.addr = SPH_FPGA_SMBUS_ADDRESS;

	s_fpga_client = i2c_new_device(adap, &info);
	if (!s_fpga_client)
		return -EFAULT;

	// Success
	s_force_update_fpga = true;

	// Read static board ID and Fab ID regs
	s_board_id = i2c_smbus_read_word_data(s_fpga_client,
					      FPGA_BOM_ID_REG);

	s_fab_id = i2c_smbus_read_word_data(s_fpga_client,
					    FPGA_FAB_ID_REG);

	s_fpga_rev = i2c_smbus_read_word_data(s_fpga_client,
					      FPGA_REVISION_REG);


	sptr = (u16 *)&s_prd_serial;
	for (i = 0; i < FPGA_FRU_PRD_SERIAL_LEN; i++)
		*(sptr++) = i2c_smbus_read_word_data(s_fpga_client,
						     FPGA_FRU_PRD_SERIAL_BASE_REG + i);

	sptr = (u16 *)&s_brd_part_no;
	for (i = 0; i < FPGA_FRU_BRD_PART_NO_LEN; i++)
		*(sptr++) = i2c_smbus_read_word_data(s_fpga_client,
						     FPGA_FRU_BRD_PART_NO_BASE_REG + i);

	/* Old FPGA revisions does not provide serial and part number */
	if (s_prd_serial[0] > 0xf0)
		strcpy(s_prd_serial, "Not-Avail");
	if (s_brd_part_no[0] > 0xf0)
		strcpy(s_brd_part_no, "Not-Avail");

	sph_log_info(MAINTENANCE_LOG, "Found FPGA SMBus device BoardID=0x%x FabID=0x%x FPGA Revision %u\n"
				      "\tbrd_part_no %s\n"
				      "\tprd_serial %s\n",
		     s_board_id, s_fab_id, s_fpga_rev, s_brd_part_no, s_prd_serial);

	return 1;
}

int sphcs_init_maint_interface(void)
{
	int ret;

	ret = alloc_chrdev_region(&s_devnum, 0, 1, SPHCS_MAINTENANCE_DEV_NAME);
	if (ret < 0) {
		sph_log_err(START_UP_LOG, "failed to allocate devnum %d\n", ret);
		return ret;
	}

	cdev_init(&s_cdev, &sphcs_maint_fops);
	s_cdev.owner = THIS_MODULE;

	ret = cdev_add(&s_cdev, s_devnum, 1);
	if (ret < 0) {
		sph_log_err(START_UP_LOG, "failed to add cdev %d\n", ret);
		unregister_chrdev_region(s_devnum, 1);
		return ret;
	}

	s_class = class_create(THIS_MODULE, SPHCS_MAINTENANCE_DEV_NAME);
	if (IS_ERR(s_class)) {
		ret = PTR_ERR(s_class);
		sph_log_err(START_UP_LOG, "failed to register class %d\n", ret);
		cdev_del(&s_cdev);
		unregister_chrdev_region(s_devnum, 1);
		return ret;
	}

	s_dev = device_create(s_class, NULL, s_devnum, NULL, SPHCS_MAINTENANCE_DEV_NAME);
	if (IS_ERR(s_dev)) {
		ret = PTR_ERR(s_dev);
		class_destroy(s_class);
		cdev_del(&s_cdev);
		unregister_chrdev_region(s_devnum, 1);
		return ret;
	}

	sph_power_init();

	memset(s_prd_serial, 0, sizeof(s_prd_serial));
	memset(s_brd_part_no, 0, sizeof(s_brd_part_no));

	// Try to attach to FPGA SMBus device if adapter already present
	ret = i2c_for_each_dev(NULL, sphcs_maint_attach_fpga);
	if (ret < 0)
		sph_log_err(START_UP_LOG, "Failed to attach to FPGA SMBus device!!\n");

	return 0;
}

void sphcs_release_maint_interface(void)
{
	// Detach FPGA SMBus device
	if (s_fpga_client) {
		i2c_unregister_device(s_fpga_client);
		s_fpga_client = NULL;
		sph_log_debug(MAINTENANCE_LOG, "Detached FPGA SMBus Device\n");
	}

	device_destroy(s_class, s_devnum);
	class_destroy(s_class);
	cdev_del(&s_cdev);
	unregister_chrdev_region(s_devnum, 1);
}

static int debug_fpga_regs_show(struct seq_file *m, void *v)
{
	if (!s_fpga_client) {
		seq_puts(m, "FPGA SMBus device not attached\n");
		return 0;
	}

#define PRINT_REG_VALUE(r) \
	seq_printf(m, #r "\t: 0x%x\n", i2c_smbus_read_word_data(s_fpga_client, r))

	PRINT_REG_VALUE(FPGA_THERMAL_SENSOR_REG);
	PRINT_REG_VALUE(FPGA_MEMORY_THERMAL_STATUS_REG);
	PRINT_REG_VALUE(FPGA_AVG_POWER_REG);
	PRINT_REG_VALUE(FPGA_BIOS_VERSION_REG);
	PRINT_REG_VALUE(FPGA_INBAND_BIOS_UPDATE_REG);
	PRINT_REG_VALUE(FPGA_MAX_THERMAL_SENSOR_REG);
	PRINT_REG_VALUE(FPGA_BOM_ID_REG);
	PRINT_REG_VALUE(FPGA_FAB_ID_REG);
	PRINT_REG_VALUE(FPGA_TDP_REG);
	PRINT_REG_VALUE(FPGA_UPPER_THERMAL_REG);
	PRINT_REG_VALUE(FPGA_LOWER_THERMAL_REG);

	return 0;
}

static int debug_fpga_regs_open(struct inode *inode, struct file *filp)
{
	return single_open(filp, debug_fpga_regs_show, inode->i_private);
}

static const struct file_operations fpga_regs_fops = {
	.open		= debug_fpga_regs_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

void sphcs_maint_init_debugfs(struct dentry *parent)
{
	struct dentry *regs;

	if (!parent)
		return;

	regs = debugfs_create_file("fpga_regs",
				   0444,
				   parent,
				   NULL,
				   &fpga_regs_fops);
	if (IS_ERR_OR_NULL(regs))
		sph_log_err(START_UP_LOG, "Failed to create debugfs fpga_regs file\n");
}
