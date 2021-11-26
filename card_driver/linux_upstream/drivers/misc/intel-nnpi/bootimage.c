// SPDX-License-Identifier: GPL-2.0-or-later

/********************************************
 * Copyright (C) 2019-2021 Intel Corporation
 ********************************************/

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/poll.h>
#include <linux/wait.h>
#include <linux/slab.h>
#include <linux/kmod.h>
#include <linux/workqueue.h>
#include <linux/sched.h>
#include <linux/firmware.h>
#include <linux/timer.h>
#include "bootimage.h"
#include "device.h"
#include "nnp_log.h"
#include "nnp_boot_defs.h"
#include "ipc_protocol.h"

enum image_state {
	IMAGE_REQUESTED = 0,
	IMAGE_LOAD_FAILED,
	IMAGE_AVAILABLE
};

struct image_wait_list {
	struct nnp_device *nnpdev;
	struct list_head   node;
};

#define MAX_IMAGE_NAME_LEN   256

struct image_info {
	char             name[MAX_IMAGE_NAME_LEN];
	enum image_state state;
	struct nnp_device *requested_nnpdev;
	struct nnpdrv_host_resource  *hostres;
	struct list_head wait_list;
	struct work_struct work;
	struct list_head node;
};

struct nnpdrv_bootimage {
	struct list_head  boot_images;
	struct timer_list garbage_collect_timer;
	struct work_struct garbage_collect_work;
	u32               unloading_module;
};

static struct nnpdrv_bootimage *s_boot_loader;
static DEFINE_MUTEX(s_lock);

static void garbage_collect_work_handler(struct work_struct *work);

static void loaded_images_garbage_collect(struct timer_list *timer)
{
	schedule_work(&s_boot_loader->garbage_collect_work);

	mod_timer(&s_boot_loader->garbage_collect_timer,
		  jiffies + msecs_to_jiffies(30000));
}

static int alloc_bootloader(void)
{
	nnp_log_debug(GENERAL_LOG, "allocating bootloader\n");

	s_boot_loader = kzalloc(sizeof(*s_boot_loader), GFP_KERNEL);
	if (!s_boot_loader)
		return -ENOMEM;

	INIT_LIST_HEAD(&s_boot_loader->boot_images);
	INIT_WORK(&s_boot_loader->garbage_collect_work,
		  garbage_collect_work_handler);

	timer_setup(&s_boot_loader->garbage_collect_timer,
		    loaded_images_garbage_collect,
		    0);
	mod_timer(&s_boot_loader->garbage_collect_timer,
		  jiffies + msecs_to_jiffies(30000));

	return 0;
}

static void free_bootloader(void)
{
	nnp_log_debug(GENERAL_LOG,
		      "unloading_module=%d\n",
		      s_boot_loader->unloading_module);

	if (!s_boot_loader->unloading_module)
		del_timer(&s_boot_loader->garbage_collect_timer);

	kfree(s_boot_loader);
	s_boot_loader = NULL;
}

/*
 * must be called when s_boot_loader->lock is held.
 * informs all waiting devices about the image load state
 */
static void image_load_state_changed(struct image_info *image)
{
	struct image_wait_list *wait_list_node, *n;

	/* inform all waiting devices about the load image state */
	list_for_each_entry_safe(wait_list_node, n, &image->wait_list, node) {
		mutex_unlock(&s_lock);
		nnpdrv_bootimage_load_boot_image(wait_list_node->nnpdev,
						 image->name);
		mutex_lock(&s_lock);
		list_del(&wait_list_node->node);
		kfree(wait_list_node);
	}
}

static int load_firmware_no_copy(struct image_info *image_info)
{
	const struct firmware *fw;
	struct kstat stat;
	struct path path;
	char *fname;
	void *vptr;
	int ret;

	fname = kzalloc(PATH_MAX, GFP_KERNEL);
	if (!fname)
		return -ENOMEM;

	ret = snprintf(fname, PATH_MAX, "/lib/firmware/%s", image_info->name);
	if (ret < 0 || ret >= PATH_MAX) {
		nnp_log_err(GENERAL_LOG,
			    "Could not aggregate path name: /lib/firmware/%s\n",
			    image_info->name);
		kfree(fname);
		return -EFAULT;
	}

	ret = kern_path(fname, LOOKUP_FOLLOW, &path);
	if (ret) {
		nnp_log_err(GENERAL_LOG,
			    "Could not find image under /lib/firmware\n");
		kfree(fname);
		return ret;
	}

	ret = vfs_getattr(&path, &stat, STATX_SIZE, 0);
	path_put(&path);
	kfree(fname);
	if (ret) {
		nnp_log_err(GENERAL_LOG,
			    "failed to get boot image size %s error=%d\n",
			    image_info->name,
			    ret);
		return ret;
	}

	nnp_log_debug(GENERAL_LOG,
		      "Found boot image size %lld\n", stat.size);

	ret = nnpdrv_hostres_create(stat.size,
				    DMA_TO_DEVICE,
				    &image_info->hostres);
	if (ret) {
		nnp_log_err(GENERAL_LOG,
			    "failed to create host resource for boot image size=%lld error=%d\n",
			    stat.size,
			    ret);
		return ret;
	}

	ret = nnpdrv_hostres_vmap(image_info->hostres, &vptr);
	if (ret) {
		nnp_log_err(GENERAL_LOG,
			    "failed to vmap host resource error=%d\n",
			    ret);
		nnpdrv_hostres_destroy(image_info->hostres);
		image_info->hostres = 0;
		return ret;
	}

	ret = request_firmware_into_buf(&fw,
			image_info->name,
			image_info->requested_nnpdev->hw_device_info->hw_device,
			vptr,
			stat.size);
	if (ret) {
		nnp_log_err(GENERAL_LOG,
			    "failed to load firmware %s ret==%d\n",
			    image_info->name, ret);
		nnpdrv_hostres_vunmap(image_info->hostres, vptr);
		nnpdrv_hostres_destroy(image_info->hostres);
		image_info->hostres = 0;
		return ret;
	}

	nnpdrv_hostres_vunmap(image_info->hostres, vptr);
	release_firmware(fw);
	image_info->state = IMAGE_AVAILABLE;

	return 0;
}

static void load_image_handler(struct work_struct *work)
{
	struct image_info *image_info = container_of(work,
						     struct image_info,
						     work);

	const struct firmware *fw;
	void *vptr;
	int ret;

	mutex_lock(&s_lock);

	/* First, try to load image without extra memcpy */
	ret = load_firmware_no_copy(image_info);
	if (ret == 0)
		goto done;

	/* Try to load firmware to kernel allocated memory */
	ret = request_firmware(&fw,
		image_info->name,
		image_info->requested_nnpdev->hw_device_info->hw_device);

	if (ret) {
		nnp_log_err(GENERAL_LOG, "failed to load boot image %s error=%d\n",
			    image_info->name,
			    ret);
		image_info->state = IMAGE_LOAD_FAILED;
		goto done;
	}

	ret = nnpdrv_hostres_create(fw->size,
				    DMA_TO_DEVICE,
				    &image_info->hostres);
	if (ret) {
		nnp_log_err(GENERAL_LOG,
			    "failed to create host resource for boot image size=%ld error=%d\n",
			    fw->size,
			    ret);
		image_info->state = IMAGE_LOAD_FAILED;
		goto free_fw;
	}

	ret = nnpdrv_hostres_vmap(image_info->hostres, &vptr);
	if (ret) {
		nnp_log_err(GENERAL_LOG,
			    "failed to vmap host resource error=%d\n", ret);
		image_info->state = IMAGE_LOAD_FAILED;
		nnpdrv_hostres_destroy(image_info->hostres);
		image_info->hostres = 0;
		goto free_fw;
	}

	/* Copy image data */
	memcpy(vptr, fw->data, fw->size);
	nnpdrv_hostres_vunmap(image_info->hostres, vptr);

	image_info->state = IMAGE_AVAILABLE;

free_fw:
	release_firmware(fw);
done:
	/* give the boot image to waiting devices */
	image_load_state_changed(image_info);
	mutex_unlock(&s_lock);
}

static int map_image(struct nnp_device    *nnpdev,
		     const char           *image_name,
		     struct image_info   **out_image_info,
		     dma_addr_t           *out_page_list_addr,
		     u32                  *out_total_chunks)
{
	struct image_info *image_info;
	struct image_wait_list *wait_list_node;
	int ret;
	bool found = false;

	mutex_lock(&s_lock);
	if (!s_boot_loader) {
		ret = alloc_bootloader();
		if (ret != 0) {
			mutex_unlock(&s_lock);
			return ret;
		}
	}

	if (!list_empty(&s_boot_loader->boot_images))
		list_for_each_entry(image_info,
				    &s_boot_loader->boot_images, node)
			if (!strncmp(image_name,
				     image_info->name, MAX_IMAGE_NAME_LEN)) {
				found = true;
				break;
			}

	if (found) {
		if (image_info->state == IMAGE_AVAILABLE) {
			ret = nnpdrv_hostres_map_device(image_info->hostres,
							nnpdev,
							true,
							out_page_list_addr,
							out_total_chunks);
		} else if (image_info->state == IMAGE_LOAD_FAILED) {
			ret = -EFAULT;
		} else {
			wait_list_node = kzalloc(sizeof(*wait_list_node),
						 GFP_NOWAIT);
			if (!wait_list_node) {
				ret = -ENOMEM;
			} else {
				wait_list_node->nnpdev = nnpdev;
				list_add_tail(&wait_list_node->node,
					      &image_info->wait_list);
				ret = -ENOENT;
			}
		}
	} else {
		/* not available, add the requested image to the wait list */
		image_info = kzalloc(sizeof(*image_info), GFP_KERNEL);
		wait_list_node = kzalloc(sizeof(*wait_list_node), GFP_KERNEL);

		if (image_info && wait_list_node) {
			if (strlen(image_name) >= sizeof(image_info->name)) {
				kfree(image_info);
				kfree(wait_list_node);
				ret = -EINVAL;
			} else {
				strncpy(image_info->name, image_name,
					MAX_IMAGE_NAME_LEN - 1);
				image_info->state = IMAGE_REQUESTED;
				image_info->requested_nnpdev = nnpdev;
				INIT_LIST_HEAD(&image_info->wait_list);
				INIT_WORK(&image_info->work,
					  load_image_handler);
				list_add_tail(&image_info->node,
					      &s_boot_loader->boot_images);

				wait_list_node->nnpdev = nnpdev;
				list_add_tail(&wait_list_node->node,
					      &image_info->wait_list);

				/* schedule work to load the image */
				schedule_work(&image_info->work);

				ret = -ENOENT;
			}
		} else {
			kfree(image_info);
			kfree(wait_list_node);
			ret = -ENOMEM;
		}
	}

	mutex_unlock(&s_lock);

	if (!ret && out_image_info)
		*out_image_info = image_info;
	return ret;
}

static bool image_remove(struct image_info *image)
{
	if (!image)
		return false;

	/*
	 * Check if the image can be removed,
	 * unless we are during unload time, in which case we
	 * force deletion of the image
	 */
	if (!s_boot_loader->unloading_module) {
		/* do not remove an image in a REQUESTED state */
		if (image->state == IMAGE_REQUESTED)
			return false;

		/* do not remove an image with non empty device wait list */
		if (!list_empty(&image->wait_list))
			return false;

		/* do not remove an image which is used by some device */
		if (image->state == IMAGE_AVAILABLE &&
		    nnpdrv_hostres_read_refcount(image->hostres) > 1)
			return false;
	}

	/* OK to destroy and delete image */
	if (image->hostres)
		nnpdrv_hostres_destroy(image->hostres);

	list_del(&image->node);

	return true;
}

static void garbage_collect_work_handler(struct work_struct *work)
{
	struct image_info *image, *n;

	mutex_lock(&s_lock);

	if (!s_boot_loader) {
		mutex_unlock(&s_lock);
		return;
	}

	if (!list_empty(&s_boot_loader->boot_images)) {
		list_for_each_entry_safe(image, n,
					 &s_boot_loader->boot_images, node) {
			if (image_remove(image)) {
				nnp_log_info(GENERAL_LOG,
					     "Removed boot image %s from memory\n",
					     image->name);
				kfree(image);
			}
		}
	}

	if (list_empty(&s_boot_loader->boot_images))
		free_bootloader();

	mutex_unlock(&s_lock);
}

bool nnpdrv_bootimage_image_list_empty(void)
{
	return list_empty(&s_boot_loader->boot_images);
}

int nnpdrv_bootimage_load_boot_image(struct nnp_device    *nnpdev,
				     const char           *boot_image_name)
{
	struct image_info *image_info;
	dma_addr_t page_list_addr;
	u32        total_chunks;
	union h2c_boot_image_ready msg;
	int ret;

	ret = map_image(nnpdev,
			boot_image_name,
			&image_info,
			&page_list_addr,
			&total_chunks);
	if (!ret) {
		nnp_log_info(GENERAL_LOG,
			     "Mapped boot image %s num_chunks=%d total_size=%d\n",
			     image_info->name, total_chunks,
			     (u32)nnpdrv_hostres_get_size(image_info->hostres));

		/* write image address directly to the command Q */
		memset(msg.value, 0, sizeof(msg));
		msg.opcode = NNP_IPC_H2C_OP_BIOS_PROTOCOL;
		msg.msg_type = NNP_IPC_H2C_TYPE_BOOT_IMAGE_READY;
		msg.size = 2 * sizeof(u64);
		msg.descriptor_addr =
			(u64)page_list_addr + sizeof(struct dma_chain_header);
		msg.descriptor_size =
			total_chunks * sizeof(struct dma_chain_entry);
		msg.image_size =
			(u32)nnpdrv_hostres_get_size(image_info->hostres);

		ret = nnpdev->hw_ops->write_mesg(nnpdev->hw_handle,
					   &msg.value[0],
					   sizeof(msg) / sizeof(u64),
					   NULL);

	} else if (ret != -ENOENT) {
		/* notify card that boot image cannot be loaded */
		nnpdev->hw_ops->set_host_doorbell_value(
			nnpdev->hw_handle,
			NNP_HOST_ERROR_CANNOT_LOAD_IMAGE <<
			NNP_HOST_ERROR_SHIFT);
	}
	return ret;
}

int nnpdrv_bootimage_unload_boot_image(struct nnp_device    *nnpdev,
				       const char           *boot_image_name)
{
	struct image_info *image_info;
	int ret;
	bool found = false;

	mutex_lock(&s_lock);

	if (!s_boot_loader) {
		mutex_unlock(&s_lock);
		return -EFAULT;
	}

	list_for_each_entry(image_info, &s_boot_loader->boot_images, node)
		if (!strncmp(boot_image_name, image_info->name,
			     MAX_IMAGE_NAME_LEN)) {
			found = true;
			break;
		}

	if (found && image_info->hostres)
		ret = nnpdrv_hostres_unmap_device(image_info->hostres, nnpdev);
	else
		ret = -ENOENT;

	mutex_unlock(&s_lock);
	return ret;
}

void nnpdrv_bootimage_fini(void)
{
	mutex_lock(&s_lock);
	if (!s_boot_loader) {
		mutex_unlock(&s_lock);
		return;
	}

	/*
	 * delete the garbage collect timer and call its
	 * callback one last time in order to remove any
	 * boot image still in memory
	 */
	del_timer(&s_boot_loader->garbage_collect_timer);
	cancel_work_sync(&s_boot_loader->garbage_collect_work);
	s_boot_loader->unloading_module = 1;
	mutex_unlock(&s_lock);
	garbage_collect_work_handler(&s_boot_loader->garbage_collect_work);
}
