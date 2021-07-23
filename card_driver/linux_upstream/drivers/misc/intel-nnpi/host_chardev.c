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
#include <linux/hashtable.h>
#include <linux/idr.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/string.h>
#include <linux/file.h>
#include <linux/atomic.h>
#include <uapi/misc/intel_nnpi.h>
#include "nnp_log.h"
#include "device.h"
#include "ipc_protocol.h"
#include "idr_allocator.h"
#include "inf_proc.h"

static struct cdev s_cdev;
static dev_t       s_devnum;
static struct class *s_class;
static struct device *s_dev;

static LIST_HEAD(s_proc_list);
static DEFINE_MUTEX(s_proc_list_lock);

#define NNP_IDR_ALLOC(p) \
	nnp_idr_alloc(&proc_info->objects_idr, (p))
#define NNP_IDR_GET_OBJECT(id, fn_check_and_get) \
	nnp_idr_get_object(&proc_info->objects_idr, (int)(id), \
			   (fn_check_and_get))
#define NNP_IDR_REMOVE_OBJECT(id) \
	nnp_idr_remove_object(&proc_info->objects_idr, (int)(id))
#define NNP_IDR_CHECK_AND_REMOVE_OBJECT(id, fn_check) \
	nnp_idr_check_and_remove_object(&proc_info->objects_idr, \
					(int)(id), (fn_check))

/**
 * transfer network utilities and macros
 *
 */

static inline int is_host_file(struct file *f);

static enum dma_data_direction convert_nnp2dma_direction(u32 nnp_dir)
{
	/* Ignore IOCTL_INF_RES_NETWORK */
	if (nnp_dir & (IOCTL_INF_RES_INPUT | IOCTL_INF_RES_OUTPUT))
		return DMA_BIDIRECTIONAL;

	if (nnp_dir & IOCTL_INF_RES_INPUT)
		return DMA_TO_DEVICE;

	if (nnp_dir & IOCTL_INF_RES_OUTPUT)
		return DMA_FROM_DEVICE;

	return DMA_NONE;
}

static long create_hostres(struct inf_process_info *proc_info,
			   void __user             *arg)
{
	int ret;
	int id = 0;
	struct nnpdrv_ioctl_create_hostres create_args;
	s32 fd;
	struct nnpdrv_host_resource *hostres;
	struct inf_hostres *inf_hostres_entry;

	ret = copy_from_user(&create_args, arg, sizeof(create_args));
	if (unlikely(ret != 0))
		return -EIO;

	if (unlikely(create_args.version != NNPI_IOCTL_INTERFACE_VERSION)) {
		create_args.o_errno = NNPER_VERSIONS_MISMATCH;
		nnp_log_err(CREATE_COMMAND_LOG,
			    "Error: kernel(v0x%x) and user space(v0x%x) use different versions\n",
			    NNPI_IOCTL_INTERFACE_VERSION, create_args.version);
		goto done;
	}

	if (create_args.byte_size == 0) { /* dma_buf fd is valid */
		ret = nnpdrv_hostres_dma_buf_create(create_args.dma_buf,
			convert_nnp2dma_direction(create_args.usage_flags),
			&hostres);
		fd = create_args.dma_buf;
		if (likely(ret == 0))
			create_args.byte_size =
				nnpdrv_hostres_get_size(hostres);
	} else if (create_args.user_handle != 0) {
		ret = nnpdrv_hostres_create_usermem(
			(void __user *)create_args.user_handle,
			create_args.byte_size,
			convert_nnp2dma_direction(create_args.usage_flags),
			&hostres);
		fd = -1;
	} else {
		ret = nnpdrv_hostres_create(create_args.byte_size,
			convert_nnp2dma_direction(create_args.usage_flags),
			&hostres);
		fd = -1;
	}
	if (unlikely(ret < 0))
		return ret;

	ret = inf_proc_add_hostres(proc_info, hostres, fd, &inf_hostres_entry);
	if (unlikely(ret < 0))
		goto destroy_hostres;

	id = NNP_IDR_ALLOC(inf_hostres_entry);
	if (unlikely(id < 0)) {
		ret = -ENOSPC;
		goto destroy_hostres_entry;
	}

	create_args.user_handle = (u64)id;
done:
	ret = copy_to_user(arg, &create_args, sizeof(create_args));
	if (unlikely(ret != 0)) {
		ret = -EIO;
		if (id > 0)
			goto idr_remove;
	}

	return 0;

idr_remove:
	NNP_IDR_REMOVE_OBJECT(id);
destroy_hostres_entry:
	inf_hostres_put(inf_hostres_entry);
destroy_hostres:
	nnpdrv_hostres_destroy(hostres);

	return ret;
}

static long destroy_hostres(struct inf_process_info *proc_info,
			    void __user             *arg)
{
	int ret;
	struct nnpdrv_ioctl_destroy_hostres destroy_args;
	struct inf_hostres *inf_hostres_entry;
	struct nnpdrv_host_resource *hostres;

	ret = copy_from_user(&destroy_args, arg, sizeof(destroy_args));
	if (unlikely(ret))
		return -EIO;

	inf_hostres_entry =
		NNP_IDR_CHECK_AND_REMOVE_OBJECT(destroy_args.user_handle,
						is_inf_hostres_ptr);
	if (unlikely(!inf_hostres_entry)) {
		destroy_args.o_errno = NNPER_NO_SUCH_RESOURCE;
		ret = -EFAULT;
		goto finish;
	}
	hostres = inf_hostres_entry->hostres;

	inf_hostres_put(inf_hostres_entry);
	nnpdrv_hostres_destroy(hostres);

finish:
	if (unlikely(copy_to_user(arg,
				  &destroy_args,
				  sizeof(destroy_args)) != 0))
		nnp_log_err(CREATE_COMMAND_LOG,
			    "Couldn't copy host resource destroy args for unmapping\n");

	return ret;
}

static long lock_hostres(struct inf_process_info *proc_info,
			 void __user             *arg)
{
	int ret;
	struct nnpdrv_ioctl_lock_hostres lock_args;
	struct inf_hostres *inf_hostres_entry;
	struct nnpdrv_host_resource *hostres;

	ret = copy_from_user(&lock_args, arg, sizeof(lock_args));
	if (unlikely(ret != 0)) {
		nnp_log_err(GENERAL_LOG, "copy from user failed\n");
		return -EIO;
	}

	lock_args.o_errno = 0;

	inf_hostres_entry = NNP_IDR_GET_OBJECT(lock_args.user_handle,
					       inf_hostres_check_and_get);
	if (unlikely(!inf_hostres_entry)) {
		lock_args.o_errno = NNPER_NO_SUCH_RESOURCE;
		ret = -EFAULT;
		goto no_put;
	}
	hostres = inf_hostres_entry->hostres;

	ret = nnpdrv_hostres_user_lock(hostres, lock_args.timeout_us);
	if (unlikely(ret < 0)) {
		nnp_log_debug(GENERAL_LOG,
			      "failed to lock host resource 0x%llx. err:%d\n",
			      lock_args.user_handle, ret);
		goto finish;
	}

finish:
	inf_hostres_put(inf_hostres_entry);
no_put:
	if (lock_args.o_errno == 0)
		return ret;

	if (unlikely(copy_to_user(arg, &lock_args, sizeof(lock_args)) != 0))
		return -EIO;
	return ret;
}

static long unlock_hostres(struct inf_process_info *proc_info,
			   void __user             *arg)
{
	int ret = 0;
	struct inf_hostres *inf_hostres_entry;
	struct nnpdrv_ioctl_lock_hostres lock_args;

	ret = copy_from_user(&lock_args, arg, sizeof(lock_args));
	if (unlikely(ret)) {
		nnp_log_err(GENERAL_LOG, "copy from user failed\n");
		return -EIO;
	}

	lock_args.o_errno = 0;

	inf_hostres_entry = NNP_IDR_GET_OBJECT(lock_args.user_handle,
					       inf_hostres_check_and_get);
	if (unlikely(!inf_hostres_entry)) {
		lock_args.o_errno = NNPER_NO_SUCH_RESOURCE;
		ret = -EFAULT;
		goto no_put;
	}

	ret = nnpdrv_hostres_user_unlock(inf_hostres_entry->hostres);
	if (unlikely(ret < 0)) {
		nnp_log_err(GENERAL_LOG,
			    "failed to unlock hostres 0x%llx. err:%d.\n",
			    lock_args.user_handle, ret);
		goto finish;
	}

finish:
	inf_hostres_put(inf_hostres_entry);
no_put:
	if (lock_args.o_errno == 0)
		return ret;

	if (unlikely(copy_to_user(arg, &lock_args, sizeof(lock_args)) != 0))
		return -EIO;

	return ret;
}

struct file *nnpdrv_host_file_get(int host_fd)
{
	struct file *host_file;

	host_file = fget(host_fd);
	if (!is_host_file(host_file)) {
		if (host_file) {
			fput(host_file);
			host_file = NULL;
		}
	}

	return host_file;
}

/*****************************************************************
 * Inference host cdev (/dev/nnpi_host) file operation functions
 *****************************************************************/

static int host_open(struct inode *inode, struct file *f)
{
	struct inf_process_info *proc_info;

	if (unlikely(!is_host_file(f)))
		return -EINVAL;

	nnp_log_debug(START_UP_LOG, "inf_open started");

	proc_info = kzalloc(sizeof(*proc_info), GFP_KERNEL);
	if (!proc_info)
		return -ENOMEM;

	inf_proc_init(proc_info, task_tgid_nr(current));

	mutex_lock(&s_proc_list_lock);
	list_add_tail(&proc_info->proc_list_node, &s_proc_list);
	mutex_unlock(&s_proc_list_lock);

	f->private_data = proc_info;

	return 0;
}

static int host_release(struct inode *inode, struct file *f)
{
	struct inf_process_info *proc_info;

	if (unlikely(!is_host_file(f)))
		return -EINVAL;

	nnp_log_debug(GO_DOWN_LOG, "inf_release started");

	proc_info = (struct inf_process_info *)f->private_data;
	NNP_ASSERT(proc_info);

	mutex_lock(&s_proc_list_lock);
	list_del(&proc_info->proc_list_node);
	mutex_unlock(&s_proc_list_lock);

	inf_proc_destroy_all(proc_info);
	f->private_data = NULL;

	return 0;
}

static long host_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	long ret = 0;
	struct inf_process_info *proc_info =
		(struct inf_process_info *)f->private_data;

	if (unlikely(!is_host_file(f)))
		return -EINVAL;

	switch (cmd) {
	case IOCTL_INF_CREATE_HOST_RESOURCE:
		ret = create_hostres(proc_info, (void __user *)arg);
		break;
	case IOCTL_INF_DESTROY_HOST_RESOURCE:
		ret = destroy_hostres(proc_info, (void __user *)arg);
		break;
	case IOCTL_INF_UNLOCK_HOST_RESOURCE:
		ret = unlock_hostres(proc_info, (void __user *)arg);
		break;
	case IOCTL_INF_LOCK_HOST_RESOURCE:
		ret = lock_hostres(proc_info, (void __user *)arg);
		break;
	default:
		nnp_log_err(GENERAL_LOG,
			    "Unsupported inference host IOCTL 0x%x\n", cmd);
		ret = -EINVAL;
	}

	return ret;
}

static int host_mmap(struct file *f, struct vm_area_struct *vma)
{
	struct inf_process_info *proc_info;
	struct inf_hostres *inf_hostres_entry;
	int ret;

	if (unlikely(!is_host_file(f))) {
		nnp_log_err(GENERAL_LOG, "Not an inference file descriptor\n");
		return -EINVAL;
	}
	if (unlikely(!vma)) {
		nnp_log_err(GENERAL_LOG, "vma should not be NULL\n");
		return -EINVAL;
	}
	proc_info = (struct inf_process_info *)f->private_data;
	if (unlikely(!proc_info)) {
		nnp_log_err(GENERAL_LOG, "Process info should not be NULL\n");
		return -EFAULT;
	}

	inf_hostres_entry = NNP_IDR_GET_OBJECT(vma->vm_pgoff,
					       inf_hostres_check_and_get);
	if (unlikely(!inf_hostres_entry)) {
		nnp_log_err(GENERAL_LOG,
			    "Host resource 0x%lx does not exist\n",
			    vma->vm_pgoff);
		return -EINVAL;
	}

	ret = nnpdrv_hostres_map_user(inf_hostres_entry->hostres, vma);
	if (unlikely(ret < 0))
		nnp_log_err(GENERAL_LOG,
			    "failed to map host resource 0x%lx to user address\n",
			    vma->vm_pgoff);

	inf_hostres_put(inf_hostres_entry);

	return ret;
}

static const struct file_operations nnpdrv_host_fops = {
	.owner = THIS_MODULE,
	.open = host_open,
	.release = host_release,
	.unlocked_ioctl = host_ioctl,
	.compat_ioctl = host_ioctl,
	.mmap = host_mmap
};

static inline int is_host_file(struct file *f)
{
	return f && f->f_op == &nnpdrv_host_fops;
}

bool is_not_in_use_hostres_ptr(void *ptr)
{
	struct inf_hostres *inf_hostres_entry = (struct inf_hostres *)ptr;
	struct nnpdrv_host_resource *hostres;

	if (!ptr ||
	    ((struct inf_hostres *)ptr)->magic != inf_proc_add_hostres)
		return false;

	hostres = inf_hostres_entry->hostres;

	/* Do not allow to give host resource if it is used */
	if (kref_read(&inf_hostres_entry->ref) > 1)
		return false;

	/* Do not allow to give host resource if it is used */
	if (nnpdrv_hostres_read_refcount(hostres) > 1 + 1)
		return false;

	return true;
}

int init_host_interface(void)
{
	int ret;

	ret = alloc_chrdev_region(&s_devnum, 0, 1, NNPDRV_INF_HOST_DEV_NAME);
	if (ret < 0) {
		nnp_log_err(START_UP_LOG,
			    "nnp_host: failed to allocate devnum %d\n", ret);
		return ret;
	}

	cdev_init(&s_cdev, &nnpdrv_host_fops);
	s_cdev.owner = THIS_MODULE;

	ret = cdev_add(&s_cdev, s_devnum, 1);
	if (ret < 0) {
		nnp_log_err(START_UP_LOG,
			    "nnp_host: failed to add cdev %d\n", ret);
		unregister_chrdev_region(s_devnum, 1);
		return ret;
	}

	s_class = class_create(THIS_MODULE, NNPDRV_INF_HOST_DEV_NAME);
	if (IS_ERR(s_class)) {
		ret = PTR_ERR(s_class);
		nnp_log_err(START_UP_LOG,
			    "nnp_inf: failed to register class %d\n", ret);
		cdev_del(&s_cdev);
		unregister_chrdev_region(s_devnum, 1);
		return ret;
	}

	s_dev = device_create(s_class, NULL, s_devnum, NULL,
			      NNPDRV_INF_HOST_DEV_NAME);
	if (IS_ERR(s_dev)) {
		ret = PTR_ERR(s_dev);
		class_destroy(s_class);
		cdev_del(&s_cdev);
		unregister_chrdev_region(s_devnum, 1);
		return ret;
	}

	ret = nnpdrv_hostres_init_sysfs(&s_dev->kobj);
	if (ret) {
		device_destroy(s_class, s_devnum);
		class_destroy(s_class);
		cdev_del(&s_cdev);
		unregister_chrdev_region(s_devnum, 1);
		return ret;
	}

	nnp_log_info(START_UP_LOG,
		     "inf_host: chardev inited at MAJOR=%u\n",
		     MAJOR(s_devnum));
	return 0;
}

void release_host_interface(void)
{
	nnpdrv_hostres_fini_sysfs(&s_dev->kobj);
	device_destroy(s_class, s_devnum);
	class_destroy(s_class);
	cdev_del(&s_cdev);
	unregister_chrdev_region(s_devnum, 1);
}
