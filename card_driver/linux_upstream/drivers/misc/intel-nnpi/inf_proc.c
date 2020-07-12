// SPDX-License-Identifier: GPL-2.0-or-later

/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 ********************************************/

#include <linux/kernel.h>
#include <linux/slab.h>
#include "nnp_log.h"
#include "inf_proc.h"

void inf_proc_init(struct inf_process_info *proc_info, pid_t curr_pid)
{
	INIT_LIST_HEAD(&proc_info->hostres_list);
	mutex_init(&proc_info->lock);
	kref_init(&proc_info->ref);
	nnp_idr_init(&proc_info->objects_idr);
	proc_info->pid = curr_pid;
}

void inf_proc_get(struct inf_process_info *proc_info)
{
	int ret;

	ret = kref_get_unless_zero(&proc_info->ref);
	NNP_ASSERT(ret != 0); /* Can happen only after close(fd) */
}

static void proc_release(struct kref *kref)
{
	struct inf_process_info *proc_info = container_of(kref,
						     struct inf_process_info,
						     ref);
	struct completion *done = proc_info->close_completion;

	NNP_ASSERT(proc_info->close_completion);
	complete(done);
}

int inf_proc_put(struct inf_process_info *proc_info)
{
	if (unlikely(!proc_info))
		return 0;
	return kref_put(&proc_info->ref, proc_release);
}

int inf_proc_add_hostres(struct inf_process_info *proc_info,
			 struct nnpdrv_host_resource *hostres,
			 s32 fd,
			 struct inf_hostres **inf_hostres_entry)
{
	struct inf_hostres *hr_entry;

	hr_entry = kmalloc(sizeof(*hr_entry), GFP_KERNEL);
	if (unlikely(!hr_entry))
		return -ENOMEM;

	nnpdrv_hostres_get(hostres);
	hr_entry->hostres = hostres;

	inf_proc_get(proc_info);
	hr_entry->proc_info = proc_info;

	kref_init(&hr_entry->ref);
	hr_entry->magic = inf_proc_add_hostres;
	hr_entry->fd = fd;

	mutex_lock(&proc_info->lock);
	list_add(&hr_entry->node, &proc_info->hostres_list);
	mutex_unlock(&proc_info->lock);

	*inf_hostres_entry = hr_entry;

	return 0;
}

bool is_inf_hostres_ptr(void *ptr)
{
	return ptr &&
		((struct inf_hostres *)ptr)->magic == inf_proc_add_hostres;
}

static void inf_proc_remove_hostres(struct kref *kref)
{
	struct inf_hostres *hr_entry = container_of(kref, struct inf_hostres,
							 ref);
	struct inf_process_info *proc_info = hr_entry->proc_info;

	mutex_lock(&proc_info->lock);
	list_del(&hr_entry->node);
	mutex_unlock(&proc_info->lock);

	nnpdrv_hostres_put(hr_entry->hostres);

	kfree(hr_entry);
	inf_proc_put(proc_info);
}

bool inf_hostres_check_and_get(void *ptr)
{
	struct inf_hostres *hostres_entry = (struct inf_hostres *)ptr;
	int ret;

	if (!is_inf_hostres_ptr(ptr))
		return false;

	ret = kref_get_unless_zero(&hostres_entry->ref);
	NNP_ASSERT(ret != 0);

	return true;
}

bool inf_hostres_put(struct inf_hostres *inf_hostres_entry)
{
	return kref_put(&inf_hostres_entry->ref, inf_proc_remove_hostres);
}

void inf_proc_destroy_all(struct inf_process_info *proc_info)
{
	struct inf_hostres *inf_hostres_entry;
	struct completion completion;

	mutex_lock(&proc_info->lock);

	/* destroy all hostreses owned by the process */
	while (!list_empty(&proc_info->hostres_list)) {
		inf_hostres_entry = list_first_entry(&proc_info->hostres_list,
						     struct inf_hostres, node);
		mutex_unlock(&proc_info->lock);

		nnpdrv_hostres_destroy(inf_hostres_entry->hostres);
		inf_hostres_put(inf_hostres_entry);

		mutex_lock(&proc_info->lock);
	}
	mutex_unlock(&proc_info->lock);

	/* wait for all contexts and hostreses to be destroyed */
	init_completion(&completion);
	proc_info->close_completion = &completion;
	inf_proc_put(proc_info);
	wait_for_completion(&completion);

	mutex_destroy(&proc_info->lock);
	idr_destroy(&proc_info->objects_idr.idr);

	proc_info->close_completion = NULL;
	kfree(proc_info);
}
