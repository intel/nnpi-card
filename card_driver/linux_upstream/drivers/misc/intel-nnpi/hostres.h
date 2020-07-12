/* SPDX-License-Identifier: GPL-2.0-or-later */

/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 ********************************************/

#ifndef _NNPDRV_HOSTRES_H
#define _NNPDRV_HOSTRES_H

#include <linux/dma-mapping.h>
#include "device.h"

struct nnpdrv_host_resource;

/**
 * @brief Creates host resource
 *
 * This function provides host resource handle. The resource can be
 * Input(read by device), Output(write by device) and both.
 * If this function fails, it frees all already allocated resources
 * and exits with error. So inconsistent state is eliminated.
 * In case of failure destroy function should not be called.
 *
 * @param[in]   size  Size of the host resource to be created
 * @param[in]   dir   Resource direction (read or write or both)
 * @param[out]  res   Handle to newly created hosr resource
 * @return error number on failure.
 */
int nnpdrv_hostres_create(size_t                        size,
			  enum                          dma_data_direction dir,
			  struct nnpdrv_host_resource **res);

/**
 * @brief Creates host resource
 *
 * This function provides host resource handle. The resource can be
 * Input(read by device), Output(write by device) and both.
 * If this function fails, it frees all already allocated resources
 * and exits with error. So inconsistent state is eliminated.
 * In case of failure destroy function should not be called.
 *
 * @param[in]   dma_buf_fd  File descriptor of struct dma_buf
 * @param[in]   dir         Resource direction (read or write or both)
 * @param[out]  res         Handle to newly created hosr resource
 * @return error number on failure.
 */
int nnpdrv_hostres_dma_buf_create(int                           dma_buf_fd,
				  enum dma_data_direction       dir,
				  struct nnpdrv_host_resource **res);

/**
 * @brief Creates host resource from user allocated memory
 *
 * This function provides host resource handle. The resource can be
 * Input(read by device), Output(write by device) and both.
 * If this function fails, it frees all already allocated resources
 * and exits with error. So inconsistent state is eliminated.
 * In case of failure destroy function should not be called.
 *
 * @param[in]   dma_buf_fd  File descriptor of struct dma_buf
 * @param[in]   dir         Resource direction (read or write or both)
 * @param[out]  res         Handle to newly created hosr resource
 * @return error number on failure.
 */
int nnpdrv_hostres_create_usermem(void __user                  *user_ptr,
				  size_t                        size,
				  enum dma_data_direction       dir,
				  struct nnpdrv_host_resource **out_resource);

int nnpdrv_hostres_vmap(struct nnpdrv_host_resource *res,
			void                       **out_ptr);

void nnpdrv_hostres_vunmap(struct nnpdrv_host_resource *res, void *ptr);

/**
 * @brief Returns the refcount of the host resource
 *
 * This function returns the number of objects reference this
 * host resource. After creation the refcount is 1.
 *
 * @param[in]  res  handle to the res
 * @return num of reference of hostres
 */
int nnpdrv_hostres_read_refcount(struct nnpdrv_host_resource *res);

/**
 * @brief Destroys the host resource previously created
 *
 * This function releases all the resourses allocated for the host resource.
 *
 * @param[in]  res  handle to the res
 * @return false if refcount is not 0
 */
bool nnpdrv_hostres_destroy(struct nnpdrv_host_resource *res);

/**
 * @brief Maps the host resource to SpringHill device
 *
 * This function maps the host resource to be accessible from device
 * and returns the dma page list of DMA addresses.
 * The resource can be mapped to multiple devices.
 * The resource can be mapped to userspace and to device at the same time.
 *
 * @param[in]   res           handle to the host resource
 * @param[in]   nnpdev        handle to the device
 * @param[in]   use_one_entry use page list with one big enough entry
 * @param[out]  page_list     DMA address of first DMA page from the page list
 * @param[out]  total_chunks  Total number of DMA chunks in the all page list,
 *                            May be NULL if not required.
 * @return error on failure.
 */
int nnpdrv_hostres_map_device(struct nnpdrv_host_resource *res,
			      struct nnp_device           *nnpdev,
			      bool                         use_one_entry,
			      dma_addr_t                  *page_list,
			      u32                         *total_chunks);

/**
 * @brief Unmaps the host resource from SpringHill device
 *
 * This function unmaps previously mapped host resource from device.
 * The resource must be mapped to this device before calling this function.
 * The resource must be unlocked from this device, if it was previously locked,
 * before calling this function.
 *
 * @param[in]   res     handle to the host resource
 * @param[in]   nnpdev  handle to the device
 * @return error on failure.
 */
int nnpdrv_hostres_unmap_device(struct nnpdrv_host_resource *res,
				struct nnp_device           *nnpdev);

/**
 * @brief Maps the host resource to userspace
 *
 * This function maps the host resource to userspace virtual memory.
 * The host resource can be mapped to userspace multiple times.
 * The host resource can be mapped to user and to device at the same time.
 *
 * @param[in]       res  handle to the host resource
 * @param[in/out]   vma  handle to the virtual memory area
 * @return error on failure.
 */
int nnpdrv_hostres_map_user(struct nnpdrv_host_resource *res,
			    struct vm_area_struct       *vma);

/**
 * @brief Lock the host resource to for access from specified device
 *
 * This function locks the host resource from being modified by anyone else,
 * neither by user, nor by any of other devices. So it can be safely
 * read/modified from the device.
 * The resource must be mapped to this device before calling this function.
 *
 * @param[in]  res     handle to the host resource
 * @param[in]  nnpdev  handle to the device
 * @param[in]  dir     desired access direction (read or write or both)
 * @return error on failure.
 */
int nnpdrv_hostres_dev_lock(struct nnpdrv_host_resource *res,
			    struct nnp_device           *nnpdev,
			    enum dma_data_direction      dir);

/**
 * @brief Unlocks the host resource from being accessed by specified device
 *
 * This function unlocks previously locked host resource from the device.
 *
 * @param[in]  res     handle to the host resource
 * @param[in]  nnpdev  handle to the device
 * @param[in]  dir     desired access direction (read or write or both)
 * @return error on failure.
 */
int nnpdrv_hostres_dev_unlock(struct nnpdrv_host_resource *res,
			      struct nnp_device           *nnpdev,
			      enum dma_data_direction      dir);

/**
 * @brief Lock the host resource to for access from userspace
 *
 * This function locks the host resource from being modified by any of devices.
 * So it can be safely read or modified from user space.
 * The resource must be mapped to userspace before calling this function.
 *
 * @param[in]  res      handle to the host resource
 * @param[in]  timeout  timeout in usec.
 *                      0 -- don't wait; "too big" timeout -- wait forever
 * @return error on failure.
 */
int nnpdrv_hostres_user_lock(struct nnpdrv_host_resource *res,
			     unsigned int                 timeout);

/**
 * @brief Unlocks the host resource from being accessed by userspace
 *
 * This function unlocks previously locked host resource from userspace.
 *
 * @param[in]  res  handle to the host resource
 * @return error on failure.
 */
int nnpdrv_hostres_user_unlock(struct nnpdrv_host_resource *res);

/**
 * @brief Increases refcount of the hostres
 *
 * This function increases refcount of the host resource.
 *
 * @param[in]  res  handle to the host resource
 */
void nnpdrv_hostres_get(struct nnpdrv_host_resource *res);

/**
 * @brief Decreases refcount of the hostres and destroyes it when it reaches 0
 *
 * This function decreases refcount of the host resource and destroyes it
 * when it reaches 0. Returns true if the host resource was destroyed.
 *
 * @param[in]  res  handle to the host resource
 * @return true if destroy happened.
 */
bool nnpdrv_hostres_put(struct nnpdrv_host_resource *res);

/**
 * @brief Returns if the host resource is input resource
 *
 * This function returns true if the host resource can be read by device.
 *
 * @param[in]  res  handle to the host resource
 * @return true if the reasource is readable.
 */
bool nnpdrv_hostres_is_input(struct nnpdrv_host_resource *res);

/**
 * @brief Returns if the host resource is output resource
 *
 * This function returns true if the host resource can be modified by device.
 *
 * @param[in]  res  handle to the host resource
 * @return true if the reasource is writable.
 */
bool nnpdrv_hostres_is_output(struct nnpdrv_host_resource *res);

/**
 * @brief Returns size of the host resource
 *
 * This function returns size of the host resource or zero in case of failure.
 *
 * @param[in]  res  handle to the host resource
 * @return true if the reasource is writable.
 */
size_t nnpdrv_hostres_get_size(struct nnpdrv_host_resource *res);

bool nnpdrv_hostres_is_usermem(struct nnpdrv_host_resource *res);

int nnpdrv_hostres_init_sysfs(struct kobject *kobj);
void nnpdrv_hostres_fini_sysfs(struct kobject *kobj);

#endif
