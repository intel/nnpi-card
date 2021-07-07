



/*******************************************************************************
 * INTEL CORPORATION CONFIDENTIAL Copyright(c) 2017-2021 Intel Corporation. All Rights Reserved.
 *
 * The source code contained or described herein and all documents related to the
 * source code ("Material") are owned by Intel Corporation or its suppliers or
 * licensors. Title to the Material remains with Intel Corporation or its suppliers
 * and licensors. The Material contains trade secrets and proprietary and
 * confidential information of Intel or its suppliers and licensors. The Material
 * is protected by worldwide copyright and trade secret laws and treaty provisions.
 * No part of the Material may be used, copied, reproduced, modified, published,
 * uploaded, posted, transmitted, distributed, or disclosed in any way without
 * Intel's prior express written permission.
 *
 * No license under any patent, copyright, trade secret or other intellectual
 * property right is granted to or conferred upon you by disclosure or delivery of
 * the Materials, either expressly, by implication, inducement, estoppel or
 * otherwise. Any license under such intellectual property rights must be express
 * and approved by Intel in writing.
 ********************************************************************************/
#pragma once

#include <stdint.h>
#include <semaphore.h>

struct um_shm_list_head {
	uintptr_t off;
	uintptr_t next_off;
	uintptr_t prev_off;
};

struct um_shm_list {
	uintptr_t list_off;
	uintptr_t free_off;
	uintptr_t head_off;
	uint32_t  node_off;
	uint32_t  list_size;
};

template<class T>
void um_shm_list_init(const char              *shm_base,
		      struct um_shm_list      *list,
		      T                       *first,
		      struct um_shm_list_head *head,
		      uint32_t		       entry_size,
		      int                      list_size,
		      void                     (*init_cb)(T *) = nullptr,
		      bool                     is_append = false)
{
	uintptr_t off = (uintptr_t)head - (uintptr_t)shm_base;
	uintptr_t prev_off = 0;

	if (is_append) {
		list->free_off = off;
		list->list_size += list_size;
	} else {
		list->list_off = (uintptr_t)list - (uintptr_t)shm_base;
		list->free_off = off;
		list->head_off = 0;
		list->node_off = (uintptr_t)head - (uintptr_t)first;
		list->list_size = list_size;
	}

	for (int i = 0; i < list_size; i++) {
		head->off = off;
		head->prev_off = prev_off;

		if (i < list_size-1)
			head->next_off = off + entry_size;
		else
			head->next_off = 0;

		if (init_cb)
			(*init_cb)((T *)((uintptr_t)first + (i * entry_size)));

		prev_off = off;
		off += entry_size;
		head = (struct um_shm_list_head *)(shm_base + off);
	}
}

bool inline um_shm_list_is_empty(struct um_shm_list *list)
{
	return list->head_off == 0;
}

template <class T>
bool um_shm_list_alloc(struct um_shm_list *list,
		       T                 *&elem,
		       sem_t              *lock)
{
	if (lock)
		sem_wait(lock);

	if (!list->free_off) {
		if (lock)
			sem_post(lock);
		elem = nullptr;
		return false;
	}

	const char *shm_base = (const char *)list - list->list_off;

	struct um_shm_list_head *head =
		(struct um_shm_list_head *)(shm_base + list->free_off);

	// Get node out of the free list
	list->free_off = head->next_off;
	if (head->next_off) {
		struct um_shm_list_head *next_head =
			(struct um_shm_list_head *)(shm_base + head->next_off);
		next_head->prev_off = 0;
	}

	// Put node as the new head
	if (list->head_off) {
		struct um_shm_list_head *cur_head =
			(struct um_shm_list_head *)(shm_base + list->head_off);
		cur_head->prev_off = head->off;
	}
	head->next_off = list->head_off;
	list->head_off = head->off;

	if (lock)
		sem_post(lock);

	elem = (T *)(shm_base + head->off - list->node_off);
	return true;
}

template <class T>
void um_shm_list_del(struct um_shm_list *list,
		     T                  *elem,
		     sem_t              *lock)
{
	if (lock)
		sem_wait(lock);

	const char *shm_base = (const char *)list - list->list_off;

	struct um_shm_list_head *node =
		(struct um_shm_list_head *)((uintptr_t)elem + list->node_off);

	// Put node out of the head list
	struct um_shm_list_head *prev_node = nullptr;
	struct um_shm_list_head *next_node = nullptr;
	if (node->prev_off) {
		prev_node = (struct um_shm_list_head *)(shm_base +
							node->prev_off);
		prev_node->next_off = node->next_off;
	} else {
		list->head_off = node->next_off;
	}

	if (node->next_off) {
		next_node = (struct um_shm_list_head *)(shm_base +
							node->next_off);
		next_node->prev_off = node->prev_off;
	}


	// Insert the node to the start of the free list
	node->prev_off = 0;
	node->next_off = list->free_off;
	if (list->free_off) {
		next_node = (struct um_shm_list_head *)(shm_base +
							list->free_off);
		next_node->prev_off = node->off;
	}
	list->free_off = node->off;

	if (lock)
		sem_post(lock);
}

inline void *um_shm_list_shm_base(const struct um_shm_list_head *node)
{
	return (void *)((uintptr_t)node - node->off);
}

template<class T>
bool um_shm_list_first(struct um_shm_list *list,
		       T                 *&elem_ptr)
{
	if (list->head_off == 0) {
		elem_ptr = nullptr;
		return false;
	}

	const char *shm_base = (const char *)list - list->list_off;

	elem_ptr = (T *)(shm_base + list->head_off - list->node_off);
	return true;
}

template<class T>
bool um_shm_list_next(struct um_shm_list *list,
		      T                 *&elem_ptr)
{
	struct um_shm_list_head *node =
		(struct um_shm_list_head *)((uintptr_t)elem_ptr + list->node_off);

	if (node->next_off == 0) {
		elem_ptr = nullptr;
		return false;
	}

	const char *shm_base = (const char *)list - list->list_off;

	elem_ptr = (T *)(shm_base + node->next_off - list->node_off);
	return true;
}
