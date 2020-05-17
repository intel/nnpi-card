/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#ifndef SPHCS_INF_DEVNET_H
#define SPHCS_INF_DEVNET_H

#include <linux/kref.h>
#include <linux/hashtable.h>
#include <linux/spinlock.h>
#include <linux/dma-buf.h>
#include "dma_page_pool.h"
#include "inf_types.h"
#include "sphcs_sw_counters.h"

struct inf_context;
struct inf_devres;
struct inf_req;

struct devres_node {
	struct list_head   node;
	struct inf_devres *devres;
	bool               attached;
};

struct inf_devnet {
	void               *magic;
	struct kref         ref;
	uint16_t            protocolID;
	uint64_t            user_handle;
	struct inf_context *context;
	struct list_head    devres_list;
	uint32_t            num_devres;
	struct inf_devres  *first_devres;
	struct hlist_node   hash_node;
	spinlock_t          lock;

	DECLARE_HASHTABLE(infreq_hash, 6);

	uint64_t            rt_handle;
	bool                created;
	enum create_status  edit_status;
	int                 destroyed;

	void               *edit_data;

	struct nnp_sw_counters *sw_counters;
	bool serial_infreq_exec;
	unsigned int ptr2id;
};

int inf_devnet_create(uint16_t protocolID,
		      struct inf_context *context,
		      struct inf_devnet **out_devnet);
void inf_devnet_on_create_or_add_res_failed(struct inf_devnet *devnet);

int inf_devnet_add_devres(struct inf_devnet *devnet,
			  struct inf_devres *devres);
void inf_devnet_attach_all_devres(struct inf_devnet *devnet);
void inf_devnet_delete_devres(struct inf_devnet *devnet,
			      bool               del_all);

int is_inf_devnet_ptr(void *ptr);

int inf_devnet_get(struct inf_devnet *devnet);
int inf_devnet_put(struct inf_devnet *devnet);

int inf_devnet_create_infreq(struct inf_devnet *devnet,
			     uint16_t           protocolID,
			     dma_addr_t         host_dma_addr,
			     uint16_t           dma_size);
struct inf_req *inf_devnet_find_infreq(struct inf_devnet *devnet,
				       uint16_t           protocolID);
struct inf_req *inf_devnet_find_and_get_infreq(struct inf_devnet *devnet,
					       uint16_t           protocolID);
int inf_devnet_find_and_destroy_infreq(struct inf_devnet *devnet,
				       uint16_t           infreqID);
int inf_devnet_destroy_all_infreq(struct inf_devnet *devnet);
struct inf_devres *inf_devnet_find_ecc_devres(struct inf_devnet *devnet,
					      uint32_t usage_flag);

#endif
