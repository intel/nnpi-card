/********************************************
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#include "inf_cmd_list.h"
#include <linux/slab.h>
#include "sph_log.h"
#include "inf_context.h"
#include "inf_copy.h"
#include "inf_req.h"
#include "inf_cpylst.h"

int inf_cmd_create(uint16_t              protocolID,
		   struct inf_context   *context,
		   struct inf_cmd_list **out_cmd)
{
	struct inf_cmd_list *cmd;

	cmd = kzalloc(sizeof(*cmd), GFP_KERNEL);
	if (unlikely(cmd == NULL))
		return -ENOMEM;

	kref_init(&cmd->ref);
	cmd->magic = inf_cmd_create;
	cmd->protocolID = protocolID;
	cmd->req_list = NULL;

	/* make sure context will not be destroyed during cmd life */
	inf_context_get(context);
	cmd->context = context;

	spin_lock_init(&cmd->lock_irq);
	cmd->status = CREATE_STARTED;
	cmd->destroyed = 0;

	cmd->num_reqs = 0;
	cmd->num_left = 0;

	if (context->chan == NULL) {
		cmd->h2c_dma_desc.dma_direction = SPHCS_DMA_DIRECTION_HOST_TO_CARD;
		cmd->h2c_dma_desc.dma_priority = SPHCS_DMA_PRIORITY_NORMAL;
		cmd->h2c_dma_desc.flags = 0;
		cmd->h2c_dma_desc.serial_channel =
			sphcs_dma_sched_create_serial_channel(g_the_sphcs->dmaSched);
	}

	*out_cmd = cmd;
	return 0;
}

int is_inf_cmd_ptr(void *ptr)
{
	struct inf_cmd_list *cmd = (struct inf_cmd_list *)ptr;

	return (ptr != NULL && cmd->magic == inf_cmd_create);
}

/* This function is called only when creation is failed,
 * to destroy already created part
 */
void destroy_cmd_on_create_failed(struct inf_cmd_list *cmd)
{
	bool should_destroy;
	unsigned long flags;

	SPH_SPIN_LOCK_IRQSAVE(&cmd->lock_irq, flags);

	should_destroy = (cmd->destroyed == 0);
	if (likely(should_destroy))
		cmd->destroyed = -1;

	SPH_SPIN_UNLOCK_IRQRESTORE(&cmd->lock_irq, flags);

	if (likely(should_destroy))
		inf_cmd_put(cmd);
}

static void release_cmd(struct kref *kref)
{
	struct inf_cmd_list *cmd = container_of(kref,
						struct inf_cmd_list,
						ref);
	uint16_t i;
	int ret;

	SPH_ASSERT(is_inf_cmd_ptr(cmd));

	SPH_SPIN_LOCK(&cmd->context->lock);
	hash_del(&cmd->hash_node);
	SPH_SPIN_UNLOCK(&cmd->context->lock);

	if (likely(cmd->req_list != NULL)) {
		for (i = 0; i < cmd->num_reqs; ++i) {
			if (likely(cmd->req_list[i].f != NULL))
				cmd->req_list[i].f->obj_put(&cmd->req_list[i]);
			if (cmd->req_list[i].cmd_type == CMDLIST_CMD_COPYLIST) {
				if (cmd->req_list[i].num_opt_depend_devres > 0)
					kfree(cmd->req_list[i].opt_depend_devres);
			} else if (cmd->req_list[i].cmd_type == CMDLIST_CMD_INFREQ) {
				if (cmd->req_list[i].i_num_opt_depend_devres > 0)
					kfree(cmd->req_list[i].i_opt_depend_devres);
				if (cmd->req_list[i].o_num_opt_depend_devres > 0)
					kfree(cmd->req_list[i].o_opt_depend_devres);
			}
		}
		kfree(cmd->req_list);
	}

	if (likely(cmd->destroyed == 1))
		sphcs_send_event_report(g_the_sphcs,
					SPH_IPC_CMD_DESTROYED,
					0,
					cmd->context->protocolID,
					cmd->protocolID);

	ret = inf_context_put(cmd->context);

	kfree(cmd);
}

inline void inf_cmd_get(struct inf_cmd_list *cmd)
{
	int ret;

	ret = kref_get_unless_zero(&cmd->ref);
	SPH_ASSERT(ret != 0);
}

inline int inf_cmd_put(struct inf_cmd_list *cmd)
{
	return kref_put(&cmd->ref, release_cmd);
}

/*
 * dependency list optimization code for commands inside command list
 */
struct id_range {
	struct list_head node;
	uint16_t         first;
	uint16_t         last;
};

struct inf_devres_list_entry {
	struct list_head   node;
	struct inf_devres *devres;
};

struct id_set {
	struct list_head node;
	struct list_head ranges;
	struct list_head req_list;
	bool             is_output;
	bool             merged;
	bool             written;

	struct list_head  devres_groups;
};

struct req_entry {
	struct list_head     node;
	struct inf_exec_req *req;
	struct id_set       *idset;
};

static struct id_set *id_set_create(bool for_write)
{
	struct id_set *idset;

	idset = kmalloc(sizeof(*idset), GFP_KERNEL);
	if (!idset)
		return NULL;

	INIT_LIST_HEAD(&idset->ranges);
	INIT_LIST_HEAD(&idset->req_list);
	INIT_LIST_HEAD(&idset->devres_groups);
	idset->is_output = for_write;
	idset->merged = false;
	idset->written = for_write;

	return idset;
}

static int id_set_add(struct id_set *idset, uint16_t first_id, uint16_t last_id)
{
	struct id_range *range, *new_range;

	list_for_each_entry(range, &idset->ranges, node) {
		if (last_id == range->first-1) {
			range->first = first_id;
			return 0;
		} else if (first_id == range->last+1) {
			range->last = last_id;
			return 0;
		} else if (last_id < range->first)
			break;
	}

	new_range = kzalloc(sizeof(struct id_range), GFP_KERNEL);
	if (!new_range)
		return -1;

	new_range->first = first_id;
	new_range->last = last_id;
	list_add_tail(&new_range->node, &idset->ranges);
	return 0;
}

static int id_set_add_req(struct id_set *set, struct inf_exec_req *req, struct id_set *idset)
{
	struct req_entry *r;

	r = kzalloc(sizeof(*r), GFP_KERNEL);
	if (!r)
		return -1;

	r->req = req;
	r->idset = idset;
	list_add_tail(&r->node, &set->req_list);

	return 0;
}

static struct id_set *id_set_intersect(struct id_set *set0, struct id_set *set1)
{
	struct id_set *isect;
	struct id_range *r0, *r1, *n;
	struct req_entry *r, *tmpr;

	if (list_empty(&set0->ranges) ||
	    list_empty(&set1->ranges))
		return NULL;

	isect = id_set_create(set0->written);

	r0 = list_first_entry(&set0->ranges, struct id_range, node);
	r1 = list_first_entry(&set1->ranges, struct id_range, node);
	while (&r0->node != &set0->ranges && &r1->node != &set1->ranges) {
		uint16_t first = (r0->first > r1->first ? r0->first : r1->first);
		uint16_t last = (r0->last < r1->last ? r0->last : r1->last);

		if (first <= last) {
			if (first > r0->first)
				r0->last = first - 1;
			else
				r0->first = last + 1;

			if (first > r1->first)
				r1->last = first - 1;
			else
				r1->first = last + 1;

			if (r0->first >= r0->last) {
				n = list_next_entry(r0, node);
				list_del(&r0->node);
				kfree(r0);
				r0 = n;
			}

			if (r1->first >= r1->last) {
				n = list_next_entry(r1, node);
				list_del(&r1->node);
				kfree(r1);
				r1 = n;
			}

			id_set_add(isect, first, last);
		} else if (r0->first < r1->first)
			r0 = list_next_entry(r0, node);
		else
			r1 = list_next_entry(r1, node);
	}

	if (list_empty(&isect->ranges)) {
		kfree(isect);
		return NULL;
	}

	list_for_each_entry_safe(r, tmpr, &set0->req_list, node)
		id_set_add_req(isect, r->req, r->idset);
	list_for_each_entry_safe(r, tmpr, &set1->req_list, node)
		id_set_add_req(isect, r->req, r->idset);
	isect->merged = true;
	return isect;
}

static int id_set_merge(struct list_head *sets, struct id_set *set)
{
	struct id_set *curr_set;
	struct id_set *isect;

	if (list_empty(sets)) {
		list_add_tail(&set->node, sets);
		return 0;
	}

	list_for_each_entry(curr_set, sets, node) {
		if (curr_set->written) {
			isect = id_set_intersect(curr_set, set);
			if (isect != NULL)
				list_add_tail(&isect->node, sets);

			if (list_empty(&set->ranges))
				break;
		}
	}

	list_add_tail(&set->node, sets);

	return 0;
}

static void id_set_free(struct id_set *set)
{
	struct id_range *range, *tmp;
	struct req_entry *r, *tmpr;
	struct inf_devres_list_entry *devres_entry, *devres_tmp;

	list_for_each_entry_safe(range, tmp, &set->ranges, node) {
		list_del(&range->node);
		kfree(range);
	}

	list_for_each_entry_safe(r, tmpr, &set->req_list, node) {
		list_del(&r->node);
		kfree(r);
	}

	list_for_each_entry_safe(devres_entry, devres_tmp, &set->devres_groups, node) {
		list_del(&devres_entry->node);
		kfree(devres_entry);
	}

	kfree(set);
}

void inf_cmd_optimize_group_devres(struct inf_cmd_list *cmd)
{
	uint16_t i, j;
	struct inf_exec_req *req;
	struct id_set *idset, *tmp;
	struct list_head sets;
	struct id_range *r;
	struct inf_devres *devres;
	struct req_entry *re;
	uint16_t id;
	struct inf_devres_list_entry *devres_entry;
	int success = false;

	SPH_ASSERT(cmd != NULL);
	SPH_ASSERT(cmd->status == CREATED);

	if (cmd->num_reqs == 0)
		return;

	INIT_LIST_HEAD(&sets);

	/* build and merge devres access groups */
	for (i = 0; i < cmd->num_reqs; i++) {
		req = &cmd->req_list[i];
		if (req->cmd_type == CMDLIST_CMD_COPY) {
			idset = id_set_create(!req->copy->card2Host);
			if (!idset)
				goto done;
			id_set_add_req(idset, req, idset);
			if (id_set_add(idset,
				       req->copy->devres->protocolID,
				       req->copy->devres->protocolID) != 0)
				goto done;
			id_set_merge(&sets, idset);
		} else if (req->cmd_type == CMDLIST_CMD_COPYLIST) {
			idset = id_set_create(!req->cpylst->copies[0]->card2Host);
			if (!idset)
				goto done;
			id_set_add_req(idset, req, idset);
			for (j = 0; j < req->cpylst->n_copies; j++)
				if (id_set_add(idset,
					       req->cpylst->copies[j]->devres->protocolID,
					       req->cpylst->copies[j]->devres->protocolID) != 0)
					goto done;
			id_set_merge(&sets, idset);
		} else if (req->cmd_type == CMDLIST_CMD_INFREQ) {
			idset = id_set_create(false);
			if (!idset)
				goto done;
			id_set_add_req(idset, req, idset);
			for (j = 0; j < req->infreq->n_inputs; j++)
				if (id_set_add(idset,
					       req->infreq->inputs[j]->protocolID,
					       req->infreq->inputs[j]->protocolID) != 0)
					goto done;
			id_set_merge(&sets, idset);

			idset = id_set_create(true);
			if (!idset)
				goto done;
			id_set_add_req(idset, req, idset);
			for (j = 0; j < req->infreq->n_outputs; j++)
				if (id_set_add(idset,
					       req->infreq->outputs[j]->protocolID,
					       req->infreq->outputs[j]->protocolID) != 0)
					goto done;
			id_set_merge(&sets, idset);
		}
	}

	/* add devres pivot of merged sets to devres_groups of requests */
	list_for_each_entry_safe(idset, tmp, &sets, node) {
		if (idset->merged && !list_empty(&idset->ranges)) {
			r = list_first_entry(&idset->ranges, struct id_range, node);
			devres = inf_context_find_devres(cmd->context, r->first);
			if (!devres)
				goto done;
			list_for_each_entry(re, &idset->req_list, node) {
				devres_entry = kzalloc(sizeof(*devres_entry), GFP_KERNEL);
				if (!devres_entry)
					goto done;
				devres_entry->devres = devres;
				list_add_tail(&devres_entry->node, &re->idset->devres_groups);
			}

			list_del(&idset->node);
			id_set_free(idset);
		}
	}

	/* final pass add free resources and build depend devres list into req */
	list_for_each_entry_safe(idset, tmp, &sets, node) {
		/* add non-merged resources to non empty devres groups */
		if (!list_empty(&idset->ranges)) {
			list_for_each_entry(re, &idset->req_list, node) {
				list_for_each_entry(r, &idset->ranges, node)
					for (id = r->first; id <= r->last; id++) {
						devres = inf_context_find_devres(cmd->context, id);
						if (!devres)
							goto done;

						devres_entry = kzalloc(sizeof(*devres_entry), GFP_KERNEL);
						if (!devres_entry)
							goto done;
						devres_entry->devres = devres;
						list_add_tail(&devres_entry->node, &idset->devres_groups);
					}
			}
		}

		/*
		 * allocate and store the list of optimized resources in the
		 * request entry
		 */
		if (!list_empty(&idset->devres_groups)) {
			uint32_t num_devres = 0;
			struct inf_devres **opt_depend_devres;
			uint32_t orig_num_devres;

			list_for_each_entry(devres_entry, &idset->devres_groups, node)
				num_devres++;

			re = list_first_entry(&idset->req_list, struct req_entry, node);
			if (!re)
				goto done;

			if (re->req->cmd_type == CMDLIST_CMD_COPYLIST)
				orig_num_devres = re->req->cpylst->n_copies;
			else if (re->req->cmd_type == CMDLIST_CMD_INFREQ)
				orig_num_devres = (idset->is_output ? re->req->infreq->n_outputs : re->req->infreq->n_inputs);
			else
				orig_num_devres = 1;

			/*
			 * if devres set is not smaller - optimization is not
			 * needed
			 */
			if (num_devres < orig_num_devres) {
				opt_depend_devres = kmalloc_array(num_devres, sizeof(struct inf_devres *), GFP_KERNEL);
				if (!opt_depend_devres)
					goto done;

				num_devres = 0;
				list_for_each_entry(devres_entry, &idset->devres_groups, node)
					opt_depend_devres[num_devres++] = devres_entry->devres;

				if (re->req->cmd_type == CMDLIST_CMD_COPYLIST) {
					re->req->opt_depend_devres = opt_depend_devres;
					re->req->num_opt_depend_devres = num_devres;
					sph_log_debug(GENERAL_LOG, "optimized dependency list for cmdlist %d cpylst %d from %d to %d\n",
						      re->req->cmd->protocolID,
						      re->req->cpylst->idx_in_cmd,
						      re->req->cpylst->n_copies,
						      num_devres);
				} else if (re->req->cmd_type == CMDLIST_CMD_INFREQ) {
					if (idset->is_output) {
						re->req->o_opt_depend_devres = opt_depend_devres;
						re->req->o_num_opt_depend_devres = num_devres;
						sph_log_debug(GENERAL_LOG, "optimized input dependency list for cmdlist %d infreq %d from %d to %d\n",
							      re->req->cmd->protocolID,
							      re->req->infreq->protocolID,
							      re->req->infreq->n_outputs,
							      num_devres);
					} else {
						re->req->i_opt_depend_devres = opt_depend_devres;
						re->req->i_num_opt_depend_devres = num_devres;
						sph_log_debug(GENERAL_LOG, "optimized output dependency list for cmdlist %d infreq %d from %d to %d\n",
							      re->req->cmd->protocolID,
							      re->req->infreq->protocolID,
							      re->req->infreq->n_inputs,
							      num_devres);
					}
				}
			}
		}

		list_del(&idset->node);
		id_set_free(idset);
	}

	success = true;

done:
	list_for_each_entry_safe(idset, tmp, &sets, node) {
		if (!success) {
			sph_log_err(GENERAL_LOG, "dependency optimization for cmdlist %d has failed!!\n", cmd->protocolID);

			list_for_each_entry(re, &idset->req_list, node) {
				if (re->req->cmd_type == CMDLIST_CMD_COPYLIST) {
					if (re->req->num_opt_depend_devres > 0) {
						kfree(re->req->opt_depend_devres);
						re->req->num_opt_depend_devres = 0;
					}
				} else if (re->req->cmd_type == CMDLIST_CMD_INFREQ) {
					if (re->req->i_num_opt_depend_devres > 0) {
						kfree(re->req->i_opt_depend_devres);
						re->req->i_num_opt_depend_devres = 0;
					}
					if (re->req->o_num_opt_depend_devres > 0) {
						kfree(re->req->o_opt_depend_devres);
						re->req->o_num_opt_depend_devres = 0;
					}
				}
			}
		}

		list_del(&idset->node);
		id_set_free(idset);
	}
}
