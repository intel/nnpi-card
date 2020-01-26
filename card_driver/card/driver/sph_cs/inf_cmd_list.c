/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
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

struct id_range {
	struct list_head node;
	uint16_t         first;
	uint16_t         last;
};

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
	cmd->edits = NULL;
	cmd->edits_idx = 0;

	/* make sure context will not be destroyed during cmd life */
	inf_context_get(context);
	cmd->context = context;

	spin_lock_init(&cmd->lock_irq);
	cmd->status = CREATE_STARTED;
	cmd->destroyed = 0;

	cmd->num_reqs = 0;
	cmd->num_left = 0;

	inf_exec_error_list_init(&cmd->error_list, context);
	INIT_LIST_HEAD(&cmd->devres_id_ranges);

	if (context->chan == NULL) {
		cmd->h2c_dma_desc.dma_direction = SPHCS_DMA_DIRECTION_HOST_TO_CARD;
		cmd->h2c_dma_desc.dma_priority = SPHCS_DMA_PRIORITY_NORMAL;
		cmd->h2c_dma_desc.flags = 0;
		cmd->h2c_dma_desc.serial_channel =
			sphcs_dma_sched_create_serial_channel(g_the_sphcs->dmaSched);
	}

	/* Allocate memory for overwrite DMA */
	cmd->vptr = dma_alloc_coherent(g_the_sphcs->hw_device, SPH_PAGE_SIZE, &cmd->dma_addr, GFP_KERNEL);
	if (unlikely(cmd->vptr == NULL)) {
		kfree(cmd);
		return -ENOMEM;
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
	struct id_range *range, *tmp;
	uint16_t i;
	int ret;
	bool optimized = false;

	SPH_ASSERT(is_inf_cmd_ptr(cmd));

	SPH_SPIN_LOCK(&cmd->context->lock);
	hash_del(&cmd->hash_node);
	SPH_SPIN_UNLOCK(&cmd->context->lock);

	if (likely(cmd->req_list != NULL)) {
		for (i = 0; i < cmd->num_reqs; ++i) {
			if (likely(cmd->req_list[i].f != NULL))
				cmd->req_list[i].f->obj_put(&cmd->req_list[i]);
			if (cmd->req_list[i].cmd_type == CMDLIST_CMD_COPYLIST) {
				if (cmd->req_list[i].num_opt_depend_devres < cmd->req_list[i].cpylst->n_copies) {
					kfree(cmd->req_list[i].opt_depend_devres);
					optimized = true;
				}
			} else if (cmd->req_list[i].cmd_type == CMDLIST_CMD_INFREQ) {
				if (cmd->req_list[i].i_num_opt_depend_devres < cmd->req_list[i].infreq->n_inputs) {
					kfree(cmd->req_list[i].i_opt_depend_devres);
					optimized = true;
				}
				if (cmd->req_list[i].o_num_opt_depend_devres < cmd->req_list[i].infreq->n_outputs) {
					kfree(cmd->req_list[i].o_opt_depend_devres);
					optimized = true;
				}
			}
		}
		kfree(cmd->req_list);
		if (optimized)
			cmd->context->num_optimized_cmd_lists--;
	}

	if (likely(cmd->edits != NULL))
		kfree(cmd->edits);

	if (!list_empty(&cmd->devres_id_ranges))
		list_for_each_entry_safe(range, tmp, &cmd->devres_id_ranges, node) {
			list_del(&range->node);
			kfree(range);
		}

	dma_free_coherent(g_the_sphcs->hw_device, //TODO GLEB: can it be at fast path?
			  SPH_PAGE_SIZE,
			  cmd->vptr,
			  cmd->dma_addr);

	inf_exec_error_list_fini(&cmd->error_list);

	if (likely(cmd->destroyed == 1))
		sphcs_send_event_report(g_the_sphcs,
					SPH_IPC_CMD_DESTROYED,
					0,
					cmd->context->protocolID,
					cmd->protocolID);

	ret = inf_context_put(cmd->context);

	kfree(cmd);
}

void inf_cmd_get(struct inf_cmd_list *cmd)
{
	int ret;

	ret = kref_get_unless_zero(&cmd->ref);
	SPH_ASSERT(ret != 0);
}

int inf_cmd_put(struct inf_cmd_list *cmd)
{
	return kref_put(&cmd->ref, release_cmd);
}

/*
 * dependency list optimization code for commands inside command list
 */
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

	return idset;
}

static int id_range_add(struct list_head *ranges, uint16_t first_id, uint16_t last_id)
{
	struct id_range *range, *new_range;

	list_for_each_entry(range, ranges, node) {
		// do not add already existing ids
		if (first_id >= range->first && first_id <= range->last) {
			if (last_id <= range->last)
				return 0;
			first_id = range->last + 1;
		}

		if (last_id == range->first-1) {
			range->first = first_id;
			return 0;
		} else if (first_id == range->last+1) {
			range->last = last_id;

			// merge with next entries
			range = list_next_entry(range, node);
			while (&range->node != ranges) {
				new_range = list_next_entry(range, node);
				if (range->first <= last_id) {
					range->first = last_id + 1;
					if (range->first > range->last)
						list_del(&range->node);
					else
						break;
				} else
					break;
				range = new_range;
			}
			return 0;
		} else if (last_id < range->first)
			break;
	}

	new_range = kzalloc(sizeof(struct id_range), GFP_KERNEL);
	if (!new_range)
		return -1;

	new_range->first = first_id;
	new_range->last = last_id;
	list_add_tail(&new_range->node, ranges);
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

static uint32_t id_range_intersect(struct list_head *isect,
				   struct list_head *ranges0,
				   struct list_head *ranges1)
{
	struct id_range *r0, *r1, *n;
	uint32_t n_intersect = 0;

	r0 = list_first_entry(ranges0, struct id_range, node);
	r1 = list_first_entry(ranges1, struct id_range, node);
	while (&r0->node != ranges0 && &r1->node != ranges1) {
		uint16_t first = (r0->first > r1->first ? r0->first : r1->first);
		uint16_t last = (r0->last < r1->last ? r0->last : r1->last);

		if (first <= last) {
			n_intersect += (last - first + 1);

			if (isect == NULL)
				return n_intersect;

			if (first > r0->first)
				r0->last = first - 1;
			else
				r0->first = last + 1;

			if (first > r1->first)
				r1->last = first - 1;
			else
				r1->first = last + 1;

			if (r0->first > r0->last) {
				n = list_next_entry(r0, node);
				list_del(&r0->node);
				kfree(r0);
				r0 = n;
			}

			if (r1->first > r1->last) {
				n = list_next_entry(r1, node);
				list_del(&r1->node);
				kfree(r1);
				r1 = n;
			}

			id_range_add(isect, first, last);
		} else if (r0->first < r1->first)
			r0 = list_next_entry(r0, node);
		else
			r1 = list_next_entry(r1, node);
	}

	return n_intersect;
}

static struct id_set *id_set_intersect(struct id_set *set0, struct id_set *set1)
{
	struct id_set *isect;
	struct req_entry *r, *tmpr;

	if (list_empty(&set0->ranges) ||
	    list_empty(&set1->ranges))
		return NULL;

	isect = id_set_create(false);
	if (!isect)
		return NULL;

	if (id_range_intersect(&isect->ranges, &set0->ranges, &set1->ranges) == 0) {
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
		isect = id_set_intersect(curr_set, set);
		if (isect != NULL)
			list_add_tail(&isect->node, sets);

		if (list_empty(&set->ranges))
			break;
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

static void inf_cmd_clear_group_devres_optimization(struct inf_cmd_list *cmd)
{
	struct inf_exec_req *req;
	uint16_t i;

	for (i = 0; i < cmd->num_reqs; i++) {
		req = &cmd->req_list[i];
		if (req->cmd_type == CMDLIST_CMD_COPYLIST) {
			if (req->num_opt_depend_devres < req->cpylst->n_copies) {
				kfree(req->opt_depend_devres);
				req->opt_depend_devres = req->cpylst->devreses;
				req->num_opt_depend_devres = req->cpylst->n_copies;
			}
		} else if (req->cmd_type == CMDLIST_CMD_INFREQ) {
			if (req->i_num_opt_depend_devres < req->infreq->n_inputs) {
				kfree(req->i_opt_depend_devres);
				req->i_opt_depend_devres = req->infreq->inputs;
				req->i_num_opt_depend_devres = req->infreq->n_inputs;
			}
			if (req->o_num_opt_depend_devres < req->infreq->n_outputs) {
				kfree(req->o_opt_depend_devres);
				req->o_opt_depend_devres = req->infreq->outputs;
				req->o_num_opt_depend_devres = req->infreq->n_outputs;
			}
		}
	}
}

static int build_access_group_sets(struct inf_cmd_list *cmd,
				   struct list_head    *sets)
{
	uint16_t i, j;
	struct inf_exec_req *req;
	struct id_set *idset;

	for (i = 0; i < cmd->num_reqs; i++) {
		req = &cmd->req_list[i];
		if (req->cmd_type == CMDLIST_CMD_COPY) {
			idset = id_set_create(!req->copy->card2Host);
			if (!idset)
				return -1;
			id_set_add_req(idset, req, idset);
			if (id_range_add(&idset->ranges,
					 req->copy->devres->protocolID,
					 req->copy->devres->protocolID) != 0)
				return -1;
			if (id_range_add(&cmd->devres_id_ranges,
					 req->copy->devres->protocolID,
					 req->copy->devres->protocolID) != 0)
				return -1;
			id_set_merge(sets, idset);
		} else if (req->cmd_type == CMDLIST_CMD_COPYLIST) {
			idset = id_set_create(!req->cpylst->copies[0]->card2Host);
			if (!idset)
				return -1;
			id_set_add_req(idset, req, idset);
			for (j = 0; j < req->cpylst->n_copies; j++) {
				if (id_range_add(&idset->ranges,
						 req->cpylst->copies[j]->devres->protocolID,
						 req->cpylst->copies[j]->devres->protocolID) != 0)
					return -1;
				if (id_range_add(&cmd->devres_id_ranges,
						 req->cpylst->copies[j]->devres->protocolID,
						 req->cpylst->copies[j]->devres->protocolID) != 0)
					return -1;
			}
			id_set_merge(sets, idset);
		} else if (req->cmd_type == CMDLIST_CMD_INFREQ) {
			idset = id_set_create(false);
			if (!idset)
				return -1;
			id_set_add_req(idset, req, idset);
			for (j = 0; j < req->infreq->n_inputs; j++) {
				if (id_range_add(&idset->ranges,
						 req->infreq->inputs[j]->protocolID,
						 req->infreq->inputs[j]->protocolID) != 0)
					return -1;
				if (id_range_add(&cmd->devres_id_ranges,
						 req->infreq->inputs[j]->protocolID,
						 req->infreq->inputs[j]->protocolID) != 0)
					return -1;
			}
			id_set_merge(sets, idset);

			idset = id_set_create(true);
			if (!idset)
				return -1;
			id_set_add_req(idset, req, idset);
			for (j = 0; j < req->infreq->n_outputs; j++) {
				if (id_range_add(&idset->ranges,
						 req->infreq->outputs[j]->protocolID,
						 req->infreq->outputs[j]->protocolID) != 0)
					return -1;
				if (id_range_add(&cmd->devres_id_ranges,
						 req->infreq->outputs[j]->protocolID,
						 req->infreq->outputs[j]->protocolID) != 0)
					return -1;
			}
			id_set_merge(sets, idset);
		}
	}

	return 0;
}

void inf_cmd_optimize_group_devres(struct inf_cmd_list *cmd)
{
	uint16_t i;
	struct id_set *idset, *tmp;
	struct list_head sets;
	struct id_range *r;
	struct inf_devres *devres;
	struct req_entry *re;
	uint16_t id;
	struct inf_devres_list_entry *devres_entry;
	struct inf_cmd_list *c;
	int success = false;

	SPH_ASSERT(cmd != NULL);
	SPH_ASSERT(cmd->status == CREATED);

	if (cmd->num_reqs == 0)
		return;

	INIT_LIST_HEAD(&sets);

	/* wait for all active scheduled requests to finish */
	wait_event(cmd->context->sched_waitq,
		   list_empty(&cmd->context->active_seq_list));

	/* build and merge devres access groups */
	if (build_access_group_sets(cmd, &sets) != 0)
		goto done;

	/*
	 * for each exising command list - merge into same set and
	 * re-optimize if some device resource is shared with the command list
	 */
	SPH_SPIN_LOCK(&cmd->context->lock);
	hash_for_each(cmd->context->cmd_hash, i, c, hash_node) {
		if (c == cmd)
			continue;

		if (id_range_intersect(NULL,
				       &cmd->devres_id_ranges,
				       &c->devres_id_ranges) > 0) {
			SPH_SPIN_UNLOCK(&cmd->context->lock);
			inf_cmd_clear_group_devres_optimization(c);
			cmd->context->num_optimized_cmd_lists--;
			if (build_access_group_sets(c, &sets) != 0)
				goto done;
			SPH_SPIN_LOCK(&cmd->context->lock);
		}
	}
	SPH_SPIN_UNLOCK(&cmd->context->lock);

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
	cmd->context->num_optimized_cmd_lists++;

done:
	if (!success)
		sph_log_err(GENERAL_LOG, "dependency optimization for cmdlist %d has failed!!\n", cmd->protocolID);

	list_for_each_entry_safe(idset, tmp, &sets, node) {
		if (!success) {
			list_for_each_entry(re, &idset->req_list, node) {
				if (re->req->cmd_type == CMDLIST_CMD_COPYLIST) {
					if (re->req->num_opt_depend_devres < re->req->cpylst->n_copies) {
						kfree(re->req->opt_depend_devres);
						re->req->opt_depend_devres = re->req->cpylst->devreses;
						re->req->num_opt_depend_devres = re->req->cpylst->n_copies;
					}
				} else if (re->req->cmd_type == CMDLIST_CMD_INFREQ) {
					if (re->req->i_num_opt_depend_devres < re->req->infreq->n_inputs) {
						kfree(re->req->i_opt_depend_devres);
						re->req->i_opt_depend_devres = re->req->infreq->inputs;
						re->req->i_num_opt_depend_devres = re->req->infreq->n_inputs;
					}
					if (re->req->o_num_opt_depend_devres < re->req->infreq->n_outputs) {
						kfree(re->req->o_opt_depend_devres);
						re->req->o_opt_depend_devres = re->req->infreq->outputs;
						re->req->o_num_opt_depend_devres = re->req->infreq->n_outputs;
					}
				}
			}
		}

		list_del(&idset->node);
		id_set_free(idset);
	}
}
