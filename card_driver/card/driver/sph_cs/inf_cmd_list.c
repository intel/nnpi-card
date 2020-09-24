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
#include "sphcs_trace.h"
#include "inf_ptr2id.h"

//#define OPT_EXTRA_DEBUG

struct id_range {
	struct list_head node;
	uint16_t         first;
	uint16_t         last;
};

int inf_cmd_create(uint16_t              protocol_id,
		   struct inf_context   *context,
		   struct inf_cmd_list **out_cmd)
{
	struct inf_cmd_list *cmd;

	cmd = kzalloc(sizeof(*cmd), GFP_KERNEL);
	if (unlikely(cmd == NULL))
		return -ENOMEM;

	kref_init(&cmd->ref);
	cmd->magic = inf_cmd_create;
	cmd->protocol_id = protocol_id;
	cmd->req_list = NULL;
	cmd->edits = NULL;
	cmd->edits_idx = 0;
	cmd->sched_failed = NNP_IPC_NO_ERROR;
	cmd->ptr2id = add_ptr2id(cmd);
	if (unlikely(cmd->ptr2id == 0)) {
		kfree(cmd);
		return -ENOMEM;
	}

	/* make sure context will not be destroyed during cmd life */
	inf_context_get(context);
	cmd->context = context;

	spin_lock_init(&cmd->lock_irq);
	cmd->status = CREATE_STARTED;
	cmd->destroyed = 0;

	cmd->num_reqs = 0;
	atomic_set(&cmd->num_left, 0);

	inf_exec_error_list_init(&cmd->error_list, context);
	INIT_LIST_HEAD(&cmd->devres_id_ranges);

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

	NNP_SPIN_LOCK_IRQSAVE(&cmd->lock_irq, flags);

	should_destroy = (cmd->destroyed == 0);
	if (likely(should_destroy))
		cmd->destroyed = -1;

	NNP_SPIN_UNLOCK_IRQRESTORE(&cmd->lock_irq, flags);

	if (likely(should_destroy))
		inf_cmd_put(cmd);
}

static void attach_depend_pivot(struct inf_devres **devres_array,
				uint16_t            array_size)
{
	uint16_t i;

	for (i = 0; i < array_size; i++)
		inf_devres_pivot_usecount_inc(devres_array[i]);
}

static void detach_depend_pivot(struct inf_devres **devres_array,
				uint16_t            array_size)
{
	uint16_t i;

	for (i = 0; i < array_size; i++)
		inf_devres_pivot_usecount_dec(devres_array[i]);
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

	NNP_ASSERT(is_inf_cmd_ptr(cmd));

	NNP_SPIN_LOCK(&cmd->context->lock);
	hash_del(&cmd->hash_node);
	NNP_SPIN_UNLOCK(&cmd->context->lock);

	if (likely(cmd->req_list != NULL)) {
		for (i = 0; i < cmd->num_reqs; ++i) {
			if (cmd->req_list[i].cmd_type == CMDLIST_CMD_COPYLIST) {
				if (cmd->req_list[i].num_opt_depend_devres < cmd->req_list[i].cpylst->n_copies) {
					kfree(cmd->req_list[i].opt_depend_devres);
					detach_depend_pivot(cmd->req_list[i].cpylst->devreses,
							    cmd->req_list[i].cpylst->n_copies);
					optimized = true;
				}
			} else if (cmd->req_list[i].cmd_type == CMDLIST_CMD_INFREQ) {
				if (cmd->req_list[i].i_num_opt_depend_devres < cmd->req_list[i].infreq->n_inputs) {
					kfree(cmd->req_list[i].i_opt_depend_devres);
					detach_depend_pivot(cmd->req_list[i].infreq->inputs,
							    cmd->req_list[i].infreq->n_inputs);
					optimized = true;
				}
				if (cmd->req_list[i].o_num_opt_depend_devres < cmd->req_list[i].infreq->n_outputs) {
					kfree(cmd->req_list[i].o_opt_depend_devres);
					detach_depend_pivot(cmd->req_list[i].infreq->outputs,
							    cmd->req_list[i].infreq->n_outputs);
					optimized = true;
				}
			}
			if (likely(cmd->req_list[i].f != NULL))
				cmd->req_list[i].f->obj_put(&cmd->req_list[i]);
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

	inf_exec_error_list_fini(&cmd->error_list);

	if (likely(cmd->destroyed == 1))
		sphcs_send_event_report(g_the_sphcs,
					NNP_IPC_CMD_DESTROYED,
					0,
					cmd->context->chan->respq,
					cmd->context->protocol_id,
					cmd->protocol_id);

	ret = inf_context_put(cmd->context);
	del_ptr2id(cmd);
	kfree(cmd);
}

void inf_cmd_get(struct inf_cmd_list *cmd)
{
	int ret;

	ret = kref_get_unless_zero(&cmd->ref);
	NNP_ASSERT(ret != 0);
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
	if (list_empty(ranges))
		list_add_tail(&new_range->node, ranges);
	else
		list_add_tail(&new_range->node, &range->node);

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
	int n_intersect = 0;
	uint16_t keep_last;

#ifdef OPT_EXTRA_DEBUG
	sph_log_debug(GENERAL_LOG, "intersect r0: (isect=0x%lx)\n", (uintptr_t)isect);
	list_for_each_entry_safe(r0, n, ranges0, node)
		sph_log_debug(GENERAL_LOG, "\t%d -> %d\n", r0->first, r0->last);
	sph_log_debug(GENERAL_LOG, "intersect r1:\n");
	list_for_each_entry_safe(r1, n, ranges1, node)
		sph_log_debug(GENERAL_LOG, "\t%d -> %d\n", r1->first, r1->last);
#endif

	r0 = list_first_entry(ranges0, struct id_range, node);
	r1 = list_first_entry(ranges1, struct id_range, node);
	while (&r0->node != ranges0 && &r1->node != ranges1) {
		uint16_t first = (r0->first > r1->first ? r0->first : r1->first);
		uint16_t last = (r0->last < r1->last ? r0->last : r1->last);

		if (first <= last) {
			n_intersect += (last - first + 1);

			if (isect == NULL) {
#ifdef OPT_EXTRA_DEBUG
				sph_log_debug(GENERAL_LOG, "intersect NULL DONE n_intersect=%d\n", n_intersect);
#endif
				return n_intersect;
			}

			if (first > r0->first) {
				keep_last = r0->last;
				if (last < keep_last) {
					n = kzalloc(sizeof(struct id_range), GFP_KERNEL);
					if (unlikely(n == NULL)) {
						n_intersect -= (last - first + 1);
						return n_intersect;
					}
					n->first = last + 1;
					n->last = keep_last;
					list_add(&n->node, &r0->node);
					r0->last = first - 1;
					r0 = n;
				} else
					r0->last = first - 1;
			} else {
				r0->first = last + 1;

				if (r0->first > r0->last) {
					n = list_next_entry(r0, node);
					list_del(&r0->node);
					kfree(r0);
					r0 = n;
				}
			}

			if (first > r1->first) {
				keep_last = r1->last;
				if (last < keep_last) {
					n = kzalloc(sizeof(struct id_range), GFP_KERNEL);
					if (unlikely(n == NULL)) {
						n_intersect -= (last - first + 1);
						return n_intersect;
					}
					n->first = last + 1;
					n->last = keep_last;
					list_add(&n->node, &r1->node);
					r1->last = first - 1;
					r1 = n;
				} else
					r1->last = first - 1;
			} else {
				r1->first = last + 1;

				if (r1->first > r1->last) {
					n = list_next_entry(r1, node);
					list_del(&r1->node);
					kfree(r1);
					r1 = n;
				}
			}

			id_range_add(isect, first, last);
		} else if (r0->first < r1->first)
			r0 = list_next_entry(r0, node);
		else
			r1 = list_next_entry(r1, node);
	}

#ifdef OPT_EXTRA_DEBUG
	sph_log_debug(GENERAL_LOG, "intersect DONE n_intersect=%d:\n", n_intersect);
	if (isect != NULL)
		list_for_each_entry_safe(r0, n, isect, node)
			sph_log_debug(GENERAL_LOG, "\t%d -> %d\n", r0->first, r0->last);
#endif

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

#ifdef OPT_EXTRA_DEBUG
static void dump_id_range(struct list_head *ranges)
{
	struct id_range *range, *tmp;

	list_for_each_entry_safe(range, tmp, ranges, node)
		sph_log_debug(GENERAL_LOG, "\tid range: %d -> %d\n", range->first, range->last);
}

static void dump_sets(struct list_head *sets)
{
	struct id_range *range, *tmp;
	struct req_entry *r, *tmpr;
	struct id_set *curr_set;

	if (list_empty(sets)) {
		sph_log_debug(GENERAL_LOG, "Dump Sets - NO Sets to dump\n");
		return;
	}

	sph_log_debug(GENERAL_LOG, "Dump Sets:\n");
	list_for_each_entry(curr_set, sets, node) {
		sph_log_debug(GENERAL_LOG, "Set 0x%lx is_output=%d merged=%d\n",
			      (uintptr_t)curr_set, curr_set->is_output, curr_set->merged);

		list_for_each_entry_safe(range, tmp, &curr_set->ranges, node)
			sph_log_debug(GENERAL_LOG, "\tid range: %d -> %d\n", range->first, range->last);

		list_for_each_entry_safe(r, tmpr, &curr_set->req_list, node) {
			if (r->req->cmd_type == CMDLIST_CMD_COPYLIST)
				sph_log_debug(GENERAL_LOG, "\treq: cpylst %d cmdlist=%d n_copies=%d\n",
				       r->req->cpylst->idx_in_cmd,
				       r->req->cmd->protocol_id,
				       r->req->cpylst->n_copies);
			else if (r->req->cmd_type == CMDLIST_CMD_INFREQ)
				sph_log_debug(GENERAL_LOG, "\treq: infreq %d cmdlist=%d n=%d\n",
					      r->req->infreq->protocol_id,
					      r->req->cmd->protocol_id,
					      r->idset->is_output ? r->req->infreq->n_outputs : r->req->infreq->n_inputs);
			else
				sph_log_debug(GENERAL_LOG, "\treq: copy %d cmdlist=%d devres=%d\n",
					      r->req->copy->protocol_id,
					      r->req->cmd->protocol_id,
					      r->req->copy->devres->protocol_id);
		}
	}
	sph_log_debug(GENERAL_LOG, "Dump Sets DONE\n");
}
#endif

static void inf_cmd_clear_group_devres_optimization(struct inf_cmd_list *cmd)
{
	struct inf_exec_req *req;
	uint16_t i;
	struct id_range *range, *tmp;

	for (i = 0; i < cmd->num_reqs; i++) {
		req = &cmd->req_list[i];
		if (req->cmd_type == CMDLIST_CMD_COPYLIST) {
			if (req->num_opt_depend_devres < req->cpylst->n_copies) {
				kfree(req->opt_depend_devres);
				req->opt_depend_devres = req->cpylst->devreses;
				req->num_opt_depend_devres = req->cpylst->n_copies;
				detach_depend_pivot(req->cpylst->devreses, req->cpylst->n_copies);
			}
		} else if (req->cmd_type == CMDLIST_CMD_INFREQ) {
			if (req->i_num_opt_depend_devres < req->infreq->n_inputs) {
				kfree(req->i_opt_depend_devres);
				req->i_opt_depend_devres = req->infreq->inputs;
				req->i_num_opt_depend_devres = req->infreq->n_inputs;
				detach_depend_pivot(req->infreq->inputs, req->infreq->n_inputs);
			}
			if (req->o_num_opt_depend_devres < req->infreq->n_outputs) {
				kfree(req->o_opt_depend_devres);
				req->o_opt_depend_devres = req->infreq->outputs;
				req->o_num_opt_depend_devres = req->infreq->n_outputs;
				detach_depend_pivot(req->infreq->outputs, req->infreq->n_outputs);
			}
		}
	}

	if (!list_empty(&cmd->devres_id_ranges))
		list_for_each_entry_safe(range, tmp, &cmd->devres_id_ranges, node) {
			list_del(&range->node);
			kfree(range);
		}
}

static int add_devres_to_set(struct inf_devres *devres,
			     struct id_set     *idset,
			     struct inf_exec_req *req,
			     struct list_head  *sets)
{
	if (inf_devres_is_p2p(devres)) {
		/* generate new idset for p2p resources - cannot be grouped with other resources */
		struct id_set *new_idset = id_set_create(idset->is_output);

		if (!new_idset)
			return -1;
		if (id_set_add_req(new_idset, req, idset) != 0) {
			id_set_free(new_idset);
			return -1;
		}
		if (id_range_add(&new_idset->ranges,
				 devres->protocol_id,
				 devres->protocol_id) != 0)
			return -1;
		id_set_merge(sets, new_idset);
	} else {
		if (id_range_add(&idset->ranges,
				 devres->protocol_id,
				 devres->protocol_id) != 0)
			return -1;
	}

	return 0;
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
			if (id_set_add_req(idset, req, idset) != 0) {
				id_set_free(idset);
				return -1;
			}
			if (id_range_add(&idset->ranges,
					 req->copy->devres->protocol_id,
					 req->copy->devres->protocol_id) != 0)
				return -1;
			if (id_range_add(&cmd->devres_id_ranges,
					 req->copy->devres->protocol_id,
					 req->copy->devres->protocol_id) != 0)
				return -1;
			id_set_merge(sets, idset);
		} else if (req->cmd_type == CMDLIST_CMD_COPYLIST) {
			idset = id_set_create(!req->cpylst->copies[0]->card2Host);
			if (!idset)
				return -1;
			if (id_set_add_req(idset, req, idset) != 0) {
				id_set_free(idset);
				return -1;
			}
			for (j = 0; j < req->cpylst->n_copies; j++) {
				if (add_devres_to_set(req->cpylst->copies[j]->devres,
						      idset,
						      req,
						      sets) != 0)
					return -1;
				if (id_range_add(&cmd->devres_id_ranges,
						 req->cpylst->copies[j]->devres->protocol_id,
						 req->cpylst->copies[j]->devres->protocol_id) != 0)
					return -1;
			}
			id_set_merge(sets, idset);
		} else if (req->cmd_type == CMDLIST_CMD_INFREQ) {
			idset = id_set_create(false);
			if (!idset)
				return -1;
			if (id_set_add_req(idset, req, idset) != 0) {
				id_set_free(idset);
				return -1;
			}
			for (j = 0; j < req->infreq->n_inputs; j++) {
				if (add_devres_to_set(req->infreq->inputs[j],
						      idset,
						      req,
						      sets) != 0)
					return -1;
				if (id_range_add(&cmd->devres_id_ranges,
						 req->infreq->inputs[j]->protocol_id,
						 req->infreq->inputs[j]->protocol_id) != 0)
					return -1;
			}
			id_set_merge(sets, idset);

			idset = id_set_create(true);
			if (!idset)
				return -1;
			if (id_set_add_req(idset, req, idset) != 0) {
				id_set_free(idset);
				return -1;
			}
			for (j = 0; j < req->infreq->n_outputs; j++) {
				if (add_devres_to_set(req->infreq->outputs[j],
						      idset,
						      req,
						      sets) != 0)
					return -1;
				if (id_range_add(&cmd->devres_id_ranges,
						 req->infreq->outputs[j]->protocol_id,
						 req->infreq->outputs[j]->protocol_id) != 0)
					return -1;
			}
			id_set_merge(sets, idset);
		}
	}

#ifdef OPT_EXTRA_DEBUG
	sph_log_debug(GENERAL_LOG, "cmdlist %d total ranges:\n", cmd->protocol_id);
	dump_id_range(&cmd->devres_id_ranges);
#endif

	return 0;
}

void inf_cmd_optimize_group_devres(struct inf_cmd_list *cmd)
{
	uint16_t i;
	struct id_set *idset, *tmp;
	struct list_head sets;
	struct id_range *r, *tmpr;
	struct inf_devres *devres;
	struct inf_devres *pivot;
	struct req_entry *re;
	uint16_t id;
	struct inf_devres_list_entry *devres_entry;
	struct inf_cmd_list *c;
	int err = -ENOMEM;

	NNP_ASSERT(cmd != NULL);
	NNP_ASSERT(cmd->status == CREATED);

	sph_log_debug(CREATE_COMMAND_LOG, "cmd_optimize %d START num_reqs=%d\n", cmd->protocol_id, cmd->num_reqs);
	if (cmd->num_reqs == 0)
		return;

	INIT_LIST_HEAD(&sets);

	/* wait for all active scheduled requests to finish */
	if (wait_event_timeout(cmd->context->sched_waitq,
				list_empty(&cmd->context->active_seq_list),
				msecs_to_jiffies(60000)) == 0)
		return;

	/* build and merge devres access groups */
	if (build_access_group_sets(cmd, &sets) != 0)
		goto done;

	/*
	 * for each exising command list - merge into same set and
	 * re-optimize if some device resource is shared with the command list
	 */
	NNP_SPIN_LOCK(&cmd->context->lock);
	hash_for_each(cmd->context->cmd_hash, i, c, hash_node) {
		if (c == cmd)
			continue;

		sph_log_debug(CREATE_COMMAND_LOG, "intersecting total cmd %d and %d\n", cmd->protocol_id, c->protocol_id);
		if (id_range_intersect(NULL,
				       &cmd->devres_id_ranges,
				       &c->devres_id_ranges) > 0) {
			NNP_SPIN_UNLOCK(&cmd->context->lock);
			sph_log_debug(CREATE_COMMAND_LOG, "clearing opts of cmdlist %d\n", c->protocol_id);
			inf_cmd_clear_group_devres_optimization(c);
			if (build_access_group_sets(c, &sets) != 0)
				goto done;
			NNP_SPIN_LOCK(&cmd->context->lock);
		}
	}
	NNP_SPIN_UNLOCK(&cmd->context->lock);

#ifdef OPT_EXTRA_DEBUG
	dump_sets(&sets);
#endif

	/* add devres pivot for non-empty sets to devres_groups of requests */
	list_for_each_entry_safe(idset, tmp, &sets, node) {
		if (!list_empty(&idset->ranges)) {
			r = list_first_entry(&idset->ranges, struct id_range, node);
			devres = inf_context_find_devres(cmd->context, r->first);
			if (!devres) {
				err = -ENXIO;
				goto done;
			}
			list_for_each_entry(re, &idset->req_list, node) {
				devres_entry = kzalloc(sizeof(*devres_entry), GFP_KERNEL);
				if (!devres_entry)
					goto done;
				devres_entry->devres = devres;
				list_add_tail(&devres_entry->node, &re->idset->devres_groups);
			}

			/* keep the "pivot" devres in all device resources of the group */
			pivot = devres;
			list_for_each_entry(r, &idset->ranges, node)
				for (id = r->first; id <= r->last; id++) {
					if (id == pivot->protocol_id)
						continue;
					devres = inf_context_find_devres(cmd->context, id);
					if (!devres) {
						err = -ENXIO;
						goto done;
					}

					err = inf_devres_set_depend_pivot(devres, pivot);
					if (err != 0) {
						sph_log_debug(CREATE_COMMAND_LOG, "Failed to set pivot for optimized set!\n");
						goto done;
					}
				}

			if (idset->merged) {
				list_del(&idset->node);
				id_set_free(idset);
			} else {
				list_for_each_entry_safe(r, tmpr, &idset->ranges, node) {
					list_del(&r->node);
					kfree(r);
				}
			}
		}
	}

	/* final pass build depend devres list into req */
	list_for_each_entry_safe(idset, tmp, &sets, node) {
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

			NNP_ASSERT(list_is_singular(&idset->req_list));
			re = list_first_entry_or_null(&idset->req_list, struct req_entry, node);
			if (unlikely(re == NULL)) {
				err = -ENXIO;
				goto done;
			}

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
				if (!opt_depend_devres) {
					err = -ENOMEM;
					goto done;
				}

				num_devres = 0;
				list_for_each_entry(devres_entry, &idset->devres_groups, node)
					opt_depend_devres[num_devres++] = devres_entry->devres;

				if (re->req->cmd_type == CMDLIST_CMD_COPYLIST) {
					re->req->opt_depend_devres = opt_depend_devres;
					re->req->num_opt_depend_devres = num_devres;
					attach_depend_pivot(re->req->cpylst->devreses, re->req->cpylst->n_copies);
					sph_log_debug(CREATE_COMMAND_LOG, "optimized dependency list for cmdlist %d cpylst %d from %d to %d\n",
						      re->req->cmd->protocol_id,
						      re->req->cpylst->idx_in_cmd,
						      re->req->cpylst->n_copies,
						      num_devres);
				} else if (re->req->cmd_type == CMDLIST_CMD_INFREQ) {
					if (idset->is_output) {
						re->req->o_opt_depend_devres = opt_depend_devres;
						re->req->o_num_opt_depend_devres = num_devres;
						attach_depend_pivot(re->req->infreq->outputs, re->req->infreq->n_outputs);
						sph_log_debug(CREATE_COMMAND_LOG, "optimized output dependency list for cmdlist %d infreq %d from %d to %d\n",
							      re->req->cmd->protocol_id,
							      re->req->infreq->protocol_id,
							      re->req->infreq->n_outputs,
							      num_devres);
					} else {
						re->req->i_opt_depend_devres = opt_depend_devres;
						re->req->i_num_opt_depend_devres = num_devres;
						attach_depend_pivot(re->req->infreq->inputs, re->req->infreq->n_inputs);
						sph_log_debug(CREATE_COMMAND_LOG, "optimized input dependency list for cmdlist %d infreq %d from %d to %d\n",
							      re->req->cmd->protocol_id,
							      re->req->infreq->protocol_id,
							      re->req->infreq->n_inputs,
							      num_devres);
					}
				}
			} else
				sph_log_debug(CREATE_COMMAND_LOG, "skip optimize %d->%d cmd_type=%d\n", orig_num_devres, num_devres, re->req->cmd_type);
		}

		list_del(&idset->node);
		id_set_free(idset);
	}

	err = 0;
	cmd->context->num_optimized_cmd_lists++;

done:
	if (unlikely(err != 0))
		sph_log_err(CREATE_COMMAND_LOG, "dependency optimization for cmdlist %hu has failed with err %d!!\n", cmd->protocol_id, err);

	sph_log_debug(CREATE_COMMAND_LOG, "cmd_optimize %d DONE err=%d num_optimized=%d\n", cmd->protocol_id, err, cmd->context->num_optimized_cmd_lists);

	list_for_each_entry_safe(idset, tmp, &sets, node) {
		if (unlikely(err != 0)) {
			list_for_each_entry(re, &idset->req_list, node) {
				if (re->req->cmd_type == CMDLIST_CMD_COPYLIST) {
					if (re->req->num_opt_depend_devres < re->req->cpylst->n_copies) {
						kfree(re->req->opt_depend_devres);
						re->req->opt_depend_devres = re->req->cpylst->devreses;
						re->req->num_opt_depend_devres = re->req->cpylst->n_copies;
						detach_depend_pivot(re->req->cpylst->devreses, re->req->cpylst->n_copies);
					}
				} else if (re->req->cmd_type == CMDLIST_CMD_INFREQ) {
					if (re->req->i_num_opt_depend_devres < re->req->infreq->n_inputs) {
						kfree(re->req->i_opt_depend_devres);
						re->req->i_opt_depend_devres = re->req->infreq->inputs;
						re->req->i_num_opt_depend_devres = re->req->infreq->n_inputs;
						detach_depend_pivot(re->req->infreq->inputs, re->req->infreq->n_inputs);
					}
					if (re->req->o_num_opt_depend_devres < re->req->infreq->n_outputs) {
						kfree(re->req->o_opt_depend_devres);
						re->req->o_opt_depend_devres = re->req->infreq->outputs;
						re->req->o_num_opt_depend_devres = re->req->infreq->n_outputs;
						detach_depend_pivot(re->req->infreq->outputs, re->req->infreq->n_outputs);
					}
				}
			}
		}

		list_del(&idset->node);
		id_set_free(idset);
	}
}

void send_cmd_list_completed_event(struct inf_cmd_list *cmd)
{
	if (cmd != NULL && atomic_dec_and_test(&cmd->num_left)) {
		sphcs_send_event_report(g_the_sphcs,
					NNP_IPC_EXECUTE_CMD_COMPLETE,
					0,
					cmd->context->chan->respq,
					cmd->context->protocol_id,
					cmd->protocol_id);
		DO_TRACE(trace_cmdlist(SPH_TRACE_OP_STATUS_COMPLETE,
			 cmd->context->protocol_id, cmd->protocol_id));
		// for schedule
		inf_cmd_put(cmd);
	}
}
