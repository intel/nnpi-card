/*
 * NNP-I Linux Driver
 * Copyright (c) 2017-2021, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 */


#ifndef	_LINUX_RBTREE_H
#define	_LINUX_RBTREE_H

#include <stdio.h>
#include <linux/kernel.h>
#include <linux/stddef.h>

struct rb_node {
	unsigned long  __rb_parent_color;
	struct rb_node *rb_right;
	struct rb_node *rb_left;
} __attribute__((aligned(sizeof(long))));
	/* The alignment might seem pointless, but allegedly CRIS needs it */

struct rb_root {
	struct rb_node *rb_node;
};


#define rb_parent(r)   ((struct rb_node *)((r)->__rb_parent_color & ~3))

#define RB_ROOT	(struct rb_root) { NULL, }
#define	rb_entry(ptr, type, member) container_of(ptr, type, member)

#define RB_EMPTY_ROOT(root)  ((root)->rb_node == NULL)

/* 'empty' nodes are nodes that are known not to be inserted in an rbree */
#define RB_EMPTY_NODE(node)  \
	((node)->__rb_parent_color == (unsigned long)(node))
#define RB_CLEAR_NODE(node)  \
	((node)->__rb_parent_color = (unsigned long)(node))


extern void rb_insert_color(struct rb_node *, struct rb_root *);
extern void rb_erase(struct rb_node *, struct rb_root *);


/* Find logical next and previous nodes in a tree */
extern struct rb_node *rb_next(struct rb_node *);
extern struct rb_node *rb_prev(struct rb_node *);
extern struct rb_node *rb_first(const struct rb_root *);
extern struct rb_node *rb_last(const struct rb_root *);

/* Postorder iteration - always visit the parent after its children */
extern struct rb_node *rb_first_postorder(const struct rb_root *);
extern struct rb_node *rb_next_postorder(struct rb_node *);

/* Fast replacement of a single node without remove/rebalance/add/rebalance */
extern void rb_replace_node(struct rb_node *victim, struct rb_node *new,
				struct rb_root *root);

static inline void rb_link_node(struct rb_node * node, struct rb_node * parent,
				struct rb_node ** rb_link)
{
	node->__rb_parent_color = (unsigned long)parent;
	node->rb_left = node->rb_right = NULL;

	*rb_link = node;
}

#define rb_entry_safe(ptr, type, member) \
	({ typeof(ptr) ____ptr = (ptr); \
	   ____ptr ? rb_entry(____ptr, type, member) : NULL; \
	})

/*
 * rbtree_postorder_for_each_entry_safe - iterate over rb_root in post order of
 * given type safe against removal of rb_node entry
 *
 * @pos:	the 'type *' to use as a loop cursor.
 * @n:		another 'type *' to use as temporary storage
 * @root:	'rb_root *' of the rbtree.
 * @field:	the name of the rb_node field within 'type'.
 */
#define rbtree_postorder_for_each_entry_safe(pos, n, root, field) \
	for (pos = rb_entry_safe(rb_first_postorder(root), typeof(*pos), field); \
		 pos && ({ n = rb_entry_safe(rb_next_postorder(&pos->field), \
			typeof(*pos), field); 1; }); \
		 pos = n)

#endif	/* _LINUX_RBTREE_H */
