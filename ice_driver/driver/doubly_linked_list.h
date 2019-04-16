/*
 * NNP-I Linux Driver
 * Copyright (c) 2017-2019, Intel Corporation.
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

#ifndef _DOUBLY_LINKED_LIST_H
#define _DOUBLY_LINKED_LIST_H

#if defined _DEBUG  && defined STANDALONE_TESTING
#include <stdio.h>
#endif

/*
 * cyclic doubly linked list
 */

struct cve_dle_t {
	struct cve_dle_t *next;
	struct cve_dle_t *prev;
	void *container;
};

void cve_dle_init(struct cve_dle_t *e, void *container);
void cve_dle_insert_before(struct cve_dle_t *e, struct cve_dle_t *newe);
void cve_dle_insert_after(struct cve_dle_t *e, struct cve_dle_t *newe);
struct cve_dle_t *cve_dle_remove(struct cve_dle_t *e);
int cve_dle_is_single(const struct cve_dle_t *e);

#define cve_dle_add_to_list_after(_anchor, _listname, _element) { \
	cve_dle_init(&(_element)->_listname, (_element)); \
	if (!(_anchor)) { \
		(_anchor) = (_element)->_listname.container; \
	} else { \
		cve_dle_insert_after \
			(&(_anchor)->_listname, &(_element)->_listname); \
	} \
}

#define cve_dle_add_to_list_before(_anchor, _listname, _element) { \
	cve_dle_init(&(_element)->_listname, (_element)); \
	if (!(_anchor)) { \
		(_anchor) = (_element)->_listname.container; \
	} else { \
		cve_dle_insert_before(&(_anchor)->_listname, \
			&(_element)->_listname); \
	} \
}

#define cve_dle_move(_anchor_to, _anchor_from, _listname, _element) { \
		typeof(_anchor_to) c = (_element); \
		cve_dle_remove_from_list(_anchor_from, _listname, c) ; \
		cve_dle_add_to_list_before(_anchor_to, _listname, c) ; \
}

#define cve_dle_remove_from_list(_anchor, _listname, _element) { \
	if (((_anchor) == (_element)) && cve_dle_is_single \
			(&(_element)->_listname)) { \
		(_anchor) = NULL; \
	} else { \
		if ((_anchor) == (_element)) { \
			(_anchor) = (typeof(_anchor))\
				((_element)->_listname.next->container); \
		} \
		cve_dle_remove(&(_element)->_listname); \
	} \
}

#define cve_dle_lookup(_anchor, _listname, _field, _val) ({ \
	typeof(_anchor) c = (_anchor); \
	int found = 0; \
	if (c) { \
		do { \
			if (c->_field == (_val)) { \
				found = 1; \
			} else { \
				c = c->_listname.next->container; \
			} \
		} while (!found && c != (_anchor)); \
	} \
	found ? c : NULL; \
})

#define cve_dle_concat(_anchor, _listname, _addend_anchor) { \
	if ((_addend_anchor)) { \
		if (!(_anchor)) { \
			(_anchor) = (_addend_anchor); \
		} else { \
			struct cve_dle_t *anchor_first = \
				&(_anchor)->_listname; \
			struct cve_dle_t *anchor_last = \
				(_anchor)->_listname.prev; \
			struct cve_dle_t *addend_anchor_first = \
				&(_addend_anchor)->_listname; \
			struct cve_dle_t *addend_anchor_last = \
				(_addend_anchor)->_listname.prev; \
			anchor_first->prev = addend_anchor_last; \
			anchor_last->next = addend_anchor_first; \
			addend_anchor_first->prev = anchor_last; \
			addend_anchor_last->next = anchor_first; \
		} \
	} \
}

#define cve_dle_prev(_element, _listname) \
	(typeof((_element)))((_element)->_listname.prev->container)
#define cve_dle_next(_element, _listname) \
	(typeof((_element)))((_element)->_listname.next->container)

#if defined _DEBUG  && defined RING3_VALIDATION
#define cve_dle_print(_anchor, _listname) { \
	char _b[4096]; \
	sprintf(_b, "%p", (_anchor)); \
	if ((_anchor)) { \
		typeof(_anchor) nc = cve_dle_next((_anchor), _listname); \
		while (nc != (_anchor)) { \
			sprintf(_b + strlen(_b), "->%p", nc); \
			nc = cve_dle_next(nc, _listname); \
		} \
	} \
	cve_os_log(CVE_LOGLEVEL_DEBUG, "%s\n", _b); \
}
#endif  /* _DEBUG */

#endif /* _DOUBLY_LINKED_LIST_H */
