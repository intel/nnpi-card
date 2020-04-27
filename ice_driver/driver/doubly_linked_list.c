/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/



#include <doubly_linked_list.h>

void
cve_dle_init(struct cve_dle_t *e, void *container)
{
	e->next = e;
	e->prev = e; /* cyclic list */
	e->container = container;
};

void
cve_dle_insert_before(struct cve_dle_t *e, struct cve_dle_t *newe)
{
	newe->prev = e->prev;
	newe->next = e;

	e->prev->next = newe;
	e->prev = newe;
}

void
cve_dle_insert_after(struct cve_dle_t *e, struct cve_dle_t *newe)
{
	newe->next = e->next;
	newe->prev = e;

	e->next->prev = newe;
	e->next = newe;
}

struct cve_dle_t *
cve_dle_remove(struct cve_dle_t *e)
{
	e->next->prev = e->prev;
	e->prev->next = e->next;
	return e->next;
}

int
cve_dle_is_single(const struct cve_dle_t *e)
{
	int is_single = (e->next->container == e->container);
	return is_single;
}

