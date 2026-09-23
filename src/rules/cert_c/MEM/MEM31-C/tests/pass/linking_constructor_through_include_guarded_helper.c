/*
 * Rule: MEM31-C
 * Source: hostap src/p2p/p2p.c p2p_create_device() + src/utils/list.h
 *
 * Status: PASS - Should NOT trigger MEM31-C violation
 *
 * The intrusive-list helper lives in an include-guarded header. The
 * cross-file summary gate for a definition inside a preprocessor
 * conditional (an earlier fix: a `#if X ... #else` stub body must not be unioned
 * as if it always held) treated the guard's `#ifndef LIST_H` as such a
 * branch, so dl_list_add() earned no stores_params, dl_list_add_tail()
 * forwarded a store into nothing, and p2p_create_device()'s returned object
 * never escaped: every dropped result of the linking constructor was a
 * leak of a block the container still held. A file-scope include guard is
 * the header's only definitions, not one arm of a choice.
 */
#include <stdlib.h>

#ifndef LIST_H
#define LIST_H

struct dl_list {
	struct dl_list *next;
	struct dl_list *prev;
};

static inline void dl_list_add(struct dl_list *list, struct dl_list *item)
{
	item->next = list->next;
	item->prev = list;
	list->next->prev = item;
	list->next = item;
}

static inline void dl_list_add_tail(struct dl_list *list, struct dl_list *item)
{
	dl_list_add(list->prev, item);
}

#endif /* LIST_H */

static void *os_zalloc(size_t size)
{
	return calloc(1, size);
}

struct p2p_device {
	struct dl_list list;
	int addr;
};

struct p2p_data {
	struct dl_list devices;
};

static struct p2p_device *p2p_create_device(struct p2p_data *p2p, int addr)
{
	struct p2p_device *dev;

	dev = os_zalloc(sizeof(*dev));
	if (dev == NULL)
		return NULL;
	dl_list_add_tail(&p2p->devices, &dev->list);
	dev->addr = addr;

	return dev;
}

int p2p_add_device(struct p2p_data *p2p, int addr)
{
	struct p2p_device *dev;

	dev = p2p_create_device(p2p, addr);
	if (dev == NULL)
		return -1;
	dev->addr = addr;
	return 0;
}
