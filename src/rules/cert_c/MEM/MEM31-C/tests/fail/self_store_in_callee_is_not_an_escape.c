/*
 * Rule: MEM31-C
 * Source: hostap src/crypto/tls_openssl.c tls_context_new() + src/utils/list.h
 *
 * Status: FAIL - Should trigger MEM31-C violation
 *
 * dl_list_init() writes `list->next = list`: a store INTO the parameter's
 * own object, which dies with the block it points into. Once the
 * include-guarded header's definitions were read at all, that self-store
 * credited dl_list_init with stores_params, and a constructor calling
 * `dl_list_init(&context->sessions)` before `return context` read as if
 * the object had reached a container. It had not, in this minimized
 * reproduction: the caller that drops tls_context_new()'s result here
 * leaks it, and that is what this test exists to catch (the rule must
 * not let dl_list_init's self-store suppress a real MEM31-C finding on
 * this shape).
 *
 * This file is a minimized reproduction of the shape described above; it
 * makes no claim about the actual behavior of hostap's own source.
 */
#include <stdlib.h>

#ifndef LIST_H
#define LIST_H

struct dl_list {
	struct dl_list *next;
	struct dl_list *prev;
};

static inline void dl_list_init(struct dl_list *list)
{
	list->next = list;
	list->prev = list;
}

#endif /* LIST_H */

static void *os_zalloc(size_t size)
{
	return calloc(1, size);
}

struct tls_context {
	struct dl_list sessions;
	int cert_in_cb;
};

static struct tls_context *tls_context_new(int cert_in_cb)
{
	struct tls_context *context = os_zalloc(sizeof(*context));

	if (context == NULL)
		return NULL;
	dl_list_init(&context->sessions);
	context->cert_in_cb = cert_in_cb;
	return context;
}

int tls_init(int cert_in_cb)
{
	struct tls_context *context = tls_context_new(cert_in_cb);

	if (context == NULL)
		return -1;
	return context->cert_in_cb;
}
