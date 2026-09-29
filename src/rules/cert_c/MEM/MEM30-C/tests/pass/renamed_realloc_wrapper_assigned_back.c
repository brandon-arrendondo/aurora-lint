/*
 * Rule: MEM30-C
 * Source: real-world (valkey ae.c: `eventLoop->events =
 *         zrealloc(eventLoop->events, ...)`, `#define zrealloc valkey_realloc`)
 * Status: PASS - Should NOT trigger MEM30-C violation
 * Description: `zrealloc` is renamed at link time, but the body the scan
 * reads is `zrealloc`'s, which returns realloc called on its first
 * parameter. Assigned back to the same field, the field holds the new block,
 * and the call and the assignment must agree on what `zrealloc` is. The
 * twin FAIL fixture uses the old pointer after a successful call.
 */
#include <stdlib.h>

#define zrealloc valkey_realloc

struct loop {
    int *events;
};

void *zrealloc(void *ptr, size_t n)
{
    return realloc(ptr, n);
}

int resize(struct loop *l, size_t n)
{
    l->events = zrealloc(l->events, n * sizeof(int));
    l->events[0] = 0;
    return 0;
}
