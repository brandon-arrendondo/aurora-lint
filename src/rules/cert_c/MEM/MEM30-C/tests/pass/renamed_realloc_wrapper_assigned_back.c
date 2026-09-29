/*
 * Rule: MEM30-C
 * Source: real-world (valkey ae.c: `eventLoop->events =
 *         zrealloc(eventLoop->events, ...)`, `#define zrealloc valkey_realloc`)
 * Status: PASS - Should NOT trigger MEM30-C violation
 * Description: `zrealloc` is renamed at link time, but the body the scan
 * reads is `zrealloc`'s, which releases its first argument and returns a
 * fresh block. Assigned back to the same field, the field holds the new
 * block, and the call and the assignment must agree on what `zrealloc` is.
 */
#include <stdlib.h>
#include <string.h>

#define zrealloc valkey_realloc

struct loop {
    int *events;
};

void *zrealloc(void *ptr, size_t n)
{
    void *fresh = malloc(n);
    if (fresh == NULL) {
        return NULL;
    }
    memcpy(fresh, ptr, 1);
    free(ptr);
    return fresh;
}

int resize(struct loop *l, size_t n)
{
    l->events = zrealloc(l->events, n * sizeof(int));
    l->events[0] = 0;
    return 0;
}
