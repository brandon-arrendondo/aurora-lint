/*
 * Rule: MEM04-C
 * Source: synthetic
 * Status: PASS - Every size is proven non-zero
 *
 * An enumerator, a string length plus one, a size guarded by `> 0`, by an
 * early return on `< 1`, and by a call that never returns, and a size the
 * function computes itself rather than takes from input or a caller.
 */

#include <stdlib.h>
#include <string.h>

enum { BUFSZ = 64 };

void *buffer(void)
{
    return malloc(BUFSZ);
}

char *dup(const char *s)
{
    return malloc(strlen(s) + 1);
}

void *positive(size_t n)
{
    if (n > 0)
        return malloc(n);
    return NULL;
}

void *at_least_one(size_t n)
{
    if (n < 1)
        return NULL;
    return malloc(n);
}

void *or_exit(size_t n)
{
    if (!n)
        exit(1);
    return calloc(n, 4);
}

void *computed(void)
{
    size_t k = 10;
    k += 2;
    return malloc(k);
}

void *resize(void *p, size_t n)
{
    if (n == 0) {
        free(p);
        return NULL;
    }
    return realloc(p, n);
}
