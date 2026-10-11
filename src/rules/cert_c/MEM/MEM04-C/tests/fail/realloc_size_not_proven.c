/*
 * Rule: MEM04-C
 * Source: synthetic
 * Status: FAIL - realloc with a size that may be zero
 *
 * realloc(p, 0) may free p and return a null pointer (C17
 * implementation-defined, C23 undefined), so a caller that frees p on a
 * null result frees it twice.
 */

#include <stdlib.h>

void *grow(void *p, size_t n)
{
    void *q = realloc(p, n);
    if (q == NULL)
        free(p);
    return q;
}
