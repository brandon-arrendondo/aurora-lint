/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - A pointer set before its allocation keeps the allocation's size
 *
 * `p` is NULL until it takes `N + 1` bytes, and nothing moves it after, so
 * the early return leaves `i` below `N` for `p[i]`.
 */

#include <stdlib.h>

#define N 64

extern size_t next_index(void);

char *terminated(void)
{
    size_t i = next_index();
    char *p = NULL;

    p = malloc(N + 1);
    if (p == NULL)
        return NULL;
    if (i >= N)
        return NULL;
    p[i] = 0;
    return p;
}
