/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: FAIL - An allocation's byte size bounds no element of a pointer array, nor a moved pointer
 * Expect: count=3
 *
 * `v` holds `N + 1` bytes, which is no more than `(N + 1) / sizeof(char *)`
 * pointers, so `i < N` does not keep `v[i]` inside it. After `p += 40`, `p`
 * points 40 bytes in, so `p[i]` may pass the end for `i` up to `N - 1`.
 * After `q = other`, `q` is another buffer, whose size the allocation says
 * nothing about.
 */

#include <stdlib.h>

#define N 64

extern size_t next_index(void);

void pointers(void)
{
    size_t i = next_index();
    char **v = malloc(N + 1);

    if (v == NULL || i >= N)
        return;
    v[i] = 0; /* Expect: here */
}

void moved(void)
{
    size_t i = next_index();
    char *p = malloc(N + 1);

    if (p == NULL)
        return;
    p += 40;
    if (i >= N)
        return;
    p[i] = 0; /* Expect: here */
}

void rebound(char *other)
{
    size_t i = next_index();
    char *q = malloc(N + 1);

    if (q == NULL)
        return;
    q = other;
    if (i >= N)
        return;
    q[i] = 0; /* Expect: here */
}
