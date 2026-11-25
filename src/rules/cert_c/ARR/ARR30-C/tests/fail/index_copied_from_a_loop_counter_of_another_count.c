/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: FAIL - The index is a copy of a loop counter the buffer may not hold
 * Expect: count=9
 *
 * `k` copies a loop counter, but the loop runs past what the buffer holds:
 * to `n + 5` over a buffer of `n` elements, to `n` over a fixed array an
 * `if (n > 8)` keeps for an `n` of up to 8 though it holds 4, and to 16
 * over a fixed array of 8. Or the allocation is not of `n` elements of the
 * pointer's type: `n` bytes, by a `sizeof(char)` multiplier or `calloc`'s,
 * or a call that allocates nothing. Or the count need not hold its value:
 * `grow` may change `p->n` after the allocation, and `bump` a global.
 */
#include <stddef.h>
#include <stdlib.h>

#define ArraySize(X) ((int)(sizeof(X) / sizeof(X[0])))

void *zero_alloc(long bytes);

void counter_runs_past_the_count(int n)
{
    int st[4];
    int *a = st;
    if (n > ArraySize(st))
        a = zero_alloc(sizeof(int) * n);
    int k = 0;
    for (int i = 0; i < n + 5; i++)
        if (i & 1)
            k = i;
    a[k] = 0; /* Expect: here */
}

void fixed_array_kept_past_its_size(int n)
{
    int st[4];
    int *a = st;
    if (n > 8)
        a = zero_alloc(sizeof(int) * n);
    int k = 0;
    for (int i = 0; i < n; i++)
        if (a[i] > a[k])
            k = i;
    a[k] = 0; /* Expect: here */
}

void constant_limit_past_the_array(void)
{
    int st[8] = {0};
    int *a = st;
    int k = 0;
    for (int i = 0; i < 16; i++)
        if (i & 3)
            k = i;
    a[k] = 0; /* Expect: here */
}

void bytes_not_elements(int n)
{
    int st[4];
    int *a = st;
    if (n > ArraySize(st))
        a = malloc(sizeof(char) * n);
    int k = 0;
    for (int i = 0; i < n; i++)
        if (a[i] > a[k])
            k = i;
    a[k] = 0; /* Expect: here */
}

void calloc_of_bytes(int n)
{
    int st[4];
    int *a = st;
    if (n > ArraySize(st))
        a = calloc(n, sizeof(char));
    int k = 0;
    for (int i = 0; i < n; i++)
        if (i & 1)
            k = i;
    a[k] = 0; /* Expect: here */
}

int *pick(int *p, size_t bytes);

void no_allocation(int n)
{
    int st[4];
    int *a = st;
    if (n > ArraySize(st))
        a = pick(st, sizeof(int) * n);
    int k = 0;
    for (int i = 0; i < n; i++)
        if (i & 1)
            k = i;
    a[k] = 0; /* Expect: here */
}

struct sized
{
    int n;
};

void grow(struct sized *p);

void count_a_callee_may_change(struct sized *p)
{
    int st[4];
    int *a = st;
    int k = 0;
    int i;
    if (p->n > ArraySize(st))
        a = malloc(sizeof(int) * p->n);
    grow(p);
    for (i = 0; i < p->n; i++)
        if (i & 1)
            k = i;
    a[k] = 0; /* Expect: here */
}

int global_count;
void bump(void);

void global_count_a_callee_may_change(void)
{
    int st[4];
    int *a = st;
    int k = 0;
    int i;
    if (global_count > ArraySize(st))
        a = malloc(sizeof(int) * global_count);
    bump();
    for (i = 0; i < global_count; i++)
        if (i & 1)
            k = i;
    a[k] = 0; /* Expect: here */
}

void counter_truncated_on_the_copy(void)
{
    int st[200] = {0};
    int *a = st;
    int k = 0;
    for (int i = 0; i < 200; i++)
        if (st[i])
            k = (signed char)i;
    a[k] = 0; /* Expect: here */
}
