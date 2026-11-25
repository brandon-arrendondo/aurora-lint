/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: FAIL - The loop's count is written after the buffer was sized by it
 * Expect: count=4
 *
 * `k` copies a counter that runs to the count the buffer was allocated
 * for, but the count changes between the allocation and the loop: a macro
 * assigns it, as an object-like macro or a function-like one, or a pointer
 * derived from the one the count is read through (`&pn[0]`, `pn + 0`)
 * stores to it.
 */
#include <stdlib.h>

#define ArraySize(X) ((int)(sizeof(X) / sizeof(X[0])))
#define RESET_COUNT n = 100
#define RESET_COUNT_CALL() (n = 100)

void object_macro_writes_the_count(int n)
{
    int st[4];
    int *a = st;
    int i, k = 0;
    if (n > ArraySize(st))
        a = malloc(sizeof(int) * n);
    RESET_COUNT;
    for (i = 0; i < n; i++)
        if (i & 1)
            k = i;
    a[k] = 0; /* Expect: here */
}

void function_macro_writes_the_count(int n)
{
    int st[4];
    int *a = st;
    int i, k = 0;
    if (n > ArraySize(st))
        a = malloc(sizeof(int) * n);
    RESET_COUNT_CALL();
    for (i = 0; i < n; i++)
        if (i & 1)
            k = i;
    a[k] = 0; /* Expect: here */
}

void element_address_writes_the_count(int *pn)
{
    int *q = &pn[0];
    int st[4];
    int *a = st;
    int i, k = 0;
    if (*pn > ArraySize(st))
        a = malloc(sizeof(int) * *pn);
    *q = 100;
    for (i = 0; i < *pn; i++)
        if (i & 1)
            k = i;
    a[k] = 0; /* Expect: here */
}

void offset_pointer_writes_the_count(int *pn)
{
    int *q;
    q = pn + 0;
    int st[4];
    int *a = st;
    int i, k = 0;
    if (*pn > ArraySize(st))
        a = malloc(sizeof(int) * *pn);
    *q = 100;
    for (i = 0; i < *pn; i++)
        if (i & 1)
            k = i;
    a[k] = 0; /* Expect: here */
}
