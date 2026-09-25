/*
 * Rule: MEM10-C
 * Source: testcases
 * Status: FAIL - Should trigger MEM10-C violation
 */

/*
 * Rule: MEM10-C - Define and use a pointer validation function
 * Status: FAIL
 * Reason: `sizeof(x)` where `x` is a pointer, and the call means the
 *         pointed-to data: a pointer parameter, a pointer typedef, and an
 *         array parameter (which decays to a pointer), each copied into or
 *         cleared through the pointee rather than the pointer itself.
 */

#include <string.h>

typedef char *strbuf;

struct rec {
    int a[16];
};

void clear_rec(struct rec *r)
{
    memset(r, 0, sizeof(r));
}

void copy_buf(char *dst, strbuf s)
{
    memcpy(dst, s, sizeof(s));
}

void clear_arr(int arr[16])
{
    memset(arr, 0, sizeof(arr));
}

#include <stdlib.h>

/* The allocation's own target sized by itself, with a count: the buffer
 * is for ints, and n * sizeof(p) allocates n pointers' worth. */
int *alloc_ints(size_t n)
{
    int *p = malloc(n * sizeof(p));
    return p;
}
