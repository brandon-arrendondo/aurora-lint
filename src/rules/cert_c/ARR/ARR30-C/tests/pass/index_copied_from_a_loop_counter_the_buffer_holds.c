/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - The index is a copy of a loop counter the buffer holds
 *
 * `k` is 0 or a copy of the counter `i` made inside a loop that runs while
 * `i < n`, where nothing but the loop's header writes `i`, so it is below
 * `n`. Nothing writes `n`. The buffer holds `n` elements: the fixed array
 * that an `if (n > ArraySize(st))` keeps only when `n` fits it, or else a
 * `malloc` of `sizeof(Reader) * n` bytes; or, for a constant limit, the
 * fixed array that limit sizes.
 */
#include <stddef.h>
#include <stdlib.h>

#define ArraySize(X) ((int)(sizeof(X) / sizeof(X[0])))

typedef struct
{
    long look;
} Reader;

int advance(long *look);

int smallest_reader_advances(int n)
{
    Reader st[4];
    Reader *a = st;
    int i;
    if (n > ArraySize(st))
    {
        long bytes = sizeof(Reader) * n;
        a = (Reader *)malloc(bytes);
    }
    if (a == NULL)
        return 0;
    for (i = 0; i < n; i++)
        a[i].look = 0;
    while (1)
    {
        int k;
        long least;
        k = 0;
        least = a[0].look;
        for (i = 0; i < n; i++)
        {
            if (a[i].look < least)
            {
                least = a[i].look;
                k = i;
            }
        }
        if (advance(&a[k].look))
            goto out;
    }
out:
    if (a != st)
        free(a);
    return 0;
}

void largest_of_a_fixed_table(void)
{
    int st[8] = {0};
    int *a = st;
    int k = 0;
    for (int i = 0; i < 8; i++)
        if (st[i] > st[k])
            k = i;
    a[k] = 0;
}
