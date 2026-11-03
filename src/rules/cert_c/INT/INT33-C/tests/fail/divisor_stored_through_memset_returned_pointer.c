/*
 * Rule: INT33-C
 * Source: synthetic
 * Status: FAIL - A store through memset's returned pointer zeroes the divisor
 *
 * `memset` returns its destination, so `q` points at `x`: the store after
 * the check sets `x` to zero.
 */

#include <string.h>

int ratio(void)
{
    int x = 1;
    int *q = memset(&x, 1, sizeof x);
    if (!x)
        return 0;
    *q = 0;
    return 100 / x;
}
