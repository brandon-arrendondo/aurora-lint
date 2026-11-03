/*
 * Rule: INT33-C
 * Source: synthetic
 * Status: FAIL - A store through memcpy's returned pointer zeroes the divisor
 *
 * `memcpy` returns its destination, so `q` points at `x`: the store after
 * the check sets `x` to zero.
 */

#include <string.h>

int ratio(int y)
{
    int x = 1;
    int *q = memcpy(&x, &y, sizeof x);
    if (x == 0)
        return 0;
    *q = 0;
    return 100 / x;
}
