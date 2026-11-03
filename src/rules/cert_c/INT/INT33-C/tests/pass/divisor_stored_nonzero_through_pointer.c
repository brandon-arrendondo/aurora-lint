/*
 * Rule: INT33-C
 * Source: synthetic
 * Status: PASS - Every value stored into the divisor is non-zero
 *
 * `x` is 1, or 5 when the store through `q` runs: never zero. The store
 * through `other` cannot reach `x`, whose address the caller never had.
 */

int ratio(int c, int *other)
{
    int x = 1;
    int *q = &x;
    if (c)
        *q = 5;
    *other = 0;
    return 100 / x;
}
