/*
 * Rule: INT33-C
 * Source: synthetic
 * Status: FAIL - A callee is handed a copy of a pointer to the divisor
 *
 * `fill` may store anything through `r`, which points at `x`.
 */

void fill(int *out);

int ratio(void)
{
    int x = 1;
    int *q = &x;
    int *r = q;
    fill(r);
    return 100 / x;
}
