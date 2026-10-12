/*
 * Rule: INT33-C
 * Source: synthetic
 * Status: FAIL - A pointer taken before the guard zeroes the divisor after it
 */

int ratio(int a, int d)
{
    int *p = &d;
    if (d == 0)
        return 0;
    *p = 0;
    return a / d;
}
