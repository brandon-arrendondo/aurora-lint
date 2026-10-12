/*
 * Rule: INT33-C
 * Source: synthetic
 * Status: FAIL - The divisor d + 1 is zero when d is UINT_MAX
 */

unsigned ratio(unsigned a, unsigned d)
{
    if (d > 0)
        return a / (d + 1);
    return 0;
}
