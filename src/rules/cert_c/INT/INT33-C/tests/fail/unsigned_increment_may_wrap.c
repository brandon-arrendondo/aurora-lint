/*
 * Rule: INT33-C
 * Source: synthetic
 * Status: FAIL - d++ wraps d to zero when d is UINT_MAX
 */

unsigned ratio(unsigned a, unsigned d)
{
    if (d > 0) {
        d++;
        return a / d;
    }
    return 0;
}
