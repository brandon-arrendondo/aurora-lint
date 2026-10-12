/*
 * Rule: INT33-C
 * Source: synthetic
 * Status: FAIL - d + 1 is zero when d is UINT_MAX
 *
 * The guard proves d positive, but the unsigned sum stored back wraps.
 */

unsigned ratio(unsigned a, unsigned d)
{
    if (d > 0) {
        d = d + 1;
        return a / d;
    }
    return 0;
}
