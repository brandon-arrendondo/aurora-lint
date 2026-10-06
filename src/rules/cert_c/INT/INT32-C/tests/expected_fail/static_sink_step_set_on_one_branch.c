/*
 * Rule: INT32-C
 * Source: regression
 * Status: EXPECTED_FAIL - known limitation: call-site constants ignore control flow
 * Settings: data_model=lp64
 *
 * `step` is INT_MAX unless `c` holds, so the caller passes INT_MAX or -5.
 * The call-site constant collection takes the last assignment in source
 * order as the value, so it proves step == -5 and `x + step` is taken to
 * fit. A join of the assignments that reach the call would leave step
 * unknown, and the addition would be reported.
 */
#include <limits.h>
#include <stdlib.h>

static int sink(int step)
{
    int x = rand();
    return x + step;
}

int caller(int c)
{
    int step = INT_MAX;
    if (c)
        step = -5;
    return sink(step);
}
