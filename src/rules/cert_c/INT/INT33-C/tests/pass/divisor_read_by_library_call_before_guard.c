/*
 * Rule: INT33-C
 * Source: synthetic
 * Status: PASS - The divisor's address goes only to a library call before
 * the guard
 *
 * sscanf writes through the pointer during the call and keeps no copy, so
 * nothing changes the divisor once the guard has run.
 */

#include <stdio.h>

int ratio(const char *text, int a)
{
    int d;
    if (sscanf(text, "%d", &d) != 1)
        return 0;
    if (d == 0)
        return 0;
    return a / d;
}
