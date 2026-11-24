/*
 * Rule: INT32-C
 * Source: synthetic
 * Status: FAIL - only the library's labs is read; the project's abs is not
 * Settings: data_model=lp64
 * Expect: count=1
 *
 * This file defines its own `abs`, taking a long, so a call of it is not
 * the library's abs of an int and says nothing about INT_MIN: neither
 * call of it is reported. The library's labs of a full-range long may
 * still be labs(LONG_MIN).
 */
#include <stdlib.h>

static long abs(long v)
{
    return v > 0 ? v : 0;
}

long widened_argument(int x)
{
    return abs((long)x);
}

long plain_argument(int x)
{
    return abs(x);
}

long library_control(long x)
{
    return labs(x);
}
