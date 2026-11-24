/*
 * Rule: INT32-C
 * Source: synthetic
 * Status: FAIL - on ILP32 an int is as wide as a long
 * Settings: data_model=ilp32
 * Expect: count=1
 *
 * On ILP32 int and long are both 32 bits, so an int may be LONG_MIN and
 * `labs((long)x)` may be labs(LONG_MIN). A long there is narrower than a
 * long long, so `llabs((long long)x)` of a long is defined.
 */
#include <stdlib.h>

long int_into_labs(int x)
{
    return labs((long)x);
}

long long long_into_llabs(long x)
{
    return llabs((long long)x);
}
