/*
 * Rule: INT32-C
 * Source: synthetic
 * Status: FAIL - a cast wider than abs's parameter converts back at the call
 * Settings: data_model=lp64
 * Expect: count=3
 *
 * abs takes an int, labs a long and llabs a long long (C11 7.22.6.1), so
 * the argument converts to that type at the call whatever it was cast to:
 * `abs((long)x)` passes INT_MIN back to abs when `x` is INT_MIN, and the
 * absolute value is not representable. On LP64 long and long long are both
 * 64 bits, so `llabs((long long)x)` of a long may be llabs(LLONG_MIN).
 */
#include <stdlib.h>

int int_cast_to_long(int x)
{
    return abs((long)x);
}

long long_cast_to_long_long(long x)
{
    return labs((long long)x);
}

long long long_into_llabs(long x)
{
    return llabs((long long)x);
}
