/*
 * Rule: INT32-C
 * Source: synthetic
 * Status: FAIL - only the library's labs is read; the macro abs is not
 * Settings: data_model=lp64
 * Expect: count=1
 *
 * `abs` is a macro here, so `abs((long)x)` is the macro's expression and
 * not a call of the library's abs of an int. The library's labs of a
 * full-range long may still be labs(LONG_MIN).
 */
#include <stdlib.h>

#define abs(v) ((v) < 0 ? -(v) : (v))

long macro_call(int x)
{
    return abs((long)x);
}

long library_control(long x)
{
    return labs(x);
}
