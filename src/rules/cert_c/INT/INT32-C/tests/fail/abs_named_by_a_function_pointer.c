/*
 * Rule: INT32-C
 * Source: synthetic
 * Status: FAIL - a parameter named abs is a pointer, not the library's abs
 * Settings: data_model=lp64
 * Expect: count=1
 *
 * Inside `through_a_pointer`, `abs` is a parameter pointing to a function
 * that takes a long (ADR-0006), so the call is not abs of an int. The
 * library's abs in the other function may still be abs(INT_MIN).
 */
#include <stdlib.h>

long through_a_pointer(int x, long (*abs)(long))
{
    return abs((long)x);
}

int library_control(int x)
{
    return abs(x);
}
