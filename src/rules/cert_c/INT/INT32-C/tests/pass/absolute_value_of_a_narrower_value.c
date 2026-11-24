/*
 * Rule: INT32-C
 * Source: synthetic
 * Status: PASS - every value of the argument is above the parameter's minimum
 * Settings: data_model=lp64
 *
 * On LP64 an int's values all fit in a long and stop above LONG_MIN, so
 * `labs((long)x)` and `llabs((long long)x)` of an int are defined; so is
 * abs of a short, of a value cast to short, or of an unsigned short, and
 * labs of an unsigned int.
 */
#include <stdlib.h>

long int_into_labs(int x)
{
    return labs((long)x);
}

long long int_into_llabs(int x)
{
    return llabs((long long)x);
}

int short_into_abs(short x)
{
    return abs(x);
}

int int_cast_to_short(int x)
{
    return abs((short)x);
}

int unsigned_short_into_abs(unsigned short x)
{
    return abs(x);
}

long unsigned_int_into_labs(unsigned int x)
{
    return labs(x);
}
