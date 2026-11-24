/*
 * Rule: INT32-C
 * Source: synthetic
 * Status: FAIL - ISO C lets a short, a signed char or an int be as wide as the parameter
 * Settings: data_model=iso
 * Expect: count=4
 *
 * With only ISO C's minimum widths (C11 5.2.4.2.1), a short or a signed
 * char may be as wide as an int, and an int as wide as a long long, so
 * each argument below may be the parameter's most negative value.
 */
#include <stdlib.h>

int cast_to_short(int x)
{
    return abs((short)x);
}

int short_argument(short s)
{
    return abs(s);
}

int cast_to_signed_char(int c)
{
    return abs((signed char)c);
}

long long int_into_llabs(int x)
{
    return llabs((long long)x);
}
