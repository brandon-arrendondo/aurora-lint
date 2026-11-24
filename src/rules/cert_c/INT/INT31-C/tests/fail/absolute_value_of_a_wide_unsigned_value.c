/*
 * Rule: INT31-C
 * Source: synthetic
 * Status: FAIL - a 64-bit unsigned value converted into labs or llabs
 * Settings: data_model=lp64
 * Expect: count=4
 *
 * Converting an unsigned value above LLONG_MAX to long long is
 * implementation-defined (C11 6.3.1.3p3): ULLONG_MAX is -1 on a
 * two's-complement target, and llabs of it is 1. So `llabs(data) <= 100`
 * does not bound an `unsigned long long` (or, on LP64, an `unsigned long`),
 * and converting `data` to short may still change its value.
 */
#include <stdlib.h>

void printIntLine(int);

void long_long_of_an_unsigned_long_long(unsigned long long data)
{
    if (llabs(data) <= 100)
    {
        short result = data;
        printIntLine(result);
    }
}

void long_of_an_unsigned_long(unsigned long data)
{
    if (labs(data) <= 100)
    {
        short result = data;
        printIntLine(result);
    }
}

void long_long_of_an_unsigned_long(unsigned long data)
{
    if (llabs(data) <= 100)
    {
        short result = data;
        printIntLine(result);
    }
}

void through_a_cast_to_long_long(unsigned long long data)
{
    if (llabs((long long)data) <= 100)
    {
        short result = data;
        printIntLine(result);
    }
}
