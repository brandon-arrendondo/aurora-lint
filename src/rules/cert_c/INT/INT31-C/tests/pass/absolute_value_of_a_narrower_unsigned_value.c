/*
 * Rule: INT31-C
 * Source: synthetic
 * Status: PASS - an unsigned value narrower than abs's parameter
 * Settings: data_model=lp64
 *
 * On LP64 every `unsigned int` value fits in a long, so `labs(data)` and
 * `llabs(data)` are `data` itself, and either guard bounds it to 0..100.
 */
#include <stdlib.h>

void printIntLine(int);

void long_of_an_unsigned_int(unsigned int data)
{
    if (labs(data) <= 100)
    {
        short result = data;
        printIntLine(result);
    }
}

void long_long_of_an_unsigned_int(unsigned int data)
{
    if (llabs(data) <= 100)
    {
        short result = data;
        printIntLine(result);
    }
}
