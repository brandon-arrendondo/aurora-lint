/*
 * Rule: INT31-C
 * Source: synthetic
 * Status: FAIL - a guard bound through sqrt that the scan cannot know
 * Settings: iec_60559_sqrt=true
 * Expect: count=4
 *
 * Even with sqrt declared correctly rounded, the bound is known only for
 * sqrt of a constant: not when the operand is a variable, not when the
 * root is too large to keep the square in a short, not when the cast's
 * type need not hold the root (signed char holds 127 at least, and a
 * double out of a type's range converts with undefined behavior, C11
 * 6.3.1.4p1), and not when `sqrt` is this file's own function.
 */
#include <math.h>
#include <stdlib.h>

void printIntLine(int);

void variable_operand(short data, int limit)
{
    if (abs((long)data) <= (long)sqrt((double)limit))
    {
        short result = data * data;
        printIntLine(result);
    }
}

void root_too_large(short data)
{
    if (abs((long)data) <= (long)sqrt((double)2000000000))
    {
        short result = data * data;
        printIntLine(result);
    }
}

void narrow_cast(short data)
{
    if (abs((long)data) <= (signed char)sqrt((double)32767))
    {
        short result = data * data;
        printIntLine(result);
    }
}

static double own_sqrt(double v) { return v; }
#define sqrt own_sqrt

void own_function(short data)
{
    if (abs((long)data) <= (long)sqrt((double)32767))
    {
        short result = data * data;
        printIntLine(result);
    }
}
