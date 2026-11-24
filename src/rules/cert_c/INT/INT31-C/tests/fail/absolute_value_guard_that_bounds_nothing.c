/*
 * Rule: INT31-C
 * Source: synthetic
 * Status: FAIL - a guard that does not bound the square's operand
 * Expect: count=5
 *
 * The square is not bounded when no guard precedes it, when the only
 * bound is on its other side (`llabs(v) > 181`), when the cast before the
 * call can change the value (a signed char does not hold every short, and
 * that cast is reported itself), or when `llabs` is this file's own
 * function rather than the library's.
 */
#include <stdlib.h>

void printIntLine(int);

void unguarded(short data)
{
    short result = data * data;
    printIntLine(result);
}

void wrong_direction(short data)
{
    if (llabs((long long)data) > 181)
    {
        short result = data * data;
        printIntLine(result);
    }
}

void narrowing_cast(short data)
{
    if (llabs((signed char)data) <= 10)
    {
        short result = data * data;
        printIntLine(result);
    }
}

static long long own_llabs(long long v) { return v; }
#define llabs own_llabs

void own_function(short data)
{
    if (llabs((long long)data) <= 181)
    {
        short result = data * data;
        printIntLine(result);
    }
}
