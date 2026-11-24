/*
 * Rule: INT08-C
 * Source: synthetic
 * Status: FAIL - a sqrt bound is unknown where sqrt is not correctly rounded
 * Settings: iec_60559_sqrt=false, data_model=lp64
 *
 * `data` is 32767. Where double is binary64 and sqrt correctly rounded,
 * `(long)sqrt((double)SHRT_MAX)` is 181 and the guard is false for it;
 * withdrawn, the accuracy of sqrt is implementation-defined (C11
 * 5.2.4.2.2p6), so the bound is unknown and the square is reported, under
 * every preset. Its companion, pass/square_root_guard_with_the_platform_declared.c,
 * declares the fact.
 */
#include <limits.h>
#include <math.h>
#include <stdlib.h>

void printIntLine(int);

void guarded(void)
{
    short data = 32767;
    if (abs((long)data) <= (long)sqrt((double)SHRT_MAX))
    {
        short result = data * data;
        printIntLine(result);
    }
}
