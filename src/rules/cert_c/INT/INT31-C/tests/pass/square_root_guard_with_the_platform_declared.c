/*
 * Rule: INT31-C
 * Source: synthetic
 * Status: PASS - a guard bound through a correctly rounded sqrt
 * Settings: iec_60559_sqrt=true, data_model=lp64
 *
 * With double declared binary64 and sqrt correctly rounded, the bound
 * `(T)sqrt((double)C)` is the square root of the constant C truncated
 * toward zero (C11 F.10.4.5, 6.3.1.4p1): 181 for SHRT_MAX. The guard then
 * bounds `data` to -181..181 under every preset, through parentheses, a
 * cast to an unsigned type that holds 181, and in either operand order. (Under the ISO data model the strict preset
 * assumes, SHRT_MAX is no constant, so the data model is declared too.)
 */
#include <limits.h>
#include <math.h>
#include <stdlib.h>

void printIntLine(int);

void guarded(short data)
{
    if (abs((long)data) <= (long)sqrt((double)SHRT_MAX))
    {
        short result = data * data;
        printIntLine(result);
    }
}

void guarded_through_parentheses(short data)
{
    if (llabs((long long)data) <= ((int)(sqrt((double)(SHRT_MAX)))))
    {
        short result = data * data;
        printIntLine(result);
    }
}

void guarded_reversed(short data)
{
    if ((unsigned)sqrt((double)32767) >= abs(data))
    {
        short result = data * data;
        printIntLine(result);
    }
}
