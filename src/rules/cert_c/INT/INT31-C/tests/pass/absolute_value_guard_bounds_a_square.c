/*
 * Rule: INT31-C
 * Source: synthetic
 * Status: PASS - an absolute-value guard bounds the operand of a square
 *
 * `abs(v) <= 181` holds only for -181 <= v <= 181, so `data * data` is
 * at most 32761 and fits in a short (C11 7.22.6.1). Each conversion on the
 * way to the call keeps every short value, since a signed type's values are
 * a subrange of those of any signed type of greater rank (C11 6.2.5p8), so
 * the guard holds whatever the data model, in either operand order.
 */
#include <stdlib.h>

void printIntLine(int);

void guarded(short data)
{
    if (llabs((long long)data) <= 181)
    {
        short result = data * data;
        printIntLine(result);
    }
}

void guarded_through_int(short data)
{
    if (abs((long)data) <= 181)
    {
        short result = data * data;
        printIntLine(result);
    }
}

void guarded_reversed(short data)
{
    if (182 > llabs(data))
    {
        short result = data * data;
        printIntLine(result);
    }
}
