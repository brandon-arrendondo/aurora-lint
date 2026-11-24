/*
 * Rule: INT31-C
 * Source: synthetic
 * Status: FAIL - a bound written with a floating constant is not read
 * Settings: iec_60559_sqrt=true, data_model=lp64
 * Expect: count=3
 *
 * sqrt is credited only for an integer constant expression (C11 6.6p6).
 * `sqrt(0.5 * 70000)` is 187.08, so the guard admits 187, whose square
 * overflows a short; `sqrt(-0.5)` is a NaN, and converting it to long is
 * undefined (C11 6.3.1.4p1). An absolute-value bound of `0.5 * 400` is 200,
 * and 200 * 200 does not fit in a short either. None of them is read as
 * a bound, so each square is reported.
 */
#include <math.h>
#include <stdlib.h>

void printIntLine(int);

void floating_product(short data)
{
    if (abs((long)data) <= (long)sqrt((double)(0.5 * 70000)))
    {
        short result = data * data;
        printIntLine(result);
    }
}

void negative_floating_operand(short data)
{
    if (abs((long)data) <= (long)sqrt((double)-0.5))
    {
        short result = data * data;
        printIntLine(result);
    }
}

void floating_absolute_bound(short data)
{
    if (abs(data) <= 0.5 * 400)
    {
        short result = data * data;
        printIntLine(result);
    }
}
