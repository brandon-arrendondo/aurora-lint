/*
 * Rule: INT31-C
 * Source: synthetic
 * Status: PASS - bounds written as integer constant expressions
 * Settings: iec_60559_sqrt=true, data_model=lp64
 *
 * `(SHRT_MAX - 1) / 2 * 2 + 1` is 32767, an integer constant expression,
 * so sqrt of it is 181; `362 / 2` is 181 too. Either guard bounds `data`
 * to -181..181 and the square fits in a short.
 */
#include <limits.h>
#include <math.h>
#include <stdlib.h>

void printIntLine(int);

void square_root_of_an_expression(short data)
{
    if (abs((long)data) <= (long)sqrt((double)((SHRT_MAX - 1) / 2 * 2 + 1)))
    {
        short result = data * data;
        printIntLine(result);
    }
}

void absolute_bound_of_an_expression(short data)
{
    if (abs(data) <= 362 / 2)
    {
        short result = data * data;
        printIntLine(result);
    }
}
