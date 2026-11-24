/*
 * Rule: INT31-C
 * Source: synthetic
 * Status: FAIL - `abs` and `sqrt` here are pointers to other functions
 * Settings: iec_60559_sqrt=true, data_model=lp64
 * Expect: count=3
 *
 * A local or a parameter named `abs` or `sqrt` that points to a function
 * is an object, not the library's function (ADR-0006): what it returns
 * bounds nothing, so each square is reported.
 */
#include <limits.h>
#include <stdlib.h>

void printIntLine(int);
int myabs(int);
double mysqrt(double);

void local_pointer_named_abs(short data)
{
    int (*abs)(int) = myabs;
    if (abs(data) <= 181)
    {
        short result = data * data;
        printIntLine(result);
    }
}

void parameter_pointer_named_abs(int (*abs)(int), short data)
{
    if (abs(data) <= 181)
    {
        short result = data * data;
        printIntLine(result);
    }
}

void local_pointer_named_sqrt(short data)
{
    double (*sqrt)(double) = mysqrt;
    if (labs((long)data) <= (long)sqrt((double)SHRT_MAX))
    {
        short result = data * data;
        printIntLine(result);
    }
}
