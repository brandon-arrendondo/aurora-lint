/*
 * Rule: INT31-C
 * Source: synthetic
 * Status: PASS - glibc's sqrt is the correctly rounded binary64 one
 * Settings: libc=glibc, data_model=lp64
 *
 * Declaring glibc (or musl) as the C library declares the platform's sqrt
 * correctly rounded, as `iec_60559_sqrt` would, under every preset: the
 * guard bounds `data` to -181..181 and the square fits in a short.
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
