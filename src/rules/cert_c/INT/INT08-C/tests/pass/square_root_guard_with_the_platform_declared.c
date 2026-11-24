/*
 * Rule: INT08-C
 * Source: synthetic
 * Status: PASS - a correctly rounded sqrt bound excludes the known value
 * Settings: iec_60559_sqrt=true, data_model=lp64
 *
 * Declared, the platform fixes `(long)sqrt((double)SHRT_MAX)` at 181
 * under every preset, so the guard is false for `data` = 32767 and the
 * square never runs with it.
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
