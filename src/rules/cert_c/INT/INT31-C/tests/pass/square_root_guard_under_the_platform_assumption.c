/*
 * Rule: INT31-C
 * Source: synthetic
 * Status: PASS under the default preset; FAIL where the platform is not assumed
 * Settings: data_model=lp64
 * Expect: default=clean strict=violation pedantic=violation
 *
 * `(long)sqrt((double)SHRT_MAX)` is 181 where double is binary64 and sqrt
 * is correctly rounded (C11 F.10.4.5), so the guard bounds `data` to
 * -181..181 and `data * data` fits in a short. The default preset assumes
 * that platform for a hosted target, as it assumes LP64. Under the strict
 * and pedantic presets nothing declares it, and without Annex F the
 * accuracy of sqrt is implementation-defined (C11 5.2.4.2.2p6), so the
 * bound is unknown and the square is reported. The data model is declared
 * so that SHRT_MAX is a constant under every preset: the platform's sqrt is
 * the only thing the presets read differently here.
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
