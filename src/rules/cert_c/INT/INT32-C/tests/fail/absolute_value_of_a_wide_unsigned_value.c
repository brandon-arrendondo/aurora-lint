/*
 * Rule: INT32-C
 * Source: synthetic
 * Status: FAIL - llabs of an unsigned long long bounds nothing
 * Settings: data_model=lp64
 * Expect: count=1
 *
 * ULLONG_MAX converts to long long as -1 on a two's-complement target
 * (C11 6.3.1.3p3), so it passes `llabs(data) <= 100`; `(int)data` is then
 * -1 as well, or any other int, and the product may overflow.
 */
#include <stdlib.h>

void printIntLine(int);

void guarded_by_llabs(unsigned long long data)
{
    if (llabs(data) <= 100)
    {
        int result = (int)data * 3000000;
        printIntLine(result);
    }
}
