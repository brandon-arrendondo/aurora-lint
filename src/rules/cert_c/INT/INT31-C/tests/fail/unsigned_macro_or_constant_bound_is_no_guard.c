/*
 * Rule: INT31-C
 * Source: synthetic
 * Status: FAIL - An unsigned bound spelled through a macro or as ~0U is no guard
 * Settings: data_model=iso
 * Expect: count=3
 *
 * `ZERO` is `0u`, so `x >= ZERO` compares as unsigned where `int` is no
 * wider than `unsigned int` and is always true: `x` may still be negative.
 * `~0U` is `UINT_MAX`, not -1, so `x <= ~0U` does not keep `x` inside an
 * `unsigned char`.
 */
#include <limits.h>

#define ZERO 0u

void takec(unsigned char v);

void at_least_an_unsigned_zero(int x)
{
    if (x >= ZERO && x <= UCHAR_MAX)
        takec((unsigned char)x); /* Expect: here */
}

void at_most_the_largest_unsigned(unsigned x)
{
    if (x <= ~0U)
        takec((unsigned char)x); /* Expect: here */
}
