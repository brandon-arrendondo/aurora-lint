/*
 * Rule: INT31-C
 * Source: synthetic
 * Status: FAIL - Comparing a signed value with an unsigned zero does not show it is not negative
 * Settings: data_model=iso
 * Expect: count=2
 *
 * `x >= 0u` converts `x` to unsigned, where a negative value reads as a
 * large one, so the comparison is true for every `x` and bounds nothing.
 * The cast narrows and may change the sign: two findings.
 */

#include <limits.h>

void sink(int);

void unsigned_zero(int x)
{
    unsigned char c = 0;
    if (x >= 0u && x <= UCHAR_MAX) {
        c = (unsigned char)x; /* Expect: here */
    }
    sink(c);
}
