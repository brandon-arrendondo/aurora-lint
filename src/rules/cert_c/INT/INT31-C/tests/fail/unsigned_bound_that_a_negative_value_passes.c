/*
 * Rule: INT31-C
 * Source: synthetic
 * Status: FAIL - An unsigned bound a negative value can pass proves nothing about the sign
 * Expect: count=5
 *
 * Compared with an unsigned bound, a negative `x` reads as a large value:
 * at least 2^(w-1). `x < n` rules a negative `x` out only when `n` is a
 * constant no larger than that. A variable `n` may be `UINT_MAX` or the
 * largest `uint64_t`, and -2 passes it, as it passes the largest
 * `unsigned long` constant.
 */
#include <stdint.h>

void take(unsigned v);
void takec(unsigned char v);

void below_a_variable(int x, unsigned n)
{
    if (x < n)
        take((unsigned)x); /* Expect: here */
}

void below_a_variable_and_a_constant(int x, unsigned n)
{
    unsigned char c = 0;
    c = (x < n && x < 100) ? (unsigned char)x : 0; /* Expect: here */
    takec(c);
}

void below_a_wide_variable(int x, uint64_t n)
{
    if (x < n)
        take((unsigned)x); /* Expect: here */
}

void below_the_largest_constant(long x)
{
    if (x <= 0xFFFFFFFFFFFFFFFFUL)
        take((unsigned)x); /* Expect: here */
}
