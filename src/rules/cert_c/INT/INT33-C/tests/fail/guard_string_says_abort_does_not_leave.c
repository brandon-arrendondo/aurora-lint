/*
 * Rule: INT33-C
 * Source: synthetic
 * Status: FAIL - Only a string literal in the zero branch mentions abort
 *
 * The message names abort() but the branch calls fputs, which returns, so
 * the division still runs when b is zero.
 */
#include <stdio.h>

int divide(int a, int b)
{
    if (b == 0) {
        fputs("would abort: zero divisor\n", stderr);
    }
    return a / b;
}
