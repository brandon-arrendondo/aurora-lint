/*
 * Rule: INT33-C
 * Source: synthetic
 * Status: FAIL - Only a comment in the zero branch mentions returning
 *
 * A comment is not a statement: the branch logs and falls through to the
 * division.
 */
#include <stdio.h>

int divide(int a, int b)
{
    if (b == 0) {
        /* should return early here */
        fputs("zero divisor\n", stderr);
    }
    return a / b;
}
