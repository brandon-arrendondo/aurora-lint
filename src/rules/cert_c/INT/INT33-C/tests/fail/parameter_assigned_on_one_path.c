/*
 * Rule: INT33-C
 * Source: synthetic
 * Status: FAIL - d keeps the caller's value when c is zero
 *
 * The only assignment is a non-zero constant, but it is conditional, and d
 * is a parameter: on the other path it holds whatever the caller passed.
 */

int divide(int a, int d, int c)
{
    if (c)
        d = 5;
    return a / d;
}
