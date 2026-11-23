/*
 * Rule: DCL03-C
 * Source: synthetic
 * Status: PASS - An assertion over sizeof of a variable-length expression
 *
 * `p` points to a variable-length array, so `sizeof(*p)` is evaluated at
 * run time (C11 6.5.3.4p2) and no static assertion can test it.
 */
#include <assert.h>

void check(int n, char (*p)[n])
{
    assert(sizeof(*p) == 16);
}
