/*
 * Rule: DCL03-C
 * Source: synthetic
 * Status: FAIL - an assertion over sizeof an element of a one-dimensional VLA
 * Expect: count=2
 *
 * An element of `int vla[n]` is an int, so `sizeof vla[0]` is an integer
 * constant (C11 6.5.3.4p2) and a static assertion could test each
 * condition.
 */
#include <assert.h>

void check(int n, int vla[n])
{
    assert(sizeof vla[0] == sizeof(int));
    assert(sizeof (vla[0] + 1) >= 2);
}
