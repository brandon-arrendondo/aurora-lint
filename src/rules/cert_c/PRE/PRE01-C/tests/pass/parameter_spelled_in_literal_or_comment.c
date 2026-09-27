/*
 * Rule: PRE01-C
 * Source: testcases
 * Status: PASS - Should not trigger PRE01-C violation
 *
 * Every use of each parameter is parenthesized or a whole function-call
 * argument. The other spellings of x sit in a string literal and a
 * comment, which are not uses.
 */

#include <stdio.h>

#define SHOW(x) printf("x = %d\n", (x))
#define IDENTITY(x) ((x)) // returns x unchanged

int use(int v)
{
    SHOW(v);
    return IDENTITY(v);
}
