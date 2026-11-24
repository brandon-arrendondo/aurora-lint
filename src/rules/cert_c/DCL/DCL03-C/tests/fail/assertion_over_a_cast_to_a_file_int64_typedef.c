/*
 * Rule: DCL03-C
 * Source: synthetic
 * Status: FAIL - an assertion over a cast to a file typedef of __int64
 * Expect: count=1
 *
 * `__int64` is an integer type, so a typedef of it in this file names one
 * as it does in a header, and the condition is an integer constant
 * expression.
 */
#include <assert.h>

typedef __int64 i64;

void check(void)
{
    assert((i64)4 == 4);
}
