/*
 * Rule: DCL03-C
 * Source: synthetic
 * Status: PASS - an assertion over a cast to a pointer typedef
 *
 * `i64p` names a pointer to `__int64`, not an integer type, so the cast
 * does not belong in an integer constant expression (C11 6.6p6).
 */
#include <assert.h>

typedef __int64 *i64p;

void check(void)
{
    assert((i64p)0 == 0);
}
