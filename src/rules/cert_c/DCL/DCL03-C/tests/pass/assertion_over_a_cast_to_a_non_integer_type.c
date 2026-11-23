/*
 * Rule: DCL03-C
 * Source: synthetic
 * Status: PASS - An assertion over casts to non-integer types
 *
 * Only a cast to an integer type belongs in an integer constant
 * expression (C11 6.6p6). A condition that casts to a floating type, to a
 * pointer type or to a floating typedef is not one, so no static
 * assertion can test it.
 */
#include <assert.h>

typedef double ratio_t;

void check(void)
{
    assert((double)1 < 2);
    assert((char *)0 == 0);
    assert((ratio_t)3 > 2);
}
