/*
 * Rule: DCL03-C
 * Source: synthetic
 * Status: FAIL - An assertion over casts to integer types
 * Expect: count=3
 *
 * A cast to an integer type, of a floating constant or of an integer
 * constant, belongs in an integer constant expression (C11 6.6p6), so a
 * static assertion could test each condition.
 */
#include <assert.h>

typedef unsigned char octet;

void check(void)
{
    assert((unsigned long)2.5 == 2);
    assert((octet)300 == 44);
    assert((int)sizeof(octet) == 1);
}
