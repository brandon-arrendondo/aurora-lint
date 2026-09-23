/*
 * Rule: DCL06-C
 * Source: testcases
 * Status: FAIL - Should trigger DCL06-C violation
 */

/*
 * Rule: DCL06-C - Use meaningful symbolic constants
 * Status: FAIL
 * Reason: The named-EXPRESSION form of the consistency-assert exemption
 *         holds only while the whole other side is names.
 *         A bare literal leaf means substituting a symbolic constant for
 *         the asserted value does NOT make the assertion `X == X` -- the
 *         spelled-out operand is still there -- so the value stays a magic
 *         number. Neither does a bitwise combination, which assembles a
 *         value rather than naming one, nor an operand built from a plain
 *         lowercase variable.
 */

#include <assert.h>

#define WALINDEX_LOCK_OFFSET 120
#define WAL_HDR_SIZE 48

void check(int nFrame)
{
    assert( 123 == WALINDEX_LOCK_OFFSET + 3 );
    assert( 96 == WAL_HDR_SIZE * 2 );
    assert( 176 == (WALINDEX_LOCK_OFFSET | WAL_HDR_SIZE) );
    assert( 168 == WALINDEX_LOCK_OFFSET + nFrame );
}
