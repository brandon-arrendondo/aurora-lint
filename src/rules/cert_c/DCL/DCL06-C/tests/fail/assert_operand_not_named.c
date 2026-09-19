/*
 * Rule: DCL06-C
 * Source: testcases
 * Status: FAIL - Should trigger DCL06-C violation
 */

/*
 * Rule: DCL06-C - Use meaningful symbolic constants
 * Status: FAIL
 * Reason: The consistency-assert exemption (task 1153) is only for a literal
 *         pinned against a NAMED quantity. A comparison with a plain variable,
 *         a literal folded into a mask on one side, a call argument inside
 *         the assert, and the same comparison outside any assert are all
 *         still magic numbers.
 */

#include <assert.h>

#define FLAGS 0
int log_est(int n);

void check(int x)
{
    assert( x == 64 );
    assert( (FLAGS & 0x80000000) == 0 );
    assert( 200 == log_est(1048576) );
    if (x == 120) {
        x = 0;
    }
}
