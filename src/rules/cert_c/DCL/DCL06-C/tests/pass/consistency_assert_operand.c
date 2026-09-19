/*
 * Rule: DCL06-C
 * Source: testcases
 * Status: PASS - Should NOT trigger DCL06-C violation
 */

/*
 * Rule: DCL06-C - Use meaningful symbolic constants
 * Status: PASS
 * Reason: A literal that an assertion pins a NAMED quantity to is not
 *         hidden program logic; it is the checked statement about the
 *         program's constants, and replacing it with the constant would make
 *         the assertion `X == X`. sqlite's `assert( sizeof(aSpecial)==32 )`,
 *         `assert( PAGER_JOURNALMODE_WAL==5 )` and `assert( 200==sqlite3LogEst(
 *         1048576) )` shapes (task 1153, mechanism 3). Only the operand of
 *         the equality is exempt.
 */

#include <assert.h>
#include <stddef.h>

#define WALINDEX_LOCK_OFFSET 120
enum { PAGER_JOURNALMODE_WAL = 5 };
enum { HDR_PAD = 32 };
struct WalIndexHdr { char pad[HDR_PAD]; };
int log_est(int n);

void check(void)
{
    assert( 120 == WALINDEX_LOCK_OFFSET );
    assert( WALINDEX_LOCK_OFFSET != 121 );
    assert( sizeof(struct WalIndexHdr) == 32 );
    assert( (sizeof(struct WalIndexHdr)) == (32) );
    assert( 200 == log_est(1) );
}
