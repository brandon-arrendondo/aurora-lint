/*
 * Rule: DCL06-C
 * Source: testcases
 * Status: PASS - Should NOT trigger DCL06-C violation
 */

/*
 * Rule: DCL06-C - Use meaningful symbolic constants
 * Status: PASS
 * Reason: The consistency-assert exemption also holds when the assert pins
 *         the literal to an ARITHMETIC COMBINATION of named quantities
 *         rather than a single one: sqlite's
 *         `assert( 121 == WALINDEX_LOCK_OFFSET + WAL_CKPT_LOCK )` block
 *         (src/wal.c, task 1153). Substituting a symbolic constant for the
 *         literal makes the assertion `X == X` exactly as it does for the
 *         bare-identifier rows above it, because every leaf of the other
 *         side is itself a name -- nothing on that side is spelled out.
 */

#include <assert.h>

#define WALINDEX_LOCK_OFFSET 120
#define WAL_CKPT_LOCK 1
#define WAL_RECOVER_LOCK 2
#define WAL_READ_LOCK(I) (3 + (I))
#define WAL_HDR_SIZE 48
#define WAL_FRAME_HDRSIZE 24

void check(void)
{
    assert( 121 == WALINDEX_LOCK_OFFSET + WAL_CKPT_LOCK );
    assert( 122 == WALINDEX_LOCK_OFFSET + WAL_RECOVER_LOCK );
    assert( 123 == WALINDEX_LOCK_OFFSET + WAL_READ_LOCK(0) );
    assert( 124 == WALINDEX_LOCK_OFFSET + WAL_READ_LOCK(1) );
    assert( 72 == WAL_HDR_SIZE + WAL_FRAME_HDRSIZE );
    assert( 1152 == WAL_HDR_SIZE * WAL_FRAME_HDRSIZE );
    assert( (WALINDEX_LOCK_OFFSET + WAL_CKPT_LOCK) != 999 );
    assert( 144 == (WAL_HDR_SIZE + WAL_FRAME_HDRSIZE) * WAL_CKPT_LOCK * WAL_RECOVER_LOCK );
}
