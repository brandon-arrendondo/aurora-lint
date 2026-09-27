/*
 * Rule: PRE31-C
 * Status: PASS - Should NOT trigger PRE31-C violation
 * Reason: apWiData[i] reads a `volatile unsigned *` (a pointer), not a
 * volatile object.
 */

#include <assert.h>

struct wal {
    int nWiData;
    volatile unsigned **apWiData;
};

void check(struct wal *pWal, int i) {
    assert(pWal->apWiData[i] == 0);
}
