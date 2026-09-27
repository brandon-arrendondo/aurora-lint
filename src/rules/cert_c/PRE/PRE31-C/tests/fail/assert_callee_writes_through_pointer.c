/*
 * Rule: PRE31-C
 * Status: FAIL - Should trigger PRE31-C violation
 * Reason: take writes through its pointer parameter, so the call has a side
 * effect that NDEBUG removes.
 */

#include <assert.h>

static int take(int *slot) {
    *slot = 0;
    return 1;
}

void a(int *slot) {
    assert(take(slot));  // VIOLATION
}
