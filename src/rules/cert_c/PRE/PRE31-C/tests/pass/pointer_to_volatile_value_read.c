/*
 * Rule: PRE31-C
 * Status: PASS - Should NOT trigger PRE31-C violation
 * Reason: p points to volatile data, but reading p itself (comparing the
 * pointer) is not a volatile access.
 */

#include <assert.h>

void a(volatile int *p) {
    assert(p != 0);
}
