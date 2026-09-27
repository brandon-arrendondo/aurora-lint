/*
 * Rule: PRE31-C
 * Status: PASS - Should NOT trigger PRE31-C violation
 * Reason: the `ready` assert reads is the local int, which shadows the
 * volatile global of the same name (resolved by scope, not spelling).
 */

#include <assert.h>

volatile int ready;

void a(void) {
    int ready = 1;
    assert(ready);
}
