/*
 * Rule: PRE31-C
 * Status: PASS - Should NOT trigger PRE31-C violation
 * Expect: default=clean strict=violation
 * Reason: assert evaluates nothing under NDEBUG, but is_valid has no
 * definition in the scan and no library contract, so the default policy
 * does not treat the call as a side effect; the strict policy does.
 */

#include <assert.h>

int is_valid(const void *p);

void a(const void *p) {
    assert(is_valid(p));
}
