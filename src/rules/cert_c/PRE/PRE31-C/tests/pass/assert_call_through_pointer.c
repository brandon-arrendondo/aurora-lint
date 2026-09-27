/*
 * Rule: PRE31-C
 * Status: PASS - Should NOT trigger PRE31-C violation
 * Expect: default=clean strict=violation
 * Reason: nothing names the body a call through a pointer reaches, so it is
 * a call to an unknown function: reported by the strict policy only.
 */

#include <assert.h>

void a(int (*check)(int), int x) {
    assert(check(x));
}
