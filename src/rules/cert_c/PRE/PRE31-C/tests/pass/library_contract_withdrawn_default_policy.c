/*
 * Rule: PRE31-C
 * Status: PASS - Should NOT trigger PRE31-C violation
 * Settings: stdlib_call_effects=false
 * Expect: default=clean strict=violation
 * Reason: with the library contract withdrawn, strtol is a call to an
 * unknown function. The policy decides unknowns (ADR-0015): the default
 * policy does not report it, the strict policy does.
 */

#include <assert.h>
#include <stdlib.h>

void f(const char *s) {
    assert(strtol(s, NULL, 10) > 0);
}
