/*
 * Rule: PRE31-C
 * Status: FAIL - Should trigger PRE31-C violation
 * Reason: the file replaces assert only under QUIET, and the call compiles
 * only without it, so the call is <assert.h>'s, whose NDEBUG arm drops
 * the argument.
 */

#include <assert.h>

#ifdef QUIET
#undef assert
#define assert(e) ((void)0)
#endif

static int counter;

static int bump(void) {
    return ++counter;
}

void check(void) {
#ifndef QUIET
    assert(bump());  // Expect: here
#endif
}
