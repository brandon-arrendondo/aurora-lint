/*
 * Rule: PRE31-C
 * Status: FAIL - Should trigger PRE31-C violation
 * Reason: chk writes a global in one configuration, so the call has a side
 * effect there, whichever definition appears last.
 */

#include <assert.h>

static int calls;

#ifndef FAST
static int chk(int x) { calls++; return x > 0; }
#else
static int chk(int x) { return x > 0; }
#endif

void f(int v) {
    assert(chk(v));  // VIOLATION
}
