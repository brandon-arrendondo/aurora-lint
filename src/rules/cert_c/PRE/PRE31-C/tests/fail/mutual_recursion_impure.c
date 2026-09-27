/*
 * Rule: PRE31-C
 * Status: FAIL - Should trigger PRE31-C violation
 * Reason: f and g call each other and f increments a global, so both calls
 * have a side effect; both asserts are violations whichever is judged first.
 */

#include <assert.h>

int counter;
static int g(int n);
static int f(int n) { int r = g(n); counter++; return r; }
static int g(int n) { return n > 0 ? f(n - 1) : 0; }

void h(int x) {
    assert(f(x));  // VIOLATION
    assert(g(x));  // VIOLATION
}
