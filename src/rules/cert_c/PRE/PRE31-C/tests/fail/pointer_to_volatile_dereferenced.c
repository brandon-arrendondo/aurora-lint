/*
 * Rule: PRE31-C
 * Status: FAIL - Should trigger PRE31-C violation
 * Reason: *p reads a volatile object (C11 5.1.2.3p2).
 */

#include <assert.h>

void a(volatile int *p) {
    assert(*p == 1);  // VIOLATION
}
