/*
 * Rule: PRE31-C
 * Status: FAIL - Should trigger PRE31-C violation
 * Reason: reading a volatile object is a side effect (C11 5.1.2.3p2).
 */

#include <assert.h>

extern volatile int ready;

void a(void) {
    assert(ready);  // VIOLATION
}
