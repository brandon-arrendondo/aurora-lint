/*
 * Rule: PRE31-C
 * Status: FAIL - Should trigger PRE31-C violation
 * Reason: ASSERT is an object-like alias of assert, which evaluates its
 * argument zero times under NDEBUG.
 */

#include <assert.h>

#define ASSERT assert

void p(int i) {
    ASSERT(i++ > 0);  // VIOLATION
}
