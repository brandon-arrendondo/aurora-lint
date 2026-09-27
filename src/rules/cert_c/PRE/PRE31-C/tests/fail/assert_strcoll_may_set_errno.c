/*
 * Rule: PRE31-C
 * Status: FAIL - Should trigger PRE31-C violation
 * Reason: POSIX lets strcoll set errno (EINVAL), a side effect.
 */

#include <assert.h>
#include <string.h>

void f(const char *a, const char *b) {
    assert(strcoll(a, b) == 0);  // VIOLATION
}
