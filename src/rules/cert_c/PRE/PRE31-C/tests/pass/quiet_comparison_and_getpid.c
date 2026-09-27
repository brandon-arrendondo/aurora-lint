/*
 * Rule: PRE31-C
 * Status: PASS - Should NOT trigger PRE31-C violation
 * Expect: default=clean strict=violation
 * Reason: isgreater (C11 7.12.14) and getpid (POSIX, always successful) have
 * no side effect by the ISO C/POSIX contract; the strict preset trusts no
 * library.
 */

#include <assert.h>
#include <math.h>
#include <unistd.h>

void f(double a, double b, int pid) {
    assert(isgreater(a, b));
    assert(getpid() == pid);
}
