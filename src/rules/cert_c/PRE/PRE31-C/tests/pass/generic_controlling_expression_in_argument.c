/*
 * Rule: PRE31-C
 * Status: PASS - Should NOT trigger PRE31-C violation
 * Reason: the controlling expression of _Generic is not evaluated
 * (C11 6.5.1.1p3), so i++ inside it is no side effect.
 */

#include <assert.h>

void f(int i) {
    assert(_Generic(i++, int: 1, default: 0));
}
