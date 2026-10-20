/*
 * Rule: CON40-C
 * Source: testcases
 * Status: FAIL - Should trigger CON40-C violation
 *
 * A compound assignment is one atomic read-modify-write of its left
 * operand, but the same object on its right is a second, separate read.
 */

#include <stdatomic.h>

static atomic_int n;

void grow(void) {
    n += n;
}
