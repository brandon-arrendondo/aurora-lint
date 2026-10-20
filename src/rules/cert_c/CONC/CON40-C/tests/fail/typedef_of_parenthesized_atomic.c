/*
 * Rule: CON40-C
 * Source: testcases
 * Status: FAIL - Should trigger CON40-C violation
 *
 * A typedef of _Atomic(int) names an atomic type.
 */

#include <stdatomic.h>

typedef _Atomic(int) pint_t;
pint_t total;

int doubled(void) {
    return total + total;
}
