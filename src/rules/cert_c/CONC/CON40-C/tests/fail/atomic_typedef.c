/*
 * Rule: CON40-C
 * Source: testcases
 * Status: FAIL - Should trigger CON40-C violation
 *
 * A typedef declared with _Atomic names an atomic type, so an object of
 * that type read twice in one expression is accessed twice.
 */

#include <stdatomic.h>

typedef _Atomic int aint_t;
aint_t total;

int square(void) {
    return total * total;
}
