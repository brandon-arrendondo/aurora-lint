/*
 * Rule: CON40-C
 * Source: testcases
 * Status: FAIL - Should trigger CON40-C violation
 *
 * The object a pointer to an atomic type points at is atomic: reading it
 * through the pointer twice is two accesses.
 */

#include <stdatomic.h>

int square(atomic_int *p) {
    return *p * *p;
}
