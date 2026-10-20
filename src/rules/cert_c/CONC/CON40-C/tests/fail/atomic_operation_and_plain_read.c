/*
 * Rule: CON40-C
 * Source: testcases
 * Status: FAIL - Should trigger CON40-C violation
 *
 * An atomic_load and a plain read of the same object in one expression
 * are two accesses.
 */

#include <stdatomic.h>

static atomic_int total;

int sum(void) {
    return total + atomic_load(&total);
}
