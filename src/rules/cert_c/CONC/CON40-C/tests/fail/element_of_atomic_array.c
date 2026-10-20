/*
 * Rule: CON40-C
 * Source: testcases
 * Status: FAIL - Should trigger CON40-C violation
 *
 * An element of an array of atomic objects is an atomic object.
 */

#include <stdatomic.h>

static atomic_int counts[4];

int square(void) {
    return counts[0] * counts[0];
}
