/*
 * Rule: CON40-C
 * Source: testcases
 * Status: FAIL - Should trigger CON40-C violation
 *
 * An access in the argument of a function-like macro the file does not
 * expand still counts: GET(x) reads x.
 */

#include <stdatomic.h>

#define GET(x) (x)

static atomic_int total;

int square(void) {
    return GET(total) * GET(total);
}
