/*
 * Rule: EXP34-C
 * Source: testcases
 * Status: FAIL - a static callee's null return reaches a dereference
 *
 * get_possibly_null() returns NULL and caller() dereferences its result
 * without a check. This was an expected miss until the rule followed a
 * null return through a static function in the same file; it is reported
 * now, so it asserts the finding.
 */

#include <stdlib.h>

static int *get_possibly_null(void) {
    return NULL;
}

void caller(void) {
    int *p = get_possibly_null();
    /* No null check — dereference of possibly-null return value */
    *p = 42;
}
