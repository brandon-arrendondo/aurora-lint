/*
 * Rule: FIO47-C
 * Source: testcases
 * Status: FAIL - Should trigger FIO47-C violation
 *
 * A parameter's type comes from its declaration like a local's does: a
 * string parameter passed to '%d' is a mismatch.
 */
#include <stdio.h>

void print_name(const char *name) {
    printf("%d\n", name);
}
