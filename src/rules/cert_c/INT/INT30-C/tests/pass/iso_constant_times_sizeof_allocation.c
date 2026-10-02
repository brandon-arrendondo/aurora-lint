/*
 * Rule: INT30-C
 * Source: regression
 * Status: PASS - no data model is declared
 *
 * Without a declared data model sizeof(int) has no known value, so the
 * product never evaluates to a number. It is still a constant expression the
 * compiler folds, with no runtime input to make it wrap, so it is not
 * reported.
 */

#include <stdlib.h>

int *two_ints(void) {
    return malloc(2 * sizeof(int));
}
