/*
 * Rule: FIO47-C
 * Source: testcases
 * Status: FAIL - Should trigger FIO47-C violation
 *
 * Joining adjacent literals must not stop the joined format string from
 * being checked: the two pieces together ask for two arguments and the call
 * supplies one.
 */
#include <stdio.h>

void print_short(int n) {
    printf("%d items, " "%s\n", n);
}
