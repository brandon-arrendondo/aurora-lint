/*
 * Rule: DCL11-C
 * Source: testcases
 * Status: FAIL - Should trigger DCL11-C violation
 *
 * The '*' width takes an int argument, and a string literal was passed for it.
 */
#include <stdio.h>

void print_mislabeled(void) {
    const char *name = "websocket";

    printf("%*s\n", "wide", name);
}
