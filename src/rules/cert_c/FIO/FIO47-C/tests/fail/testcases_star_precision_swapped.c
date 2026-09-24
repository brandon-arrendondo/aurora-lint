/*
 * Rule: FIO47-C
 * Source: testcases
 * Status: FAIL - Should trigger FIO47-C violation
 *
 * The int a '*' precision consumes comes before the string: passing the
 * string first hands the precision a pointer.
 */
#include <stdio.h>

void print_swapped(void) {
    const char *name = "websocket";
    int len = 3;

    printf("%.*s\n", name, len);
}
