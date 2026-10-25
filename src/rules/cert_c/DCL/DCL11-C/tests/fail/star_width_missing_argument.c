/*
 * Rule: DCL11-C
 * Source: testcases
 * Status: FAIL - Should trigger DCL11-C violation
 *
 * "%*s" consumes an int width and then the string. Passing only the string
 * leaves the conversion reading an argument that was never passed.
 */
#include <stdio.h>

void print_unpadded(void) {
    const char *name = "websocket";

    printf("%*s\n", name);
}
