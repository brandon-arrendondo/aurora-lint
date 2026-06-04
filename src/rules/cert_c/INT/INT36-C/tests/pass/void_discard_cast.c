/*
 * Rule: INT36-C
 * Source: real-world FP pattern
 * Status: PASS - (void) discard casts are NOT integer-to-pointer conversions
 */

#include <stdio.h>
#include <stdlib.h>

void print_error(int code, const char *msg) {
    (void)fprintf(stderr, "Error %d: %s\n", code, msg);
    (void)fflush(stderr);
}

int get_value(void) { return 42; }

void example(void) {
    /* Discarding return values with (void) cast is standard C practice */
    (void)printf("hello\n");
    (void)get_value();
}
