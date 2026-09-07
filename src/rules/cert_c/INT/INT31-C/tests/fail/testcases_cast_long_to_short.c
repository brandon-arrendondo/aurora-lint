/*
 * Rule: INT31-C
 * Status: DETECTED. Was expected_fail until the provenance gate learned to
 * read a parameter's provenance off its callers rather than treating every
 * parameter as bounded local state. No caller of this function is visible in
 * the scan set, so its parameters carry unbounded input and the arithmetic is
 * reported.
 */

#include <stdio.h>

void f(long val) {
    char c = val;  /* VIOLATION: implicit narrowing from long to char */
    printf("%d\n", c);
}
