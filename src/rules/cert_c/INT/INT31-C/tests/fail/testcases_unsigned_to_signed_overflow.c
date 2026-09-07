/*
 * Rule: INT31-C
 * Status: DETECTED. Was expected_fail until the provenance gate learned to
 * read a parameter's provenance off its callers rather than treating every
 * parameter as bounded local state. No caller of this function is visible in
 * the scan set, so its parameters carry unbounded input and the arithmetic is
 * reported.
 */

#include <stdio.h>

void f(unsigned long ul) {
    int i = ul;  /* VIOLATION: unsigned long to int may overflow */
    printf("%d\n", i);
}
