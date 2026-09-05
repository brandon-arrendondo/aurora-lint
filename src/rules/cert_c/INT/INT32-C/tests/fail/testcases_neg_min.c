// sqc-test: prescan
// Needs the project context a real scan builds: the INT3x provenance gate
// runs in every configuration now, and without context it has no summaries
// to resolve this file's own callees against.
/*
 * Rule: INT32-C
 * Source: testcases
 * Status: FAIL - Should trigger INT32-C violation
 */

/*
 * Rule: INT32-C - Ensure that operations on signed integers do not result in overflow
 * Status: FAIL
 * Reason: Negating INT_MIN causes overflow because -INT_MIN > INT_MAX
 */

#include <limits.h>
#include <stdio.h>

int main() {
    int value = INT_MIN;
    int result = -value; // VIOLATION: negating INT_MIN overflows

    printf("Original: %d, Negated: %d\n", value, result);
    return 0;
}