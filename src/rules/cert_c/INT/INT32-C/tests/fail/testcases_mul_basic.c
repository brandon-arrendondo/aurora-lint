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
 * Reason: Multiplication of two large integers without overflow checking
 */

#include <limits.h>
#include <stdio.h>

int main() {
    int a = 100000;
    int b = 50000;
    int result = a * b; // VIOLATION: 5,000,000,000 exceeds INT_MAX

    printf("Result: %d\n", result);
    return 0;
}