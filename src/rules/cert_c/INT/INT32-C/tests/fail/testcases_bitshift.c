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
 * Reason: Bit shifting with large shift counts or values can cause overflow
 */

#include <limits.h>
#include <stdio.h>

int main() {
    int value = 1;
    int shift_count = 31;

    // VIOLATION: 1 << 31 in signed int is undefined behavior/overflow
    int result = value << shift_count;

    printf("1 << 31 = %d\n", result);

    // Another violation: shifting a large value
    int large_value = INT_MAX / 4;
    int result2 = large_value << 3; // VIOLATION: likely to overflow

    printf("(%d) << 3 = %d\n", large_value, result2);

    return 0;
}