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
 * Reason: Pointer arithmetic offset calculation can overflow
 */

#include <stdio.h>

int compute_offset(int base, int extra) {
    // VIOLATION: addition can overflow when base and extra are large
    int total_offset = base + extra;

    printf("Total offset: %d\n", total_offset);
    return total_offset;
}

int main() {
    int array[100];
    int result = compute_offset(2000000000, 500000000);
    return 0;
}
