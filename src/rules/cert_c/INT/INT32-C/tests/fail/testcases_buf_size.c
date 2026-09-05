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
 * Reason: Buffer size calculation can overflow when computing total needed space
 */

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
    int num_strings = 50000;
    int avg_string_length = 50000;

    // VIOLATION: multiplication can overflow
    int total_buffer_size = num_strings * avg_string_length;

    printf("Calculated buffer size: %d bytes\n", total_buffer_size);

    // This could allocate wrong amount of memory
    char* buffer = malloc(total_buffer_size);
    if (buffer) {
        printf("Buffer allocated\n");
        free(buffer);
    } else {
        printf("Buffer allocation failed\n");
    }

    return 0;
}