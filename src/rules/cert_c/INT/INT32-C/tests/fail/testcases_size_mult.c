/*
 * Rule: INT32-C
 * Source: testcases
 * Status: FAIL - Should trigger INT32-C violation
 */

/*
 * Rule: INT32-C - Ensure that operations on signed integers do not result in overflow
 * Status: FAIL
 * Reason: Size calculation for memory allocation can overflow
 */

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
    int num_elements = 1000000;
    int element_size = 3000;

    // VIOLATION: multiplication can overflow
    int total_size = num_elements * element_size;

    printf("Attempting to allocate %d bytes\n", total_size);

    void* ptr = malloc(total_size);
    if (ptr) {
        printf("Allocation succeeded\n");
        free(ptr);
    } else {
        printf("Allocation failed\n");
    }

    return 0;
}