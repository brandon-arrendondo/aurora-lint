/*
 * Rule: INT30-C
 * Source: testcases
 * Status: FAIL - Should trigger INT30-C violation
 */

/*
 * Rule: INT30-C - Ensure that unsigned integer operations do not wrap
 * Status: FAIL
 * Reason: Nested multiplication expressions without wrap check
 */

#include <stdlib.h>

void allocate_3d(unsigned int x, unsigned int y, unsigned int z) {
    // Multiple multiplications - each may wrap
    size_t size = x * y * z * sizeof(int);  // Line 10 - VIOLATION

    int *array = malloc(size);
    if (array) {
        free(array);
    }
}

int main(void) {
    allocate_3d(10000, 10000, 100);  // Will wrap
    return 0;
}
