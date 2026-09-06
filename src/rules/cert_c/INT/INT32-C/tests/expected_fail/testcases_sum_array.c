/*
 * Rule: INT32-C
 * Source: testcases
 * Status: EXPECTED FAIL - Known limitation: the overflow is definite only across
 * loop iterations, and VRA's per-node ranges do not carry an accumulator's
 * value from one iteration to the next. With no proof of definite overflow
 * and no taint on any operand, INT32-C's provenance gate suppresses the
 * report. A genuine INT32-C violation.
 */

/*
 * Rule: INT32-C - Ensure that operations on signed integers do not result in overflow
 * Status: EXPECTED FAIL
 * Reason: Array summation can overflow without checking intermediate results
 */

#include <limits.h>
#include <stdio.h>

int main() {
    int array[] = {INT_MAX / 2, INT_MAX / 2, INT_MAX / 2, 1000};
    int size = sizeof(array) / sizeof(array[0]);
    int sum = 0;

    // VIOLATION: no overflow checking in accumulation
    for (int i = 0; i < size; i++) {
        sum += array[i];
    }

    printf("Sum: %d\n", sum);
    return 0;
}