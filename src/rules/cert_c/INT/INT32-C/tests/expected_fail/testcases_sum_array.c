/*
 * Rule: INT32-C
 * Source: testcases
 * Status: EXPECTED FAIL, by measurement rather than oversight. The overflow is
 * definite only across loop iterations -- the accumulator exceeds the band
 * after many passes, not at any single evaluation. VRA carries per-node
 * ranges, which cannot express that, so no definite-overflow check can prove
 * it and a possible-overflow check would flag every accumulator loop.
 * Genuine violation; kept as evidence.
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