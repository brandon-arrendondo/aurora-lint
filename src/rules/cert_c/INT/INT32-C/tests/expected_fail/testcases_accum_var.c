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
 * Reason: Accumulator variable can overflow during repeated additions
 */

#include <limits.h>
#include <stdio.h>

int main() {
    int accumulator = 0;
    int increment = 100000;

    // VIOLATION: no overflow check in accumulation loop
    for (int i = 0; i < 25000; i++) {
        accumulator += increment;
        if (i % 5000 == 0) {
            printf("Step %d: accumulator = %d\n", i, accumulator);
        }
    }

    printf("Final accumulator: %d\n", accumulator);
    return 0;
}