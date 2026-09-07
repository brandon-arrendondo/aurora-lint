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