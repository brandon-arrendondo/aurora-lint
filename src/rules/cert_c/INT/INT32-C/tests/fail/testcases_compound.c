/*
 * Rule: INT32-C
 * Source: testcases
 * Status: DETECTED. Was expected_fail until the value-based channels gained
 * interval division/remainder, a compound-assignment arm, a
 * definitely-negative left shift, and -- for INT31-C -- a definite-truncation
 * channel of its own. The operands here are compile-time known and the
 * operation provably misbehaves, so it is reported whatever their provenance.
 */

/*
 * Rule: INT32-C - Ensure that operations on signed integers do not result in overflow
 * Status: DETECTED
 * Reason: Compound assignment operators can cause overflow
 */

#include <limits.h>
#include <stdio.h>

int main() {
    int value1 = INT_MAX;
    int value2 = INT_MIN;
    int value3 = 1000000;

    printf("Initial values: %d, %d, %d\n", value1, value2, value3);

    // VIOLATION: compound addition overflow
    value1 += 1;

    // VIOLATION: compound subtraction underflow
    value2 -= 1;

    // VIOLATION: compound multiplication overflow
    value3 *= 3000;

    printf("After compound operations: %d, %d, %d\n", value1, value2, value3);
    return 0;
}