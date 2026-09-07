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
 * Reason: Dividing INT_MIN by -1 causes overflow
 */

#include <limits.h>
#include <stdio.h>

int main() {
    int dividend = INT_MIN;
    int divisor = -1;
    int result = dividend / divisor; // VIOLATION: INT_MIN / -1 overflows

    printf("Result: %d\n", result);
    return 0;
}