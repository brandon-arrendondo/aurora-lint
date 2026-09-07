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
 * Reason: Left shifting negative values is undefined behavior and can cause overflow
 */

#include <limits.h>
#include <stdio.h>

int main() {
    int value = -5;
    int result = value << 2; // VIOLATION: left shifting negative value is undefined

    printf("Result: %d\n", result);
    return 0;
}