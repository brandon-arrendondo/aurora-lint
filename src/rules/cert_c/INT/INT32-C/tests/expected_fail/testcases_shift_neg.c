/*
 * Rule: INT32-C
 * Source: testcases
 * Status: EXPECTED FAIL - Known limitation: left-shifting a negative value is
 * undefined regardless of magnitude, so no value-range channel proves it
 * -- the shift result here is in range. With the operands untainted locals
 * the provenance gate suppresses the report; catching it needs a sign
 * check on the shifted operand rather than an overflow check. A genuine
 * INT32-C violation.
 */

/*
 * Rule: INT32-C - Ensure that operations on signed integers do not result in overflow
 * Status: EXPECTED FAIL
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