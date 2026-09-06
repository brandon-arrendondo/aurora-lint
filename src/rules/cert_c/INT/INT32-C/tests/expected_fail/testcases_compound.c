/*
 * Rule: INT32-C
 * Source: testcases
 * Status: EXPECTED FAIL - Known limitation: every operand is a compile-time
 * constant and each operation definitely overflows, but the definite-
 * overflow channel (const_eval::expression_overflows_signed_vra) evaluates
 * ranges only for binary_expression / unary_expression / update_expression
 * -- an assignment_expression such as `value1 += 1` yields no range -- so
 * the provenance gate suppresses it. A genuine INT32-C violation.
 */

/*
 * Rule: INT32-C - Ensure that operations on signed integers do not result in overflow
 * Status: EXPECTED FAIL
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