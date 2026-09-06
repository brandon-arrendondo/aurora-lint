/*
 * Rule: INT32-C
 * Source: testcases
 * Status: EXPECTED FAIL - Known limitation: INT_MIN / -1 definitely overflows and
 * both operands are compile-time known, but const_eval::try_evaluate_range
 * implements only + - * << for binary operators, so `/` yields no range,
 * the definite-overflow channel proves nothing and the provenance gate
 * suppresses the report. (Written as `INT_MIN / -1` in one expression it
 * IS reported -- the constants must survive into locals for this to be
 * missed.) A genuine INT32-C violation.
 */

/*
 * Rule: INT32-C - Ensure that operations on signed integers do not result in overflow
 * Status: EXPECTED FAIL
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