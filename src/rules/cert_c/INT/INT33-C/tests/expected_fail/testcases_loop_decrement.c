/*
 * Rule: INT33-C
 * Source: testcases
 * Status: EXPECTED FAIL - Known limitation: the divisor reaching zero is a
 * property of the loop's induction variable (for (i = 5; i >= 0; i--)),
 * not of the division expression, and INT33-C does not read the loop's
 * value range for the divisor. Reports nothing with or without -d; the old
 * green came from the harness running the rule with no CFGs and no value
 * ranges, a configuration the tool never runs in. A genuine INT33-C
 * violation.
 */

/*
 * Rule: INT33-C - Ensure that division and remainder operations do not result in divide-by-zero errors
 * Status: EXPECTED FAIL
 * Reason: Loop variable becomes zero and is used as divisor without checking
 */

#include <stdio.h>

int main() {
    for (int i = 5; i >= 0; i--) {
        int result = 100 / i;  // When i becomes 0, this causes divide by zero
        printf("100 / %d = %d\n", i, result);
    }
    return 0;
}