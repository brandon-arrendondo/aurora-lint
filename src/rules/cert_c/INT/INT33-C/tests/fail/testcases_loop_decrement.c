/*
 * Rule: INT33-C
 * Source: testcases
 * Status: FAIL - Should trigger INT33-C violation
 * Reason: the divisor reaching zero is a property of the loop's induction
 * variable (for (i = 5; i >= 0; i--)), not of the division expression. VRA
 * gives `i` the range [0, 5] in the loop body, which contains zero, so the
 * divisor is not provably non-zero.
 */

/*
 * Rule: INT33-C - Ensure that division and remainder operations do not result in divide-by-zero errors
 * Status: FAIL
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