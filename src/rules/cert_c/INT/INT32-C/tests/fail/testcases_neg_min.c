/*
 * Rule: INT32-C
 * Source: testcases
 * Status: FAIL - Should trigger INT32-C violation
 * Settings: data_model=lp64
 *
 * The overflow is proven from INT_MAX's value, which a declared model fixes;
 * the Juliet builds these shapes come from are LP64.
 */

/*
 * Rule: INT32-C - Ensure that operations on signed integers do not result in overflow
 * Status: FAIL
 * Reason: Negating INT_MIN causes overflow because -INT_MIN > INT_MAX
 */

#include <limits.h>
#include <stdio.h>

int main() {
    int value = INT_MIN;
    int result = -value; // VIOLATION: negating INT_MIN overflows

    printf("Original: %d, Negated: %d\n", value, result);
    return 0;
}