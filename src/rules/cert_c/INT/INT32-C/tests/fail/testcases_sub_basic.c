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
 * Reason: Subtraction of a negative number from a positive number without overflow checking
 */

#include <limits.h>
#include <stdio.h>

int main() {
    int a = INT_MAX;
    int b = -1;
    int result = a - b; // VIOLATION: equivalent to INT_MAX + 1, causes overflow

    printf("Result: %d\n", result);
    return 0;
}