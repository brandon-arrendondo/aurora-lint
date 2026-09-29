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
 * Reason: Decrementing INT_MIN causes underflow
 */

#include <limits.h>
#include <stdio.h>

int main() {
    int value = INT_MIN;
    value--; // VIOLATION: decrementing INT_MIN underflows

    printf("Result: %d\n", value);
    return 0;
}