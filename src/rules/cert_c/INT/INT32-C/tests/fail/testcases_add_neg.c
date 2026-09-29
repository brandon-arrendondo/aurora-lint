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
 * Reason: Addition of two large negative integers without overflow checking causes underflow
 */

#include <limits.h>
#include <stdio.h>

int main() {
    int a = INT_MIN;
    int b = -1;
    int result = a + b; // VIOLATION: underflow not checked

    printf("Result: %d\n", result);
    return 0;
}