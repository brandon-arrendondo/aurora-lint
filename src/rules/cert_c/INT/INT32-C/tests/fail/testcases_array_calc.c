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
 * Reason: Array index calculation can overflow without proper checking
 */

#include <limits.h>
#include <stdio.h>

int main() {
    int array[100];
    int base_index = INT_MAX - 5;
    int offset = 10;

    // VIOLATION: index calculation can overflow
    int final_index = base_index + offset;

    printf("Accessing array[%d]\n", final_index);
    // This would likely cause a segmentation fault
    // array[final_index] = 42;

    return 0;
}