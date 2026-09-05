/*
 * Rule: INT32-C
 * Source: testcases
 * Status: FAIL - Should trigger INT32-C violation
 */

/*
 * Rule: INT32-C - Ensure that operations on signed integers do not result in overflow
 * Status: FAIL
 * Reason: Time calculation converting seconds to milliseconds can overflow
 */

#include <limits.h>
#include <stdio.h>

int main() {
    int seconds = 3000000; // 3 million seconds
    int milliseconds_per_second = 1000;

    // VIOLATION: multiplication can overflow
    int total_milliseconds = seconds * milliseconds_per_second;

    printf("Total milliseconds: %d\n", total_milliseconds);
    return 0;
}