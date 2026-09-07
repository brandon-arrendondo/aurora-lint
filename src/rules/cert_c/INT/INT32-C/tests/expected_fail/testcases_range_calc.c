/*
 * Rule: INT32-C
 * Source: testcases
 * Status: EXPECTED FAIL, by measurement rather than oversight. The operand is a
 * parameter, and the provenance gate now does reason about parameters via the
 * call graph -- but it judges this one BOUNDED, because the only caller in the
 * scan set is a taint-free `main`. That approximation is the gate's limit: the
 * prescan summaries carry per-function taint, not per-argument value ranges, so
 * `main` handing this function INT_MAX or SIZE_MAX/2 is unbounded in value yet
 * carries no taint. Detecting it needs per-call-site argument ranges joined
 * across callers into a summary field -- a distinct piece of work, and NOT a
 * reason to loosen the gate, which would restore the parameter false positives
 * the caller-set rule exists to avoid. Genuine violation; kept as evidence.
 */

/*
 * Rule: INT32-C - Ensure that operations on signed integers do not result in overflow
 * Status: EXPECTED FAIL
 * Reason: Range calculation between two points can overflow on subtraction
 */

#include <limits.h>
#include <stdio.h>

int calculate_range(int start, int end) {
    // VIOLATION: subtraction can overflow
    return end - start;
}

int main() {
    int test_cases[][2] = {
        {INT_MIN, INT_MAX},     // Maximum possible range
        {-1000000, INT_MAX},    // Large positive range
        {INT_MAX, -1000000},    // Large negative range (end - start)
        {INT_MIN, 1000000}      // Another problematic case
    };

    int count = sizeof(test_cases) / sizeof(test_cases[0]);

    for (int i = 0; i < count; i++) {
        int range = calculate_range(test_cases[i][0], test_cases[i][1]);
        printf("Range from %d to %d: %d\n",
               test_cases[i][0], test_cases[i][1], range);
    }

    return 0;
}