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
 * Reason: Average calculation can overflow when summing before dividing
 */

#include <limits.h>
#include <stdio.h>

int calculate_average(int values[], int count) {
    int sum = 0;

    // VIOLATION: sum can overflow during accumulation
    for (int i = 0; i < count; i++) {
        sum += values[i];
    }

    return sum / count;
}

int main() {
    int large_values[] = {
        INT_MAX / 2,
        INT_MAX / 2,
        INT_MAX / 3,
        INT_MAX / 4
    };

    int count = sizeof(large_values) / sizeof(large_values[0]);
    int avg = calculate_average(large_values, count);

    printf("Average: %d\n", avg);
    return 0;
}