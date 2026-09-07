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
 * Reason: Power calculation using repeated multiplication can overflow
 */

#include <limits.h>
#include <stdio.h>

int power(int base, int exponent) {
    int result = 1;
    for (int i = 0; i < exponent; i++) {
        result *= base; // VIOLATION: no overflow checking
    }
    return result;
}

int main() {
    int test_cases[][2] = {
        {2, 30},
        {10, 9},
        {-2, 31},
        {100, 5}
    };

    int count = sizeof(test_cases) / sizeof(test_cases[0]);

    for (int i = 0; i < count; i++) {
        int result = power(test_cases[i][0], test_cases[i][1]);
        printf("%d^%d = %d\n", test_cases[i][0], test_cases[i][1], result);
    }

    return 0;
}