/*
 * Rule: INT32-C
 * Source: testcases
 * Status: EXPECTED FAIL - Known limitation: the operand here is a function
 * parameter (or a local with no traced taint source), and INT32-C's opt-in
 * provenance gate (has_risky_operand_provenance, backed by int_provenance)
 * treats that as bounded local state, so the signed overflow is not
 * reported. That gate is what removes the bounded-counter false positives
 * on real code; flagging every unconstrained parameter is the noise it
 * exists to avoid. Detecting this needs caller-side bounds reasoning, not
 * a louder gate. The fixture is a genuine INT32-C violation and stays as
 * tracked evidence of the trade.
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