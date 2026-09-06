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