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
 * Reason: Function performs addition without checking for overflow
 */

#include <limits.h>
#include <stdio.h>

int add_values(int a, int b) {
    return a + b; // VIOLATION: no overflow check
}

int main() {
    int result1 = add_values(INT_MAX, 1);
    int result2 = add_values(INT_MIN, -1);

    printf("Result 1: %d\n", result1);
    printf("Result 2: %d\n", result2);

    return 0;
}