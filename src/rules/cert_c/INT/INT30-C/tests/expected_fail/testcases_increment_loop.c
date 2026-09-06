/*
 * Rule: INT30-C
 * Source: testcases
 * Status: EXPECTED FAIL - Known limitation: the operand here is a function
 * parameter (or a local with no traced taint source), and INT30-C's opt-in
 * provenance gate (has_risky_operand_provenance, backed by int_provenance)
 * treats that as bounded local state, so the unsigned wrap is not
 * reported. That gate is what removes the bounded-counter false positives
 * on real code; flagging every unconstrained parameter is the noise it
 * exists to avoid. Detecting this needs caller-side bounds reasoning, not
 * a louder gate. The fixture is a genuine INT30-C violation and stays as
 * tracked evidence of the trade.
 */

/*
 * Rule: INT30-C - Ensure that unsigned integer operations do not wrap
 * Status: EXPECTED FAIL
 * Reason: Addition in loop condition without bounds check
 */

#include <limits.h>

void increment_no_check(unsigned int start) {
    unsigned int i;

    // Loop with unchecked unsigned addition in condition
    for (i = start; i < start + 100; i++) {
        // Process...
    }
}

int main(void) {
    increment_no_check(UINT_MAX - 50);
    return 0;
}
