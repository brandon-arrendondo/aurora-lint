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
 * Reason: Multiple additions without wrap check
 */

#include <stddef.h>

void calculate_offset(size_t base, size_t offset1, size_t offset2, size_t offset3) {
    // Multiple additions - any may wrap
    size_t total = base + offset1 + offset2 + offset3;  // Line 11 - VIOLATION

    // Use total for file seeking or memory access...
}

int main(void) {
    calculate_offset(SIZE_MAX / 2, SIZE_MAX / 4, SIZE_MAX / 4, 100);
    return 0;
}
