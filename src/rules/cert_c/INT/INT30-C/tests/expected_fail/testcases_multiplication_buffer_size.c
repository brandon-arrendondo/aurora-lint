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
 * Reason: Multiplication for buffer size calculation without wrap check
 */

#include <stddef.h>

void calculate_buffer_size(size_t num_rows, size_t num_cols) {
    // Multiplication may wrap
    size_t buffer_size = num_rows * num_cols;  // Line 11 - VIOLATION

    // Use buffer_size for allocation...
}

int main(void) {
    calculate_buffer_size(SIZE_MAX / 100, 200);  // Will wrap
    return 0;
}
