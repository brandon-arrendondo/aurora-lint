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
 * Reason: User input multiplication without wrap check
 */

#include <stdlib.h>

void allocate_user_buffer(unsigned int user_count) {
    // User-controlled multiplication - security risk
    size_t size = user_count * 1024;  // Line 10 - VIOLATION

    void *buffer = malloc(size);
    if (buffer) {
        free(buffer);
    }
}

int main(void) {
    // Simulate malicious user input
    allocate_user_buffer(UINT_MAX / 512);  // Will wrap
    return 0;
}
