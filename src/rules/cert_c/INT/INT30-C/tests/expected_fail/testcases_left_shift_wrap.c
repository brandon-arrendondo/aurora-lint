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
 * Reason: Left shift causing wrap used in security context
 */

void bit_shift_unsafe(unsigned int value, unsigned int shift) {
    // Left shift may wrap - used in security-critical context
    unsigned int mask = value << shift;  // Line 9 - VIOLATION

    // Use mask in access control decision...
}

int main(void) {
    bit_shift_unsafe(0xFFFFFFFFU, 4);  // Will wrap
    return 0;
}
