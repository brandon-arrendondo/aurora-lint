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
 * Reason: Compound left shift in security-critical code without check
 */

void shift_mask(unsigned int *flags, unsigned int shift_amount) {
    // Compound left shift may wrap - security context
    *flags <<= shift_amount;  // Line 9 - VIOLATION

    // Use flags for permission checks...
}

int main(void) {
    unsigned int permissions = 0xFFFFU;
    shift_mask(&permissions, 20);  // Will wrap
    return 0;
}
