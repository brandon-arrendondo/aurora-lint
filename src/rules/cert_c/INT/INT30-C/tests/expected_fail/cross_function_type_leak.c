/*
 * Rule: INT30-C
 * Source: task-403 regression
 * Status: EXPECTED FAIL - Known limitation: the operand here is a function
 * parameter (or a local with no traced taint source), and INT30-C's opt-in
 * provenance gate (has_risky_operand_provenance, backed by int_provenance)
 * treats that as bounded local state, so the unsigned wrap is not
 * reported. That gate is what removes the bounded-counter false positives
 * on real code; flagging every unconstrained parameter is the noise it
 * exists to avoid. Detecting this needs caller-side bounds reasoning, not
 * a louder gate. The fixture is a genuine INT30-C violation and stays as
 * tracked evidence of the trade.
 *
 * Guards against a same-named-variable-across-functions type leak: an
 * earlier function declares `x` as float (not an integer type), and a
 * later, unrelated function reuses the name `x` for an unsigned int used
 * in an unchecked addition. If the rule's type map is not scoped per
 * function, the whole-file map's last-write-wins semantics let one
 * function's declared type for `x` leak into the other function's lookup,
 * either wrongly suppressing the real unsigned-wrap finding below or
 * (in the reverse order) wrongly flagging the float use.
 */

void safe_use(void) {
    float x;
    x = 1.5f;
    x = x + 1.0f;
}

unsigned int risky(unsigned int x, unsigned int y) {
    unsigned int sum = x + y;  // VIOLATION: unsigned wrap, no overflow check
    return sum;
}
