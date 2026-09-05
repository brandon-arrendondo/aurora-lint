/*
 * Rule: INT32-C
 * Source: wiki
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

void func(signed long s_a) {
  signed long result = -s_a;
  /* ... */
}