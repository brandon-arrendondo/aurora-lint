/*
 * Rule: INT31-C
 * Source: custom
 * Status: EXPECTED FAIL - Known limitation: the operand here is a function
 * parameter (or a local with no traced taint source), and INT31-C's opt-in
 * provenance gate (converted_value_is_risky, backed by int_provenance)
 * treats that as bounded local state, so the lossy conversion is not
 * reported. That gate is what removes the bounded-counter false positives
 * on real code; flagging every unconstrained parameter is the noise it
 * exists to avoid. Detecting this needs caller-side bounds reasoning, not
 * a louder gate. The fixture is a genuine INT31-C violation and stays as
 * tracked evidence of the trade.
 * Description: Explicit cast narrowing an unguarded float parameter to
 * unsigned char, e.g. raylib's rlColor4f(float r, ...) { (unsigned char)(r*255) }.
 * Not FLP34-C's territory (that's float<->float precision loss); this is a
 * float value narrowed into an integer type with no local range check.
 */

unsigned char to_byte(float ratio) {
    return (unsigned char)(ratio * 255.0f);
}
