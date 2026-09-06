/*
 * Rule: INT31-C
 * Source: real-world FN pattern
 * Status: EXPECTED FAIL - Known limitation: the operand here is a function
 * parameter (or a local with no traced taint source), and INT31-C's opt-in
 * provenance gate (converted_value_is_risky, backed by int_provenance)
 * treats that as bounded local state, so the lossy conversion is not
 * reported. That gate is what removes the bounded-counter false positives
 * on real code; flagging every unconstrained parameter is the noise it
 * exists to avoid. Detecting this needs caller-side bounds reasoning, not
 * a louder gate. The fixture is a genuine INT31-C violation and stays as
 * tracked evidence of the trade.
 * Description: Cast widens to uint16_t, then implicit assignment narrows to uint8_t
 */

#include <stdint.h>

void parse_tag(const uint8_t *buffer) {
    uint8_t tag = (uint16_t)(buffer[0] << 8);  /* Violation: uint16_t → uint8_t */
    (void)tag;
}
