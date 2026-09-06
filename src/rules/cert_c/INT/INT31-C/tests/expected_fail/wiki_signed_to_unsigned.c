/*
 * Rule: INT31-C
 * Source: wiki
 * Status: EXPECTED FAIL - Known limitation: the operand here is a function
 * parameter (or a local with no traced taint source), and INT31-C's opt-in
 * provenance gate (converted_value_is_risky, backed by int_provenance)
 * treats that as bounded local state, so the lossy conversion is not
 * reported. That gate is what removes the bounded-counter false positives
 * on real code; flagging every unconstrained parameter is the noise it
 * exists to avoid. Detecting this needs caller-side bounds reasoning, not
 * a louder gate. The fixture is a genuine INT31-C violation and stays as
 * tracked evidence of the trade.
 * Description: Signed to unsigned conversion without bounds check
 */

#include <limits.h>

void func(signed int si) {
    /* Cast eliminates warning but allows negative values */
    unsigned int ui = (unsigned int)si;  /* Violation: no bounds check */

    /* ... */
    (void)ui;
}

void testcase_signed_to_unsigned_no_check(void) {
    func(INT_MIN);
}
