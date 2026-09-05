/*
 * Rule: INT31-C
 * Status: EXPECTED FAIL - Known limitation: the operand here is a function
 * parameter (or a local with no traced taint source), and INT31-C's opt-in
 * provenance gate (converted_value_is_risky, backed by int_provenance)
 * treats that as bounded local state, so the lossy conversion is not
 * reported. That gate is what removes the bounded-counter false positives
 * on real code; flagging every unconstrained parameter is the noise it
 * exists to avoid. Detecting this needs caller-side bounds reasoning, not
 * a louder gate. The fixture is a genuine INT31-C violation and stays as
 * tracked evidence of the trade.
 */

#include <stdio.h>

void f(long val) {
    char c = val;  /* VIOLATION: implicit narrowing from long to char */
    printf("%d\n", c);
}
