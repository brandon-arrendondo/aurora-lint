/*
 * Rule: INT16-C
 * Source: task-follow-up (shift-count vs shifted-value)
 * Status: PASS - should NOT trigger INT16-C violation
 * Description: a shift's COUNT (the right operand of `<<`/`>>`) never has
 * representation-dependent risk -- only the value being shifted does. The
 * checker previously flagged both operands identically, so a signed loop
 * variable used only as a shift count (never itself bitwise-operated on)
 * was wrongly reported.
 */
void shift_by_signed_count(unsigned int val, int count) {
    unsigned int shifted = val << count;
    (void)shifted;
}

void shift_right_by_signed_count(unsigned int val, int count) {
    unsigned int shifted = val >> count;
    (void)shifted;
}
