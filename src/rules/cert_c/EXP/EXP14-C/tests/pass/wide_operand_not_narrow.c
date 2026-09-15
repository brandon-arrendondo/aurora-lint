/*
 * Rule: EXP14-C
 * Source: task-follow-up (post-adjudication 95.2% FP fix)
 * Status: PASS - Should NOT trigger EXP14-C violation
 * Description: Bitwise NOT/shift on an operand that's already int-or-wider
 * is never at risk from integer promotion (promotion is a no-op, or the
 * operand is already wider than int). Dominant real-world FP driver:
 * `flags &= ~SOME_FLAG` (an unresolvable macro name defaults to `int`) and
 * left-shifting an already-wide variable.
 */

#define FLAG_A 0x01u

void clear_flag(unsigned int flags) {
    flags &= ~FLAG_A;
}

void shift_wide(unsigned long val) {
    unsigned long shifted = val << 4;
}
