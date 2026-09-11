/*
 * Rule: INT08-C
 * Source: custom
 * Status: FAIL - should trigger INT08-C violation
 * Description: Twin of tests/pass/store_in_contradicted_branch_is_unreachable.c.
 * Here the guard is satisfied: `data` is CHAR_MAX and the branch asks for
 * exactly that, so the store runs and 128 does not fit a char. A previous
 * version withdrew the claim whenever ANY dominating comparison mentioned
 * an operand, which silenced this shape along with the dead one (44 true
 * positives in Juliet's CWE-190 cohort). The guard is not a reason to stay
 * quiet; it is the proof. Every function here was silent under that gate.
 */

#include <limits.h>

void guard_agrees(void) {
    char data = CHAR_MAX;
    if (data == CHAR_MAX) {
        char result = data + 1;
        (void)result;
    }
}

void guard_agrees_short(void) {
    short data = SHRT_MAX;
    if (data >= SHRT_MAX) {
        short result = data + 1;
        (void)result;
    }
}
