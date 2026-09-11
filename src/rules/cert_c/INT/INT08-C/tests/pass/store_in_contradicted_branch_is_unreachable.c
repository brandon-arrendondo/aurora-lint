/*
 * Rule: INT08-C
 * Source: custom
 * Status: PASS - should NOT trigger INT08-C violation
 * Description: Juliet's CWE-190 good sink. `data` is CHAR_MAX, the branch
 * asks for `data < CHAR_MAX`, so the store inside it never executes and the
 * 128 it would compute is not a value the program ever holds. The range
 * engine gives a contradicted branch no entry at all, and a store with no
 * range is never judged. This rule used to add its own guard test on top
 * (any dominating comparison on an operand withdrew the claim) -- that is
 * gone, so this fixture is what now keeps the good sink silent, through
 * VRA alone. Twin: tests/fail/store_in_branch_whose_guard_proves_it.c.
 */

#include <limits.h>

void good_sink(void) {
    char data = CHAR_MAX;
    if (data < CHAR_MAX) {
        char result = data + 1;
        (void)result;
    }
}

void good_sink_short(void) {
    short data = SHRT_MAX;
    if (data < SHRT_MAX) {
        short result = data + 1;
        (void)result;
    }
}
