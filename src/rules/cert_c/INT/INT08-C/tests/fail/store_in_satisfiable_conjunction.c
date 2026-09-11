/*
 * Rule: INT08-C
 * Source: custom
 * Status: FAIL - should trigger INT08-C violation
 * Description: Guard for the empty-set rule in the range engine's compound
 * merge. These conjunctions are satisfiable (their operands' constraints
 * intersect to a live range that still contains CHAR_MAX / SHRT_MAX), and a
 * disjunction with one unsatisfiable operand is exactly its other operand.
 * Every block below runs with the maximum value, so the truncating store
 * must be reported: the dead-branch treatment of an empty intersection must
 * neither widen nor kill a live one. Twin:
 * tests/pass/store_in_self_contradictory_branch_is_unreachable.c.
 */

#include <limits.h>

void satisfiable_conjunction(void) {
    char data = CHAR_MAX;
    if (data > 5 && data < 200) {
        char result = data + 1;
        (void)result;
    }
}

void empty_operand_leaves_the_other(void) {
    short data = SHRT_MAX;
    if ((data > 5 && data < 3) || data == SHRT_MAX) {
        short result = data + 1;
        (void)result;
    }
}
