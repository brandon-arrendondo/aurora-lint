/*
 * Rule: INT08-C
 * Source: custom
 * Status: PASS - should NOT trigger INT08-C violation
 * Description: The branch condition contradicts ITSELF, not the incoming
 * value: no integer is both above 5 and below 3, and no value both satisfies
 * `data < 3` and fails it. Each block below therefore never executes, and
 * the out-of-range store it would make is not a value the program holds.
 * Merging the two operands of `&&` (or the negated operands of `||` on the
 * else edge) intersects their constraints to the empty set, and the range
 * engine must keep that empty set as an answer -- "no value" -- rather than
 * let it collapse to "no constraint", which would carry CHAR_MAX into a dead
 * block and have the store judged there. A third conjunct must not revive
 * the branch either. Twin: tests/fail/store_in_satisfiable_conjunction.c.
 */

#include <limits.h>

void contradictory_conjunction(void) {
    char data = CHAR_MAX;
    if (data > 5 && data < 3) {
        char result = data + 1;
        (void)result;
    }
}

void later_conjunct_cannot_revive(void) {
    char data = CHAR_MAX;
    if (data > 5 && data < 3 && data == CHAR_MAX) {
        char result = data + 1;
        (void)result;
    }
}

void tautology_else_branch(void) {
    short data = SHRT_MAX;
    if (data < 3 || data >= 3) {
        (void)data;
    } else {
        short result = data + 1;
        (void)result;
    }
}
