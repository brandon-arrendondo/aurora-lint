/*
 * Rule: EXP34-C
 * Source: task 1327
 * Status: PASS - the && case is legitimate and must stay suppressed
 *
 * The polarity trap for task 1327. Reaching the right operand of `&&` means
 * the left really did evaluate true, so `isIndex` IS known true at the
 * dereference and `!(isIndex && (!p || ...))` collapses to `p != NULL`.
 *
 * If a future change fixes the `||` polarity by dropping short-circuit
 * operands from conditions_known_true_at altogether rather than by resolving
 * their branch, this file starts failing -- which is the point. The fix is the
 * polarity, not the source.
 */

#include <stdlib.h>

struct S {
    int flags;
};

int and_operand_is_known_true(int isIndex) {
    struct S *p = malloc(sizeof *p);

    if (isIndex && (!p || (p->flags & 1) == 0)) {
        return 1;
    }
    if (isIndex && p->flags) {
        return 2;
    }
    return 0;
}
