/*
 * Rule: EXP34-C
 * Source: task 1327
 * Status: FAIL - a || left operand does not establish its correlated guard
 *
 * is_nonnull_by_correlated_exit_guard collapses an exit guard's negation using
 * the conditions known true at the site: where `isIndex` is true,
 * `!(isIndex && (!p || ...))` does prove `p` non-null.
 *
 * The bug was which conditions counted as "known true". enclosing_conditions
 * hands back the left operand of a short-circuit expression for `&&` and `||`
 * alike, but reaching the right operand of `||` means the left was FALSE. So
 * at `isIndex || p->flags` the guard was being discharged by a fact that does
 * not hold there, and a genuinely possibly-null dereference was dropped.
 *
 * `malloc` is the null source on purpose: null_state seeds a parameter
 * NotNull, so a parameter dereference masks this entirely and the first
 * attempts to demonstrate it came back clean for the wrong reason.
 *
 * The discriminator is the pair below. The only difference between
 * or_operand_is_correlated and or_operand_is_unrelated is whether the `||`
 * left operand happens to be the guard's own flag; both must be reported.
 */

#include <stdlib.h>

struct S {
    int flags;
};

/* Control: nothing guards this at all. */
int plain_unguarded(void) {
    struct S *p = malloc(sizeof *p);
    return p->flags;
}

/* The bug: isIndex is FALSE at the dereference, so the guard proves nothing. */
int or_operand_is_correlated(int isIndex) {
    struct S *p = malloc(sizeof *p);

    if (isIndex && (!p || (p->flags & 1) == 0)) {
        return 1;
    }
    if (isIndex || p->flags) {
        return 2;
    }
    return 0;
}

/* Discriminator: same guard, unrelated operand. Always was reported. */
int or_operand_is_unrelated(int isIndex, int other) {
    struct S *p = malloc(sizeof *p);

    if (isIndex && (!p || (p->flags & 1) == 0)) {
        return 1;
    }
    if (other || p->flags) {
        return 2;
    }
    return 0;
}
