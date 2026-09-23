/*
 * Rule: INT30-C
 * Source: real-world
 * Status: FAIL - the short-circuit operand does not guard THIS subtraction
 *
 * The negative control for an earlier fix's guard. A dominating short-circuit
 * operand only proves what it actually compares: here the earlier operand
 * bounds an unrelated variable, so `size - offset` is still unguarded and
 * must still be reported. Without this case, widening the guard walk to
 * short-circuit operands could suppress every subtraction that happens to
 * sit in a condition.
 */

#include <stddef.h>

extern size_t read_len(void);
extern int consume(const void *p, size_t n);

int unrelated_operand_is_not_a_guard(const void *p, size_t size) {
    size_t offset = read_len();
    size_t other = read_len();
    size_t len = read_len();

    /* `other > size` says nothing about `offset`. */
    if (other > size || len > size - offset) {
        return -1;
    }
    return consume(p, len);
}

/*
 * Polarity trap. Reaching the right operand of `&&` means the left was TRUE,
 * so `n < 8` holds and the subtraction is genuinely unsafe. Suppressing this
 * would mean the `&&` arm had been given the `||` arm's rule -- the exact
 * inversion that guard_dominance::dominating_condition_branch exists to
 * prevent, and the reason this rule asks it rather than assuming.
 */
int and_operand_proves_the_opposite(const void *p) {
    size_t n = read_len();

    if (n < 8 && n - 8 > 0) {
        return consume(p, n - 8);
    }
    return 0;
}
