/*
 * Rule: INT30-C
 * Source: task 1324
 * Status: PASS - a guard in an earlier operand of the same && / || expression
 *
 * The rule already recognises a guard that is a separate statement (an
 * early-return `if`, or an if/else branch). What it missed is a guard
 * evaluated as an EARLIER OPERAND of the short-circuit expression the
 * subtraction itself sits in: walking up from the subtraction finds the
 * enclosing `if`, then rejects it because the site is in the condition
 * rather than the consequence.
 *
 * Polarity is what makes the two operators differ, and it is delegated to
 * guard_dominance::dominating_condition_branch rather than assumed: reaching
 * the right operand of `&&` means the left was TRUE, reaching the right
 * operand of `||` means the left was FALSE.
 *
 * Both shapes below come from the real-world corpus and were adjudicated FP:
 * pureftpd puredb/src/puredb_read.c:307 and hostap src/ap/wpa_auth.c:1753.
 */

#include <stddef.h>

extern size_t read_len(void);
extern int consume(const void *p, size_t n);

/* `||` form. By the time `size - offset` is evaluated, `offset > size` has
 * short-circuited to the early return, so offset <= size holds. The cast on
 * the operand must not defeat the match -- the corpus instance carries one. */
int or_form(const void *p, size_t size) {
    size_t offset = read_len();
    size_t len = read_len();

    if (offset > size || len > size - (size_t) offset) {
        return -1;
    }
    return consume(p, len);
}

/* `&&` form. `n >= 8` is an earlier conjunct of the same condition, so the
 * subtraction in the later conjunct cannot underflow. */
int and_form(const void *p) {
    size_t n = read_len();

    if (n >= 8 && n - 8 > 0) {
        return consume(p, n - 8);
    }
    return 0;
}
