/*
 * Rule: INT33-C
 * Source: testcases
 * Status: FAIL - Same-statement conditions that do NOT prove the divisor non-zero
 *
 * Counterparts to testcases_same_statement_guards.c: the divisor is tested,
 * but in the wrong arm, on the wrong side of the short-circuit, against a
 * bound that still admits zero, or asserted before being reassigned.
 */

#include <assert.h>

/* Division in the arm the zero-test does NOT guard */
long wrong_arm(long total, long n) {
    return n ? 0 : total / n;
}

/* || whose left operand is the NON-zero test: the right runs only when n == 0 */
int wrong_polarity(int hits, int n) {
    return n != 0 || (hits / n) > 3;
}

/* Division on the LEFT of &&: evaluated before the test */
int wrong_side(int hits, int n) {
    return (hits / n) > 3 && n != 0;
}

/* Bound that still admits zero */
int admits_zero(int x, int n) {
    if (n >= 0) return x / n;
    return 0;
}

/* Assert made stale by a reassignment before the division */
int stale_assert(int x, int n) {
    assert(n != 0);
    n = x - 1;
    return x / n;
}
