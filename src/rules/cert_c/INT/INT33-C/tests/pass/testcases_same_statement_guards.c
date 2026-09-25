/*
 * Rule: INT33-C
 * Source: testcases
 * Status: PASS - Divisor proven non-zero by a same-statement or preceding guard
 *
 * Shapes from an earlier fix (valkey INT33-C batch): the zero-test is the condition
 * of a ?: whose guarded arm divides, the left operand of a short-circuit && / ||
 * whose right operand divides, an enclosing if whose condition proves non-zero
 * by ordering (n > 0) rather than equality, or an exit guard written as a
 * disjunction. A preceding NDEBUG-strippable assert is not among them: see
 * fail/testcases_strippable_assert_is_not_a_guard.c.
 */

struct stats { long sampled; long ttl_sum; int *cats; int cats_count; };

/* ?: whose condition is the zero-test, division in the guarded arm */
long avg_ternary(long total, long n) {
    return n ? total / n : 0;
}

/* Truthy test as the left operand of && */
int pct_and(int hits, int buckets) {
    return buckets > 0 && (hits * 100) / buckets > 50;
}

/* Field divisor guarded by == 0 || on the same line */
long avg_or(struct stats *s) {
    if (s->sampled == 0 || s->ttl_sum / s->sampled > 1000) return 1;
    return 0;
}

/* Enclosing if proving non-zero by ordering, on a field through -> */
int pick(struct stats *s, unsigned r) {
    if (s->cats && s->cats_count > 0) {
        return s->cats[r % s->cats_count];
    }
    return -1;
}

/* Exit guard written as a disjunction: falling past it makes every term false */
int ratio_after_break(int score, int len) {
    int out = 0;
    for (;;) {
        if (score == 0 || len == 0) break;
        out = score / len;
        break;
    }
    return out;
}

/* Condition known true by ordering with a positive constant */
int at_least_one(int x, int n) {
    if (n >= 1) return x / n;
    return 0;
}

/* Negated zero-test in a ternary condition */
int not_zero(int x, int n) {
    return !(n == 0) ? x / n : 0;
}
