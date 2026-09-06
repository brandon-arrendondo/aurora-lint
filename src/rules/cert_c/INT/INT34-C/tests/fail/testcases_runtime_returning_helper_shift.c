/*
 * Rule: INT34-C
 * Status: FAIL - Shift amount is a call to a helper whose return depends on
 * run-time data.
 *
 * The negative half of the constant-returning-helper case: hoisting the
 * constant-shift reasoning across a call must not degrade into "any call is
 * fine". Neither helper here has a fixed return, so both shifts stay
 * violations.
 */

typedef unsigned long word_t;

static unsigned int passthrough_amount(unsigned int n) {
    return n;
}

static unsigned int clamped_at_runtime(unsigned int n, int flag) {
    if (flag) {
        return n;
    }
    return 8;
}

word_t shift_by_passthrough(word_t x, unsigned int n) {
    return x << passthrough_amount(n);
}

word_t shift_by_partly_constant(word_t x, unsigned int n, int flag) {
    return x >> clamped_at_runtime(n, flag);
}
