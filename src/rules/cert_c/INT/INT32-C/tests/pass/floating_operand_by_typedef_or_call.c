/*
 * Rule: INT32-C
 * Source: synthetic
 * Status: PASS - Should not trigger INT32-C violation
 *
 * Each compound assignment has a floating right operand: a typedef of
 * double, or a call to a function defined here that returns double. The
 * arithmetic is floating-point (C11 6.3.1.8), so there is no signed integer
 * overflow to check.
 */
typedef double real_t;

static double ratio(int k) {
    return k * 0.5;
}

int add_typedef(int i, real_t f) {
    i += f;
    return i;
}

int scale_by_call(int i, int k) {
    i *= ratio(k);
    return i;
}
