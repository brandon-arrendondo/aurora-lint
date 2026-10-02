/*
 * Rule: INT30-C
 * Source: synthetic
 * Status: PASS - Should not trigger INT30-C violation
 *
 * Each multiplication has a floating operand: a typedef of double, or a
 * call to a function defined here that returns double. The unsigned operand
 * is converted to double (C11 6.3.1.8), so nothing wraps.
 */
typedef double real_t;

static double ratio(int k) {
    return k * 0.5;
}

double scale_by_typedef(unsigned u, real_t f) {
    return u * f;
}

double scale_by_call(unsigned u, int k) {
    return u * ratio(k);
}
