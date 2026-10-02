/*
 * Rule: INT33-C
 * Source: synthetic
 * Status: PASS - Should not trigger INT33-C violation
 *
 * Each division has a floating divisor: a typedef of double, or a call to a
 * function defined here that returns double. That makes it floating-point
 * division (C11 6.3.1.8), not the integer division INT33-C covers.
 */
typedef double real_t;

static double ratio(int k) {
    return k * 0.5;
}

double divide_by_typedef(int n, real_t d) {
    return n / d;
}

double divide_by_call(int n, int k) {
    return n / ratio(k);
}
