/*
 * Rule: FLP00-C
 * Source: aurora-lint
 * Status: PASS under the default preset; VIOLATION under strict and pedantic
 * Expect: default=clean strict=violation pedantic=violation count=4
 *
 * A zero cast to an arithmetic type is a zero, written in the comparison
 * as in a macro: under parentheses and a sign too.
 */

int is_unset(double x, float y, long double z) {
    if (x == (double)0) /* Expect: here */
        return 1;
    if (y != (float)0) /* Expect: here */
        return 2;
    if (x == -(double)0) /* Expect: here */
        return 3;
    return z == ((long double)0); /* Expect: here */
}
