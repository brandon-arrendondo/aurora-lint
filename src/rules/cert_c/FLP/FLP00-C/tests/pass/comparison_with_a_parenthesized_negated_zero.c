/*
 * Rule: FLP00-C
 * Source: aurora-lint
 * Status: PASS under the default preset; VIOLATION under strict and pedantic
 * Expect: default=clean strict=violation pedantic=violation count=1
 *
 * A zero negated and parenthesized is still an exact zero.
 */

int is_origin(double x) {
    return x == -(0.0); /* Expect: here */
}
