/*
 * Rule: FLP00-C
 * Source: aurora-lint
 * Status: PASS under the default preset; VIOLATION under strict and pedantic
 * Expect: default=clean strict=violation pedantic=violation count=1
 *
 * -0.0 compares equal to 0.0: an exact zero, with its sign.
 */

int is_zero(float x) {
    return -0.0f == x; /* Expect: here */
}
