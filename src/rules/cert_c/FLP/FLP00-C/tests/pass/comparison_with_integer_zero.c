/*
 * Rule: FLP00-C
 * Source: aurora-lint
 * Status: PASS under the default preset; VIOLATION under strict and pedantic
 * Expect: default=clean strict=violation pedantic=violation count=1
 *
 * The integer constant 0 is converted to double: still a comparison with an
 * exact zero.
 */

int is_nonzero(double x) {
    return x != 0; /* Expect: here */
}
