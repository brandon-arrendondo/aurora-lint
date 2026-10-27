/*
 * Rule: FLP00-C
 * Source: aurora-lint
 * Status: PASS under the default preset; VIOLATION under strict and pedantic
 * Expect: default=clean strict=violation pedantic=violation count=1
 *
 * The hexadecimal escape '\x0' is the null character, whose value is zero.
 */

int is_unset(double x) {
    return x != '\x0'; /* Expect: here */
}
