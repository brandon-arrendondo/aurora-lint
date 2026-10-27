/*
 * Rule: FLP00-C
 * Source: aurora-lint
 * Status: PASS under the default preset; VIOLATION under strict and pedantic
 * Expect: default=clean strict=violation pedantic=violation count=1
 *
 * The character constant '\0' is an integer constant whose value is zero,
 * converted to double: a comparison with an exact zero.
 */

int is_unset(double x) {
    return x == '\0'; /* Expect: here */
}
