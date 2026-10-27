/*
 * Rule: FLP00-C
 * Source: aurora-lint
 * Status: PASS under the default preset; VIOLATION under strict and pedantic
 * Expect: default=clean strict=violation pedantic=violation count=1
 *
 * Zero is exactly representable, and testing a double against it is a
 * common idiom, so the default policy does not report it
 * (flp00_exact_zero_comparison_exempt). The strict policy reports it as any
 * other floating-point comparison.
 */

int is_unset(double x) {
    return x == 0.0; /* Expect: here */
}
