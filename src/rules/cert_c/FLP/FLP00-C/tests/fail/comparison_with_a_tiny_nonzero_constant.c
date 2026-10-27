/*
 * Rule: FLP00-C
 * Source: aurora-lint
 * Status: FAIL - a comparison with a small constant that is not zero
 * Expect: count=1
 *
 * 1e-9 is not an exact zero, so the default policy's exemption does not
 * apply.
 */

int is_negligible(double x) {
    return x == 1e-9; /* Expect: here */
}
