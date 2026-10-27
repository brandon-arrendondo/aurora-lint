/*
 * Rule: FLP00-C
 * Source: aurora-lint
 * Status: FAIL - two variables declared double compared with ==
 * Expect: count=1
 *
 * Neither operand is a literal or a cast; their declarations make the
 * comparison a floating-point one.
 */

int same_reading(double a, double b) {
    return a == b; /* Expect: here */
}
