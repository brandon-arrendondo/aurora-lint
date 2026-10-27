/*
 * Rule: FLP00-C
 * Source: aurora-lint
 * Status: FAIL - a double compared with the hexadecimal constant 0x0f
 * Expect: count=1
 *
 * 0x0f is fifteen: in a hexadecimal constant `f` is a digit, not a floating
 * suffix, so the constant is not a zero.
 */

int is_fifteen(double x) {
    return x == 0x0f; /* Expect: here */
}
