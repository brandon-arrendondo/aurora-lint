/*
 * Rule: FLP00-C
 * Source: aurora-lint
 * Status: FAIL - '0' is the digit character, whose value is not zero
 * Expect: count=1
 */

int is_digit_code(double x) {
    return x == '0'; /* Expect: here */
}
