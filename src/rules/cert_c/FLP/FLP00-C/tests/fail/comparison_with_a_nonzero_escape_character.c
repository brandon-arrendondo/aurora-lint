/*
 * Rule: FLP00-C
 * Source: aurora-lint
 * Status: FAIL - the escape '\1' has the value one, not zero
 * Expect: count=1
 */

int is_start_of_heading(double x) {
    return x == '\1'; /* Expect: here */
}
