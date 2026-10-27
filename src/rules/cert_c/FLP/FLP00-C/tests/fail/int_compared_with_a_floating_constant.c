/*
 * Rule: FLP00-C
 * Source: aurora-lint
 * Status: FAIL - an int compared with a nonzero floating constant
 * Expect: count=1
 */

int is_half(int n) {
    return n == 0.5; /* Expect: here */
}
