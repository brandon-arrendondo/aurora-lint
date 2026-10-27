/*
 * Rule: FLP00-C
 * Source: aurora-lint
 * Status: FAIL - operands of a typedef of double compared with !=
 * Expect: count=1
 */

typedef double real;

int changed(real before, real after) {
    return before != after; /* Expect: here */
}
