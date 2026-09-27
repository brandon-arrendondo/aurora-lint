/*
 * Rule: PRE31-C
 * Status: PASS - Should NOT trigger PRE31-C violation
 * Reason: `low` is the left operand of &&, evaluated exactly once on every
 * path, so the macro is safe for that argument (CERT's definition of an
 * unsafe macro: a parameter evaluated more than once or not at all).
 */

#define IS_VALID_RANGE(x, low, high) ((x) >= (low) && (x) <= (high))

void range_check(int val) {
    int lower = 0;
    if (IS_VALID_RANGE(val, ++lower, 100)) {
    }
}
