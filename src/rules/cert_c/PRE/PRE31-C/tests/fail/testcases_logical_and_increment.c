/*
 * Rule: PRE31-C
 * Source: testcases
 * Status: FAIL - Should trigger PRE31-C violation
 */

/*
 * Rule: PRE31-C - Avoid side effects in arguments to unsafe macros
 * Status: FAIL
 * Reason: `high` is the right operand of &&, so the macro evaluates it zero
 * times or once depending on `x`; the increment passed for it may not run.
 */

#define IS_VALID_RANGE(x, low, high) ((x) >= (low) && (x) <= (high))  /* UNSAFE */

void range_check(int val) {
    int upper = 99;
    if (IS_VALID_RANGE(val, 0, ++upper)) {  // VIOLATION
    }
}

int main(void) {
    range_check(50);
    return 0;
}
