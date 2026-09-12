/*
 * Rule: PRE31-C
 * Source: testcases
 * Status: PASS - Should NOT trigger PRE31-C violation
 */

/*
 * Rule: PRE31-C - Avoid side effects in arguments to unsafe macros
 * Status: PASS
 * Reason: Macro parameter is referenced exactly once in the replacement
 * text (a plain passthrough), so the argument is evaluated exactly once
 * regardless of what side effects it carries.
 */

#define DEBUGF(x) x

int side_effecting(int *n);

void func(int *n) {
    // Single-evaluation macro - COMPLIANT even with a side-effecting call
    DEBUGF(side_effecting(n));
}

int main(void) {
    int n = 5;
    func(&n);
    return 0;
}
