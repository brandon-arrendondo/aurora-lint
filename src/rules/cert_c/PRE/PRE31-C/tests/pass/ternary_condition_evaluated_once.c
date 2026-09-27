/*
 * Rule: PRE31-C
 * Status: PASS - Should NOT trigger PRE31-C violation
 * Reason: x is the condition of ?:, evaluated exactly once on every path.
 */

#define TO_BOOL(x) ((x) ? 1 : 0)

int a(int i) {
    return TO_BOOL(i++);
}
