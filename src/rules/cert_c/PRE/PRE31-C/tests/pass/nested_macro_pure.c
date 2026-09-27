/*
 * Rule: PRE31-C
 * Status: PASS - Should NOT trigger PRE31-C violation
 * Reason: IS_ODD neither writes nor calls anything, so passing it to an
 * unsafe macro has no side effect.
 */

#define IS_ODD(v) ((v) & 1)
#define ABS(x) (((x) < 0) ? -(x) : (x))

int a(int n) {
    return ABS(IS_ODD(n));
}
