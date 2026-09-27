/*
 * Rule: PRE31-C
 * Status: PASS - Should NOT trigger PRE31-C violation
 * Reason: __builtin_expect computes a value and changes nothing, so it is
 * not an unknown call even under the strict policy.
 */

#define likely(x) __builtin_expect(!!(x), 1)
#define ABS(x) (((x) < 0) ? -(x) : (x))

int f(int n) {
    return ABS(likely(n));
}
