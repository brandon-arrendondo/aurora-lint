/*
 * Rule: PRE31-C
 * Status: PASS - Should NOT trigger PRE31-C violation
 * Reason: GETX evaluates s once; `s.x` is s, `.`, x, not one token.
 */

struct pt { int x; };
#define GETX(s) s.x

int f(struct pt *arr, int i) {
    return GETX(arr[i++]);
}
