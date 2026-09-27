/*
 * Rule: PRE31-C
 * Status: PASS - Should NOT trigger PRE31-C violation
 * Reason: the nested macros initialize a local pointer and a local array of
 * their own; neither is a side effect, so ABS evaluating them twice is safe.
 */

#define FIRST(x) ({ const int *q_ = &(x); *q_; })
#define SUM2(x) ({ int a_[2] = { (x), (x) }; a_[0] + a_[1]; })
#define ABS(x) (((x) < 0) ? -(x) : (x))

int f(int n) {
    return ABS(FIRST(n)) + ABS(SUM2(n));
}
