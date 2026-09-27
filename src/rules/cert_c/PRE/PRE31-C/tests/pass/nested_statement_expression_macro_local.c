/*
 * Rule: PRE31-C
 * Status: PASS - Should NOT trigger PRE31-C violation
 * Reason: IS_NAN's statement expression initializes its own local; that
 * is not a side effect of evaluating it, so ABS evaluating it twice is safe.
 */

#define IS_NAN(x) __extension__({ __typeof(x) x_a = (x); x_a != x_a; })
#define ABS(x) (((x) < 0) ? -(x) : (x))

int g(double score) {
    return ABS(IS_NAN(score));
}
