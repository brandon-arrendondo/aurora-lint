/*
 * Rule: MSC12-C
 * Source: aurora-lint
 * Status: PASS - Should NOT trigger MSC12-C violation
 *
 * X expands through Y to foo. The first call hands XCAT the argument X,
 * whose expansion reaches Y; the second hands it Y itself, and Y's own
 * expansion reaches foo, so XCAT(Y, _b)() calls foo_b.
 */

#define CAT(a, b) a##b
#define XCAT(a, b) CAT(a, b)
#define X Y
#define Y L1
#define L1 L2
#define L2 L3
#define L3 L4
#define L4 foo

int X_a;

static int foo_b(void) { return 1; }

int api(void) {
    (void)XCAT(X, _q);
    return XCAT(Y, _b)();
}
