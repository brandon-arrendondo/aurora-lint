/*
 * Rule: PRE31-C
 * Status: PASS - Should NOT trigger PRE31-C violation
 * Expect: default=clean strict=clean
 * Reason: wrap's own block declares the typedef step, so (step) (v) casts
 * its operand and wrap evaluates nothing with a side effect.
 */

#define TWICE(x) ((x) + (x))

static int wrap(int v) {
    typedef int step;
    return (step) (v);
}

int use(void) {
    return TWICE(wrap(1));
}
