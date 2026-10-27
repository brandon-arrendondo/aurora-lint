/*
 * Rule: PRE31-C
 * Status: FAIL - Should trigger PRE31-C violation
 * Expect: default=clean strict=violation
 * Reason: the typedef step belongs to other's block alone, so in wrap
 * (step) (v) calls the function step declares, which nothing proves pure,
 * and the strict preset reports TWICE(wrap(1)).
 */

#define TWICE(x) ((x) + (x))

int step(int);

static int other(void) {
    typedef int step;
    step q = 0;
    return q;
}

static int wrap(int v) {
    return (step) (v);
}

int use(void) {
    return TWICE(wrap(1)) + other();  // Expect: here
}
