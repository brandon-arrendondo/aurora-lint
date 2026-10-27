/*
 * Rule: PRE31-C
 * Status: FAIL - Should trigger PRE31-C violation
 * Expect: default=clean strict=violation
 * Reason: foo_t is declared a function here, so (foo_t) (v) calls it
 * rather than casting, and nothing proves the function pure, so the
 * strict preset reports TWICE(wrap(1)).
 */

#define TWICE(x) ((x) + (x))

int foo_t(int);

static int wrap(int v) {
    return (foo_t) (v);
}

int use(void) {
    return TWICE(wrap(1));  // Expect: here
}
