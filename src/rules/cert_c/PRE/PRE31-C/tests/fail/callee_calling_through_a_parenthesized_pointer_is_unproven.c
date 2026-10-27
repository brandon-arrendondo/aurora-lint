/*
 * Rule: PRE31-C
 * Status: FAIL - Should trigger PRE31-C violation
 * Expect: default=clean strict=violation
 * Reason: call's body calls through (hook), a pointer, which nothing
 * proves pure, so the strict preset reports TWICE(call(1)).
 */

#define TWICE(x) ((x) + (x))

static int (*hook)(int);

static int call(int v) {
    return (hook) (v);
}

int use(void) {
    return TWICE(call(1));  // Expect: here
}
